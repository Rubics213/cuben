"""
credential_harvester.py
=======================
Automatically extracts auth tokens and session cookies from Burp proxy
history. Works on ANY target without configuration.

Strategy:
  1. Search Burp history for ALL requests (not filtered by host)
  2. Extract every Authorization header and every non-tracking cookie
  3. Score and rank credential sets by quality
  4. Group by token to identify distinct accounts
  5. Fall back to guided manual entry if nothing found

No hardcoded targets, no target-specific logic.
"""

import re
import sys
import time
import asyncio
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from config import BurpConfig
from pipeline import (
    BurpMCPClient, extract_history_items,
    parse_request_line, get_request_response_text,
    parse_target
)
from models import SessionConfig


# ─────────────────────────────────────────────
# Known tracking/noise cookies to ignore
# Everything else is kept
# ─────────────────────────────────────────────

IGNORE_COOKIE_PATTERNS = [
    # Analytics
    r'^_ga', r'^_gid', r'^_gat', r'^_gcl',
    r'^_fbp', r'^fbp', r'^_fbc',
    r'^ajs_anonymous',
    r'^amplitude',
    r'^mixpanel',
    r'^segment',
    r'^hotjar',
    r'^hubspot',
    r'^_dd_',          # Datadog
    r'^dd_',
    # Cloudflare noise (not session tokens)
    r'^cf_clearance',
    r'^__cf_bm',
    r'^_cfuvid',
    r'^__cfruid',
    # Stripe noise
    r'^__stripe_mid',
    r'^__stripe_sid',
    # Consent/preferences
    r'consent',
    r'preferences',
    r'cookie_accept',
    r'gdpr',
    r'ccpa',
    r'^ch-prefers',
    r'^app-shell',
    r'optanon',
    # Google OAuth state (not a session)
    r'^g_state',
    # Tracking IDs
    r'^_gcl_au',
    r'anonymous_id',
    # Feature flags / UI prefs
    r'sidebar',
    r'pinned',
    r'theme',
    r'color.scheme',
    r'dark.mode',
    r'seed.done',
]


def is_tracking_cookie(name: str) -> bool:
    """Return True if this cookie is tracking/noise, not a session token."""
    n = name.lower().strip()
    return any(re.search(p, n) for p in IGNORE_COOKIE_PATTERNS)


def looks_like_session_value(value: str) -> bool:
    """
    Return True if a cookie value looks like a session token.
    Heuristic: long, random-looking, no spaces.
    """
    v = value.strip()
    if len(v) < 16:
        return False
    if ' ' in v or '\n' in v:
        return False
    # Must contain alphanumeric chars
    if not re.search(r'[A-Za-z0-9]', v):
        return False
    # JSON values are not session tokens
    if v.startswith('{') or v.startswith('['):
        return False
    return True


# ─────────────────────────────────────────────
# Harvested credential set
# ─────────────────────────────────────────────

@dataclass
class HarvestedCreds:
    auth_header: str = ""       # Authorization header value
    session_cookies: dict = field(default_factory=dict)  # name → value
    custom_auth_headers: dict = field(default_factory=dict)  # x-api-key etc
    org_id: str = ""
    account_hint: str = ""
    source_host: str = ""
    source_endpoint: str = ""

    @property
    def cookie_string(self) -> str:
        return "; ".join(f"{k}={v}" for k, v in self.session_cookies.items())

    @property
    def is_valid(self) -> bool:
        return bool(self.auth_header or self.session_cookies or self.custom_auth_headers)

    @property
    def token_key(self) -> str:
        """Unique key representing this specific auth token."""
        if self.auth_header:
            return self.auth_header.split(" ", 1)[-1][:64]
        if self.session_cookies:
            # Use the longest cookie value as the key
            longest = max(self.session_cookies.values(), key=len)
            return longest[:64]
        return ""

    def score(self) -> int:
        """Higher = better credentials."""
        s = 0
        if self.auth_header:
            s += 20
            token = self.auth_header.split(" ", 1)[-1] if " " in self.auth_header else self.auth_header
            s += min(len(token) // 20, 15)  # longer = better
        if self.session_cookies:
            s += 10
            s += min(len(self.session_cookies) * 2, 10)
            # Bonus for known high-value cookie names
            HIGH_VALUE = ['session', 'sessionkey', 'auth', 'token', 'jwt',
                          'sid', 'access', 'id_token', 'routinghint']
            for name in self.session_cookies:
                if any(h in name.lower() for h in HIGH_VALUE):
                    s += 5
        if self.custom_auth_headers:
            s += 15
        if self.org_id:
            s += 8
        if self.account_hint:
            s += 5
        return s

    def to_session_config(self, name: str = "Account") -> SessionConfig:
        # Build auth header — prefer Authorization, fall back to custom headers
        auth = self.auth_header
        if not auth and self.custom_auth_headers:
            # Use the first custom auth header
            k, v = next(iter(self.custom_auth_headers.items()))
            auth = f"{k} {v}"

        return SessionConfig(
            name=name,
            auth_header=auth,
            cookie=self.cookie_string,
            org_id=self.org_id,
            source_host=self.source_host,
        )


# ─────────────────────────────────────────────
# Extraction from a single raw HTTP request
# ─────────────────────────────────────────────

# Headers that carry authentication (beyond Authorization)
AUTH_HEADER_NAMES = {
    'x-api-key', 'x-auth-token', 'x-session-token',
    'x-session-key', 'x-access-token', 'x-token',
    'x-user-token', 'x-app-token', 'x-client-token',
    'api-key', 'apikey', 'api_key',
}

# Headers that carry org/tenant info
ORG_HEADER_NAMES = {
    'x-org-id', 'x-organization-id', 'x-tenant-id',
    'x-workspace-id', 'x-account-id', 'x-team-id',
}

# Headers that carry user identity
USER_HEADER_NAMES = {
    'x-user-id', 'x-user-email', 'x-username',
    'x-forwarded-user', 'x-authenticated-user',
}


def extract_from_request(raw_request: str) -> HarvestedCreds:
    """
    Extract all auth signals from a raw HTTP request.
    Completely generic — works on any target.
    """
    creds = HarvestedCreds()
    if not raw_request:
        return creds

    lines = raw_request.splitlines()
    in_body = False
    body_lines = []

    # Parse request line for host
    if lines:
        method_line = lines[0].strip()

    for line in lines[1:]:
        if line.strip() == "" and not in_body:
            in_body = True
            continue
        if in_body:
            body_lines.append(line)
            continue

        if not line.strip() or ':' not in line:
            continue

        key, _, val = line.partition(':')
        key_lower = key.strip().lower()
        val = val.strip()

        # Host
        if key_lower == 'host':
            creds.source_host = val

        # Authorization header (the main one)
        elif key_lower == 'authorization':
            if not creds.auth_header or val.lower().startswith('bearer '):
                creds.auth_header = val

        # Cookie header
        elif key_lower == 'cookie':
            for cookie_part in val.split(';'):
                cookie_part = cookie_part.strip()
                if '=' not in cookie_part:
                    continue
                cname, _, cval = cookie_part.partition('=')
                cname = cname.strip()
                cval  = cval.strip()

                if is_tracking_cookie(cname):
                    continue
                if looks_like_session_value(cval):
                    creds.session_cookies[cname] = cval

        # Custom auth headers
        elif key_lower in AUTH_HEADER_NAMES:
            creds.custom_auth_headers[key.strip()] = val

        # Org/tenant headers
        elif key_lower in ORG_HEADER_NAMES and not creds.org_id:
            creds.org_id = val

        # User identity headers
        elif key_lower in USER_HEADER_NAMES and not creds.account_hint:
            creds.account_hint = val

    # Extract org/user from body if JSON
    body = '\n'.join(body_lines).strip()
    if body and not creds.org_id:
        for pattern in [
            r'"org(?:anization)?[_-]?id"\s*:\s*"([^"]{6,64})"',
            r'"tenant[_-]?id"\s*:\s*"([^"]{6,64})"',
            r'"workspace[_-]?id"\s*:\s*"([^"]{6,64})"',
            r'"account[_-]?id"\s*:\s*"([^"]{6,64})"',
        ]:
            m = re.search(pattern, body, re.IGNORECASE)
            if m:
                creds.org_id = m.group(1)
                break

    # Extract user hint from URL path (e.g. /users/email@example.com)
    if lines and not creds.account_hint:
        path = lines[0].split(' ')[1] if len(lines[0].split(' ')) > 1 else ''
        m = re.search(r'/(?:users?|accounts?|members?|profile)/([^/?@\s]+@[^/?@\s]+)', path)
        if m:
            creds.account_hint = m.group(1)

    # Extract org from URL path — must look like a real ID (UUID or long alphanumeric)
    # NOT a word like "deletion-allowed", "profile", "settings" etc
    UUID_RE = re.compile(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        re.IGNORECASE
    )
    ALPHANUM_ID_RE = re.compile(r'^[a-zA-Z0-9]{8,32}$')

    def is_real_id(candidate: str) -> bool:
        if candidate.lower() in ('true', 'false', 'null', 'me', 'self',
                                  'new', 'edit', 'list', 'all', 'api',
                                  'v1', 'v2', 'v3', 'admin', 'public'):
            return False
        if '-' in candidate and not UUID_RE.match(candidate):
            return False  # hyphenated words like "deletion-allowed"
        if UUID_RE.match(candidate):
            return True
        if ALPHANUM_ID_RE.match(candidate):
            return True
        return False

    if lines and not creds.org_id:
        path = lines[0].split(' ')[1] if len(lines[0].split(' ')) > 1 else ''
        for pattern in [
            r'/org(?:anization)?s?/([a-zA-Z0-9_-]{6,64})(?:/|$|[?])',
            r'/tenant(?:s)?/([a-zA-Z0-9_-]{6,64})(?:/|$|[?])',
            r'/workspace(?:s)?/([a-zA-Z0-9_-]{6,64})(?:/|$|[?])',
            r'[?&]org(?:anization)?[_-]?id=([a-zA-Z0-9_-]{6,64})',
        ]:
            m = re.search(pattern, path, re.IGNORECASE)
            if m:
                candidate = m.group(1)
                if is_real_id(candidate):
                    creds.org_id = candidate
                    break

    return creds


# ─────────────────────────────────────────────
# Main Harvester
# ─────────────────────────────────────────────

class CredentialHarvester:
    def __init__(self, burp_config: BurpConfig, extra_scope: list[str] = None):
        self.burp_config = burp_config
        self.extra_scope = extra_scope or []

    async def _fetch_all_history(self) -> list[dict]:
        """Fetch ALL Burp history — no host filter, all pages."""
        async with BurpMCPClient(self.burp_config) as burp:
            try:
                # Use large page size and paginate to get everything
                all_items = []
                offset = 0
                page_size = 500
                while True:
                    raw = await burp.get_proxy_http_history(
                        count=page_size, offset=offset
                    )
                    from pipeline import extract_history_items
                    page = extract_history_items(raw)
                    if not page:
                        break
                    all_items.extend(page)
                    if len(page) < page_size:
                        break
                    offset += page_size
                return all_items
            except Exception as e:
                print(f"  [Harvester] Error: {e}")
                return []

    def _extract_all_creds(self, items: list[dict],
                           target_host: str) -> list[HarvestedCreds]:
        """
        Extract credentials from ALL history items.
        Prioritise target host but don't exclude others —
        apps often authenticate on a subdomain.
        """
        all_creds: dict[str, HarvestedCreds] = {}  # token_key → creds

        for item in items:
            req_text, resp_text = get_request_response_text(item)
            if not req_text:
                continue

            method, path, req_host = parse_request_line(req_text)

            creds = extract_from_request(req_text)
            if not creds.is_valid:
                continue

            creds.source_endpoint = path

            # Score boost for target-related hosts
            if target_host in req_host or any(
                s in req_host for s in self.extra_scope
            ):
                creds._target_boost = 10
            else:
                creds._target_boost = 0

            # Also check response for user identity clues
            if resp_text and not creds.account_hint:
                m = re.search(
                    r'"(?:email|username|login|name)"\s*:\s*"([^"@]{1,50}@[^"]{1,50})"',
                    resp_text[:3000], re.IGNORECASE
                )
                if m:
                    creds.account_hint = m.group(1)

            # Group by token — same token = same session
            key = creds.token_key
            if not key:
                continue

            if key not in all_creds:
                all_creds[key] = creds
            else:
                # Merge — keep the richer set
                existing = all_creds[key]
                if not existing.org_id and creds.org_id:
                    existing.org_id = creds.org_id
                if not existing.account_hint and creds.account_hint:
                    existing.account_hint = creds.account_hint
                # Merge cookies
                existing.session_cookies.update(creds.session_cookies)

        return list(all_creds.values())

    def _pick_best_two(self, all_creds: list[HarvestedCreds],
                       target_host: str = ""
                       ) -> tuple[Optional[HarvestedCreds],
                                  Optional[HarvestedCreds]]:
        """
        Pick best Account A and Account B.
        MUST prefer credentials from the target host or its related domains.
        Only falls back to other hosts if nothing target-related is found.
        """
        if not all_creds:
            return None, None

        # Split into target-related and unrelated
        target_creds = [c for c in all_creds
                        if getattr(c, '_target_boost', 0) > 0]
        other_creds  = [c for c in all_creds
                        if getattr(c, '_target_boost', 0) == 0]

        # Sort each group by score
        target_creds.sort(key=lambda c: c.score(), reverse=True)
        other_creds.sort(key=lambda c: c.score(), reverse=True)

        # Always prefer target-related credentials
        pool = target_creds if target_creds else other_creds

        if not pool:
            return None, None

        best = pool[0]
        second = None

        # Find a second account — must be target-related AND different token
        second_pool = target_creds if target_creds else other_creds
        for creds in second_pool:
            if creds is best:
                continue
            if creds.token_key == best.token_key:
                continue
            if creds.token_key[:16] == best.token_key[:16]:
                continue
            # Must be same service (same host family) — not Firefox vs Coveo
            if target_creds and getattr(creds, '_target_boost', 0) == 0:
                continue
            second = creds
            break

        return best, second

    async def harvest(self, target: str,
                      max_retries: int = 2,
                      debug: bool = False
                      ) -> tuple[Optional[SessionConfig],
                                 Optional[SessionConfig]]:
        """
        Main entry point. Returns (session_a, session_b).
        Works on any target — no configuration needed.
        """
        host = urlparse(target if '://' in target else f'https://{target}').hostname or target

        print(f"\n{'─'*50}")
        print(f"  Auto-harvesting credentials for {host}...")
        print(f"{'─'*50}")

        for attempt in range(max_retries + 1):
            print(f"  [Harvester] Fetching all Burp history...")
            items = await self._fetch_all_history()
            print(f"  [Harvester] Scanning {len(items)} requests for credentials...")

            all_creds = self._extract_all_creds(items, host)

            if debug:
                print(f"\n  [Debug] Found {len(all_creds)} distinct credential sets:")
                for i, c in enumerate(sorted(all_creds,
                                             key=lambda x: x.score(), reverse=True)[:10]):
                    print(f"    [{i+1}] score={c.score()} host={c.source_host}")
                    print(f"          auth   : {c.auth_header[:50] + '...' if c.auth_header else 'none'}")
                    print(f"          cookies: {list(c.session_cookies.keys())}")
                    print(f"          hint   : {c.account_hint or 'unknown'}")
                    print(f"          org_id : {c.org_id or 'not found'}")
                    print(f"          source : {c.source_endpoint}")
                print()

            if all_creds:
                best, second = self._pick_best_two(all_creds, target_host=host)

                if best:
                    print(f"\n  ✓ Found credentials in Burp history!")
                    print(f"  Account A: {best.account_hint or 'unknown user'} "
                          f"@ {best.source_host}")
                    print(f"    Auth     : {'yes (' + best.auth_header[:40] + '...)' if best.auth_header else 'cookies only'}")
                    print(f"    Cookies  : {list(best.session_cookies.keys())}")
                    print(f"    Org ID   : {best.org_id or 'not found'}")

                    session_a = best.to_session_config(
                        f"Account A ({best.account_hint})" if best.account_hint
                        else "Account A"
                    )

                    session_b = None
                    if second:
                        print(f"\n  ✓ Found second account for IDOR testing!")
                        print(f"  Account B: {second.account_hint or 'unknown user'} "
                              f"@ {second.source_host}")
                        session_b = second.to_session_config(
                            f"Account B ({second.account_hint})" if second.account_hint
                            else "Account B"
                        )
                    else:
                        print(f"\n  ℹ  Only one account in history.")
                        print(f"     For IDOR: log in with a second account through Burp,")
                        print(f"     or pass --token-b / --cookie-b manually.")

                    return session_a, session_b

            # Not found — guide user
            if attempt < max_retries:
                print(f"\n  ✗ No usable credentials found in {len(items)} requests.")
                self._print_browse_guide(target)
                print(f"\n  Waiting 15s then retrying... (Ctrl+C → manual entry)")
                try:
                    time.sleep(15)
                except KeyboardInterrupt:
                    break
            else:
                print(f"\n  ✗ No credentials found after {max_retries + 1} attempts.")

        return self._manual_entry()

    def _print_browse_guide(self, target: str):
        host = urlparse(target if '://' in target else f'https://{target}').hostname or target
        print(f"""
  ┌─ Generate auth traffic through Burp (127.0.0.1:8080) ───────
  │
  │  1. Make sure your browser proxy is set to 127.0.0.1:8080
  │  2. Log in to {target}
  │  3. Browse to authenticated pages:
  │     - Account/profile settings
  │     - API keys or tokens page
  │     - Dashboard or admin panel
  │     - Any page that shows your user data
  │  4. Make at least 5-10 authenticated requests
  │
  │  Then come back here — the tool will retry automatically.
  │
  └──────────────────────────────────────────────────────────────""")

    def _manual_entry(self) -> tuple[Optional[SessionConfig],
                                     Optional[SessionConfig]]:
        print(f"\n{'─'*50}")
        print("  Manual credential entry")
        print(f"{'─'*50}")
        print("""
  How to find your credentials in Burp:
    1. Burp → Proxy → HTTP History
    2. Find any authenticated request (look for /api/, /rest/, /graphql)
    3. In the Request panel, find:
       - Authorization: Bearer <token>   ← copy everything after "Authorization: "
       - Cookie: session=...             ← copy the full cookie header value
    4. Paste below
""")
        try:
            token_a = input("  Account A — Authorization value (or Enter to skip): ").strip()
            cookie_a = input("  Account A — Cookie value (or Enter to skip): ").strip()
            org_a    = input("  Account A — Org/tenant ID (or Enter to skip): ").strip()

            if not token_a and not cookie_a:
                print("  No credentials. Running unauthenticated tests only.")
                return None, None

            session_a = SessionConfig(
                name="Account A (manual)",
                auth_header=token_a,
                cookie=cookie_a,
                org_id=org_a,
            )
            print("  ✓ Account A set.")

            want_b = input("\n  Add second account for IDOR testing? (y/N): ").strip().lower()
            session_b = None
            if want_b == 'y':
                token_b  = input("  Account B — Authorization value: ").strip()
                cookie_b = input("  Account B — Cookie value: ").strip()
                org_b    = input("  Account B — Org/tenant ID: ").strip()
                session_b = SessionConfig(
                    name="Account B (manual)",
                    auth_header=token_b,
                    cookie=cookie_b,
                    org_id=org_b,
                )
                print("  ✓ Account B set.")

            return session_a, session_b

        except (KeyboardInterrupt, EOFError):
            print("\n  Skipped.")
            return None, None
