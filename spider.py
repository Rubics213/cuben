"""
spider.py — Generic Auto-Spider
================================
Crawls a target by:
1. Seeding from existing Burp proxy history
2. Extracting all links/endpoints from responses
3. Replaying new URLs through Burp (so they appear in history for analysis)
4. Repeating until no new endpoints found or max depth reached

Works on any target — no hardcoded paths.
Discovers: HTML links, JS fetch/axios calls, API paths in JS bundles,
           form actions, redirects, sitemap.xml, robots.txt
"""

import re
import ssl
import time
import json
import asyncio
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from urllib.parse import urlparse, urljoin, urlencode
from typing import Optional

from pipeline import (
    BurpMCPClient, extract_history_items,
    parse_request_line, get_request_response_text,
    parse_target, in_scope
)
from config import BurpConfig


# ─────────────────────────────────────────────
# Link Extractor — works on any response
# ─────────────────────────────────────────────

# Patterns that reveal API endpoints and links in any web app
LINK_PATTERNS = [
    # HTML href and src
    r'href=["\']([^"\'#>]{4,})["\']',
    r'src=["\']([^"\'#>]{4,})["\']',
    r'action=["\']([^"\'#>]{4,})["\']',
    # JS fetch/axios/XHR
    r'fetch\(["\']([^"\')\s]{4,})["\']',
    r'axios\.[a-z]+\(["\']([^"\')\s]{4,})["\']',
    r'\.get\(["\']([/][^"\')\s]{3,})["\']',
    r'\.post\(["\']([/][^"\')\s]{3,})["\']',
    r'\.put\(["\']([/][^"\')\s]{3,})["\']',
    r'\.delete\(["\']([/][^"\')\s]{3,})["\']',
    # URL strings in JS
    r'["\'](/(?:api|v[0-9]+|rest|graphql|auth|user|account|admin)[^"\')\s]{0,100})["\']',
    # next.js / react router style routes
    r'path:\s*["\']([/][^"\')\s]{3,})["\']',
    r'route:\s*["\']([/][^"\')\s]{3,})["\']',
    # Template literals
    r'`(/[^`\s$]{3,})`',
    # Redirect headers in responses
    r'[Ll]ocation:\s*([^\r\n]+)',
]

# Skip these when found
SKIP_EXTENSIONS = re.compile(
    r'\.(png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|mp4|mp3|pdf|zip|gz|tar)$',
    re.IGNORECASE
)
SKIP_PREFIXES = ('mailto:', 'tel:', 'javascript:', 'data:', '#', 'void(')


def extract_links(base_url: str, response_body: str) -> list[str]:
    """Extract all URLs from a response body. Generic — works on HTML and JS."""
    links = set()
    parsed_base = urlparse(base_url)

    for pattern in LINK_PATTERNS:
        for match in re.finditer(pattern, response_body, re.IGNORECASE):
            url = match.group(1).strip().rstrip('/')
            if not url:
                continue
            if any(url.startswith(p) for p in SKIP_PREFIXES):
                continue
            if SKIP_EXTENSIONS.search(url.split('?')[0]):
                continue

            # Resolve relative URLs
            if url.startswith('//'):
                url = f"{parsed_base.scheme}:{url}"
            elif url.startswith('/'):
                url = f"{parsed_base.scheme}://{parsed_base.netloc}{url}"
            elif not url.startswith('http'):
                url = urljoin(base_url, url)

            # Clean up
            url = url.split('#')[0].rstrip('/')
            if url:
                links.add(url)

    return list(links)


def extract_from_js(js_content: str, base_host: str) -> list[str]:
    """
    Extract API paths from JavaScript bundles.
    Finds string literals that look like API paths.
    """
    paths = set()

    # Find all string literals that look like API paths
    for match in re.finditer(
        r'["\`](/(?:api|v[0-9]+|rest|graphql|auth|user|account|admin|'
        r'search|report|submission|profile|setting|payment|webhook|'
        r'notification|message|comment|upload|download|export|import)'
        r'[^"\'`\s]{0,150})["\`]',
        js_content, re.IGNORECASE
    ):
        path = match.group(1)
        # Replace template literal variables with placeholder
        path = re.sub(r'\$\{[^}]+\}', '{id}', path)
        if len(path) > 3:
            paths.add(f"https://{base_host}{path}")

    return list(paths)


# ─────────────────────────────────────────────
# HTTP Fetcher (direct, fast)
# ─────────────────────────────────────────────

class DirectFetcher:
    """Fetches URLs directly without going through Burp proxy."""

    def __init__(self, timeout: int = 10, delay: float = 0.3):
        self.timeout = timeout
        self.delay = delay
        self.ctx = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode = ssl.CERT_NONE
        self._last_request = 0.0

    def fetch(self, url: str, cookies: str = "",
              auth: str = "") -> tuple[int, str, str]:
        """Returns (status, content_type, body)."""
        # Rate limit
        elapsed = time.time() - self._last_request
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last_request = time.time()

        headers = {
            "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            "Accept": "text/html,application/json,*/*",
        }
        if cookies:
            headers["Cookie"] = cookies
        if auth:
            headers["Authorization"] = auth

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=self.ctx
            ) as resp:
                ct = resp.headers.get("Content-Type", "")
                body = resp.read().decode("utf-8", errors="replace")
                return resp.status, ct, body
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            return e.code, "", body
        except Exception:
            return 0, "", ""


# ─────────────────────────────────────────────
# Burp Replayer — sends through Burp so it appears in history
# ─────────────────────────────────────────────

class BurpReplayer:
    """
    Sends requests through Burp's send_http1_request so they appear
    in proxy history and get picked up by the main pipeline.
    """

    def __init__(self, burp: BurpMCPClient):
        self.burp = burp

    def _build_raw_request(self, url: str, method: str = "GET",
                            cookies: str = "", auth: str = "",
                            body: str = "") -> tuple[str, str, int, bool]:
        """Build a raw HTTP request string from a URL."""
        parsed = urlparse(url)
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_https = parsed.scheme == "https"
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"

        lines = [
            f"{method} {path} HTTP/1.1",
            f"Host: {host}",
            "User-Agent: Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            "Accept: text/html,application/json,*/*",
            "Accept-Encoding: gzip, deflate",
            "Connection: close",
        ]
        if cookies:
            lines.append(f"Cookie: {cookies}")
        if auth:
            lines.append(f"Authorization: {auth}")
        if body:
            lines.append(f"Content-Length: {len(body)}")
            lines.append("Content-Type: application/json")
        lines.append("")
        if body:
            lines.append(body)

        return "\r\n".join(lines), host, port, use_https

    async def replay(self, url: str, method: str = "GET",
                     cookies: str = "", auth: str = "",
                     body: str = "") -> tuple[int, str]:
        """Send URL through Burp. Returns (status, response_body)."""
        raw, host, port, use_https = self._build_raw_request(
            url, method, cookies, auth, body
        )
        try:
            result = await self.burp.call("send_http1_request", {
                "targetHostname": host,
                "targetPort": port,
                "usesHttps": use_https,
                "content": raw,
            })
            
            # The MCP tool might return the raw response string directly
            resp = ""
            if isinstance(result, dict):
                resp = result.get("response", "")
            elif isinstance(result, str):
                resp = result
                if resp:
                    # The response looks like: "HttpRequestResponse{httpRequest=..., httpResponse=HTTP/2 307 ..., ...}"
                    # We need to find the start of httpResponse
                    status = 0
                    if "httpResponse=" in resp:
                        res_part = resp.split("httpResponse=", 1)[1]
                        lines = res_part.splitlines()
                        if lines:
                            parts = lines[0].split(" ")
                            try:
                                # parts[1] is the status code
                                if len(parts) > 1:
                                    status = int(parts[1])
                            except ValueError:
                                pass
                    return status, resp

            return 0, ""
        except Exception as e:
            # print(f"    [Replay Error] {e}")
            return 0, str(e)


# ─────────────────────────────────────────────
# Spider
# ─────────────────────────────────────────────

@dataclass
class SpiderResult:
    discovered: list[str] = field(default_factory=list)
    replayed: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    js_endpoints: list[str] = field(default_factory=list)


class Spider:
    def __init__(self, burp_config: BurpConfig,
                 max_depth: int = 3,
                 max_urls: int = 200,
                 delay: float = 0.5,
                 cookies: str = "",
                 auth: str = ""):
        self.burp_config = burp_config
        self.max_depth   = max_depth
        self.max_urls    = max_urls
        self.delay       = delay
        self.cookies     = cookies
        self.auth        = auth
        self.fetcher     = DirectFetcher(delay=delay)

    async def run(self, target: str,
                  extra_scope: list[str] = None) -> SpiderResult:
        """
        Spider a target starting from its proxy history as seeds.
        Discovers new endpoints and replays them through Burp.
        """
        host, port, use_https = parse_target(target)
        extra_scope = extra_scope or []
        result = SpiderResult()

        print(f"\n[Spider] Starting on {target}")
        print(f"         Max depth: {self.max_depth}, Max URLs: {self.max_urls}")

        async with BurpMCPClient(self.burp_config) as burp:
            replayer = BurpReplayer(burp)

            # Seed from existing Burp history
            seeds = await self._get_seeds(burp, host, extra_scope)
            print(f"[Spider] {len(seeds)} seeds from Burp history")

            # Also add standard discovery paths
            seeds.extend(self._standard_paths(target))

            visited: set[str] = set()
            queue: list[tuple[str, int]] = [(url, 0) for url in seeds]

            while queue and len(visited) < self.max_urls:
                url, depth = queue.pop(0)

                if url in visited:
                    continue
                if depth > self.max_depth:
                    continue
                if not self._in_scope(url, host, extra_scope):
                    continue

                visited.add(url)

                # Fetch the URL
                status, ct, body = self.fetcher.fetch(
                    url, self.cookies, self.auth
                )

                if status == 0:
                    continue

                print(f"[Spider] [{status}] {url[:80]}", end="\r")

                if status in (200, 201, 206):
                    result.discovered.append(url)

                    # Extract links from response
                    new_links = extract_links(url, body)

                    # Extract API paths from JS
                    if 'javascript' in ct or url.endswith('.js'):
                        js_paths = extract_from_js(body, host)
                        for jp in js_paths:
                            if jp not in visited:
                                result.js_endpoints.append(jp)
                                # Add to queue for further spidering and replay
                                queue.append((jp, depth + 1))

                    # Queue new in-scope links
                    for link in new_links:
                        if (link not in visited and
                                self._in_scope(link, host, extra_scope)):
                            queue.append((link, depth + 1))

                    # Replay through Burp if it looks like an API endpoint
                    if self._looks_like_api(url):
                        r_status, _ = await replayer.replay(
                            url, cookies=self.cookies, auth=self.auth
                        )
                        if r_status > 0:
                            result.replayed.append(url)

                time.sleep(self.delay)

            print()  # Clear the \r line
            print(f"[Spider] Done — {len(result.discovered)} discovered, "
                  f"{len(result.replayed)} replayed through Burp")
            print(f"[Spider] {len(result.js_endpoints)} API paths extracted from JS")

        return result

    async def _get_seeds(self, burp: BurpMCPClient,
                         host: str, extra_scope: list[str]) -> list[str]:
        """Get seed URLs from existing Burp proxy history."""
        seeds = []
        try:
            all_items = await burp.get_full_history(page_size=500)
            for item in all_items:
                req, _ = get_request_response_text(item)
                method, path, item_host = parse_request_line(req)
                if item_host and (host in item_host or
                                  any(s in item_host for s in extra_scope)):
                    scheme = "https"
                    url = f"{scheme}://{item_host}{path}"
                    seeds.append(url)
        except Exception:
            pass
        return list(set(seeds))

    def _standard_paths(self, target: str) -> list[str]:
        """Universal discovery paths that exist on most web apps."""
        base = target.rstrip('/')
        return [
            f"{base}/robots.txt",
            f"{base}/sitemap.xml",
            f"{base}/.well-known/security.txt",
            f"{base}/api",
            f"{base}/api/v1",
            f"{base}/api/v2",
            f"{base}/graphql",
            f"{base}/swagger.json",
            f"{base}/openapi.json",
            f"{base}/api-docs",
            f"{base}/swagger-ui.html",
            f"{base}/__debug__",
            f"{base}/health",
            f"{base}/status",
            f"{base}/metrics",
        ]

    def _in_scope(self, url: str, host: str,
                  extra_scope: list[str]) -> bool:
        return in_scope(url, host, extra_scope)

    def _looks_like_api(self, url: str) -> bool:
        """True if URL looks like an API endpoint worth replaying."""
        path = urlparse(url).path.lower()
        return any(seg in path for seg in (
            '/api/', '/v1/', '/v2/', '/v3/', '/rest/',
            '/graphql', '/auth/', '/user', '/account',
            '/report', '/submission', '/profile',
            '/admin', '/search', '/upload', '/export',
        ))
