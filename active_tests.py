"""
active_tests.py — Active Auth + IDOR Tester
===========================================
Performs active security tests on discovered endpoints:
  1. Auth Stripping (removing tokens/cookies)
  2. Two-Account IDOR (accessing Account A with Account B's token)
  3. Header/Cookie focus (testing which credential gives access)

Strategy:
  - Fetch history for the target
  - Filter for "interesting" endpoints (API, REST, JSON)
  - For each, perform a baseline request (Account A)
  - Then perform unauthorized and cross-account requests
  - Compare responses to find vulnerabilities
"""

import os
import json
import time
import asyncio
import ssl
import urllib.request
import urllib.error
from datetime import datetime
from urllib.parse import urlparse
from dataclasses import dataclass, field

from config import BurpConfig, GroqConfig, OllamaConfig
from models import SessionConfig, ActiveFinding, ActiveTestRun
from pipeline import (
    BurpMCPClient, get_request_response_text,
    parse_request_line, parse_target, in_scope
)


# ─────────────────────────────────────────────
# HTTP Helper (Direct)
# ─────────────────────────────────────────────

class Requester:
    def __init__(self, delay: float = 0.5, timeout: int = 12):
        self.delay   = delay
        self.timeout = timeout
        self.ctx     = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode    = ssl.CERT_NONE
        self._last   = 0.0

    async def request(self, method: str, url: str, body: str = "",
                      cookies: str = "", auth: str = "",
                      headers: dict = None) -> tuple[int, str]:
        # Rate limit
        elapsed = time.time() - self._last
        if elapsed < self.delay:
            await asyncio.sleep(self.delay - elapsed)
        self._last = time.time()

        hdrs = {
            "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            "Accept": "application/json, text/html, */*",
        }
        if cookies:
            hdrs["Cookie"] = cookies
        if auth:
            hdrs["Authorization"] = auth
        if headers:
            hdrs.update(headers)

        data = body.encode() if body else None
        
        try:
            req = urllib.request.Request(
                url, data=data, headers=hdrs, method=method
            )
            # Run in thread pool since urlopen is blocking
            loop = asyncio.get_event_loop()
            status, body_text = await loop.run_in_executor(
                None, self._sync_request, req
            )
            return status, body_text
        except Exception as ex:
            return 0, str(ex)

    def _sync_request(self, req):
        try:
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=self.ctx
            ) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace")
        except Exception as ex:
            return 0, str(ex)


# ─────────────────────────────────────────────
# LLM Comparison Helper
# ─────────────────────────────────────────────

class LLMAnalyser:
    def __init__(self, groq_cfg: GroqConfig = None, ollama_cfg: OllamaConfig = None):
        self.groq_cfg = groq_cfg
        self.ollama_cfg = ollama_cfg
        self.groq_client = None
        if groq_cfg and groq_cfg.api_key:
            from groq import Groq
            self.groq_client = Groq(api_key=groq_cfg.api_key)

    def is_available(self) -> bool:
        return self.groq_client is not None or (self.ollama_cfg and self.ollama_cfg.model)

    async def compare_responses(self, url: str, method: str, 
                                 body_a: str, body_v: str,
                                 status_a: int, status_v: int) -> tuple[bool, str]:
        """
        Ask LLM if body_v actually contains the same private data as body_a,
        or if it's just a generic success/error/login page.
        """
        if not self.is_available():
            return False, "LLM not available for comparison"

        system = """You are a senior security analyst specializing in IDOR and Broken Auth.
Compare two HTTP responses: 'Baseline' (authenticated user) and 'Test' (unauthorized/other user).
Determine if the 'Test' response actually leaks private data or just shows a generic page.

Rules:
1. If Test contains JSON with user-specific data (emails, IDs, private settings) same as Baseline, it's a VULNERABILITY.
2. If Test is a generic login page, "Unauthorized" message, or empty JSON ({}), it is NOT a vulnerability.
3. If Test is a 'Success' message but contains no private data, it is NOT a vulnerability.

Return ONLY a JSON object: {"vulnerable": true/false, "reason": "short explanation"}"""

        user = f"""Endpoint: {method} {url}
Baseline Status: {status_a}
Test Status: {status_v}

BASELINE RESPONSE (first 1000 chars):
{body_a[:1000]}

TEST RESPONSE (first 1000 chars):
{body_v[:1000]}"""

        try:
            raw_resp = await self._call_llm(system, user)
            # Basic JSON extraction
            match = re.search(r'\{.*\}', raw_resp, re.DOTALL)
            if match:
                data = json.loads(match.group())
                return data.get("vulnerable", False), data.get("reason", "No reason provided")
            return False, "Failed to parse LLM response"
        except Exception as e:
            return False, f"LLM Error: {str(e)}"

    async def _call_llm(self, system: str, user: str) -> str:
        # Prefer Groq if available
        if self.groq_client:
            loop = asyncio.get_event_loop()
            resp = await loop.run_in_executor(None, self._sync_groq_call, system, user)
            return resp
        
        # Fallback to Ollama
        if self.ollama_cfg:
            return await self._call_ollama(system, user)
        
        return ""

    def _sync_groq_call(self, system: str, user: str) -> str:
        response = self.groq_client.chat.completions.create(
            model=self.groq_cfg.model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ],
            temperature=0.1
        )
        return response.choices[0].message.content

    async def _call_ollama(self, system: str, user: str) -> str:
        payload = json.dumps({
            "model": self.ollama_cfg.model,
            "stream": False,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user}
            ]
        }).encode()
        
        loop = asyncio.get_event_loop()
        try:
            req = urllib.request.Request(
                f"{self.ollama_cfg.base_url}/api/chat",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            # Simple sync call in executor
            def do_req():
                with urllib.request.urlopen(req, timeout=30) as r:
                    return json.loads(r.read())["message"]["content"]
            
            return await loop.run_in_executor(None, do_req)
        except Exception:
            return ""


# ─────────────────────────────────────────────
# Parameter & Body Manipulation
# ─────────────────────────────────────────────

class ParameterFuzzer:
    """
    Identifies and swaps IDs in URL and Body to find IDOR.
    If we are testing with Account B's token, we should try to inject 
    Account A's IDs to see if Account B can access Account A's data.
    """
    
    ID_FIELDS = (
        'id', 'uuid', 'user_id', 'userId', 'org_id', 'orgId',
        'project_id', 'projectId', 'account_id', 'accountId',
        'tenant_id', 'tenantId', 'workspace_id', 'workspaceId'
    )

    def __init__(self, session_a: SessionConfig, session_b: SessionConfig):
        self.session_a = session_a
        self.session_b = session_b

    def fuzz_url(self, url: str) -> list[str]:
        """Replace Account B IDs in URL with Account A IDs if found."""
        if not self.session_a.org_id or not self.session_b.org_id:
            return []
        
        variants = []
        if self.session_b.org_id in url:
            variants.append(url.replace(self.session_b.org_id, self.session_a.org_id))
        
        return variants

    def fuzz_body(self, body: str) -> list[str]:
        """Parse JSON body and swap Account B IDs with Account A IDs."""
        if not body or '{' not in body:
            return []
            
        try:
            data = json.loads(body)
            modified = False
            
            # Helper for recursive swap
            def swap_ids(obj):
                nonlocal modified
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if k in self.ID_FIELDS and v == self.session_b.org_id:
                            obj[k] = self.session_a.org_id
                            modified = True
                        elif isinstance(v, (dict, list)):
                            swap_ids(v)
                elif isinstance(obj, list):
                    for item in obj:
                        swap_ids(item)

            # Deep copy and swap
            new_data = json.loads(body)
            swap_ids(new_data)
            
            if modified:
                return [json.dumps(new_data)]
        except Exception:
            pass
            
        return []


# ─────────────────────────────────────────────
# Active Test Runner
# ─────────────────────────────────────────────

class ActiveTestRunner:
    def __init__(self, burp_config: BurpConfig,
                 session_a: SessionConfig,
                 session_b: SessionConfig = None,
                 groq_config: GroqConfig = None,
                 ollama_config: OllamaConfig = None,
                 extra_scope: list[str] = None,
                 delay: float = 1.0):
        self.burp_cfg   = burp_config
        self.session_a  = session_a
        self.session_b  = session_b
        self.groq_cfg   = groq_config
        self.ollama_cfg = ollama_config
        self.extra_scope = extra_scope or []
        self.delay      = delay
        self.req        = Requester(delay=delay)
        self.llm        = LLMAnalyser(groq_config, ollama_config)
        self.fuzzer     = ParameterFuzzer(session_a, session_b) if session_b else None
        self.results    = ActiveTestRun(target="")

    async def run(self, target: str):
        self.results.target = target
        host, _, _ = parse_target(target)
        
        print(f"\n[Active] Starting tests for {target}")
        if self.session_b:
            print(f"[Active] Mode: Two-account IDOR + Auth Strip")
        else:
            print(f"[Active] Mode: Auth Strip only (no second account)")

        if self.llm.is_available():
            print(f"[Active] Smart Diffing: Enabled (Model: {self.groq_cfg.model if self.groq_cfg else self.ollama_cfg.model})")
        else:
            print(f"[Active] Smart Diffing: Disabled (Heuristics only)")

        # 1. Fetch history
        async with BurpMCPClient(self.burp_cfg) as burp:
            print(f"[Active] Fetching Burp history...")
            history = await burp.get_full_history(page_size=500)
        
        # 2. Filter interesting endpoints
        endpoints = self._find_testable_endpoints(history, host)
        print(f"[Active] Found {len(endpoints)} interesting endpoints for testing.")

        # 3. Test each
        for i, (method, url, body) in enumerate(endpoints):
            print(f"[Active] [{i+1}/{len(endpoints)}] {method} {url[:70]}...")
            await self._test_endpoint(method, url, body)
            self.results.tested_count += 1

        # 4. Report
        self._save_report()
        print(f"[Active] Done. {len(self.results.idor_findings)} IDOR, "
              f"{len(self.results.auth_findings)} Auth findings.")

    def _find_testable_endpoints(self, history: list[dict], target_host: str):
        """Find API/REST/JSON endpoints in history."""
        seen = set()
        testable = []

        for item in history:
            req_text, resp_text = get_request_response_text(item)
            method, path, host = parse_request_line(req_text)
            
            if not host or not in_scope(f"https://{host}{path}", target_host, self.extra_scope):
                continue
            
            # Key for deduplication
            key = (method, host, path.split('?')[0])
            if key in seen:
                continue
            
            # Look for API-like markers
            is_api = any(seg in path.lower() for seg in (
                '/api/', '/v1/', '/v2/', '/rest/', '/graphql',
                '/auth/', '/user', '/account', '/settings'
            ))
            
            # Look for JSON markers in response
            is_json = False
            if resp_text and (
                'application/json' in resp_text.lower() or
                resp_text.strip().startswith(('{', '['))
            ):
                is_json = True
            
            if is_api or is_json:
                seen.add(key)
                # Extract body for POST/PUT
                body = ""
                if method in ("POST", "PUT", "PATCH"):
                    parts = req_text.split("\r\n\r\n", 1)
                    if len(parts) > 1:
                        body = parts[1]
                
                testable.append((method, f"https://{host}{path}", body))
        
        return testable

    async def _test_endpoint(self, method: str, url: str, body: str):
        # Account A baseline
        s_a, b_a = await self.req.request(
            method, url, body,
            cookies=self.session_a.cookie,
            auth=self.session_a.auth_header
        )
        
        if s_a not in (200, 201, 204):
            return # Endpoint not working even for baseline

        # --- Test 1: IDOR (Account B accessing A's resource) ---
        if self.session_b:
            # 1.1 Simple credential swap
            s_b, b_b = await self.req.request(
                method, url, body,
                cookies=self.session_b.cookie,
                auth=self.session_b.auth_header
            )
            
            idor, evidence = await self._is_vulnerable(url, method, s_a, b_a, s_b, b_b)
            if idor:
                self._add_idor_finding(url, method, evidence, b_a, b_b, s_a, s_b)

            # 1.2 ID Injection (Fuzzing)
            # If the request was made by B, but with A's ID, it's a stronger IDOR test
            # Current implementation: we swap B's ID for A's ID while using B's token.
            if self.fuzzer:
                url_variants = self.fuzzer.fuzz_url(url)
                body_variants = self.fuzzer.fuzz_body(body)

                for v_url in url_variants:
                    s_v, b_v = await self.req.request(
                        method, v_url, body,
                        cookies=self.session_b.cookie,
                        auth=self.session_b.auth_header
                    )
                    v, e = await self._is_vulnerable(v_url, method, s_a, b_a, s_v, b_v)
                    if v:
                        self._add_idor_finding(v_url, method, f"ID Injection in URL: {e}", b_a, b_v, s_a, s_v)

                for v_body in body_variants:
                    s_v, b_v = await self.req.request(
                        method, url, v_body,
                        cookies=self.session_b.cookie,
                        auth=self.session_b.auth_header
                    )
                    v, e = await self._is_vulnerable(url, method, s_a, b_a, s_v, b_v)
                    if v:
                        self._add_idor_finding(url, method, f"ID Injection in Body: {e}", b_a, b_v, s_a, s_v)

        # --- Test 2: Broken Auth (No credentials) ---
        s_none, b_none = await self.req.request(method, url, body)
        
        vuln, evidence = await self._is_vulnerable(url, method, s_a, b_a, s_none, b_none)
        if vuln:
            self.results.auth_findings.append(ActiveFinding(
                test_type="BROKEN_AUTH",
                severity="CRITICAL",
                endpoint=url,
                method=method,
                description=f"Endpoint accessible without any authentication tokens or cookies.",
                evidence=f"No-auth request returned HTTP {s_none}. {evidence}",
                response_a=b_a[:500],
                response_b=b_none[:500],
                status_a=s_a,
                status_b=s_none,
            ))
            print(f"  [!] 🔴 Auth Bypass found: {url}")

    def _add_idor_finding(self, url, method, evidence, b_a, b_b, s_a, s_b):
        self.results.idor_findings.append(ActiveFinding(
            test_type="IDOR",
            severity="HIGH",
            endpoint=url,
            method=method,
            description=f"Endpoint accessible using Account B's credentials. Possible IDOR or cross-account access.",
            evidence=evidence,
            response_a=b_a[:500],
            response_b=b_b[:500],
            status_a=s_a,
            status_b=s_b,
        ))
        print(f"  [!] 🔴 IDOR found: {url}")

    async def _is_vulnerable(self, url, method, s_a, b_a, s_v, b_v) -> tuple[bool, str]:
        """Compare baseline (A) vs test (V) to see if V is vulnerable."""
        if s_v in (401, 403, 404):
            return False, ""
        
        # Initial heuristic check
        is_suspicious = False
        heuristic_evidence = ""
        
        if s_v in (200, 201, 204):
            # Check for generic error messages in body
            v_lower = b_v.lower()
            if any(msg in v_lower for msg in ("unauthorized", "forbidden", "login required", "sign in")):
                return False, ""
            
            # Compare response lengths and structures
            # DEBUG: print(f"    [Debug] Comparing {len(b_a)} vs {len(b_v)} bytes")
            if len(b_v) > 2 and (abs(len(b_v) - len(b_a)) < (len(b_a) * 0.5) or len(b_v) > 50):
                is_suspicious = True
                heuristic_evidence = f"HTTP {s_v} with {len(b_v)} bytes (A got {len(b_a)} bytes)."

        if not is_suspicious:
            return False, ""

        # Smart Diffing if available
        if self.llm.is_available():
            print(f"    [LLM] Verifying suspicious response...", end="\r")
            is_vuln, reason = await self.llm.compare_responses(url, method, b_a, b_v, s_a, s_v)
            if is_vuln:
                return True, f"LLM Verified: {reason}"
            else:
                return False, ""
        
        return True, heuristic_evidence

    def _save_report(self):
        os.makedirs("reports", exist_ok=True)
        slug = self.results.target.replace("https://","").replace("http://","").replace("/","_")
        path = f"reports/{slug}_active.md"
        
        findings = self.results.idor_findings + self.results.auth_findings
        
        lines = [
            f"# Active Security Test Report — {self.results.target}",
            f"**Date:** {datetime.now().isoformat()}",
            f"**Total Endpoints Tested:** {self.results.tested_count}",
            f"**Findings:** {len(findings)}",
            "",
            "## Summary",
            f"- IDOR Findings: {len(self.results.idor_findings)}",
            f"- Broken Auth Findings: {len(self.results.auth_findings)}",
            "",
        ]
        
        for f in findings:
            lines += [
                f"## [{f.severity}] {f.test_type} — {f.endpoint}",
                f"**Method:** {f.method}",
                f"**Description:** {f.description}",
                f"**Evidence:** {f.evidence}",
                "",
                "### Account A Response (Baseline)",
                f"HTTP {f.status_a}",
                "```json",
                f.response_a[:500],
                "```",
                "",
                "### Test Account Response",
                f"HTTP {f.status_b}",
                "```json",
                f.response_b[:500],
                "```",
                "---",
                "",
            ]
        
        with open(path, "w") as f:
            f.write("\n".join(lines))
        print(f"[Active] Report saved to {path}")
