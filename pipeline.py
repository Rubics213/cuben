"""
Burp MCP + Hybrid AI Pipeline
- Ollama (local, free, unlimited) → triage + rescore
- Groq (cloud)                    → deep analysis + executive summary only
Saves ~70% of Groq tokens vs running everything on cloud.
"""

import asyncio
import json
import os
import re
import time
import hashlib
import urllib.request
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional

from mcp import ClientSession
from mcp.client.sse import sse_client
from groq import Groq

from config import BurpConfig, GroqConfig, OllamaConfig
from report import generate_report


# ─────────────────────────────────────────────
# Data Models
# ─────────────────────────────────────────────

@dataclass
class Finding:
    severity: str
    category: str
    endpoint: str
    method: str
    description: str
    evidence: str
    recommendation: str
    raw_request: str = ""
    rescored: bool = False
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def is_high_priority(self) -> bool:
        return self.severity in ("CRITICAL", "HIGH")

    def fingerprint(self) -> str:
        return hashlib.md5(
            f"{self.category}:{self.endpoint}:{self.method}".encode()
        ).hexdigest()


@dataclass
class PipelineRun:
    target: str
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    findings: list[Finding] = field(default_factory=list)
    flagged: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    tech_stack: list[str] = field(default_factory=list)
    analysed_count: int = 0
    skipped_dup: int = 0
    skipped_scope: int = 0


# ─────────────────────────────────────────────
# Retry decorator
# ─────────────────────────────────────────────

def with_retry(max_attempts: int = 4, base_delay: float = 2.0):
    def decorator(fn):
        def wrapper(*args, **kwargs):
            for attempt in range(max_attempts):
                try:
                    return fn(*args, **kwargs)
                except Exception as e:
                    if attempt == max_attempts - 1:
                        raise
                    wait = base_delay * (2 ** attempt)
                    print(f"      [Retry {attempt+1}/{max_attempts}] {e} — waiting {wait:.0f}s")
                    time.sleep(wait)
        return wrapper
    return decorator


# ─────────────────────────────────────────────
# Ollama Client (local, no token limits)
# ─────────────────────────────────────────────

class OllamaAnalyser:
    """Calls a local Ollama model — free, unlimited, offline."""

    def __init__(self, config: OllamaConfig):
        self.config = config
        self._available = None

    def is_available(self) -> bool:
        if self._available is not None:
            return self._available
        try:
            req = urllib.request.urlopen(
                f"{self.config.base_url}/api/tags", timeout=3
            )
            data = json.loads(req.read())
            models = [m["name"] for m in data.get("models", [])]
            model_base = self.config.model.split(":")[0]
            self._available = any(model_base in m for m in models)
            if not self._available:
                print(f"      [Ollama] Model '{self.config.model}' not found. "
                      f"Available: {models}")
            return self._available
        except Exception as e:
            self._available = False
            print(f"      [Ollama] Not reachable at {self.config.base_url}: {e}")
            return False

    def _call(self, system: str, user: str) -> str:
        payload = json.dumps({
            "model":  self.config.model,
            "stream": False,
            "options": {
                "temperature": 0.1,
                "num_predict": self.config.max_tokens,
            },
            "messages": [
                {"role": "system",  "content": system},
                {"role": "user",    "content": user},
            ]
        }).encode()

        req = urllib.request.Request(
            f"{self.config.base_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = json.loads(resp.read())
            return data["message"]["content"]

    def triage_batch(self, summaries: list[dict], tech_stack: list[str]) -> list[dict]:
        """Local triage — runs on qwen2.5-coder or any Ollama model."""
        tech_ctx = f"Tech: {', '.join(tech_stack)}." if tech_stack else ""
        system = f"""Security analyst. {tech_ctx}
Pick HTTP endpoints most worth testing for vulnerabilities.
Focus on: auth, admin, APIs with params, file ops, data exposure.
Return ONLY a JSON array, no explanation."""

        user = f"""Select the best security testing targets.

Return ONLY this JSON (no markdown):
[{{"idx":0,"endpoint":"/path","method":"POST","reason":"why","priority":"HIGH"}}]

Priority: HIGH, MEDIUM, or LOW only.

Requests:
{json.dumps(summaries, indent=2)[:6000]}"""

        try:
            raw = self._call(system, user)
            clean = re.sub(r"```(?:json)?|```", "", raw).strip()
            # Extract JSON array even if model adds text around it
            match = re.search(r'\[.*\]', clean, re.DOTALL)
            if match:
                return json.loads(match.group())
            return json.loads(clean)
        except Exception as e:
            return []

    def rescore_finding(self, finding: Finding, request: str, response: str) -> str:
        """Local severity QA — runs free on Ollama."""
        system = """Security QA engineer. Re-evaluate severity based on evidence.
Be conservative. Downgrade if evidence is weak or theoretical.
Reply with ONLY one word: CRITICAL, HIGH, MEDIUM, LOW, or INFO."""

        user = f"""Re-evaluate this finding's severity.

Category: {finding.category}
Current severity: {finding.severity}
Evidence: {finding.evidence}
Description: {finding.description}

Request (first 800 chars): {request[:800]}
Response (first 800 chars): {response[:800]}

Reply with ONE WORD only."""

        try:
            raw = self._call(system, user).strip().upper()
            # Extract just the severity word if model adds extra text
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                if sev in raw:
                    return sev
            return finding.severity
        except Exception:
            return finding.severity


# ─────────────────────────────────────────────
# Groq Analyser (cloud — used only for deep analysis)
# ─────────────────────────────────────────────

class GroqAnalyser:
    def __init__(self, config: GroqConfig):
        self.client = Groq(api_key=config.api_key)
        self.model = config.model
        self.config = config

    @with_retry(max_attempts=4, base_delay=2.0)
    def _call(self, system: str, user: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model,
            temperature=0.1,
            max_tokens=self.config.max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user",   "content": user}
            ]
        )
        return response.choices[0].message.content

    def analyse_endpoint(self, request: str, response: str,
                         endpoint: str, params: dict,
                         tech_stack: list[str]) -> list[dict]:
        """Deep vulnerability analysis — runs on Groq (cloud)."""
        tech_ctx = f"Tech stack: {', '.join(tech_stack)}. " if tech_stack else ""
        param_ctx = ""
        if params.get("query_params"):
            param_ctx += f"Query params: {params['query_params']}. "
        if params.get("post_params"):
            param_ctx += f"POST params: {params['post_params']}. "
        if params.get("auth_headers"):
            param_ctx += "Auth present: yes. "
        if params.get("cookies"):
            param_ctx += f"Cookies: {params['cookies'][:5]}. "

        system = f"""You are an expert penetration tester.
{tech_ctx}{param_ctx}
Check for: SQLi, XSS, IDOR, auth flaws, info disclosure, SSRF, XXE,
command injection, insecure deserialisation, business logic flaws,
mass assignment, path traversal, GraphQL abuse, OAuth flaws.
Only flag real issues with concrete evidence. Return ONLY valid JSON."""

        user = f"""Analyse for vulnerabilities.

Required JSON:
{{
  "vulnerabilities": [
    {{
      "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
      "category": "e.g. SQL Injection",
      "description": "what the issue is",
      "evidence": "exact snippet proving it",
      "recommendation": "how to fix"
    }}
  ]
}}

Endpoint: {endpoint}

REQUEST:
{request[:3000]}

RESPONSE:
{response[:3000]}"""

        raw = self._call(system, user)
        try:
            clean = re.sub(r"```(?:json)?|```", "", raw).strip()
            return json.loads(clean).get("vulnerabilities", [])
        except Exception:
            return []

    def generate_executive_summary(self, run: PipelineRun) -> str:
        high_findings = [f for f in run.findings if f.severity in ("CRITICAL", "HIGH")]
        other_counts  = {}
        for f in run.findings:
            if f.severity not in ("CRITICAL", "HIGH"):
                other_counts[f.severity] = other_counts.get(f.severity, 0) + 1

        findings_text = json.dumps(
            [{"severity": f.severity, "category": f.category,
              "endpoint": f.endpoint, "description": f.description[:200]}
             for f in high_findings[:15]],
            indent=2
        )
        tech = ", ".join(run.tech_stack) if run.tech_stack else "unknown"

        system = """You are writing an executive summary of a security assessment.
CRITICAL RULE: Only mention findings that are explicitly listed in the findings JSON below.
Do NOT invent, assume, or hallucinate any vulnerabilities not in the list.
If there are no HIGH/CRITICAL findings, say so clearly.
Be factual and concise."""

        user = f"""Write an executive summary based ONLY on these actual findings.

Target: {run.target}
Tech stack: {tech}
Endpoints analysed: {run.analysed_count}
Total findings: {len(run.findings)}
Severity breakdown: HIGH={len(high_findings)}, other={other_counts}

ACTUAL FINDINGS (summarise only these, nothing else):
{findings_text if findings_text != "[]" else "No HIGH or CRITICAL findings were identified."}

Keep it under 250 words. Non-technical. Do not add findings not listed above."""

        return self._call(system, user)


# ─────────────────────────────────────────────
# Hybrid Analyser — routes tasks to right model
# ─────────────────────────────────────────────

class HybridAnalyser:
    """
    Routes:
      triage    → Ollama (local, free, unlimited)
      rescore   → Ollama (local, free, unlimited)
      deep analysis → Groq (cloud, costs tokens)
      summary   → Groq (cloud, costs tokens)
    Falls back to Groq for everything if Ollama unavailable.
    """

    def __init__(self, groq_config: GroqConfig, ollama_config: OllamaConfig):
        self.groq   = GroqAnalyser(groq_config)
        self.ollama = OllamaAnalyser(ollama_config)
        self._ollama_ok = None  # checked lazily

    def _use_ollama(self) -> bool:
        if self._ollama_ok is None:
            self._ollama_ok = self.ollama.is_available()
            if self._ollama_ok:
                print(f"      [Hybrid] Ollama available — "
                      f"triage+rescore → local ({self.ollama.config.model}), "
                      f"deep analysis → Groq ({self.groq.model})")
            else:
                print(f"      [Hybrid] Ollama unavailable — "
                      f"all tasks → Groq ({self.groq.model})")
        return self._ollama_ok

    def triage_batch(self, summaries: list[dict], tech_stack: list[str]) -> list[dict]:
        if self._use_ollama():
            result = self.ollama.triage_batch(summaries, tech_stack)
            if result:
                return result
            # Ollama returned nothing — fall back to Groq silently
        return self.groq_triage_batch(summaries, tech_stack)

    def groq_triage_batch(self, summaries: list[dict], tech_stack: list[str]) -> list[dict]:
        """Groq triage fallback."""
        tech_ctx = f"Detected tech: {', '.join(tech_stack)}" if tech_stack else ""
        system = f"""Security analyst. {tech_ctx}
Pick HTTP endpoints most worth testing. Focus on auth, APIs, params, uploads.
Return ONLY a JSON array."""
        user = f"""Select best security testing targets.

Return ONLY this JSON (no markdown):
[{{"idx":0,"endpoint":"/path","method":"POST","reason":"why","priority":"HIGH"}}]

Requests:
{json.dumps(summaries, indent=2)}"""

        try:
            raw = self.groq._call(system, user)
            clean = re.sub(r"```(?:json)?|```", "", raw).strip()
            match = re.search(r'\[.*\]', clean, re.DOTALL)
            return json.loads(match.group() if match else clean)
        except Exception:
            return []

    def analyse_endpoint(self, request: str, response: str,
                         endpoint: str, params: dict,
                         tech_stack: list[str]) -> list[dict]:
        """Always uses Groq for deep analysis — best accuracy."""
        return self.groq.analyse_endpoint(
            request, response, endpoint, params, tech_stack
        )

    def rescore_finding(self, finding: Finding,
                        request: str, response: str) -> str:
        if self._use_ollama():
            return self.ollama.rescore_finding(finding, request, response)
        return self.groq_rescore(finding, request, response)

    def groq_rescore(self, finding: Finding, request: str, response: str) -> str:
        system = """Security QA. Re-evaluate severity. Be conservative.
Return ONLY one word: CRITICAL, HIGH, MEDIUM, LOW, or INFO."""
        user = f"""Re-evaluate severity.
Category: {finding.category} | Current: {finding.severity}
Evidence: {finding.evidence}
Request: {request[:1000]} | Response: {response[:1000]}
ONE WORD reply."""
        try:
            raw = self.groq._call(system, user).strip().upper()
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                if sev in raw:
                    return sev
        except Exception:
            pass
        return finding.severity

    def generate_executive_summary(self, run: PipelineRun) -> str:
        """Always Groq — needs best reasoning."""
        return self.groq.generate_executive_summary(run)


# ─────────────────────────────────────────────
# Parameter Extractor
# ─────────────────────────────────────────────

def extract_parameters(request: str, url: str) -> dict:
    params = {
        "query_params": [], "post_params": [], "cookies": [],
        "auth_headers": [], "interesting_headers": [], "content_type": "",
    }
    lines = request.splitlines() if isinstance(request, str) else []
    try:
        parsed = urlparse(url)
        params["query_params"] = list(parse_qs(parsed.query).keys())
    except Exception:
        pass

    in_body = False
    body_lines = []
    for line in lines:
        if line.strip() == "" and not in_body:
            in_body = True
            continue
        if not in_body:
            lower = line.lower()
            if lower.startswith("cookie:"):
                cookies = line.split(":", 1)[-1].strip()
                params["cookies"] = [c.split("=")[0].strip()
                                     for c in cookies.split(";") if "=" in c]
            elif lower.startswith("authorization:"):
                params["auth_headers"].append(line.strip())
            elif lower.startswith("content-type:"):
                params["content_type"] = line.split(":", 1)[-1].strip()
            elif any(kw in lower for kw in
                     ("x-api-key", "x-token", "x-auth", "bearer", "x-forwarded",
                      "x-real-ip", "x-original-url", "x-rewrite")):
                params["interesting_headers"].append(line.strip())
        else:
            body_lines.append(line)

    body = "\n".join(body_lines).strip()
    ct = params["content_type"].lower()
    if body:
        if "json" in ct:
            try:
                obj = json.loads(body)
                if isinstance(obj, dict):
                    params["post_params"] = list(obj.keys())
            except Exception:
                pass
        elif "form" in ct or "urlencoded" in ct:
            params["post_params"] = [p.split("=")[0] for p in body.split("&") if "=" in p]
        elif body.startswith("<"):
            params["post_params"] = re.findall(r'<(\w+)', body)[:20]

    return params


# ─────────────────────────────────────────────
# Tech Fingerprinter
# ─────────────────────────────────────────────

TECH_SIGNATURES = {
    "WordPress":  [r"wp-content", r"wp-login"],
    "React":      [r"__NEXT_DATA__", r"react-dom", r"_next/"],
    "Angular":    [r"ng-version", r"ng-app"],
    "Vue":        [r"__vue__", r"vue\.js"],
    "Django":     [r"csrfmiddlewaretoken"],
    "Laravel":    [r"laravel_session", r"XSRF-TOKEN"],
    "ASP.NET":    [r"__VIEWSTATE", r"\.aspx"],
    "Spring":     [r"jsessionid"],
    "Cloudflare": [r"cf-ray", r"cloudflare"],
    "AWS":        [r"x-amz-", r"amazonaws\.com"],
    "GraphQL":    [r"graphql", r"__schema", r"operationName"],
    "JWT":        [r"eyJ[A-Za-z0-9_-]+\.eyJ"],
    "OAuth":      [r"access_token", r"oauth", r"bearer "],
    "Nginx":      [r"nginx"],
    "Apache":     [r"apache"],
}

def fingerprint_tech(items: list[dict]) -> list[str]:
    detected = set()
    sample = "\n".join([
        str(i.get("response") or i.get("rawResponse") or "")
        for i in items[:30]
    ]).lower()
    for tech, patterns in TECH_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, sample, re.IGNORECASE):
                detected.add(tech)
                break
    return sorted(detected)


# ─────────────────────────────────────────────
# Checkpoint Manager
# ─────────────────────────────────────────────

class Checkpoint:
    def __init__(self, target: str):
        os.makedirs(".checkpoints", exist_ok=True)
        slug = re.sub(r'[^\w]', '_', target)
        self.path = f".checkpoints/{slug}.json"
        self.data = self._load()

    def _load(self) -> dict:
        try:
            return json.loads(open(self.path).read())
        except Exception:
            return {"analysed": [], "findings": []}

    def save(self):
        open(self.path, "w").write(json.dumps(self.data, indent=2))

    def mark_done(self, key: str):
        if key not in self.data["analysed"]:
            self.data["analysed"].append(key)
        self.save()

    def is_done(self, key: str) -> bool:
        return key in self.data["analysed"]

    def add_finding(self, finding: Finding):
        self.data["findings"].append(asdict(finding))
        self.save()

    def clear(self):
        self.data = {"analysed": [], "findings": []}
        self.save()


# ─────────────────────────────────────────────
# Scope Filter
# ─────────────────────────────────────────────

ALWAYS_SKIP = [
    "google-analytics.com", "googletagmanager.com", "doubleclick.net",
    "facebook.net", "hotjar.com", "segment.com", "intercom.io",
    "mixpanel.com", "amplitude.com", "cloudfront.net", "jsdelivr.net",
    "unpkg.com", "cdnjs.cloudflare.com", "fonts.googleapis.com",
]

def in_scope(url: str, target_host: str, extra_scope: list[str] = None) -> bool:
    if not url:
        return False
    parsed = urlparse(url if url.startswith("http") else f"http://{url}")
    host = parsed.hostname or ""
    for skip in ALWAYS_SKIP:
        if skip in host:
            return False
    if re.search(r'\.(png|jpg|jpeg|gif|ico|woff|woff2|ttf|eot|mp4|mp3|pdf|css|map)(\?|$)', url):
        return False
    # Skip static JS bundles (versioned asset paths like /assets/*.js, /externals/*.js)
    if re.search(r'/(assets|externals|static|dist|build)/[^/]+\.(js)(\?|$)', url):
        return False
    if target_host in host:
        return True
    if extra_scope:
        for domain in extra_scope:
            if domain in host:
                return True
    return False


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

def parse_request_line(raw_request: str) -> tuple[str, str, str]:
    method, path, host = "GET", "/", ""
    if not raw_request:
        return method, path, host
    lines = raw_request.splitlines()
    if lines:
        parts = lines[0].strip().split(" ")
        if len(parts) >= 2:
            method = parts[0]
            path   = parts[1]
    for line in lines[1:]:
        if line.lower().startswith("host:"):
            host = line.split(":", 1)[-1].strip()
            break
    return method, path, host


def extract_history_items(raw: any) -> list[dict]:
    """Parse Burp NDJSON — one JSON object per line."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("items", "requests", "history", "results", "data"):
            if key in raw and isinstance(raw[key], list):
                return raw[key]
    if isinstance(raw, str):
        items = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    items.append(obj)
            except json.JSONDecodeError:
                continue
        if items:
            return items
        try:
            obj = json.loads(raw)
            return obj if isinstance(obj, list) else [obj]
        except Exception:
            pass
    return []


def item_to_summary(idx: int, item: dict) -> dict:
    raw_req = item.get("request") or item.get("rawRequest") or ""
    method, path, host = parse_request_line(raw_req)
    url = item.get("url") or item.get("requestUrl") or (
        f"https://{host}{path}" if host else path
    )
    params = extract_parameters(raw_req, url)
    raw_resp = item.get("response") or item.get("rawResponse") or ""
    status = ""
    resp_first = raw_resp.splitlines()[0] if raw_resp else ""
    parts = resp_first.split(" ")
    status = parts[1] if len(parts) > 1 else ""
    return {
        "idx":          idx,
        "method":       method,
        "url":          url,
        "path":         path,
        "host":         host,
        "status":       status,
        "query_params": params["query_params"],
        "post_params":  params["post_params"],
        "has_auth":     bool(params["auth_headers"] or params["cookies"]),
        "content_type": params["content_type"],
    }


def get_request_response_text(item: dict) -> tuple[str, str]:
    request  = item.get("request")  or item.get("rawRequest")  or \
               item.get("requestBody")  or ""
    response = item.get("response") or item.get("rawResponse") or \
               item.get("responseBody") or ""
    return str(request), str(response)


def dedup_key(item: dict) -> str:
    raw_req = item.get("request") or item.get("rawRequest") or ""
    method, path, host = parse_request_line(raw_req)
    url = item.get("url") or item.get("requestUrl") or (
        f"https://{host}{path}" if host else path
    )
    parsed = urlparse(url)
    param_names = sorted(parse_qs(parsed.query).keys())
    param_key = ",".join(param_names) if param_names else ""

    body_key = ""
    if method.upper() in ("POST", "PUT", "PATCH"):
        parts = raw_req.split("\n\n", 1) if "\n\n" in raw_req else raw_req.split("\r\n\r\n", 1)
        body = parts[1].strip() if len(parts) > 1 else ""
        if body:
            try:
                obj = json.loads(body)
                if isinstance(obj, dict):
                    op = obj.get("operationName") or obj.get("action") or obj.get("type") or ""
                    top_keys = ",".join(sorted(obj.keys())[:5])
                    body_key = f"|{op}|{top_keys}" if op else f"|{top_keys}"
            except Exception:
                body_key = "|" + ",".join(sorted(
                    p.split("=")[0] for p in body.split("&") if "=" in p
                )[:5])

    return f"{method.upper()}:{host}{parsed.path}[{param_key}]{body_key}"


def parse_target(target: str) -> tuple[str, int, bool]:
    parsed = urlparse(target)
    use_https = parsed.scheme == "https"
    host = parsed.hostname or target
    port = parsed.port or (443 if use_https else 80)
    return host, port, use_https


def batch(lst: list, size: int):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


# ─────────────────────────────────────────────
# Burp MCP Client
# ─────────────────────────────────────────────

class BurpMCPClient:
    def __init__(self, config: BurpConfig):
        self.config = config
        self.session: Optional[ClientSession] = None
        self._available_tools: list[str] = []

    async def __aenter__(self):
        url = f"http://{self.config.mcp_host}:{self.config.mcp_port}/"
        print(f"[Burp] Connecting to {url}")
        self._cm_outer = sse_client(url)
        self._read, self._write = await self._cm_outer.__aenter__()
        self._cm_inner = ClientSession(self._read, self._write)
        self.session = await self._cm_inner.__aenter__()
        await self.session.initialize()
        tools_result = await self.session.list_tools()
        self._available_tools = [t.name for t in tools_result.tools]
        print(f"[Burp] Connected — {len(self._available_tools)} tools available.")
        return self

    async def __aexit__(self, *args):
        await self._cm_inner.__aexit__(*args)
        await self._cm_outer.__aexit__(*args)

    def has_tool(self, name: str) -> bool:
        return name in self._available_tools

    async def call(self, tool: str, args: dict) -> any:
        if not self.has_tool(tool):
            raise ValueError(f"Tool '{tool}' not available.")
        result = await self.session.call_tool(tool, arguments=args)
        if hasattr(result, "content") and isinstance(result.content, list):
            parts = [b.text for b in result.content if hasattr(b, "text")]
            raw = "\n".join(parts)
            try:
                return json.loads(raw)
            except json.JSONDecodeError:
                return raw
        return result

    async def get_proxy_http_history(self, count: int = 200, offset: int = 0) -> any:
        return await self.call("get_proxy_http_history", {"count": count, "offset": offset})

    async def get_proxy_history_regex(self, pattern: str, count: int = 200, offset: int = 0) -> any:
        return await self.call("get_proxy_http_history_regex",
                               {"regex": pattern, "count": count, "offset": offset})

    async def get_proxy_websocket_history(self, count: int = 100, offset: int = 0) -> any:
        if self.has_tool("get_proxy_websocket_history"):
            return await self.call("get_proxy_websocket_history",
                                   {"count": count, "offset": offset})
        return None

    async def get_full_history(self, page_size: int = 200) -> list[dict]:
        all_items, offset = [], 0
        while True:
            raw = await self.get_proxy_http_history(count=page_size, offset=offset)
            page = extract_history_items(raw)
            if not page:
                break
            all_items.extend(page)
            if len(page) < page_size:
                break
            offset += page_size
        return all_items

    async def get_full_history_regex(self, pattern: str, page_size: int = 200) -> list[dict]:
        all_items, offset = [], 0
        while True:
            raw = await self.get_proxy_history_regex(pattern, count=page_size, offset=offset)
            page = extract_history_items(raw)
            if not page:
                break
            all_items.extend(page)
            if len(page) < page_size:
                break
            offset += page_size
        return all_items

    async def create_repeater_tab(self, host: str, port: int,
                                   use_https: bool, request: str,
                                   name: str = "") -> any:
        args = {
            "targetHostname": host, 
            "targetPort": port, 
            "usesHttps": use_https, 
            "content": request
        }
        if name:
            args["tabName"] = name
        return await self.call("create_repeater_tab", args)


# ─────────────────────────────────────────────
# Pipeline Orchestrator
# ─────────────────────────────────────────────

class BurpGroqPipeline:
    def __init__(self, burp_config: BurpConfig,
                 groq_config: GroqConfig,
                 ollama_config: OllamaConfig,
                 extra_scope: list[str] = None,
                 rescore: bool = True,
                 resume: bool = False,
                 batch_size: int = 25):
        self.burp_config = burp_config
        self.ai          = HybridAnalyser(groq_config, ollama_config)
        self.extra_scope = extra_scope or []
        self.rescore     = rescore
        self.resume      = resume
        self.batch_size  = batch_size

    async def run(self, target: str) -> PipelineRun:
        run  = PipelineRun(target=target)
        host, port, use_https = parse_target(target)
        ckpt = Checkpoint(target)
        if not self.resume:
            ckpt.clear()

        print(f"\n{'='*60}")
        print(f"  Pipeline: {target}")
        print(f"  Mode: Ollama triage + Groq deep analysis")
        if self.resume and ckpt.data["analysed"]:
            print(f"  Resuming — {len(ckpt.data['analysed'])} already done")
        print(f"{'='*60}\n")

        async with BurpMCPClient(self.burp_config) as burp:

            # ── Stage 1: Fetch ─────────────────────────────
            print("[1/5] Fetching proxy history from Burp...")
            all_items = await self._fetch_history(burp, host, run)

            if not all_items:
                print("      No history found. Browse the target through Burp proxy first.")
                self._print_summary(run)
                return run

            ws_items = await self._fetch_ws_history(burp, run)
            if ws_items:
                print(f"      + {len(ws_items)} WebSocket messages")

            run.tech_stack = fingerprint_tech(all_items)
            if run.tech_stack:
                print(f"      Tech: {', '.join(run.tech_stack)}")

            # ── Stage 2: Dedup + scope ─────────────────────
            print("[2/5] Deduplicating and filtering scope...")
            unique: dict[str, dict] = {}
            for item in all_items:
                raw_req = item.get("request") or item.get("rawRequest") or ""
                _, path, item_host = parse_request_line(raw_req)
                url = item.get("url") or item.get("requestUrl") or (
                    f"https://{item_host}{path}" if item_host else path
                )
                if not in_scope(url, host, self.extra_scope):
                    run.skipped_scope += 1
                    continue
                key = dedup_key(item)
                if key not in unique:
                    unique[key] = item
                else:
                    run.skipped_dup += 1

            items = list(unique.values())
            print(f"      {len(items)} unique endpoints "
                  f"({run.skipped_dup} dupes, {run.skipped_scope} out-of-scope dropped)")

            if not items:
                print("      Nothing in scope to analyse.")
                self._print_summary(run)
                return run

            # ── Stage 3: Triage (Ollama local) ────────────
            print(f"[3/5] Triage in batches of {self.batch_size}...")
            # Check Ollama availability once here so it prints clearly
            self.ai._use_ollama()

            all_prioritised: list[tuple[dict, dict]] = []
            for chunk_idx, chunk in enumerate(batch(items, self.batch_size)):
                summaries = [item_to_summary(i, item) for i, item in enumerate(chunk)]
                print(f"      Batch {chunk_idx+1}/{-(-len(items)//self.batch_size)}: "
                      f"{len(summaries)} endpoints...", end="\r")

                if len(summaries) <= 5:
                    picks = [{"idx": i, "endpoint": s.get("url", ""),
                               "method": s.get("method", ""), "priority": "HIGH"}
                              for i, s in enumerate(summaries)]
                else:
                    picks = self.ai.triage_batch(summaries, run.tech_stack)
                    if not picks:
                        picks = [{"idx": i, "endpoint": s.get("url", ""),
                                   "method": s.get("method", ""), "priority": "MEDIUM"}
                                  for i, s in enumerate(summaries[:max(1, len(summaries)//2)])]

                for pick in picks:
                    idx = pick.get("idx", 0)
                    if idx < len(chunk):
                        all_prioritised.append((pick, chunk[idx]))

            print(f"\n      Selected {len(all_prioritised)} endpoints for deep analysis.")

            # ── Stage 4: Deep analysis (Groq cloud) ───────
            print("[4/5] Deep analysis (Groq)...")
            seen_findings: set[str] = set()

            for pick, item in all_prioritised:
                endpoint = pick.get("endpoint", "")
                method   = pick.get("method", "")
                priority = pick.get("priority", "MEDIUM")
                ep_key   = f"{method}:{endpoint}"

                if ckpt.is_done(ep_key):
                    print(f"      [SKIP] {endpoint}")
                    continue

                request_text, response_text = get_request_response_text(item)
                params = extract_parameters(request_text, endpoint)
                print(f"      [{priority}] {method} {endpoint}")

                # Small sleep to stay under TPM rate limit (6000 tokens/min on free tier)
                time.sleep(1.5)
                vulns = self.ai.analyse_endpoint(
                    request_text, response_text, endpoint, params, run.tech_stack
                )

                for vuln in vulns:
                    finding = Finding(
                        severity=vuln.get("severity", "INFO"),
                        category=vuln.get("category", "Unknown"),
                        endpoint=endpoint,
                        method=method,
                        description=vuln.get("description", ""),
                        evidence=vuln.get("evidence", ""),
                        recommendation=vuln.get("recommendation", ""),
                        raw_request=request_text,
                    )

                    fp = finding.fingerprint()
                    if fp in seen_findings:
                        continue
                    seen_findings.add(fp)

                    # Rescore HIGH+ with Ollama (free)
                    if self.rescore and finding.is_high_priority():
                        original = finding.severity
                        finding.severity = self.ai.rescore_finding(
                            finding, request_text, response_text
                        )
                        finding.rescored = True
                        if finding.severity != original:
                            print(f"      ↓ Rescored {original}→{finding.severity}: "
                                  f"{finding.category}")

                    run.findings.append(finding)
                    ckpt.add_finding(finding)

                    if finding.is_high_priority():
                        run.flagged.append(finding)
                        label = f"[{finding.severity}] {finding.category}"
                        print(f"      ⚑  AUTO-FLAGGED {label} @ {endpoint}")
                        try:
                            await burp.create_repeater_tab(
                                host=host, port=port, use_https=use_https,
                                request=request_text, name=label,
                            )
                        except Exception as e:
                            run.errors.append(f"Repeater failed for {endpoint}: {e}")

                ckpt.mark_done(ep_key)
                run.analysed_count += 1

            # ── Stage 5: Report ────────────────────────────
            print("\n[5/5] Generating report...")
            if run.findings:
                summary = self.ai.generate_executive_summary(run)
                generate_report(run, summary)
            else:
                print("      No findings to report.")

        self._print_summary(run)
        return run

    async def _fetch_history(self, burp: BurpMCPClient,
                              host: str, run: PipelineRun) -> list[dict]:
        try:
            items = await burp.get_full_history_regex(re.escape(host))
            if items:
                print(f"      {len(items)} items via regex filter.")
                return items
        except Exception as e:
            run.errors.append(f"Regex filter error: {e}")
        try:
            all_items = await burp.get_full_history()
            def _host(i):
                raw = i.get("request") or i.get("rawRequest") or ""
                _, _, h = parse_request_line(raw)
                return h or i.get("url") or ""
            items = [i for i in all_items if host in _host(i)] or all_items
            print(f"      {len(items)} items from full history.")
            return items
        except Exception as e:
            run.errors.append(f"History fetch error: {e}")
        return []

    async def _fetch_ws_history(self, burp: BurpMCPClient,
                                 run: PipelineRun) -> list[dict]:
        try:
            raw = await burp.get_proxy_websocket_history(count=100, offset=0)
            if raw:
                return extract_history_items(raw)
        except Exception as e:
            run.errors.append(f"WebSocket history error: {e}")
        return []

    def _print_summary(self, run: PipelineRun):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in run.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        print(f"\n{'='*60}")
        print(f"  Pipeline Complete — {run.target}")
        print(f"{'='*60}")
        print(f"  Endpoints analysed : {run.analysed_count}")
        print(f"  Dupes skipped      : {run.skipped_dup}")
        print(f"  Out-of-scope skip  : {run.skipped_scope}")
        print(f"  Total findings     : {len(run.findings)}")
        print(f"  Auto-flagged (H+)  : {len(run.flagged)}")
        if run.tech_stack:
            print(f"  Tech stack         : {', '.join(run.tech_stack)}")
        print()
        for sev, count in counts.items():
            if count:
                icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🔵","INFO":"⚪"}[sev]
                print(f"  {icon} {sev:<10}: {count}")
        if run.errors:
            print(f"\n  Errors ({len(run.errors)}):")
            for e in run.errors:
                print(f"    - {e}")
        slug = run.target.replace("https://","").replace("http://","").replace("/","_")
        print(f"\n  Report: reports/{slug}.md")
        print(f"{'='*60}\n")
