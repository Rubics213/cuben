"""
enumerator.py — Generic ID Enumeration + GraphQL Introspection
==============================================================

ID Enumeration:
  - Finds numeric/UUID IDs in captured requests
  - Tests sequential IDs with both accounts (IDOR detection)
  - Works on /api/submissions/123, /reports/456, /users/789 etc.
  - No hardcoded paths — discovers patterns from actual traffic

GraphQL Introspection:
  - Detects GraphQL endpoints automatically
  - Runs introspection to map full schema
  - Generates test requests for every query/mutation
  - Tests each operation with and without auth
  - Detects: missing auth, IDOR via args, info disclosure
"""

import re
import ssl
import json
import time
import asyncio
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from urllib.parse import urlparse
from typing import Optional

from pipeline import (
    BurpMCPClient, extract_history_items,
    parse_request_line, get_request_response_text,
    parse_target
)
from config import BurpConfig
from models import ActiveFinding


# ─────────────────────────────────────────────
# HTTP Helper
# ─────────────────────────────────────────────

class Requester:
    def __init__(self, delay: float = 0.5, timeout: int = 12):
        self.delay   = delay
        self.timeout = timeout
        self.ctx     = ssl.create_default_context()
        self.ctx.check_hostname = False
        self.ctx.verify_mode    = ssl.CERT_NONE
        self._last   = 0.0

    def get(self, url: str, cookies: str = "", auth: str = "",
            headers: dict = None) -> tuple[int, str]:
        return self._request("GET", url, cookies=cookies, auth=auth,
                             headers=headers)

    def post(self, url: str, body: str, cookies: str = "",
             auth: str = "", content_type: str = "application/json"
             ) -> tuple[int, str]:
        return self._request("POST", url, body=body, cookies=cookies,
                             auth=auth, content_type=content_type)

    def _request(self, method: str, url: str, body: str = "",
                 cookies: str = "", auth: str = "",
                 content_type: str = "application/json",
                 headers: dict = None) -> tuple[int, str]:
        elapsed = time.time() - self._last
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self._last = time.time()

        hdrs = {
            "User-Agent": "Mozilla/5.0 (compatible; SecurityScanner/1.0)",
            "Accept": "application/json, text/html, */*",
        }
        if cookies:
            hdrs["Cookie"] = cookies
        if auth:
            hdrs["Authorization"] = auth
        if body:
            hdrs["Content-Type"] = content_type
        if headers:
            hdrs.update(headers)

        data = body.encode() if body else None
        try:
            req = urllib.request.Request(
                url, data=data, headers=hdrs, method=method
            )
            with urllib.request.urlopen(
                req, timeout=self.timeout, context=self.ctx
            ) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace")
        except Exception as ex:
            return 0, str(ex)


# ─────────────────────────────────────────────
# ID Pattern Detector
# ─────────────────────────────────────────────

# Regex for IDs in URL paths
NUMERIC_ID = re.compile(r'/(\d{1,12})(?:/|$|\?)')
UUID_ID     = re.compile(
    r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$|\?)',
    re.IGNORECASE
)
SLUG_ID = re.compile(r'/([a-z0-9]{8,32})(?:/|$|\?)', re.IGNORECASE)


@dataclass
class IDPattern:
    template: str      # e.g. "https://api.example.com/reports/{id}"
    id_type: str       # "numeric" | "uuid" | "slug"
    sample_id: str     # The original ID seen in traffic
    method: str        # GET / POST etc
    host: str


def detect_id_patterns(items: list[dict]) -> list[IDPattern]:
    """
    Scan Burp history and find URL patterns containing IDs.
    Returns deduplicated list of patterns with template URLs.
    """
    patterns: dict[str, IDPattern] = {}

    for item in items:
        req, _ = get_request_response_text(item)
        method, path, host = parse_request_line(req)
        if not host or not path:
            continue

        url = f"https://{host}{path}"

        # Try numeric IDs
        for m in NUMERIC_ID.finditer(path):
            id_val = m.group(1)
            # Skip obvious non-IDs (version numbers, pagination)
            if int(id_val) < 1000 and len(id_val) < 4:
                continue
            template = NUMERIC_ID.sub('/{id}', path, count=1)
            key = f"{method}:{host}{template}"
            if key not in patterns:
                patterns[key] = IDPattern(
                    template=f"https://{host}{template}",
                    id_type="numeric",
                    sample_id=id_val,
                    method=method,
                    host=host,
                )

        # Try UUIDs
        for m in UUID_ID.finditer(path):
            id_val = m.group(1)
            template = UUID_ID.sub('/{id}', path, count=1)
            key = f"{method}:{host}{template}"
            if key not in patterns:
                patterns[key] = IDPattern(
                    template=f"https://{host}{template}",
                    id_type="uuid",
                    sample_id=id_val,
                    method=method,
                    host=host,
                )

    return list(patterns.values())


# ─────────────────────────────────────────────
# ID Enumerator
# ─────────────────────────────────────────────

@dataclass
class EnumResult:
    findings: list[ActiveFinding] = field(default_factory=list)
    tested: int = 0
    errors: list[str] = field(default_factory=list)


class IDEnumerator:
    """
    Tests ID-based endpoints for IDOR by:
    1. Fetching with Account A's ID using Account A's token (baseline)
    2. Fetching with Account A's ID using Account B's token (IDOR test)
    3. Fetching with sequential/nearby IDs using both tokens
    """

    def __init__(self, delay: float = 1.0, test_range: int = 5):
        self.delay      = delay
        self.test_range = test_range  # How many sequential IDs to test
        self.req        = Requester(delay=delay)

    def run(self, patterns: list[IDPattern],
            cookies_a: str, auth_a: str,
            cookies_b: str = "", auth_b: str = "") -> EnumResult:
        result = EnumResult()

        print(f"\n[IDEnum] Testing {len(patterns)} ID patterns...")

        for pattern in patterns:
            print(f"[IDEnum] Pattern: {pattern.method} {pattern.template}")

            # Build test IDs
            test_ids = self._generate_test_ids(
                pattern.sample_id, pattern.id_type
            )

            for test_id in test_ids:
                url = pattern.template.replace('{id}', test_id)

                # Baseline — Account A fetching with own token
                status_a, body_a = self.req.get(url, cookies_a, auth_a)
                result.tested += 1

                if status_a not in (200, 201):
                    continue  # Endpoint doesn't return data for this ID

                # Test 1: Account B accessing Account A's resource
                if cookies_b or auth_b:
                    status_b, body_b = self.req.get(url, cookies_b, auth_b)

                    idor, evidence = self._compare_responses(
                        body_a, body_b, status_a, status_b
                    )
                    if idor:
                        finding = ActiveFinding(
                            test_type="IDOR",
                            severity="HIGH",
                            endpoint=url,
                            method=pattern.method,
                            description=(
                                f"Account B can access resource at "
                                f"{pattern.template} with ID {test_id}. "
                                f"Possible unauthorised cross-account access."
                            ),
                            evidence=evidence,
                            response_a=body_a[:400],
                            response_b=body_b[:400],
                            status_a=status_a,
                            status_b=status_b,
                        )
                        result.findings.append(finding)
                        print(f"[IDEnum] 🔴 IDOR: {url}")

                # Test 2: No-auth access
                status_none, body_none = self.req.get(url)
                if status_none in (200, 201) and len(body_none.strip()) > 100:
                    if body_none.strip().startswith(('{', '[')):
                        finding = ActiveFinding(
                            test_type="BROKEN_AUTH",
                            severity="CRITICAL",
                            endpoint=url,
                            method=pattern.method,
                            description=f"Resource accessible without any authentication",
                            evidence=f"HTTP {status_none} with {len(body_none)} bytes, no auth required",
                            response_b=body_none[:400],
                            status_a=status_a,
                            status_b=status_none,
                        )
                        result.findings.append(finding)
                        print(f"[IDEnum] 🔴 NO AUTH: {url}")

        print(f"[IDEnum] Done — {result.tested} requests, "
              f"{len(result.findings)} findings")
        return result

    def _generate_test_ids(self, sample_id: str, id_type: str) -> list[str]:
        """Generate IDs to test around a sample."""
        ids = [sample_id]

        if id_type == "numeric":
            try:
                n = int(sample_id)
                # Test nearby IDs
                for delta in range(1, self.test_range + 1):
                    if n - delta > 0:
                        ids.append(str(n - delta))
                    ids.append(str(n + delta))
                # Test boundary values
                ids.extend(['1', '2', '3', '0', '-1', '999999999'])
            except ValueError:
                pass
        elif id_type == "uuid":
            # For UUIDs just test the original — can't enumerate sequentially
            # but we still test auth bypass
            ids = [sample_id]

        return ids

    def _compare_responses(self, body_a: str, body_b: str,
                           status_a: int, status_b: int) -> tuple[bool, str]:
        """Check if Account B got real data it shouldn't have."""
        if status_b in (401, 403, 404):
            return False, ""
        if status_b not in (200, 201):
            return False, ""
        if len(body_b.strip()) < 50:
            return False, ""

        # Both returned data — check if B got meaningful content
        body_b_clean = body_b.strip()
        has_data = (
            body_b_clean.startswith('{') or
            body_b_clean.startswith('[') or
            any(k in body_b_clean for k in (
                '"id"', '"email"', '"user"', '"token"',
                '"data"', '"result"', '"name"',
            ))
        )

        if has_data:
            # Check if responses are suspiciously similar (same data returned)
            overlap = len(set(body_a[:200].split()) &
                         set(body_b[:200].split()))
            if overlap > 5:
                return True, (
                    f"Account B (HTTP {status_b}) received "
                    f"{len(body_b)} bytes of data. "
                    f"Response overlaps with Account A's response."
                )

        return False, ""


# ─────────────────────────────────────────────
# GraphQL Introspection + Tester
# ─────────────────────────────────────────────

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind ofType { name kind } } }
      }
      inputFields {
        name
        type { name kind ofType { name kind } }
      }
    }
  }
}
"""


@dataclass
class GraphQLResult:
    endpoint: str = ""
    schema: dict = field(default_factory=dict)
    operations: list[dict] = field(default_factory=list)
    findings: list[ActiveFinding] = field(default_factory=list)
    introspection_allowed: bool = False


class GraphQLTester:
    """
    Detects and tests GraphQL endpoints generically.
    No hardcoded operation names — discovers everything via introspection.
    """

    # Common GraphQL endpoint paths
    GRAPHQL_PATHS = [
        '/graphql', '/api/graphql', '/v1/graphql', '/v2/graphql',
        '/query', '/api/query', '/gql', '/api/gql',
        '/graphql/v1', '/graphql/v2',
    ]

    def __init__(self, delay: float = 1.0):
        self.delay = delay
        self.req   = Requester(delay=delay)

    def find_and_test(self, target: str, history_items: list[dict],
                      cookies: str = "", auth: str = "",
                      cookies_b: str = "", auth_b: str = ""
                      ) -> list[GraphQLResult]:
        """
        Find GraphQL endpoints from history + common paths, then test each.
        """
        host, _, use_https = parse_target(target)
        base = f"https://{host}"
        results = []

        # Detect from history
        endpoints = set()
        for item in history_items:
            req, resp = get_request_response_text(item)
            method, path, item_host = parse_request_line(req)
            if not item_host:
                continue

            # GraphQL detection signals
            is_graphql = (
                'graphql' in path.lower() or
                '"query"' in req or
                '"operationName"' in req or
                '"__schema"' in resp or
                'application/graphql' in req.lower()
            )
            if is_graphql:
                endpoints.add(f"https://{item_host}{path.split('?')[0]}")

        # Add common paths
        for path in self.GRAPHQL_PATHS:
            endpoints.add(f"{base}{path}")
            # Also try on any extra subdomains found in history
            seen_hosts = set()
            for item in history_items:
                req, _ = get_request_response_text(item)
                _, _, item_host = parse_request_line(req)
                if item_host and host in item_host:
                    seen_hosts.add(item_host)
            for h in seen_hosts:
                endpoints.add(f"https://{h}{path}")

        print(f"\n[GraphQL] Testing {len(endpoints)} potential endpoints...")

        for endpoint in endpoints:
            result = self._test_endpoint(
                endpoint, cookies, auth, cookies_b, auth_b
            )
            if result.introspection_allowed or result.findings:
                results.append(result)
                print(f"[GraphQL] ✓ Found: {endpoint} "
                      f"({'introspectable' if result.introspection_allowed else 'restricted'})")

        return results

    def _test_endpoint(self, endpoint: str,
                       cookies: str, auth: str,
                       cookies_b: str, auth_b: str) -> GraphQLResult:
        result = GraphQLResult(endpoint=endpoint)

        # Test 1: Introspection with auth
        status, body = self.req.post(
            endpoint,
            json.dumps({"query": INTROSPECTION_QUERY}),
            cookies=cookies, auth=auth
        )

        if status == 200:
            try:
                data = json.loads(body)
                schema = data.get("data", {}).get("__schema", {})
                if schema:
                    result.introspection_allowed = True
                    result.schema = schema
                    operations = self._extract_operations(schema)
                    result.operations = operations
                    print(f"[GraphQL]   Schema: {len(operations)} operations")

                    # Test 2: Introspection without auth
                    s2, b2 = self.req.post(
                        endpoint,
                        json.dumps({"query": INTROSPECTION_QUERY})
                    )
                    if s2 == 200:
                        try:
                            d2 = json.loads(b2)
                            if d2.get("data", {}).get("__schema"):
                                result.findings.append(ActiveFinding(
                                    test_type="BROKEN_AUTH",
                                    severity="MEDIUM",
                                    endpoint=endpoint,
                                    method="POST",
                                    description="GraphQL introspection accessible without authentication",
                                    evidence="Full schema returned with no auth token",
                                    status_a=status,
                                    status_b=s2,
                                ))
                        except Exception:
                            pass

                    # Test 3: Test individual operations for auth
                    for op in operations[:10]:  # Test first 10
                        self._test_operation(
                            endpoint, op, result,
                            cookies, auth, cookies_b, auth_b
                        )

            except json.JSONDecodeError:
                pass

        return result

    def _extract_operations(self, schema: dict) -> list[dict]:
        """Extract all queries and mutations from introspection schema."""
        ops = []
        types = {t['name']: t for t in schema.get('types', [])}

        for type_key in ('queryType', 'mutationType'):
            type_info = schema.get(type_key)
            if not type_info:
                continue
            type_name = type_info.get('name')
            if not type_name or type_name not in types:
                continue
            op_type = 'query' if type_key == 'queryType' else 'mutation'
            for field in types[type_name].get('fields') or []:
                args = field.get('args', []) or []
                ops.append({
                    'name': field['name'],
                    'type': op_type,
                    'args': [a['name'] for a in args],
                    'return_type': (field.get('type') or {}).get('name', ''),
                })

        return ops

    def _test_operation(self, endpoint: str, op: dict,
                        result: GraphQLResult,
                        cookies: str, auth: str,
                        cookies_b: str, auth_b: str):
        """Test a single GraphQL operation for auth issues."""
        op_type = op['type']
        op_name = op['name']

        # Build minimal query
        args_str = ""
        if op['args']:
            # Use placeholder values
            arg_vals = []
            for arg in op['args'][:3]:
                if 'id' in arg.lower():
                    arg_vals.append(f'{arg}: "test-id-123"')
                elif 'limit' in arg.lower() or 'first' in arg.lower():
                    arg_vals.append(f'{arg}: 1')
                else:
                    arg_vals.append(f'{arg}: "test"')
            args_str = f"({', '.join(arg_vals)})"

        query = f'{op_type} {{ {op_name}{args_str} }}'
        body  = json.dumps({"query": query, "operationName": None})

        # Test without auth
        s_none, b_none = self.req.post(endpoint, body)
        if s_none == 200:
            try:
                d = json.loads(b_none)
                # Real data returned without auth?
                data = d.get('data', {})
                if data and data.get(op_name) is not None:
                    errors = d.get('errors', [])
                    if not errors:
                        result.findings.append(ActiveFinding(
                            test_type="BROKEN_AUTH",
                            severity="HIGH",
                            endpoint=endpoint,
                            method="POST",
                            description=(
                                f"GraphQL operation '{op_name}' returns data "
                                f"without authentication"
                            ),
                            evidence=f"Query: {query[:200]} | Response: {b_none[:200]}",
                            status_a=200,
                            status_b=s_none,
                        ))
            except Exception:
                pass

        # IDOR: Test with Account B's credentials on Account A's operation
        if (cookies_b or auth_b) and 'id' in str(op['args']).lower():
            s_b, b_b = self.req.post(
                endpoint, body, cookies=cookies_b, auth=auth_b
            )
            s_a, b_a = self.req.post(
                endpoint, body, cookies=cookies, auth=auth
            )
            if s_a == 200 and s_b == 200:
                try:
                    d_a = json.loads(b_a).get('data', {})
                    d_b = json.loads(b_b).get('data', {})
                    if (d_a and d_b and d_a != d_b and
                            d_b.get(op_name) is not None):
                        result.findings.append(ActiveFinding(
                            test_type="IDOR",
                            severity="HIGH",
                            endpoint=endpoint,
                            method="POST",
                            description=(
                                f"GraphQL operation '{op_name}' may expose "
                                f"data across accounts"
                            ),
                            evidence=f"Different data returned for Account A vs B",
                            response_a=b_a[:300],
                            response_b=b_b[:300],
                            status_a=s_a,
                            status_b=s_b,
                        ))
                except Exception:
                    pass
