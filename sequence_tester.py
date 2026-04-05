"""
sequence_tester.py — Stateful Multi-Step Scenario Tester
========================================================
Identifies sequences of related requests (e.g. Create -> View -> Delete)
and tests for IDOR by swapping tokens mid-sequence.
"""

import json
import re
import asyncio
from dataclasses import dataclass, field
from urllib.parse import urlparse

from models import SessionConfig, ActiveFinding, ActiveTestRun
from active_tests import Requester, LLMAnalyser
from pipeline import get_request_response_text, parse_request_line

@dataclass
class Step:
    method: str
    url: str
    body: str
    orig_response: str
    status: int

@dataclass
class Sequence:
    entity_id: str
    steps: list[Step] = field(default_factory=list)

class SequenceTester:
    def __init__(self, burp_config, session_a: SessionConfig, session_b: SessionConfig, 
                 llm: LLMAnalyser = None, delay: float = 1.0):
        self.burp_cfg = burp_config
        self.session_a = session_a
        self.session_b = session_b
        self.llm = llm
        self.req = Requester(delay=delay)
        self.findings = []

    async def run(self, history: list[dict]):
        print(f"\n[Sequence] Analyzing history for multi-step flows...")
        sequences = self._discover_sequences(history)
        
        if not sequences:
            print("[Sequence] No clear multi-step entity flows discovered.")
            return []

        print(f"[Sequence] Found {len(sequences)} potential sequences. Testing cross-account interference...")
        
        for seq in sequences[:5]: # Limit to top 5 sequences for now
            await self._test_sequence(seq)
            
        return self.findings

    def _discover_sequences(self, history: list[dict]) -> list[Sequence]:
        """
        Heuristic: Find a POST that returns a UUID/ID, 
        then find other requests with that same ID.
        """
        sequences = {}
        # 1. Find potential creation IDs
        for item in history:
            req_text, resp_text = get_request_response_text(item)
            method, path, host = parse_request_line(req_text)
            
            if method != "POST" or not resp_text:
                continue

            # Look for ID-like things in response
            # Matches UUIDs or 6+ digit numbers
            ids = re.findall(r'"(?:id|uuid|slug)":\s*"([a-zA-Z0-9-]{6,64})"', resp_text)
            for eid in ids:
                if eid not in sequences:
                    sequences[eid] = Sequence(entity_id=eid)
                    # Add the creation step
                    body = ""
                    parts = req_text.split("\r\n\r\n", 1)
                    if len(parts) > 1: body = parts[1]
                    
                    sequences[eid].steps.append(Step(
                        method=method,
                        url=f"https://{host}{path}",
                        body=body,
                        orig_response=resp_text,
                        status=200 # Placeholder
                    ))

        # 2. Find other requests using those IDs
        for eid, seq in sequences.items():
            for item in history:
                req_text, resp_text = get_request_response_text(item)
                method, path, host = parse_request_line(req_text)
                
                # If ID is in URL or Body and it's NOT the creation step
                if eid in req_text and f"https://{host}{path}" != seq.steps[0].url:
                    body = ""
                    parts = req_text.split("\r\n\r\n", 1)
                    if len(parts) > 1: body = parts[1]
                    
                    seq.steps.append(Step(
                        method=method,
                        url=f"https://{host}{path}",
                        body=body,
                        orig_response=resp_text,
                        status=200
                    ))

        # Only return sequences with at least one follow-up action (e.g. GET/PUT/DELETE)
        return [s for s in sequences.values() if len(s.steps) > 1]

    async def _test_sequence(self, seq: Sequence):
        """
        The Attack:
        1. Account A performs the sequence (Baseline)
        2. Account B tries to perform the follow-up steps using the ID created by Account A.
        """
        if not self.session_b:
            return

        print(f"  [Sequence] Testing entity {seq.entity_id[:10]}... ({len(seq.steps)} steps)")
        
        # Step 0: Create the resource as Account A
        first = seq.steps[0]
        s_a, b_a = await self.req.request(
            first.method, first.url, first.body,
            cookies=self.session_a.cookie,
            auth=self.session_a.auth_header
        )
        
        if s_a not in (200, 201):
            print(f"    [-] Failed to create baseline resource.")
            return

        # Extract the NEW ID from Account A's actual creation (it might be different from history)
        new_id_match = re.search(r'"(?:id|uuid|slug)":\s*"([a-zA-Z0-9-]{6,64})"', b_a)
        if not new_id_match:
            return
        
        real_id = new_id_match.group(1)
        
        # Step 1+: Try follow-up steps as Account B
        for step in seq.steps[1:]:
            # Replace the old ID with the new real ID in URL and Body
            target_url = step.url.replace(seq.entity_id, real_id)
            target_body = step.body.replace(seq.entity_id, real_id)
            
            print(f"    [!] Attacking: {step.method} {target_url[:50]}... as Account B")
            s_b, b_b = await self.req.request(
                step.method, target_url, target_body,
                cookies=self.session_b.cookie,
                auth=self.session_b.auth_header
            )
            
            # Use LLM or Heuristics to see if Account B succeeded in interfering
            is_vuln, reason = await self._is_vulnerable(step, s_b, b_b)
            if is_vuln:
                finding = ActiveFinding(
                    test_type="STATEFUL_IDOR",
                    severity="HIGH",
                    endpoint=target_url,
                    method=step.method,
                    description=f"Account B can interfere with a sequence started by Account A. Action: {step.method}",
                    evidence=f"Step succeeded with HTTP {s_b}. {reason}",
                    response_a=step.orig_response[:500],
                    response_b=b_b[:500],
                    status_a=200,
                    status_b=s_b
                )
                self.findings.append(finding)
                print(f"    [!] 🔴 STATEFUL IDOR: {step.method} {target_url}")

    async def _is_vulnerable(self, step, s_b, b_b) -> tuple[bool, str]:
        if s_b in (401, 403, 404):
            return False, ""
        
        if s_b in (200, 201, 204):
            # If it's a GET, check if data leaked
            if step.method == "GET":
                if self.llm and self.llm.is_available():
                    return await self.llm.compare_responses(step.url, step.method, step.orig_response, b_b, 200, s_b)
                
                if len(b_b) > 50:
                    return True, "Data returned to unauthorized account."
            
            # If it's a DELETE/PUT/PATCH, success code usually means vulnerability
            if step.method in ("DELETE", "PUT", "PATCH"):
                return True, f"Mutation succeeded with {s_b}."

        return False, ""
