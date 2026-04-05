#!/usr/bin/env python3
"""
recon.py — Full Automated Recon Pipeline
=========================================
"""

import asyncio
import argparse
import json
import os
import sys
import time
from datetime import datetime
from urllib.parse import urlparse

from config import BurpConfig, GroqConfig, OllamaConfig
from pipeline import BurpGroqPipeline
from spider import Spider
from enumerator import IDEnumerator, GraphQLTester, detect_id_patterns
from active_tests import ActiveTestRunner, LLMAnalyser
from sequence_tester import SequenceTester
from active_main import parse_args as parse_active_args
from credential_harvester import CredentialHarvester
from models import SessionConfig
from pipeline import (
    BurpMCPClient, get_request_response_text,
    parse_request_line, extract_history_items, parse_target, in_scope
)


def parse_args():
    p = argparse.ArgumentParser(
        description="Full Automated Security Recon Pipeline"
    )
    p.add_argument("--target", required=True,
                   help="Target URL (e.g. https://app.example.com)")
    p.add_argument("--scope", action="append", default=[], metavar="DOMAIN",
                   help="Extra in-scope domains (repeatable)")

    # Stage toggles
    p.add_argument("--no-spider",   action="store_true", help="Skip spidering")
    p.add_argument("--no-pipeline", action="store_true", help="Skip Groq analysis")
    p.add_argument("--no-enum",     action="store_true", help="Skip ID enumeration")
    p.add_argument("--no-graphql",  action="store_true", help="Skip GraphQL testing")
    p.add_argument("--no-active",   action="store_true", help="Skip active tests")

    # Credentials
    p.add_argument("--token-a",  default="", help="Account A auth token")
    p.add_argument("--cookie-a", default="", help="Account A cookies")
    p.add_argument("--org-a",    default="", help="Account A org ID")
    p.add_argument("--token-b",  default="", help="Account B auth token")
    p.add_argument("--cookie-b", default="", help="Account B cookies")
    p.add_argument("--org-b",    default="", help="Account B org ID")
    p.add_argument("--no-auto-harvest", action="store_true",
                   help="Skip auto credential harvesting")

    # Tuning
    p.add_argument("--groq-model",   default=None)
    p.add_argument("--ollama-model", default=None)
    p.add_argument("--batch-size",   type=int, default=25)
    p.add_argument("--delay",        type=float, default=1.0,
                   help="Delay between requests (default: 1.0s)")
    p.add_argument("--spider-depth", type=int, default=2,
                   help="Spider crawl depth (default: 2)")
    p.add_argument("--resume",       action="store_true")
    p.add_argument("--burp-port",    type=int, default=None)
    p.add_argument("--debug-harvest",action="store_true")

    return p.parse_args()


async def resolve_credentials(args, burp_cfg: BurpConfig
                               ) -> tuple[SessionConfig, SessionConfig]:
    """Get Account A and B credentials — auto or manual."""
    if args.token_a or args.cookie_a:
        print("[Creds] Using manually provided credentials.")
        session_a = SessionConfig(
            name="Account A",
            auth_header=args.token_a,
            cookie=args.cookie_a,
            org_id=args.org_a
        )
        session_b = None
        if args.token_b or args.cookie_b:
            session_b = SessionConfig(
                name="Account B",
                auth_header=args.token_b,
                cookie=args.cookie_b,
                org_id=args.org_b
            )
        return session_a, session_b

    if args.no_auto_harvest:
        return None, None

    # Auto-harvest from Burp history
    host, _, _ = parse_target(args.target)
    print(f"\n{'-'*50}")
    print(f"  Auto-harvesting credentials for {host}...")
    print(f"{'-'*50}")

    harvester = CredentialHarvester(burp_cfg)
    try:
        session_a, session_b = await harvester.get_sessions(host, debug=args.debug_harvest)
        return session_a, session_b
    except Exception as e:
        print(f"  [Harvester] Error: {e}")
        return None, None


def print_stage(n, total, name):
    print(f"\n{'━'*60}")
    print(f"  Stage {n}/{total}: {name}")
    print(f"{'━'*60}\n")


async def run_recon(args):
    burp_cfg   = BurpConfig(port=args.burp_port)
    groq_cfg   = GroqConfig(model=args.groq_model)
    ollama_cfg = OllamaConfig(model=args.ollama_model)

    if not groq_cfg.api_key and not args.no_pipeline:
        print("Warning: GROQ_API_KEY not set — pipeline stage will be skipped.")
        args.no_pipeline = True

    # Build stage list
    stages = [
        not args.no_spider,
        not args.no_pipeline,
        not args.no_enum,
        not args.no_graphql,
        not args.no_active,
    ]
    total_stages = sum(stages)
    stage_n = 0

    print(f"\n{'='*60}")
    print(f"  Full Recon: {args.target}")
    print(f"  Stages: {'Spider ' if not args.no_spider else ''}"
          f"{'Pipeline ' if not args.no_pipeline else ''}"
          f"{'IDEnum ' if not args.no_enum else ''}"
          f"{'GraphQL ' if not args.no_graphql else ''}"
          f"{'Active ' if not args.no_active else ''}")
    print(f"{'='*60}")

    # Resolve credentials once, reuse everywhere
    session_a, session_b = await resolve_credentials(args, burp_cfg)
    cookies_a = session_a.cookie if session_a else ""
    auth_a    = session_a.auth_header if session_a else ""
    cookies_b = session_b.cookie if session_b else ""
    auth_b    = session_b.auth_header if session_b else ""

    if session_a:
        print(f"\n[Creds] Account A: {session_a.name}")
    if session_b:
        print(f"[Creds] Account B: {session_b.name}")
    else:
        print("[Creds] No Account B — IDOR tests will be auth-strip only")

    # ── Stage 1: Spider ───────────────────────────────────────
    if not args.no_spider:
        stage_n += 1
        print_stage(stage_n, total_stages, "Auto-Spider")

        spider = Spider(
            burp_config=burp_cfg,
            max_depth=args.spider_depth,
            max_urls=300,
            delay=args.delay,
            cookies=cookies_a,
            auth=auth_a,
        )
        spider_result = await spider.run(args.target, args.scope)

        if spider_result.js_endpoints:
            print(f"\n[Spider] JS API paths found:")
            for ep in spider_result.js_endpoints[:20]:
                print(f"  {ep}")
            if len(spider_result.js_endpoints) > 20:
                print(f"  ... and {len(spider_result.js_endpoints)-20} more")

    # ── Stage 2: Pipeline (Triage + Deep Analysis) ─────────────
    if not args.no_pipeline:
        stage_n += 1
        print_stage(stage_n, total_stages, "Ollama Triage + Groq Analysis")

        pipeline_runner = BurpGroqPipeline(
            burp_config=burp_cfg,
            groq_config=groq_cfg,
            ollama_config=ollama_cfg,
            extra_scope=args.scope,
            rescore=True,
            resume=args.resume,
            batch_size=args.batch_size,
        )
        await pipeline_runner.run(args.target)

    # ── Fetch history for enum + graphql + active stages ───────
    all_history = []
    if not args.no_enum or not args.no_graphql or not args.no_active:
        print("\n[Recon] Fetching full history for history-based stages...")
        async with BurpMCPClient(burp_cfg) as burp:
            all_history = await burp.get_full_history(page_size=500)
        print(f"[Recon] {len(all_history)} history items loaded.")

    # ── Stage 3: ID Enumeration ────────────────────────────────
    if not args.no_enum:
        stage_n += 1
        print_stage(stage_n, total_stages, "Sequential ID Enumeration")

        patterns = detect_id_patterns(all_history)
        # Filter to in-scope patterns
        host = urlparse(args.target).hostname or args.target
        patterns = [p for p in patterns
                    if in_scope(p.template, host, args.scope)]

        if patterns:
            print(f"[IDEnum] Found {len(patterns)} ID patterns:")
            for p in patterns:
                print(f"  {p.method} {p.template} (sample: {p.sample_id})")

            enumerator = IDEnumerator(
                delay=args.delay,
                test_range=5,
            )
            enum_result = enumerator.run(
                patterns,
                cookies_a=cookies_a, auth_a=auth_a,
                cookies_b=cookies_b, auth_b=auth_b,
            )

            if enum_result.findings:
                _save_enum_findings(args.target, enum_result.findings)
        else:
            print("[IDEnum] No ID patterns found in history.")
            print("         Browse more authenticated pages to generate traffic.")

    # ── Stage 4: GraphQL ───────────────────────────────────────
    if not args.no_graphql:
        stage_n += 1
        print_stage(stage_n, total_stages, "GraphQL Introspection + Testing")

        gql_tester = GraphQLTester(delay=args.delay)
        gql_results = gql_tester.find_and_test(
            args.target,
            history_items=all_history,
            cookies=cookies_a, auth=auth_a,
            cookies_b=cookies_b, auth_b=auth_b,
        )

        if gql_results:
            _save_graphql_findings(args.target, gql_results)
        else:
            print("[GraphQL] No GraphQL endpoints found.")

    # ── Stage 5: Active Tests ──────────────────────────────────
    if not args.no_active:
        stage_n += 1
        print_stage(stage_n, total_stages, "Active Auth + IDOR Tests")

        runner = ActiveTestRunner(
            burp_config=burp_cfg,
            session_a=session_a or SessionConfig(name="No auth"),
            session_b=session_b,
            extra_scope=args.scope,
            delay=args.delay,
        )
        await runner.run(args.target)

        # Multi-step sequences
        if session_b and all_history:
            seq_tester = SequenceTester(
                burp_config=burp_cfg,
                session_a=session_a,
                session_b=session_b,
                llm=runner.llm,
                delay=args.delay
            )
            seq_findings = await seq_tester.run(all_history)
            if seq_findings:
                runner.results.idor_findings.extend(seq_findings)
                # Re-save report with sequence findings
                runner._save_report()

    print(f"\n{'='*60}")
    print(f"  Recon Complete: {args.target}")
    print(f"  Reports saved to: reports/")
    print(f"{'='*60}\n")


def _save_enum_findings(target: str, findings: list):
    os.makedirs("reports", exist_ok=True)
    slug = target.replace("https://","").replace("http://","").replace("/","_")
    path = f"reports/{slug}_enum.md"

    lines = [
        f"# ID Enumeration Findings — {target}",
        f"**Date:** {datetime.now().isoformat()}",
        f"**Total findings:** {len(findings)}",
        "",
    ]
    for f in findings:
        lines += [
            f"## [{f.severity}] {f.test_type} — {f.endpoint}",
            f"**Description:** {f.description}",
            f"**Evidence:** {f.evidence}",
            f"```",
            f.response_b[:500] if f.response_b else "",
            f"```",
            "",
        ]
    open(path, "w").write("\n".join(lines))
    print(f"[Report] {path}")


def _save_graphql_findings(target: str, results: list):
    os.makedirs("reports", exist_ok=True)
    slug = target.replace("https://","").replace("http://","").replace("/","_")
    path = f"reports/{slug}_graphql.md"

    lines = [
        f"# GraphQL Assessment — {target}",
        f"**Date:** {datetime.now().isoformat()}",
        "",
    ]
    for r in results:
        lines += [
            f"## Endpoint: {r.endpoint}",
            f"- Introspection allowed: {r.introspection_allowed}",
            f"- Operations found: {len(r.operations)}",
        ]
        if r.operations:
            lines.append("- Operations:")
            for op in r.operations[:30]:
                lines.append(f"  - [{op['type']}] {op['name']}({', '.join(op['args'])})")
        if r.findings:
            lines.append(f"- **Findings ({len(r.findings)}):**")
            for f in r.findings:
                lines += [
                    f"  ### [{f.severity}] {f.description}",
                    f"  Evidence: {f.evidence[:300]}",
                    "",
                ]
        lines.append("")

    open(path, "w").write("\n".join(lines))
    print(f"[Report] {path}")


if __name__ == "__main__":
    asyncio.run(run_recon(parse_args()))
