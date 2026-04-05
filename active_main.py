#!/usr/bin/env python3
"""
active_main.py — IDOR + Broken Auth Tester with Auto Credential Harvesting

The tool will:
  1. Automatically extract your auth tokens/cookies from Burp history
  2. If not found, guide you on what to browse and retry
  3. If still nothing, prompt you to enter them manually

Usage:
  # Fully automatic (no args needed if you've browsed the target):
  python active_main.py --target https://coveo.com \\
    --scope platform.cloud.coveo.com

  # Skip auto-harvest, enter manually:
  python active_main.py --target https://coveo.com \\
    --token-a "Bearer eyJ..." --cookie-a "__Host-session=ABC..."

  # Full manual two-account IDOR:
  python active_main.py --target https://coveo.com \\
    --token-a "Bearer eyJ..." --cookie-a "__Host-session=AAA..." --org-a "orgA" \\
    --token-b "Bearer eyJ..." --cookie-b "__Host-session=BBB..." --org-b "orgB"
"""

import asyncio
import argparse
import sys
from config import BurpConfig, GroqConfig, OllamaConfig
from active_tests import ActiveTestRunner
from models import SessionConfig
from credential_harvester import CredentialHarvester


def parse_args():
    parser = argparse.ArgumentParser(
        description="Active IDOR + Broken Auth Tester"
    )
    parser.add_argument("--target", required=True,
                        help="Target URL (e.g. https://coveo.com)")
    parser.add_argument("--scope", action="append", default=[], metavar="DOMAIN",
                        help="Extra in-scope domains (repeatable)")
    parser.add_argument("--delay", type=float, default=1.0,
                        help="Seconds between requests (default: 1.0)")
    parser.add_argument("--burp-port", type=int, default=None)
    parser.add_argument("--no-auto-harvest", action="store_true",
                        help="Skip auto-harvest, go straight to manual entry")
    parser.add_argument("--debug-harvest", action="store_true",
                        help="Print every credential set found in Burp history")

    # Manual overrides (auto-harvest used if these not provided)
    parser.add_argument("--token-a", default="",
                        help="Account A auth token (skips auto-harvest)")
    parser.add_argument("--cookie-a", default="",
                        help="Account A session cookie")
    parser.add_argument("--org-a", default="",
                        help="Account A org/tenant ID")
    parser.add_argument("--token-b", default="",
                        help="Account B auth token (enables IDOR testing)")
    parser.add_argument("--cookie-b", default="",
                        help="Account B session cookie")
    parser.add_argument("--org-b", default="",
                        help="Account B org/tenant ID")

    return parser.parse_args()


async def main():
    args = parse_args()

    burp_cfg   = BurpConfig()
    groq_cfg   = GroqConfig()
    ollama_cfg = OllamaConfig()

    if args.burp_port:
        burp_cfg.mcp_port = args.burp_port

    # ── Credential resolution ──────────────────────────────────────
    session_a = None
    session_b = None

    manual_provided = bool(args.token_a or args.cookie_a)

    if manual_provided:
        # User gave explicit creds — use them directly
        print("[Creds] Using manually provided credentials.")
        session_a = SessionConfig(
            name="Account A",
            auth_header=args.token_a,
            cookie=args.cookie_a,
            org_id=args.org_a,
        )
        if args.token_b or args.cookie_b:
            session_b = SessionConfig(
                name="Account B",
                auth_header=args.token_b,
                cookie=args.cookie_b,
                org_id=args.org_b,
            )

    elif args.no_auto_harvest:
        # Skip auto, go straight to manual prompt
        harvester = CredentialHarvester(burp_cfg, args.scope)
        session_a, session_b = harvester._manual_entry()

    else:
        # Auto-harvest from Burp history (default behaviour)
        print("[Creds] Auto-harvesting credentials from Burp history...")
        harvester = CredentialHarvester(burp_cfg, args.scope)
        session_a, session_b = await harvester.harvest(
            args.target, max_retries=2,
            debug=args.debug_harvest
        )

    if not session_a:
        print("\n[!] No Account A credentials available.")
        print("    Running auth-strip test with no credentials.")
        print("    (This will only test for missing auth, not IDOR)")
        print()

    # ── Mode summary ───────────────────────────────────────────────
    print()
    if session_a and session_b:
        print(f"[Mode] Full IDOR + Broken Auth")
        print(f"       Account A: {session_a.name}")
        print(f"       Account B: {session_b.name}")
        if session_a.org_id:
            print(f"       Org A: {session_a.org_id}")
        if session_b.org_id:
            print(f"       Org B: {session_b.org_id}")
    elif session_a:
        print(f"[Mode] Broken Auth + Auth Strip only")
        print(f"       Account A: {session_a.name}")
        print(f"       No second account — IDOR skipped")
        print(f"       Tip: Browse with a second account through Burp to enable IDOR")
    else:
        print(f"[Mode] Unauthenticated endpoint discovery only")

    # ── Run active tests ───────────────────────────────────────────
    runner = ActiveTestRunner(
        burp_config=burp_cfg,
        session_a=session_a or SessionConfig(name="No auth"),
        session_b=session_b,
        groq_config=groq_cfg,
        ollama_config=ollama_cfg,
        extra_scope=args.scope,
        delay=args.delay,
    )

    await runner.run(args.target)


if __name__ == "__main__":
    asyncio.run(main())
