#!/usr/bin/env python3
"""
Burp MCP + Hybrid AI Pipeline

Ollama (local) → triage + rescore   [free, unlimited, offline]
Groq   (cloud) → deep analysis      [costs tokens, best accuracy]

Usage:
    python main.py --target https://hackerone.com
    python main.py --target https://coveo.com --scope platform.cloud.coveo.com
    python main.py --target https://example.com --resume
    python main.py --target https://example.com --ollama-model llama3.2:3b
    python main.py --target https://example.com --no-rescore --batch-size 10
"""

import asyncio
import argparse
import sys
from config import BurpConfig, GroqConfig, OllamaConfig
from pipeline import BurpGroqPipeline


def parse_args():
    parser = argparse.ArgumentParser(
        description="Burp MCP + Hybrid AI Security Pipeline"
    )
    parser.add_argument("--target", required=True,
                        help="Target URL (e.g. https://example.com)")
    parser.add_argument("--scope", action="append", default=[], metavar="DOMAIN",
                        help="Extra in-scope domains (repeatable)")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from last checkpoint")
    parser.add_argument("--no-rescore", action="store_true",
                        help="Skip severity re-scoring pass")
    parser.add_argument("--batch-size", type=int, default=25,
                        help="Triage batch size (default: 25)")

    # Groq options
    parser.add_argument("--groq-model", default=None,
                        help="Groq model for deep analysis (default: llama-3.1-8b-instant)")

    # Ollama options
    parser.add_argument("--ollama-model", default=None,
                        help="Local Ollama model for triage (default: qwen2.5-coder:3b)")
    parser.add_argument("--ollama-host", default=None,
                        help="Ollama host URL (default: http://127.0.0.1:11434)")
    parser.add_argument("--no-ollama", action="store_true",
                        help="Disable Ollama, use Groq for everything")

    # Burp options
    parser.add_argument("--burp-port", type=int, default=None,
                        help="Burp MCP port (default: 9876)")

    return parser.parse_args()


async def main():
    args = parse_args()

    burp_cfg = BurpConfig()
    if args.burp_port:
        burp_cfg.mcp_port = args.burp_port

    groq_cfg = GroqConfig()
    if args.groq_model:
        groq_cfg.model = args.groq_model
    if not groq_cfg.api_key:
        print("Error: GROQ_API_KEY not set.")
        sys.exit(1)

    ollama_cfg = OllamaConfig()
    if args.ollama_model:
        ollama_cfg.model = args.ollama_model
    if args.ollama_host:
        ollama_cfg.base_url = args.ollama_host
    if args.no_ollama:
        # Point to a non-existent host so OllamaAnalyser marks itself unavailable
        ollama_cfg.base_url = "http://127.0.0.1:1"

    pipeline = BurpGroqPipeline(
        burp_config=burp_cfg,
        groq_config=groq_cfg,
        ollama_config=ollama_cfg,
        extra_scope=args.scope,
        rescore=not args.no_rescore,
        resume=args.resume,
        batch_size=args.batch_size,
    )

    await pipeline.run(args.target)


if __name__ == "__main__":
    asyncio.run(main())
