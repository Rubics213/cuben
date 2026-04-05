"""
Debug script — prints raw output from Burp MCP tools
so we can see exactly what structure is returned.
Run: python debug_burp.py
"""
import asyncio
import json
from mcp import ClientSession
from mcp.client.sse import sse_client

BURP_URL = "http://127.0.0.1:9876/"

async def main():
    async with sse_client(BURP_URL) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # ── 1. Full history (no filter) ────────────────
            print("\n" + "="*60)
            print("RAW: get_proxy_http_history (no filter)")
            print("="*60)
            result = await session.call_tool("get_proxy_http_history", arguments={"count": 20, "offset": 0})

            raw_blocks = []
            if hasattr(result, "content"):
                for block in result.content:
                    if hasattr(block, "text"):
                        raw_blocks.append(block.text)

            raw = "\n".join(raw_blocks)
            print(f"Total chars returned: {len(raw)}")
            print(f"First 2000 chars:\n{raw[:2000]}")

            # Try to parse
            try:
                parsed = json.loads(raw)
                print(f"\nParsed type: {type(parsed)}")
                if isinstance(parsed, list):
                    print(f"List length: {len(parsed)}")
                    if parsed:
                        print(f"\nFirst item keys: {list(parsed[0].keys()) if isinstance(parsed[0], dict) else 'not a dict'}")
                        print(f"First item:\n{json.dumps(parsed[0], indent=2)[:1000]}")
                elif isinstance(parsed, dict):
                    print(f"Dict keys: {list(parsed.keys())}")
                    for k, v in parsed.items():
                        if isinstance(v, list):
                            print(f"  Key '{k}' is a list of {len(v)} items")
                            if v:
                                print(f"  First item: {json.dumps(v[0], indent=2)[:500]}")
            except json.JSONDecodeError:
                print("\nNot JSON — raw text response")
                print("Lines:", raw.count('\n'))

            # ── 2. Regex filter ────────────────────────────
            print("\n" + "="*60)
            print("RAW: get_proxy_http_history_regex (hackerone)")
            print("="*60)
            result2 = await session.call_tool(
                "get_proxy_http_history_regex",
                arguments={"regex": "hackerone", "count": 20, "offset": 0}
            )

            raw2_blocks = []
            if hasattr(result2, "content"):
                for block in result2.content:
                    if hasattr(block, "text"):
                        raw2_blocks.append(block.text)

            raw2 = "\n".join(raw2_blocks)
            print(f"Total chars returned: {len(raw2)}")
            print(f"First 2000 chars:\n{raw2[:2000]}")

            try:
                parsed2 = json.loads(raw2)
                if isinstance(parsed2, list):
                    print(f"\nList of {len(parsed2)} items")
                    if parsed2:
                        print(f"First item keys: {list(parsed2[0].keys()) if isinstance(parsed2[0], dict) else type(parsed2[0])}")
                        print(f"First item:\n{json.dumps(parsed2[0], indent=2)[:1000]}")
            except json.JSONDecodeError:
                print("Not JSON")

            # ── 3. Tool schema ─────────────────────────────
            print("\n" + "="*60)
            print("TOOL SCHEMAS (input params)")
            print("="*60)
            tools = await session.list_tools()
            for t in tools.tools:
                if "history" in t.name.lower() or "proxy" in t.name.lower():
                    print(f"\n{t.name}:")
                    print(f"  Description: {t.description}")
                    print(f"  Input schema: {json.dumps(t.inputSchema, indent=4)}")

asyncio.run(main())
