"""
debug_hosts.py — Show exactly which hosts Burp MCP returns in history
Run: python3 debug_hosts.py
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

            print("Fetching history (count=500, offset=0)...")
            result = await session.call_tool(
                "get_proxy_http_history",
                arguments={"count": 500, "offset": 0}
            )

            raw = ""
            if hasattr(result, "content"):
                for block in result.content:
                    if hasattr(block, "text"):
                        raw += block.text

            print(f"Total chars returned: {len(raw)}")

            # Parse NDJSON
            hosts = {}
            items = 0
            for line in raw.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    req = obj.get("request", "")
                    # Extract host from request
                    for rline in req.splitlines():
                        if rline.lower().startswith("host:"):
                            host = rline.split(":", 1)[-1].strip()
                            hosts[host] = hosts.get(host, 0) + 1
                            break
                    items += 1
                except Exception:
                    continue

            print(f"\nTotal items parsed: {items}")
            print(f"\nHosts in Burp MCP history (sorted by count):")
            for host, count in sorted(hosts.items(), key=lambda x: -x[1]):
                marker = " ← TARGET" if any(
                    t in host for t in ["anthropic", "claude", "coveo", "hackerone"]
                ) else ""
                print(f"  {count:4d}  {host}{marker}")

            # Check if claude.ai is missing
            claude_hosts = [h for h in hosts if "claude" in h or "anthropic" in h]
            if not claude_hosts:
                print("\n⚠  NO claude.ai or anthropic.com requests in MCP history!")
                print("   Burp MCP is filtering them out.")
                print("\n   Fix: In Burp → MCP tab → Auto-Approved HTTP Targets, add:")
                print("   claude.ai, *.claude.ai, anthropic.com, *.anthropic.com")
                print("\n   Also check: Burp → MCP tab → 'Always allow HTTP history access'")
                print("   Make sure that checkbox is ticked.")
            else:
                print(f"\n✓ Found Anthropic/Claude hosts: {claude_hosts}")

asyncio.run(main())
