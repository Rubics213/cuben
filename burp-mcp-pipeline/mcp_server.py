#!/usr/bin/env python3
"""
mcp_server.py — MCP Server for the Burp AI Recon Suite
======================================================
Exposes the automated recon pipeline as an MCP tool.
"""

import asyncio
from mcp.server.fastmcp import FastMCP
from recon import run_recon

# Initialize FastMCP server
mcp = FastMCP("Burp-AI-Recon")

class MockArgs:
    """Helper to mock argparse object for run_recon."""
    def __init__(self, **kwargs):
        self.target = kwargs.get("target")
        self.scope = kwargs.get("scope", [])
        self.no_spider = kwargs.get("no_spider", False)
        self.no_pipeline = kwargs.get("no_pipeline", False)
        self.no_enum = kwargs.get("no_enum", False)
        self.no_graphql = kwargs.get("no_graphql", False)
        self.no_active = kwargs.get("no_active", False)
        self.token_a = kwargs.get("token_a", "")
        self.cookie_a = kwargs.get("cookie_a", "")
        self.org_a = kwargs.get("org_a", "")
        self.token_b = kwargs.get("token_b", "")
        self.cookie_b = kwargs.get("cookie_b", "")
        self.org_b = kwargs.get("org_b", "")
        self.no_auto_harvest = kwargs.get("no_auto_harvest", False)
        self.groq_model = kwargs.get("groq_model", None)
        self.ollama_model = kwargs.get("ollama_model", None)
        self.batch_size = kwargs.get("batch_size", 25)
        self.delay = kwargs.get("delay", 1.0)
        self.spider_depth = kwargs.get("spider_depth", 2)
        self.resume = kwargs.get("resume", False)
        self.burp_port = kwargs.get("burp_port", None)
        self.debug_harvest = kwargs.get("debug_harvest", False)

@mcp.tool()
async def full_recon(target: str, scope: list[str] = None, 
                     no_active: bool = False,
                     token_a: str = "", cookie_a: str = "") -> str:
    """
    Run the full automated recon pipeline on a target.
    Includes spidering, AI analysis, IDOR testing, and GraphQL assessment.
    
    :param target: The target URL (e.g. https://app.example.com)
    :param scope: Optional list of extra in-scope domains.
    :param no_active: If true, skip the active auth/IDOR testing stage.
    :param token_a: Optional manual Authorization header for Account A.
    :param cookie_a: Optional manual Cookie header for Account A.
    """
    args = MockArgs(
        target=target,
        scope=scope or [],
        no_active=no_active,
        token_a=token_a,
        cookie_a=cookie_a
    )
    
    print(f"[MCP] Starting full recon for {target}...")
    try:
        # We run this in the background or wait for it? 
        # For MCP tools, it's better to wait so the user sees the output.
        await run_recon(args)
        return f"Recon completed for {target}. Check the 'reports/' directory for results."
    except Exception as e:
        return f"Error during recon: {str(e)}"

@mcp.tool()
async def test_idor(target: str, token_a: str, token_b: str, 
                    cookie_a: str = "", cookie_b: str = "") -> str:
    """
    Specifically run the Active IDOR and Stateful Sequence tests.
    Requires credentials for two different accounts to be effective.
    """
    args = MockArgs(
        target=target,
        token_a=token_a,
        token_b=token_b,
        cookie_a=cookie_a,
        cookie_b=cookie_b,
        no_spider=True,
        no_pipeline=True,
        no_enum=True,
        no_graphql=True
    )
    
    print(f"[MCP] Starting IDOR tests for {target}...")
    try:
        await run_recon(args)
        return f"IDOR testing completed for {target}. Results saved to reports."
    except Exception as e:
        return f"Error during IDOR test: {str(e)}"

if __name__ == "__main__":
    mcp.run()
