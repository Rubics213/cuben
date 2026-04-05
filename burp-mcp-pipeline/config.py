"""
Configuration for Burp MCP + Hybrid AI Pipeline
"""

import os
from dataclasses import dataclass, field


@dataclass
class BurpConfig:
    mcp_host: str = os.getenv("BURP_MCP_HOST", "127.0.0.1")
    mcp_port: int = int(os.getenv("BURP_MCP_PORT", "9876"))


@dataclass
class GroqConfig:
    api_key: str = field(default_factory=lambda: os.getenv("GROQ_API_KEY", ""))

    # Used ONLY for deep analysis + executive summary
    # Use smaller model to save tokens: llama-3.1-8b-instant
    model: str = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")
    max_tokens: int = 2048


@dataclass
class OllamaConfig:
    # Local Ollama instance — no API key, no token limits
    base_url: str = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")

    # Model for triage + rescore (free, local, unlimited)
    # Install: ollama pull qwen2.5-coder:3b
    model: str = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:3b")

    max_tokens: int = 1024  # Triage responses are short so keep small
