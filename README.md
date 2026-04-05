<<<<<<< HEAD
# cuben
# cuben
# cuben
=======
# Burp MCP + AI Advanced Recon Framework

Automated security pipeline that combines **Burp Suite** for infrastructure, **Groq/Ollama** for analysis, and **Custom Logic** for stateful IDOR testing.

## Core Capabilities

- **Auto-Spider:** Discovers endpoints, extracts API paths from JS, and replays them through Burp.
- **Smart IDOR Testing:** Uses LLM-verified "Smart Diffing" to compare responses and reduce false positives.
- **Stateful Multi-Step Scenarios:** Automatically identifies *Create → View → Delete* entity flows and tests cross-account interference.
- **Parameter Fuzzing:** Automatically swaps sensitive IDs (org_id, user_id) in JSON bodies and URLs.
- **Auto-Credential Harvesting:** Automatically extracts auth tokens/cookies from Burp history.
- **Hybrid AI:** Triage via local Ollama (free) and deep analysis via Groq (cloud).

---

## Usage

### The Main Command
The primary entry point is `recon.py`. It chains all modules automatically.

```bash
# Basic run (auto-harvests credentials from history)
python recon.py --target https://app.example.com

# Full run with extra scope
python recon.py --target https://app.example.com --scope api.example.com

# Manual credentials (Account A vs Account B for IDOR)
python recon.py --target https://app.example.com \
  --token-a "Bearer eyJ..." --cookie-a "session=A" \
  --token-b "Bearer eyJ..." --cookie-b "session=B"
```

### Help Flag
Run with `--help` to see all tuning options:
```bash
python recon.py --help
```

---

## Configuration

Set your environment variables:

```bash
export GROQ_API_KEY="gsk_..."
export BURP_MCP_COMMAND="path/to/burp-mcp-server" 

# Optional
export GROQ_MODEL="llama-3.3-70b-versatile"
export OLLAMA_MODEL="qwen2.5-coder:7b" 
```

---

## Output

- **Live Console Progress:** Real-time status of spidering, fuzzing, and AI analysis.
- **Auto-Flagging:** HIGH/CRITICAL findings are automatically sent to **Burp Repeater**.
- **Reports:** Detailed Markdown reports saved to `reports/`, including:
  - `target_active.md` (IDOR, Auth, and Multi-step findings)
  - `target_enum.md` (Sequential ID findings)
  - `target_graphql.md` (Introspection findings)
  - `target.md` (Groq deep analysis summary)

---

## File Structure

- `recon.py`: Main orchestrator.
- `spider.py`: Endpoint discovery + JS extraction.
- `active_tests.py`: Smart diffing + ID fuzzing logic.
- `sequence_tester.py`: Stateful multi-step scenario logic.
- `pipeline.py`: AI analysis and Burp MCP client.
- `credential_harvester.py`: Automatic session management.
- `models.py`: Shared data structures.
>>>>>>> ea372c2 (Initial commit: AI-powered Burp MCP Recon Framework with Stateful IDOR and Smart Diffing)
