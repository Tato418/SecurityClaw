# SecurityClaw Onboarding Guide

## Quick Start

The interactive configuration wizard guides you through setting up SecurityClaw in minutes.

### Step 1: Run the Onboarding Wizard

```bash
.venv/bin/python main.py onboard
```

### Step 0 (Optional): Quick Ollama Setup

The current example config uses these local Ollama models:

- `qwen2.5:7b-instruct-q4_K_M`
- `tinyllama`

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve
ollama pull qwen2.5:7b-instruct-q4_K_M
ollama pull tinyllama
```

This launches an interactive CLI that will ask you about:

**Phase 1: Database Configuration**
- Which DB backend? (OpenSearch or Elasticsearch)
- Database host and port
- SSL/TLS settings
- Authentication credentials (optional)
- **Network logs index** — where to scan for historical logs (e.g., `securityclaw-logs`, `logs-*`, `filebeat-*`)
- **Anomaly detection findings index** — where AD detector results are stored (e.g., `securityclaw-anomalies` or OpenSearch's built-in `.opendistro-anomaly-results*`)
- **RAG vector index** — where to store embeddings for behavioral context (e.g., `securityclaw-vectors`)
- Tests the connection

**Phase 2: LLM Provider Configuration**
- Which LLM? (Ollama or OpenAI)
  - If **Ollama**: Base URL and model name
  - If **OpenAI**: API key and model name
- Tests the connection

**Phase 3: Configuration Save**
- Writes to `config.yaml` (DB, LLM, and index settings)
- Writes to `.env` (credentials)
- Resets the configuration singleton so changes take effect immediately

### Step 2: Verify Configuration

After onboarding, view what was saved:

```bash
cat config.yaml     # DB and LLM provider settings
# .env contains secrets — verify keys exist, but do not paste or commit it.
```

### Step 3: List Available Skills

```bash
.venv/bin/python main.py list-skills
```

Output example:
```
  anomaly_watcher — every 60s
  network_baseliner — every 21600s
  threat_analyst — every 300s
```

### Step 4: Start the Agent

```bash
.venv/bin/python main.py run
```

The agent will:
- Discover all skills in `/skills`
- Schedule each skill according to its interval
- Poll OpenSearch for logs and anomaly findings
- Build RAG context from normal behavior
- Issue threat verdicts using the LLM

### Feature Maturity Notes

- **anomaly_watcher** — still in progress for broader real-environment validation.
- **forensic_examiner** — still in progress for broader real-environment validation.
- **baseline_querier** — still in progress and not yet publication-hardened.

---

## Manual Configuration (Advanced)

If you prefer manual setup, edit these files directly:

**`config.yaml`** — Centralized configuration
```yaml
db:
  provider: opensearch              # or: elasticsearch
  host: localhost
  port: 9200
  username: ""                      # load from .env if used
  password: ""                      # load from .env if used
  use_ssl: false
  verify_certs: false

llm:
  provider: ollama                  # or: openai
  ollama_base_url: http://localhost:11434
  ollama_model: qwen2.5:7b-instruct-q4_K_M
  ollama_embed_model: tinyllama
  # or:
  # openai_model: gpt-4o
  # openai_api_key_env: OPENAI_API_KEY
```

**`.env`** — Secret credentials (git-ignored)
```
OPENSEARCH_USERNAME=<your-opensearch-username>
OPENSEARCH_PASSWORD=<your-opensearch-password>
OPENAI_API_KEY=<your-openai-api-key>
```

---

## CLI Commands Reference

| Command | Purpose |
|---------|---------|
| `.venv/bin/python main.py onboard` | Interactive configuration wizard |
| `.venv/bin/python main.py run` | Start the full agent (foreground) |
| `.venv/bin/python main.py list-skills` | List discovered skills and intervals |
| `.venv/bin/python main.py dispatch <skill>` | Fire a skill once (e.g., `anomaly_watcher`) |
| `.venv/bin/python main.py status` | Print current SITUATION.md |
| `.venv/bin/python main.py --log-level DEBUG run` | Start with debug logging |

---

## Troubleshooting

**"Cannot connect to OpenSearch"**
- Verify OpenSearch is running on the configured host:port
- Check firewall rules
- Ensure credentials are correct

**"Cannot connect to Ollama"**
- Ensure Ollama is running (`ollama serve`)
- Ensure the example models are present (`ollama list`)
- Check the base URL (default: `http://localhost:11434`)

**"No skills found"**
- Verify `/skills` directory exists with `skill_name/logic.py` files
- Each skill must have a `run(context) -> dict` function

**Re-running onboarding**
```bash
.venv/bin/python main.py onboard
```
Simply repeat the wizard to update any settings (existing values are shown as defaults).

---

## Architecture

- **Modular Skills**: Each skill in `/skills/<name>/` has `logic.py` (Python) + `instruction.md` (LLM system prompt)
- **Scheduler**: APScheduler fires skills on intervals (1-minute watcher, 6-hour baseliner)
- **Memory**: SITUATION.md tracks active investigations, findings, decisions, and escalations
- **RAG**: Embeddings stored in vector index; retrieved for contextual LLM analysis
- **Provider Agnostic**: Swap DB backends and LLMs via config without code changes

For full architecture details, see the main README or source code.
