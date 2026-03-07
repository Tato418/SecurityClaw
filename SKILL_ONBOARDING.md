# Skill Onboarding System

This document explains SecurityClaw's dynamic skill variable discovery and onboarding system.

## Overview

SecurityClaw automatically detects and prompts users to configure variables that individual skills require. This enables:

- **Dynamic Discovery** — Each skill declares its required variables in `manifest.yaml`
- **First-Chat Onboarding** — Missing variables are detected on first `python main.py chat`
- **Selective Configuration** — Only configure variables for skills you plan to use
- **Easy Updates** — Re-run `python main.py onboard` to add more skill variables

## How It Works

### 1. Skills Declare Requirements

Each skill can declare required or optional environment variables in its `manifest.yaml`:

```yaml
name: threat_analyst
description: "Analyzes security findings for threat level"

required_env_vars:
  - name: ABUSEIPDB_API_KEY
    description: "AbuseIPDB API Key (optional—for IP reputation)"
    env_key: ABUSEIPDB_API_KEY
    optional: true
    is_secret: true
  
  - name: MAXMIND_LICENSE_KEY
    description: "MaxMind License Key (required—for GeoIP database downloads)"
    env_key: MAXMIND_LICENSE_KEY
    optional: false
    is_secret: true
```

### 2. Discovery Phase

When you run `python main.py onboard` or first use `python main.py chat`:

1. **Scan** — System scans all skills in `/skills` for `manifest.yaml` files
2. **Parse** — Extracts `required_env_vars` section from each manifest
3. **Filter** — Identifies which variables are missing from the environment
4. **Prompt** — Interactively asks user to configure missing variables

### 3. State Tracking

An optional `.onboarding_state.json` file tracks which skills have been onboarded:

```json
{
  "skills_onboarded": ["threat_analyst", "geoip_lookup"],
  "timestamp": "2026-03-07T12:00:00Z"
}
```

This prevents re-prompting for the same skill on subsequent runs (currently unused but available for future enhancements).

## Current Skill Requirements

### threat_analyst
Optional external threat intelligence APIs:

```
ABUSEIPDB_API_KEY         — IP abuse reputation scoring [optional]
ALIENVAULT_API_KEY        — Threat intelligence pulses [optional]
VIRUSTOTAL_API_KEY        — Malware detection [optional]
TALOS_CLIENT_ID           — Cisco enterprise intelligence [optional]
TALOS_CLIENT_SECRET       — Cisco enterprise intelligence [optional]
```

**Note:** All threat_analyst APIs are optional. The skill works with local baselines even without them.

### geoip_lookup
MaxMind GeoIP database management:

```
MAXMIND_LICENSE_KEY       — Download GeoIP database [REQUIRED]
```

**Note:** This is required because without it, geoip_lookup cannot download the GeoIP database.

## Creating a Custom Skill with Variables

To create a new skill that requires specific variables:

### 1. Create the skill structure:
```
skills/my_skill/
├── logic.py           # Skill implementation
├── instruction.md     # LLM system prompt
├── manifest.yaml      # Skill metadata (NEW)
└── reputation_intel.py (optional)
```

### 2. Declare variables in manifest.yaml:
```yaml
name: my_skill
description: "Does something special"

required_env_vars:
  - name: MY_API_KEY
    description: "API key for my external service"
    env_key: MY_API_KEY
    optional: false
    is_secret: true
  
  - name: MY_WEBHOOK_URL
    description: "Webhook URL for notifications"
    env_key: MY_WEBHOOK_URL
    optional: true
    is_secret: false
```

### 3. Use variables in logic.py:
```python
import os
from core.config import Config

def run(context):
    cfg = Config()
    api_key = os.getenv("MY_API_KEY", cfg.get("apis", "my_api_key"))
    webhook = os.getenv("MY_WEBHOOK_URL")
    
    # Use the variables...
    return {...}
```

## Usage

### Onboarding Phase
```bash
python main.py onboard
```

This will:
1. Prompt for core SecurityClaw variables (DB, LLM, etc.)
2. Scan skills and prompt for missing variables
3. Save everything to `config.yaml` and `.env`

### Chat Phase
```bash
python main.py chat
```

On first run, this will:
1. Check for missing skill variables
2. Prompt to configure any missing variables
3. Start the interactive chat

### Manual Configuration
Edit `.env` directly:
```bash
# Core variables
DB_USERNAME=admin
DB_PASSWORD=secret123
OPENAI_API_KEY=sk-...

# Skill variables
ABUSEIPDB_API_KEY=abc123
MAXMIND_LICENSE_KEY=xyz789
```

## Variable Specification Schema

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `name` | string | ✓ | Display name for the variable |
| `description` | string | ✓ | Human-friendly description (shown in prompts) |
| `env_key` | string | ✗ | Environment variable name (defaults to `name`) |
| `optional` | boolean | ✗ | If true, won't block onboarding (default: false) |
| `is_secret` | boolean | ✗ | If true, input is hidden in CLI (default: false) |

## API Reference

### `discover_skill_requirements()`
Scans all skills and returns their required variables.

```python
from core.skill_onboarding import discover_skill_requirements

reqs = discover_skill_requirements()
# Returns: {skill_name: {var_name: {description, env_key, optional, ...}}}
```

### `get_missing_skill_variables()`
Returns only variables that are required but not set in environment.

```python
from core.skill_onboarding import get_missing_skill_variables

missing = get_missing_skill_variables()
# Returns: {skill_name: [var_names]}
```

### `ensure_skill_variables_onboarded()`
Checks for missing variables and prompts user to configure them (if interactive).

```python
from core.skill_onboarding import ensure_skill_variables_onboarded

ensure_skill_variables_onboarded()  # Called automatically on first chat
```

### `prompt_for_skill_variables(requirements)`
Interactively prompts for variables.

```python
from core.skill_onboarding import prompt_for_skill_variables

reqs = {
    "threat_analyst": {
        "ABUSEIPDB_API_KEY": {...},
    }
}
collected = prompt_for_skill_variables(reqs)
# Returns: {env_key: value, ...}
```

## Testing

Tests for the skill onboarding system are in `tests/test_skill_onboarding.py`:

```bash
python -m pytest tests/test_skill_onboarding.py -v
```

Tests cover:
- Discovering skill requirements from manifest files
- Identifying missing variables
- State tracking (save/load)
- Variable descriptions and metadata
- Manifest validation

## Future Enhancements

Potential improvements:

1. **Validation** — Validate API keys work before saving
2. **Secrets Management** — Integration with HashiCorp Vault or AWS Secrets Manager
3. **Skill Dependencies** — Handle skills that depend on other skills' variables
4. **Update Prompts** — Only re-prompt when new skills are added
5. **Web UI** — Add variables via web interface instead of CLI
6. **Documentation Links** — Include signup links for API services
