# Supervisor Orchestration Strategy

## Overview
The supervisor uses a structured query-plan-execute-reflect-retry cycle to answer questions
without hallucinating or fabricating data.

## Orchestration Loop

```
┌─ PLAN: Determine what skill to use
│  └─ Analyze question intent
│  └─ Check skill capabilities
│  └─ Choose skill(s) that CAN answer this
│
├─ EXECUTE: Run the chosen skill(s)
│  └─ Collect results and metadata
│
├─ REFLECT: Evaluate results for relevance
│  └─ Is this actual data or hallucination?
│  └─ Does it answer the question?
│  └─ Are we on the right track?
│
└─ RETRY: If unsatisfied, try alternative approach
   └─ If skill returned zero results: try different parameters
   └─ If results exist but aren't relevant: try different skill
   └─ If all approaches exhausted: report "insufficient data"
```

## Skill Manifests: What Each Skill Can Answer

Each skill declares what it CAN and CANNOT answer:

### forensic_examiner
- **CAN:** Reconstruct incident timelines, link DNS→flows→alerts, analyze behavior patterns
- **CANNOT:** Answer general "what's normal?" questions, provide threat reputation
- **Good for:** "What happened with this IP?" "Build timeline of incident"
- **Bad for:** "Is this IP malicious?" (use threat_analyst instead)

### baseline_querier
- **CAN:** Search behavioral RAG baselines and raw logs with schema-aware field mapping
- **CANNOT:** Direct IP reputation lookup, multi-domain threat analysis, field schema discovery
- **Good for:** "Show me traffic..." "Find records where..." "Any alerts today?"
- **Bad for:** "What's the reputation?" (use threat_analyst instead)

### fields_querier
- **CAN:** Answer field schema questions (what fields exist, which field holds IP, field types)
- **CANNOT:** Search logs, do reputation lookups, run analytics
- **Good for:** "What field name stores bytes?" "What fields are in my logs?" "Which field is the source IP?"
- **Bad for:** Any data/log query (use baseline_querier/opensearch_querier for those)

### opensearch_querier
- **CAN:** Direct keyword/field-based searches when exact field names are known
- **CANNOT:** Convert user-friendly terms to field names, handle complex multi-field logic
- **Good for:** "Find logs with src_ip=X and dest_port=Y" (when field names are explicit)
- **Bad for:** "Show byte transfers" (field name unknown - use fields_querier to discover first)

### threat_analyst
- **CAN:** IP reputation, domain reputation, threat intel enrichment, maliciousness assessment
- **CANNOT:** Timeline reconstruction, general log searching
- **Good for:** "What's the reputation?" "Is this malicious?" "Threat level?"
- **Bad for:** "Show me traffic from Iran" (use baseline_querier instead)

  - **fields_baseliner** and **network_baseliner**: explicit-only, never auto-scheduled

### network_baseliner
- **CAN:** Create behavioral baselines, define "normal" patterns
- **CANNOT:** Search existing data, answer questions about specific incidents
- **Good for:** Explicit request: "Generate a baseline" or "Create a model of normal"
- **Bad for:** Auto-routing for general questions (explicit-only skill)

### fields_baseliner
- **CAN:** Catalog all fields in the logs index (name, type, frequency, examples)
- **CANNOT:** Answer questions, search logs, do analytics
- **Good for:** Explicit: "Refresh field catalog" "Rebuild field schema"
- **Bad for:** Auto-routing — explicit-only skill

### anomaly_triage
- **CAN:** Detect and enrich anomalies in real-time, flag deviations from baseline
- **CANNOT:** Explain why something is normal, provide historical context
- **Good for:** "What anomalies detected?" "Anything suspicious?"
- **Bad for:** "Is this normal?" (too binary/vague)


## Anti-Hallucination Rules

### Rule 1: Data Relevance Check
When skill returns results, explicitly validate:
- Do the results contain actual field values, not LLM-generated data?
- Do field names exist in the index (not imaginary)?
- Is the data directly responsive to the question, or is it tangential?

### Rule 2: Exhaustion Detection
Stop exploring when:
- Same skill tried with 2+ different parameter variations → 0 results
- All applicable skills have been tried → no data
- At max_steps (usually 4) with partial data → return what we have

**DO NOT:**
- Try the same skill with identical parameters twice
- Guess/fabricate when data is missing
- Report "likely" or "probably" without evidence

### Rule 3: Graceful Degradation
If no perfect answer found:
- Report what WAS found with confidence level
- Explicitly list what's missing
- Suggest what additional data would help

Example: "Found 2 records matching the criteria. No bytes-to-client/bytes-to-server field 
was available in the returned logs — this field may not exist in the current index."


## Supervisor Decision Logic

### Step 1: Question Analysis
```
If question contains ["reputation", "threat", "malicious", "risk", "vulnerable"]:
  → try threat_analyst FIRST

If question contains ["byte", "packet", "field", "schema"]:
  → try fields_querier FIRST to discover actual field names

If question contains ["timeline", "incident", "what happened", "sequence"]:
  → try forensic_examiner FIRST

If question contains ["traffic", "flows", "country", "port"]:
  → try baseline_querier or opensearch_querier
```

### Step 2: Custom Skill Selection
If no category match:
  1. Ask LLM: "Which skill best answers this?"
  2. LLM considers skill manifests above
  3. Select top 1-2 skills to execute

### Step 3: Execution & Validation
```
Execute selected skill(s)
  ↓
Validate results:
  - Did skill return status="ok"?
  - Are there actual records (results_count > 0)?
  - Are field names recognizable (not hallucinated)?
  ↓
If all valid: evaluate satisfaction
If some missing: plan retry
If no valid data: try alternative skill
```

### Step 4: Intelligent Retry
**Retry Scenarios:**

| Scenario | Action |
|----------|--------|
| Skill returned 0 results | Vary time_range; add/remove filters; try different skill |
| Results exist but not relevant | Reanalyze question; try different skill that can answer better |
| Field names unknown | Use fields_querier to discover BEFORE attempting direct query |
| Ambiguous question | Ask supervisor to clarify intent before executing |

**Avoid:**
- Repeating same skill with same parameters
- Overwriting previous results without tracking alternatives


## Example Walkthroughs

### Example 1: "What's the reputation of 62.60.131.168?"
```
Plan:     Question asks "reputation" → threat_analyst is listed as CAN answer this
Execute:  threat_analyst queries AbuseIPDB/VirusTotal/OTX
Reflect:  Results show "161 reports, High risk" → Directly answers the question ✓
Outcome:  Satisfied. Return verdict with confidence and sources.
```

### Example 2: "What were the byte transfers to client and server?"
```
Plan:     Question asks "byte...field" → fields_querier can discover field names
Execute:  fields_querier reads field catalog, finds "flow.bytes_toclient" and "flow.bytes_toserver"
Reflect:  Now we have field names ✓ and sample values ✓
Retry:    Plan stage 2 - can now use opensearch_querier directly with proper field names
Execute:  opensearch_querier queries exact fields
Outcome:  Return byte counts with evidence
```

### Example 3: "Show me traffic from Iran"
```
Plan:     Question asks "traffic...country" → baseline_querier or opensearch_querier
Execute:  opensearch_querier tries: countries=["Iran"] with keyword search
Reflect:  0 results (bad strategy - "Iran" is a name, not a field value)
Retry:    Fallback to match_phrase + ISO code ("IR")
Execute:  opensearch_querier retry with proper country matching
Outcome:  Returns 2 records with country="IR" ✓
```

### Example 4: "Can you run forensic analysis?"
```
Plan:     Question asks "forensic analysis" → forensic_examiner, THEN threat_analyst
Execute:  forensic_examiner reconstructs timeline
Reflect:  Timeline found + entities identified ✓
Retry:    Now route to threat_analyst for reputation of entities in timeline
Execute:  threat_analyst evaluates entities found by forensic
Outcome:  Full analysis: timeline + threat verdicts
```


## Configuration

In `config.yaml`:

```yaml
supervisor:
  max_steps: 4            # Max orchestration iterations (1-8)
  retry_threshold: 2      # Max times to retry same skill
  anti_hallucination: true    # Validate data relevance before returning
  skill_capability_aware: true  # Use skill manifests for smarter routing
```
