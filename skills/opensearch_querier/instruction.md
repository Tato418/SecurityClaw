# OpenSearch Querier Skill

## Purpose

Centralized OpenSearch/Elasticsearch query execution. This is the **single point of contact** for all database searches.

Instead of each skill building its own queries (causing duplication and hardcoded field names), all skills now use opensearch_querier to execute searches consistently.

## How It Works

1. **Field Discovery**: Queries RAG for field_documentation (created by network_baseliner)
2. **Intelligent Query Building**: Uses discovered field names instead of hardcoding "source_ip", "message", etc.
3. **Execution**: Runs the constructed query against OpenSearch
4. **Results**: Returns both data and metadata about which fields were used

## For Direct User Queries

Users can query OpenSearch directly via chat:
```
User: Find all logs from IP 185.200.116.46 on port 1194
Agent: (routing to opensearch_querier)
Result: X matching documents...
```

## For Other Skills

Other skills import query_builder utilities:
```python
from core.query_builder import discover_field_mappings, build_keyword_query

# In your skill:
field_mappings = discover_field_mappings(db, llm)
query, metadata = build_keyword_query(keywords, field_mappings)
results = db.search(index, query, size=100)
```

This ensures NO hardcoded field names anywhere in the codebase.

## Query Planning Strategy

See `PLANNING_PROMPT.md` for the detailed LLM prompt that guides query planning:
- How to extract countries, ports, protocols, time_range from natural language
- Examples of question → structured fields conversion
- Error handling for ambiguous or partial information

**Architecture Decision:** The planning prompt is kept in markdown (not embedded in Python code) to:
- Enable prompt engineering without code redeploy
- Make prompt changes auditable
- Allow iterative refinement of query extraction logic

Python code (`_plan_opensearch_query_with_llm`) loads `PLANNING_PROMPT.md` at runtime and combines it with dynamic conversation context and field mappings.

### Justification for Separating Static vs Dynamic Content

| Content Type | Location | Reason |
|---|---|---|
| Static JSON examples, error handling, extraction rules | `PLANNING_PROMPT.md` | Reusable, maintainable, auditable |
| Dynamic context assembly, conversation history, runtime field mapping | `logic.py` | Changes based on actual conversation and available fields |
| Query execution, result handling | `logic.py` | Implementation detail, not guidance |

This pattern allows the LLM prompt to evolve without code changes while keeping implementation details encapsulated.
