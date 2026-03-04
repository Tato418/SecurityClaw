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
