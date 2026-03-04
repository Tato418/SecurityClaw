"""
skills/opensearch_querier/logic.py

Skill wrapper around core.query_builder utilities.

This skill provides:
1. A direct interface for user queries via chat
2. Shared query_builder utilities that other skills import

All query logic is in core.query_builder (DRY principle).
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

INSTRUCTION_PATH = Path(__file__).parent / "instruction.md"
SKILL_NAME = "opensearch_querier"


def run(context: dict) -> dict:
    """Entry point for opensearch_querier skill."""
    from core.query_builder import (
        discover_field_mappings,
        build_keyword_query,
    )

    db = context.get("db")
    llm = context.get("llm")
    cfg = context.get("config")
    parameters = context.get("parameters", {})

    if db is None:
        logger.warning("[%s] db not available — skipping.", SKILL_NAME)
        return {"status": "skipped", "reason": "no db"}

    # Get query parameters - if provided explicitly, use them
    # Otherwise, use defaults and let LLM determine search strategy
    index = parameters.get("index", cfg.get("db", "logs_index", default="securityclaw-logs"))
    question = parameters.get("question", parameters.get("query"))
    
    # If neither question/query provided, this was likely a direct dispatch with
    # explicit parameters like keywords, query_type, etc.
    if not question and (parameters.get("keywords") or parameters.get("raw_query")):
        return _execute_explicit_query(context, index)
    
    if not question:
        logger.warning("[%s] No question provided in parameters", SKILL_NAME)
        return {"status": "skipped", "reason": "no question"}
    
    # ── LLM PLANNING PHASE (like rag_querier) ────────────────────────────────
    # Use LLM to understand what to search for
    if llm is None:
        logger.warning("[%s] LLM not available for query planning.", SKILL_NAME)
        return {"status": "skipped", "reason": "no llm"}
    
    conversation_history = parameters.get("conversation_history", [])
    field_mappings = discover_field_mappings(db, llm)
    
    query_plan = _plan_opensearch_query_with_llm(
        question, conversation_history, field_mappings, llm
    )
    
    if not query_plan or query_plan.get("skip_search"):
        logger.info("[%s] LLM determined no search needed.", SKILL_NAME)
        return {"status": "no_action", "reason": "query not needed for raw logs"}
    
    search_terms = query_plan.get("search_terms", [])
    time_range = query_plan.get("time_range", "now-90d")
    
    if not search_terms:
        logger.info("[%s] LLM planning: no search terms extracted.", SKILL_NAME)
        return {"status": "no_action"}
    
    # ── EXECUTE SEARCH ─────────────────────────────────────────────────────
    query, metadata = build_keyword_query(search_terms, field_mappings)
    query["query"]["bool"]["filter"] = {
        "range": {"@timestamp": {"gte": time_range}}
    }
    query["size"] = parameters.get("size", 50)
    
    logger.info(
        "[%s] Querying '%s': %s | Time: %s | Terms: %s",
        SKILL_NAME, index, query_plan.get("reasoning", ""), time_range, search_terms
    )
    
    try:
        results = db.search(index, query, size=query["size"])
        
        return {
            "status": "ok",
            "results_count": len(results) if results else 0,
            "results": results[:10],  # Return top 10 for display
            "search_terms": search_terms,
            "time_range": time_range,
            "reasoning": query_plan.get("reasoning", ""),
        }
    except Exception as exc:
        logger.error("[%s] Search failed: %s", SKILL_NAME, exc)
        return {"status": "error", "error": str(exc)}


def _execute_explicit_query(context: dict, index: str) -> dict:
    """
    Execute an explicitly parameterized query (backward compatibility).
    Used when query_type, keywords, raw_query, etc. are passed directly.
    """
    from core.query_builder import (
        discover_field_mappings,
        build_keyword_query,
        build_structured_query,
        build_time_range_query,
    )
    
    db = context.get("db")
    llm = context.get("llm")
    parameters = context.get("parameters", {})
    
    query_type = parameters.get("query_type", "keyword_search")
    size = parameters.get("size", 100)
    field_mappings = discover_field_mappings(db, llm)
    
    logger.info(
        "[%s] Executing explicit %s query against index: %s",
        SKILL_NAME, query_type, index
    )
    
    try:
        query = None
        
        if query_type == "raw_query":
            query = parameters.get("raw_query")
            if not query:
                return {"status": "failed", "reason": "raw_query required"}
        
        elif query_type == "keyword_search":
            keywords = parameters.get("keywords", [])
            if isinstance(keywords, str):
                keywords = [keywords]
            if not keywords:
                return {"status": "failed", "reason": "keywords required"}
            query, _ = build_keyword_query(keywords, field_mappings)
        
        elif query_type == "structured_search":
            ips = parameters.get("ips", [])
            if isinstance(ips, str):
                ips = [ips]
            domains = parameters.get("domains", [])
            if isinstance(domains, str):
                domains = [domains]
            ports = parameters.get("ports", [])
            if isinstance(ports, str):
                ports = [ports]
            time_range = parameters.get("time_range")
            query, _ = build_structured_query(ips, domains, ports, time_range, field_mappings)
        
        elif query_type == "time_range_search":
            time_range = parameters.get("time_range")
            if not time_range:
                return {"status": "failed", "reason": "time_range required"}
            query, _ = build_time_range_query(time_range, field_mappings)
        
        else:
            return {"status": "failed", "reason": f"Unknown query_type: {query_type}"}
        
        if not query:
            return {"status": "failed", "reason": "could not build query"}
        
        results = db.search(index, query, size=size)
        return {
            "status": "ok",
            "results_count": len(results) if results else 0,
            "results": results[:10] if results else [],
        }
    
    except Exception as exc:
        logger.error("[%s] Explicit query failed: %s", SKILL_NAME, exc)
        return {"status": "error", "error": str(exc)}


def _plan_opensearch_query_with_llm(
    question: str,
    conversation_history: list[dict],
    field_mappings: dict,
    llm: Any,
) -> dict:
    """
    Use LLM to plan OpenSearch query for a natural language question.
    Similar to the LLM planning in rag_querier but for direct log queries.
    """
    # Build conversation context
    conversation_summary = ""
    if conversation_history:
        relevant_msgs = conversation_history[-4:] if len(conversation_history) > 4 else conversation_history
        conversation_parts = []
        for msg in relevant_msgs:
            role = msg.get("role", "unknown").upper()
            content = msg.get("content", "")[:200]
            conversation_parts.append(f"[{role}]: {content}")
        conversation_summary = "\n".join(conversation_parts)
    
    prompt = f"""You are analyzing a user's question to plan a log search. Do NOT assume knowledge of the database schema.

CONVERSATION CONTEXT:
{conversation_summary if conversation_summary else "(No prior context)"}

CURRENT QUESTION: "{question}"

TASK:
Identify what data the user wants to search for:
1. TIME RANGE: What time period is mentioned
2. SEARCH INTENT: What to search for (IPs, domains, keywords, event types, etc.)
3. WHETHER TO SEARCH: Is raw log search needed

DO NOT mention specific field names. You don't know if this system has 'source.ip' or 'src_ip'.
Just identify the INTENT ("search for Iran", "find traffic on port 443") and Python will map it.

RESPOND IN JSON:
{{
  "reasoning": "What the user is looking for",
  "detected_time_range": "Time period (or 'none')",
  "time_range": "Elasticsearch range code (now-3M, now-1w, etc.)",
  "search_terms": ["term1", "term2"],
  "skip_search": false
}}

EXAMPLES:
- User: "traffic from Iran past 3 months" → search_terms: ["iran"], time_range: "now-3M"
- User: "port 443 activity" → search_terms: ["443"], time_range: "now-90d"
- User: "DNS queries for example.com" → search_terms: ["example.com"], time_range: "now-90d"

KEY POINT: You extract INTENT. Python discovers the actual fields."""

    try:
        response = llm.complete(prompt)
        logger.debug("[%s] LLM Plan: %s", SKILL_NAME, response[:200])

        
        import json
        plan = json.loads(response)
        
        if not isinstance(plan.get("search_terms"), list):
            plan["search_terms"] = []
        if not isinstance(plan.get("time_range"), str):
            plan["time_range"] = "now-90d"
        
        logger.info(
            "[%s] LLM Plan: Time=%s | Terms=%s | Reasoning=%s",
            SKILL_NAME, plan.get("time_range"), plan.get("search_terms"), 
            plan.get("reasoning", "")[:60]
        )
        
        return plan
    except Exception as exc:
        logger.warning("[%s] LLM planning failed: %s", SKILL_NAME, exc)
        return {
            "reasoning": "LLM planning failed",
            "search_terms": [],
            "time_range": "now-90d",
            "skip_search": True,
        }

        if not results:
            return {
                "status": "no_results",
                "results": [],
                "result_count": 0,
                "search_metadata": search_metadata,
            }

        return {
            "status": "ok",
            "results": results,
            "result_count": len(results),
            "search_metadata": search_metadata,
        }

    except Exception as exc:
        logger.error("[%s] Search failed: %s", SKILL_NAME, exc)
        return {
            "status": "failed",
            "reason": str(exc),
            "search_metadata": search_metadata,
        }
