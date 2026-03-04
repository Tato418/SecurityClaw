"""
skills/rag_querier/logic.py

Data-agnostic RAG querier skill. Searches stored baseline knowledge
to answer user questions about network/system behavior.

Context keys consumed:
    context["db"]         -> BaseDBConnector
    context["llm"]        -> BaseLLMProvider
    context["memory"]     -> AgentMemory
    context["config"]     -> Config
    context["parameters"] -> {"question": "user question"}
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

INSTRUCTION_PATH = Path(__file__).parent / "instruction.md"
SKILL_NAME = "rag_querier"


def run(context: dict) -> dict:
    """Entry point called by the Runner."""
    db = context.get("db")
    llm = context.get("llm")
    cfg = context.get("config")
    parameters = context.get("parameters", {})

    if db is None or llm is None:
        logger.warning("[%s] db or llm not available — skipping.", SKILL_NAME)
        return {"status": "skipped", "reason": "no db/llm"}

    user_question = parameters.get("question")
    if not user_question:
        logger.warning("[%s] No question provided in parameters.", SKILL_NAME)
        return {"status": "no_question"}
    
    # Extract conversation history if available
    conversation_history = parameters.get("conversation_history", [])

    instruction = INSTRUCTION_PATH.read_text(encoding="utf-8")
    logs_index = cfg.get("db", "logs_index", default="securityclaw-logs")
    vector_index = cfg.get("db", "vector_index", default="securityclaw-vectors")

    # ── 0. Query schema observations to learn available fields ──────────────────
    # This makes the system data-agnostic by discovering what fields exist
    schema_observations = []
    try:
        from core.rag_engine import RAGEngine
        rag_temp = RAGEngine(db=db, llm=llm)
        
        # Ask for field mappings from schema observations
        schema_question = "What fields and data structure are in this dataset?"
        schema_docs = rag_temp.retrieve(schema_question, k=3)
        schema_observations = [
            doc for doc in schema_docs 
            if doc.get("category") == "schema_observation"
        ]
        
        if schema_observations:
            logger.info(
                "[%s] Found %d schema observations — using for intelligent field selection.",
                SKILL_NAME, len(schema_observations)
            )
    except Exception as exc:
        logger.debug("[%s] Schema observation lookup failed (non-critical): %s", SKILL_NAME, exc)
        # Continue without schema info; the multi-format search will still work

    # ── 1. Search RAG for relevant baselines ──────────────────────────────────
    logger.info("[%s] Searching for: %s", SKILL_NAME, user_question)

    rag_docs = []
    try:
        from core.rag_engine import RAGEngine

        rag = RAGEngine(db=db, llm=llm)
        rag_docs = rag.retrieve(user_question, k=5)
        logger.info("[%s] Found %d relevant baselines in RAG.", SKILL_NAME, len(rag_docs))
    except Exception as exc:
        logger.warning("[%s] RAG retrieval failed: %s", SKILL_NAME, exc)
        # Continue with raw logs even if RAG fails

    # ── 2. Search raw logs for matching data ──────────────────────────────────
    raw_logs = []
    search_terms_used = []
    try:
        raw_logs, search_terms_used = _search_raw_logs(
            user_question, db, logs_index, llm, conversation_history
        )
        logger.info(
            "[%s] Found %d matching records in logs (search terms: %s).",
            SKILL_NAME, len(raw_logs), search_terms_used
        )
    except Exception as exc:
        logger.error("[%s] Raw log search failed: %s", SKILL_NAME, exc)

    # ── 3. If neither RAG nor raw logs have data, return no_data ──────────────
    if not rag_docs and not raw_logs:
        logger.info("[%s] No data found (RAG or logs).", SKILL_NAME)
        return {
            "status": "no_data",
            "findings": {
                "question": user_question,
                "answer": "No data found to answer this question.",
                "confidence": 0.0,
            },
        }

    # ── 4. Analyze combined data with LLM to extract answer ──────────────────
    combined_context = _format_combined_context(
        rag_docs, raw_logs, user_question, search_terms_used
    )
    answer = _extract_answer_from_data(user_question, combined_context, instruction, llm)

    findings = {
        "question": user_question,
        "answer": answer,
        "rag_sources": len(rag_docs),
        "log_records": len(raw_logs),
        "confidence": 0.85 if (rag_docs or raw_logs) else 0.0,
        "summary": {
            "baseline_insights": len(rag_docs),
            "raw_observations": len(raw_logs),
        },
    }

    logger.info(
        "[%s] Answer compiled from %d baselines + %d log records. "
        "RAG docs delivered: %d/%d, Raw logs delivered: %d/%d",
        SKILL_NAME,
        len(rag_docs),
        len(raw_logs),
        len(rag_docs),
        len(rag_docs),
        min(len(raw_logs), 25),  # Up to 25 raw logs shown to LLM
        len(raw_logs),
    )

    return {
        "status": "ok",
        "findings": findings,
    }


def _search_raw_logs(
    question: str,
    db: Any,
    logs_index: str,
    llm: Any = None,
    conversation_history: list[dict] = None,
) -> tuple[list[dict], list[str]]:
    """
    Search raw logs for data matching the user question.
    
    Strategy: Let the LLM plan what to search for.
    The LLM understands context, temporal references, and entities better than hardcoded rules.
    """
    from core.query_builder import discover_field_mappings, build_keyword_query
    
    if llm is None:
        logger.warning("[%s] LLM not available for query planning.", SKILL_NAME)
        return [], []
    
    # ── LLM PLANS THE SEARCH ──────────────────────────────────────────────────
    # The LLM decides: what to search for, what time range, whether to search at all
    field_mappings = discover_field_mappings(db, llm)
    query_plan = _plan_query_with_llm(question, conversation_history, field_mappings, llm)
    
    if not query_plan or query_plan.get("skip_search"):
        logger.info("[%s] LLM determined no raw log search needed.", SKILL_NAME)
        return [], []
    
    search_terms = query_plan.get("search_terms", [])
    ports = query_plan.get("ports", [])
    countries = query_plan.get("countries", [])
    protocols = query_plan.get("protocols", [])
    time_range = query_plan.get("time_range", "now-90d")
    
    # Check if we have any search criteria
    has_search_criteria = bool(search_terms or ports or countries or protocols)
    if not has_search_criteria:
        logger.info("[%s] LLM planning: no search terms needed.", SKILL_NAME)
        return [], []
    
    # ── EXECUTE QUERY USING LLM'S PLAN ────────────────────────────────────────
    # Build structured query based on what was extracted
    query = _build_structured_query_from_plan(
        search_terms=search_terms,
        ports=ports,
        countries=countries,
        protocols=protocols,
        time_range=time_range,
        field_mappings=field_mappings,
    )
    
    if not query or query.get("query") == {"match_none": {}}:
        logger.warning("[%s] No valid query built from plan", SKILL_NAME)
        return [], []
    
    query["size"] = 50
    
    logger.info(
        "[%s] Built Query: Ports=%s, Countries=%s, Protocols=%s | Time: %s",
        SKILL_NAME, ports, countries, protocols, time_range
    )
    
    logger.debug("[%s] Discovered field_mappings: %s", SKILL_NAME, field_mappings)
    logger.debug("[%s] Built query: %s", SKILL_NAME, json.dumps(query, indent=2))
    
    try:
        results = db.search(logs_index, query, size=50)
        return results, search_terms
    except Exception as exc:
        logger.error("[%s] Raw log search error: %s | Query: %s", SKILL_NAME, exc, json.dumps(query, indent=2))
        return [], []


def _build_structured_query_from_plan(
    search_terms, ports, countries, protocols, time_range, field_mappings
):
    """
    Build an OpenSearch query using structured parameters extracted by LLM.
    
    Args:
        search_terms: List of generic keywords to search
        ports: List of destination ports (e.g., [1194])
        countries: List of country names (e.g., ["Iran"])
        protocols: List of protocols (e.g., ["tcp"])
        time_range: Time range string or date range
        field_mappings: Mapping of field types to actual field names
    
    Returns:
        dict: OpenSearch query with proper structure for ports, countries, etc.
    """
    from core.query_builder import build_keyword_query
    
    must_clauses = []
    
    # ── PORTS FILTER ────────────────────────────────────────────────────────
    if ports:
        # Try mapping to dest_port or other port fields discovered
        port_field = None
        if "dest_port" in field_mappings.get("all_fields", {}):
            port_field = "dest_port"
        elif "port" in field_mappings.get("all_fields", {}):
            port_field = "port"
        
        if port_field:
            # Build should clause for multiple ports
            port_clauses = [{"term": {port_field: p}} for p in ports]
            if len(port_clauses) == 1:
                must_clauses.append(port_clauses[0])
            else:
                must_clauses.append({"bool": {"should": port_clauses, "minimum_should_match": 1}})
            logger.info(
                "[%s] Added port filter: %s to field %s",
                SKILL_NAME, ports, port_field
            )
        else:
            logger.warning("[%s] No port field found in mappings", SKILL_NAME)
    
    # ── COUNTRIES/GEOIP FILTER ─────────────────────────────────────────────
    if countries:
        # Map country names to country codes for geoIP
        country_codes = _map_country_names_to_codes(countries)
        
        # Try mapping to geoip country field - prefer specific code versions
        geoip_field = None
        if "geoip.country_code2" in field_mappings.get("all_fields", []):
            geoip_field = "geoip.country_code2.keyword"  # Use .keyword subfield for exact term matching
        elif "geoip.country_code" in field_mappings.get("all_fields", []):
            geoip_field = "geoip.country_code.keyword"
        elif "geoip.country_code3" in field_mappings.get("all_fields", []):
            geoip_field = "geoip.country_code3.keyword"  # 3-letter ISO code
        elif "country_code" in field_mappings.get("all_fields", []):
            geoip_field = "country_code.keyword" if "country_code.keyword" in field_mappings.get("all_fields", []) else "country_code"
        elif "geoip.country_name" in field_mappings.get("all_fields", []):
            geoip_field = "geoip.country_name"  # Fallback to country name
        
        if geoip_field and country_codes:
            # Build should clause for multiple countries
            country_clauses = [{"term": {geoip_field: code}} for code in country_codes]
            if len(country_clauses) == 1:
                must_clauses.append(country_clauses[0])
            else:
                must_clauses.append(
                    {"bool": {"should": country_clauses, "minimum_should_match": 1}}
                )
            logger.info(
                "[%s] Added country filter: %s (codes: %s) to field %s",
                SKILL_NAME, countries, country_codes, geoip_field
            )
        else:
            logger.warning("[%s] No geoIP field found in mappings for countries", SKILL_NAME)
    
    # ── PROTOCOLS FILTER ────────────────────────────────────────────────────
    if protocols:
        proto_field = None
        if "protocol" in field_mappings.get("all_fields", {}):
            proto_field = "protocol"
        elif "service_protocol" in field_mappings.get("all_fields", {}):
            proto_field = "service_protocol"
        
        if proto_field:
            proto_clauses = [
                {"term": {proto_field: p.lower()}} for p in protocols
            ]
            if len(proto_clauses) == 1:
                must_clauses.append(proto_clauses[0])
            else:
                must_clauses.append(
                    {"bool": {"should": proto_clauses, "minimum_should_match": 1}}
                )
            logger.info(
                "[%s] Added protocol filter: %s to field %s",
                SKILL_NAME, protocols, proto_field
            )
    
    # ── GENERIC KEYWORD SEARCH ──────────────────────────────────────────────
    if search_terms:
        # Use existing keyword query building
        keyword_query, _ = build_keyword_query(search_terms, field_mappings)
        # Extract the query part
        if "bool" in keyword_query.get("query", {}):
            must_clauses.append(keyword_query["query"]["bool"])
        elif "query" in keyword_query and keyword_query["query"]:
            must_clauses.append(keyword_query["query"])
        logger.info("[%s] Added keyword search: %s", SKILL_NAME, search_terms)
    
    # ── BUILD FINAL QUERY ───────────────────────────────────────────────────
    if not must_clauses:
        logger.warning("[%s] No must clauses built, returning match_none", SKILL_NAME)
        return {"query": {"match_none": {}}, "size": 50}
    
    # Build bool query with all filters
    if len(must_clauses) == 1:
        final_query = {"query": {"bool": {"must": must_clauses[0]}}}
    else:
        final_query = {"query": {"bool": {"must": must_clauses}}}
    
    # ── ADD TIME RANGE FILTER ───────────────────────────────────────────────
    # Parse time_range (could be "now-90d" or "2026-02-01:2026-03-01")
    range_filter = _parse_time_range(time_range)
    if range_filter:
        # Add to filter clause (not must, so it doesn't affect scoring)
        if "filter" not in final_query["query"]["bool"]:
            final_query["query"]["bool"]["filter"] = []
        elif not isinstance(final_query["query"]["bool"]["filter"], list):
            final_query["query"]["bool"]["filter"] = [final_query["query"]["bool"]["filter"]]
        
        if isinstance(final_query["query"]["bool"]["filter"], list):
            final_query["query"]["bool"]["filter"].append(range_filter)
        else:
            final_query["query"]["bool"]["filter"] = range_filter
        
        logger.info("[%s] Added time range filter: %s", SKILL_NAME, time_range)
    
    return final_query


def _map_country_names_to_codes(country_names):
    """
    Map human-readable country names to ISO country codes.
    
    Args:
        country_names: List of country names (e.g., ["Iran", "China"])
    
    Returns:
        List of country codes (e.g., ["IR", "CN"])
    """
    # Simple mapping for common countries
    country_map = {
        "iran": "IR",
        "iraq": "IQ",
        "syria": "SY",
        "north korea": "KP",
        "china": "CN",
        "russia": "RU",
        "united states": "US",
        "usa": "US",
        "uk": "GB",
        "united kingdom": "GB",
        "france": "FR",
        "germany": "DE",
        "india": "IN",
        "pakistan": "PK",
        "cloudflare": "US",  # Cloudflare is USA-based infrastructure
    }
    
    codes = []
    for name in country_names:
        code = country_map.get(name.lower())
        if code:
            codes.append(code)
            logger.debug(
                "[%s] Mapped country '%s' to code '%s'", SKILL_NAME, name, code
            )
        else:
            logger.warning("[%s] Unknown country mapping: %s", SKILL_NAME, name)
    
    return codes


def _parse_time_range(time_range_str):
    """
    Parse time range string into OpenSearch range filter.
    
    Supports formats:
    - "now-90d" -> relative time
    - "2026-02-01:2026-03-01" -> absolute date range
    - "february" -> infer month (current year assumed)
    
    Args:
        time_range_str: Time range specification string
    
    Returns:
        dict: OpenSearch range filter or None
    """
    if not time_range_str:
        return None
    
    # Handle relative times like "now-90d"
    if time_range_str.startswith("now"):
        return {
            "range": {
                "@timestamp": {
                    "gte": time_range_str
                }
            }
        }
    
    # Handle absolute date ranges like "2026-02-01:2026-03-01"
    if ":" in time_range_str:
        parts = time_range_str.split(":")
        if len(parts) == 2:
            return {
                "range": {
                    "@timestamp": {
                        "gte": parts[0],
                        "lte": parts[1]
                    }
                }
            }
    
    # Handle month names like "february"
    month_map = {
        "january": ("01", "01"), "february": ("02", "02"), "march": ("03", "03"),
        "april": ("04", "04"), "may": ("05", "05"), "june": ("06", "06"),
        "july": ("07", "07"), "august": ("08", "08"), "september": ("09", "09"),
        "october": ("10", "10"), "november": ("11", "11"), "december": ("12", "12"),
    }
    
    month_abbr = time_range_str.lower()
    if month_abbr in month_map:
        month, end_month = month_map[month_abbr]
        # Assume current year (2026 for testing, in production use current year)
        return {
            "range": {
                "@timestamp": {
                    "gte": f"2026-{month}-01",
                    "lte": f"2026-{end_month}-28"  # or 31 depending on month
                }
            }
        }
    
    logger.warning("[%s] Could not parse time range: %s", SKILL_NAME, time_range_str)
    return None


def _plan_query_with_llm(
    question: str,
    conversation_history: list[dict],
    field_mappings: dict,
    llm: Any,
) -> dict:
    """
    Use the LLM to plan what search query to run given the user question.
    
    Specifically asks the LLM to:
    1. Identify temporal context (time range in the question)
    2. Extract entity references (IPs, ports, countries, protocols)
    3. Determine query type (should we search raw logs at all?)
    4. Form appropriate search strategy
    
    Returns dict with:
        - reasoning: explanation of the query plan
        - search_terms: list of generic search terms
        - ports: list of port numbers if mentioned
        - countries: list of country names if mentioned
        - time_range: Elasticsearch time range string (e.g., "now-3d", "now-3M")
        - skip_search: whether to skip searching (True if question doesn't need raw log search)
    """
    # Build conversation summary with focus on what was previously discussed
    conversation_summary = ""
    if conversation_history:
        # Keep last 6 exchanges for context
        relevant_msgs = conversation_history[-6:] if len(conversation_history) > 6 else conversation_history
        conversation_parts = []
        for msg in relevant_msgs:
            role = msg.get("role", "unknown").upper()
            content = msg.get("content", "")[:300]  # Keep reasonable length
            conversation_parts.append(f"[{role}]: {content}")
        conversation_summary = "\n".join(conversation_parts)
    
    prompt = f"""You are a cybersecurity analyst planning a log search. Your job is to understand what the user is looking for.

CONVERSATION HISTORY:
{conversation_summary if conversation_summary else "(No prior context)"}

USER'S NEW QUESTION: "{question}"

TASK:
Analyze what the user wants to find. Extract specific, structured data:
1. PORTS: Any port numbers mentioned (e.g., "port 443", "port 1194")
2. COUNTRIES: Any country/region names mentioned (e.g., "from Iran", "traffic to Russia")
3. PROTOCOLS: Any protocols mentioned (e.g., "HTTP", "DNS", "TLS")
4. TIME RANGE: What time period ("February", "past 3 months", "yesterday")
5. OTHER TERMS: Generic search keywords

DO NOT mention specific field names - you don't know the structure of this log database.
Instead, extract WHAT DATA to search for.

COUNTRY EXTRACTION EXAMPLES:
- "traffic from Iran" → countries: ["Iran"]
- "connections to China" → countries: ["China"]  
- "requests from Russia in February" → countries: ["Russia"], time_range: February

PORT EXTRACTION EXAMPLES:
- "port 443" → ports: [443]
- "connections on port 1194" → ports: [1194]
- "port 443 in February" → ports: [443], time_range: February

TIME RANGES:
- "February" or "last month" or "past month" → "2026-02-01:2026-03-01" (use current year)
- "past 3 months" → "now-3M"
- "last week" → "now-1w"
- "yesterday" → "now-1d"
- "past 90 days" → "now-90d"
- No time mention → "now-90d"

RESPOND IN JSON:
{{
  "reasoning": "What the user is asking for (2-3 sentences)",
  "detected_time_range": "Time period mentioned verbatim",
  "time_range": "Elasticsearch range format",
  "ports": [list of port numbers, empty if none],
  "countries": [list of country names, empty if none],
  "protocols": [list of protocols, empty if none],
  "search_terms": [other generic search terms],
  "skip_search": false
}}

EXAMPLES OF GOOD RESPONSES:

Q: "any traffic from iran in the past 3 months?"
A: {{
  "reasoning": "User asking for network traffic originating from Iran in the last 3 months",
  "detected_time_range": "past 3 months",
  "time_range": "now-3M",
  "countries": ["Iran"],
  "ports": [],
  "protocols": [],
  "search_terms": [],
  "skip_search": false
}}

Q: "traffic on port 1194 in february"
A: {{
  "reasoning": "User asking for traffic on specific port in February",
  "detected_time_range": "February",
  "time_range": "2026-02-01:2026-03-01",
  "ports": [1194],
  "countries": [],
  "protocols": [],
  "search_terms": [],
  "skip_search": false
}}"""

    try:
        response = llm.complete(prompt)
        logger.debug("[%s] LLM Query Plan Response: %s", SKILL_NAME, response[:200])
        
        # Parse JSON response
        import json
        plan = json.loads(response)
        
        # Validate and sanitize - ensure required fields exist
        if not isinstance(plan.get("search_terms"), list):
            plan["search_terms"] = []
        if not isinstance(plan.get("ports"), list):
            plan["ports"] = []
        if not isinstance(plan.get("countries"), list):
            plan["countries"] = []
        if not isinstance(plan.get("protocols"), list):
            plan["protocols"] = []
        if not isinstance(plan.get("time_range"), str):
            plan["time_range"] = "now-90d"
        if not isinstance(plan.get("reasoning"), str):
            plan["reasoning"] = response[:100]
        
        logger.info(
            "[%s] Query Plan: Detected '%s' → range=%s | Ports=%s | Countries=%s | Protocols=%s | Terms=%s | Skip=%s",
            SKILL_NAME,
            plan.get("detected_time_range", "no explicit time range"),
            plan.get("time_range"),
            plan.get("ports", []),
            plan.get("countries", []),
            plan.get("protocols", []),
            plan.get("search_terms"),
            plan.get("skip_search", False)
        )
        
        return plan
    except Exception as exc:
        logger.warning("[%s] LLM query planning failed: %s. Cannot proceed without LLM.", SKILL_NAME, exc)
        
        # No fallback to hardcoded term extraction - LLM should handle this
        # If LLM fails, it's better to have no log search than a wrong one
        return {
            "reasoning": "LLM planning failed",
            "search_terms": [],
            "time_range": "now-90d",
            "skip_search": True,
            "detected_time_range": "(error)",
        }




def _format_combined_context(
    rag_docs: list[dict], raw_logs: list[dict], question: str, search_terms: list[str] = None
) -> str:
    """Format both RAG baseline data and raw logs for LLM analysis."""
    if search_terms is None:
        search_terms = []
    
    context_parts = []
    
    # Add user's question for clarity
    context_parts.append(f"User Question: {question}")
    
    # Add search terms used if any
    if search_terms:
        context_parts.append(f"Search Terms Extracted: {', '.join(search_terms)}")
    
    if rag_docs:
        context_parts.append("=== BASELINE KNOWLEDGE (from stored baselines) ===")
        for i, doc in enumerate(rag_docs, 1):  # All retrieved RAG docs (typically 5)
            category = doc.get("category", "unknown")
            source = doc.get("source", "unknown")
            text = doc.get("text", "")
            similarity = doc.get("similarity", 0.0)
            context_parts.append(
                f"[Baseline {i} | {source} | {category} | Match: {similarity:.1%}]\n{text}"
            )
    
    if raw_logs:
        context_parts.append("\n=== OBSERVED DATA (from recent logs) ===")
        # Add note about what was searched for
        if search_terms:
            context_parts.append(
                f"Note: These logs were selected because they match your search for: {', '.join(search_terms)}"
            )
        context_parts.append(_summarize_raw_logs(raw_logs, question, search_terms))
    
    return "\n\n".join(context_parts)


def _summarize_raw_logs(logs: list[dict], question: str, search_terms: list[str] = None) -> str:
    """
    Return raw logs with all fields intact for the LLM to parse.
    Shows up to 25 records (enough for analysis, manageable token count).
    No guessing about "relevant" fields - the LLM decides what matters.
    """
    if search_terms is None:
        search_terms = []
        
    if not logs:
        return "No recent log records found."
    
    # Cap at 25 records for reasonable LLM token usage while still showing plenty of data
    display_logs = logs[:25]
    
    summary_lines = [
        f"Found {len(logs)} matching log records (showing first {len(display_logs)}):"
    ]
    
    if search_terms:
        summary_lines.append(f"(matched on search terms: {', '.join(search_terms)})")
    
    summary_lines.append("")
    
    # Show all fields from each record (no filtering, no guessing)
    # LLM is smart enough to find @timestamp and extract what it needs
    for i, log in enumerate(display_logs, 1):
        summary_lines.append(f"Record {i}:")
        
        # Display all fields from the record, sorted for readability
        for field in sorted(log.keys()):
            value = log[field]
            
            # Handle nested structures
            if isinstance(value, dict):
                value = str(value)[:100]  # Truncate very long nested structures
            elif isinstance(value, (list, str)):
                value = str(value)[:200]
            
            summary_lines.append(f"  {field}: {value}")
        
        summary_lines.append("")
    
    if len(logs) > len(display_logs):
        summary_lines.append(f"(... {len(logs) - len(display_logs)} more records omitted for brevity)")
    
    return "\n".join(summary_lines)


def _extract_answer_from_data(
    question: str,
    context_text: str,
    instruction: str,
    llm: Any,
) -> str:
    """Use LLM to extract specific, detailed answers from RAG baselines and raw logs."""
    prompt = f"""User Question: "{question}"

Available Context (baselines and raw log records):
{context_text}

Follow the Data Extraction Rules from your instructions to answer this question:
- Extract EXACT values from the data (timestamps, IPs, ports, protocols)
- Quote ALL matching records with complete field information
- Handle timezone conversions if requested
- Use exact counts, not vague language
- Never say data is unavailable if it's in the records shown above"""

    messages = [
        {"role": "system", "content": instruction},
        {"role": "user", "content": prompt},
    ]

    try:
        response = llm.chat(messages)
        return response.strip()
    except Exception as exc:
        logger.error("Failed to extract answer: %s", exc)
        return f"Error analyzing data: {exc}"
