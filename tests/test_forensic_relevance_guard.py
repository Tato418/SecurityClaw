from __future__ import annotations

from unittest.mock import Mock

from skills.forensic_examiner.logic import (
    _anchor_coverage_score,
    _augment_keywords_with_context,
    _build_time_filter_from_context,
    _execute_searches,
    _is_relevant_search_query,
    _run_iterative_investigation,
)


def test_dns_query_is_skipped_when_incident_has_no_dns_intent():
    incident_context = {
        "ips": ["62.60.131.168", "192.168.0.16"],
        "domains": [],
        "ports": ["1194"],
        "countries": ["iran"],
        "protocols": ["tcp"],
        "has_dns_intent": False,
    }

    dns_search = {
        "description": "Find DNS queries related to Iran",
        "keywords": ["dns", "iran"],
    }

    assert _is_relevant_search_query(dns_search, incident_context) is False


def test_ip_port_anchored_search_is_kept():
    incident_context = {
        "ips": ["62.60.131.168", "192.168.0.16"],
        "domains": [],
        "ports": ["1194"],
        "countries": ["iran"],
        "protocols": ["tcp"],
        "has_dns_intent": False,
    }

    relevant_search = {
        "description": "Find traffic to 192.168.0.16 on port 1194 from Iran",
        "keywords": ["192.168.0.16", "1194", "iran", "tcp"],
    }

    assert _is_relevant_search_query(relevant_search, incident_context) is True


def test_foreign_ip_query_is_rejected_when_known_ips_exist():
    incident_context = {
        "ips": ["62.60.131.168", "192.168.0.16"],
        "domains": [],
        "ports": ["1194"],
        "countries": ["iran"],
        "protocols": ["tcp"],
        "has_dns_intent": False,
    }

    foreign_ip_search = {
        "description": "Investigate suspicious source 100.29.192.126",
        "keywords": ["100.29.192.126", "threat intelligence"],
    }

    assert _is_relevant_search_query(foreign_ip_search, incident_context) is False


def test_time_filter_prefers_context_timestamp_window():
    incident_context = {
        "time_range_hint": {
            "gte": "2026-02-11T10:22:10Z",
            "lte": "2026-02-15T10:23:13Z",
        }
    }
    strategy = {"time_window": "2025-12-01 to 2025-12-31"}

    filt = _build_time_filter_from_context(incident_context, strategy)
    assert filt == {
        "range": {
            "@timestamp": {
                "gte": "2026-02-11T10:22:10Z",
                "lte": "2026-02-15T10:23:13Z",
            }
        }
    }


def test_execute_searches_augments_vague_query_with_incident_anchors():
    db = Mock()
    captured = {}

    def _search(index, query, size=100):
        captured["query"] = query
        return []

    db.search = Mock(side_effect=_search)

    field_docs = """
    - source.ip (IPv4 address): Source IP
    - destination.ip (IPv4 address): Destination IP
    - destination.port (Port number): Destination port
    - protocol (Protocol): Transport protocol
    - @timestamp (Timestamp): Event time
    - event.message (Text): Event message
    """

    strategy = {
        "search_queries": [
            {"description": "Identify traffic to known IP addresses from Iran", "keywords": ["iran"]}
        ]
    }
    incident_context = {
        "ips": ["62.60.131.168", "192.168.0.16"],
        "domains": [],
        "ports": ["1194"],
        "countries": ["iran"],
        "protocols": ["tcp"],
        "has_dns_intent": False,
        "time_range_hint": {
            "gte": "2026-02-11T10:22:10Z",
            "lte": "2026-02-15T10:23:13Z",
        },
    }

    _execute_searches(db, "logstash*", strategy, field_docs, llm=None, incident_context=incident_context)

    query = captured.get("query")
    assert query is not None
    bool_q = query["query"]["bool"]
    assert "must" in bool_q
    assert "filter" in bool_q
    assert bool_q["filter"][0]["range"]["@timestamp"]["gte"] == "2026-02-11T10:22:10Z"
    assert bool_q["filter"][0]["range"]["@timestamp"]["lte"] == "2026-02-15T10:23:13Z"

    hard_constraints = bool_q["must"][1:]
    assert len(hard_constraints) >= 2
    hard_text = str(hard_constraints)
    assert "minimum_should_match': 2" in hard_text or '"minimum_should_match": 2' in hard_text

    # Ensure anchor clause includes incident IP/port (not just generic Iran text)
    serialized = str(query)
    assert "62.60.131.168" in serialized or "192.168.0.16" in serialized
    assert "1194" in serialized


def test_iterative_investigation_executes_next_action_until_sufficient():
    class _LoopLLM:
        def __init__(self):
            self.eval_calls = 0

        def chat(self, messages):
            prompt = messages[-1]["content"]
            if "iterative workflow" in prompt:
                return (
                    '{"summary":"plan","todos":[{"title":"step1","goal":"start","search_queries":'
                    '[{"description":"first","keywords":["iran","1194"]}]}],'
                    '"time_window":"2026-02-01 to 2026-02-20","stop_criteria":"enough"}'
                )
            if "Re-evaluate this forensic investigation progress" in prompt:
                self.eval_calls += 1
                if self.eval_calls == 1:
                    return (
                        '{"is_relevant":true,"is_sufficient":false,"confidence":0.4,'
                        '"reasoning":"need more context","gaps":["missing source ip"],'
                        '"next_action":{"title":"step2","goal":"pivot","search_queries":'
                        '[{"description":"second","keywords":["62.60.131.168","192.168.0.16","1194"]}]}}'
                    )
                return (
                    '{"is_relevant":true,"is_sufficient":true,"confidence":0.9,'
                    '"reasoning":"sufficient","gaps":[],"next_action":null}'
                )
            return "{}"

    db = Mock()
    call_count = {"n": 0}

    def _search(index, query, size=100):
        call_count["n"] += 1
        if call_count["n"] == 1:
            return [{"_id": "1", "event.message": "generic iran activity", "destination.port": 1194}]
        return [{"_id": "2", "source.ip": "62.60.131.168", "destination.ip": "192.168.0.16", "destination.port": 1194}]

    db.search = Mock(side_effect=_search)

    field_docs = """
    - source.ip (IPv4 address): Source IP
    - destination.ip (IPv4 address): Destination IP
    - destination.port (Port number): Destination port
    - event.message (Text): Event message
    - @timestamp (Timestamp): Event time
    """

    incident_context = {
        "ips": ["62.60.131.168", "192.168.0.16"],
        "domains": [],
        "ports": ["1194"],
        "countries": ["iran"],
        "protocols": ["tcp"],
        "has_dns_intent": False,
        "time_range_hint": {"gte": "2026-02-11T00:00:00Z", "lte": "2026-02-15T23:59:59Z"},
    }

    result = _run_iterative_investigation(
        db=db,
        llm=_LoopLLM(),
        logs_index="logstash*",
        incident_question="forensic analysis",
        conversation_history=[],
        field_docs=field_docs,
        incident_context=incident_context,
    )

    assert result["iterations_completed"] == 2
    assert len(result["all_results"]) == 2
    assert _anchor_coverage_score(result["all_results"], incident_context) >= 0.5
