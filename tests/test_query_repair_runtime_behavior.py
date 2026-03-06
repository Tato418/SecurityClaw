from __future__ import annotations

from unittest.mock import MagicMock

from core.db_connector import QueryMalformedException
from core.query_repair import IntelligentQueryRepair
from skills.forensic_examiner import logic as forensic_logic


class _MemoryStub:
    def __init__(self):
        self.saved: list[tuple[str, dict, dict]] = []

    def record_error_fix(self, error_msg: str, original_query: dict, fixed_query: dict):
        self.saved.append((error_msg, original_query, fixed_query))


def test_forensic_repair_success_with_zero_results_is_not_failure():
    db = MagicMock()
    llm = MagicMock()

    field_docs = """
    - source.ip (IPv4 address): Source IP
    - destination.ip (IPv4 address): Destination IP
    - event.message (Text): Event message
    """
    strategy = {
        "search_queries": [
            {"description": "keyword search", "keywords": ["tehran"]}
        ]
    }

    malformed_query = {
        "query": {"bool": {"should": [{"multi_match": {"query": "tehran", "fields": ["destination.port"]}}], "minimum_should_match": 1}},
        "size": 100,
    }

    db.search.side_effect = [
        QueryMalformedException("logstash*", malformed_query, "RequestError(400, 'search_phase_execution_exception', 'failed to create query: For input string: \"Tehran\"')"),
        [],
    ]

    results = forensic_logic._execute_searches(db, "logstash*", strategy, field_docs, llm)
    assert results == []


def test_query_repair_records_only_execution_successful_fix():
    db = MagicMock()
    llm = MagicMock()

    original_query = {"query": {"bool": {"should": "bad"}}}

    db.search.side_effect = [
        QueryMalformedException("idx", original_query, "RequestError(400, 'x_content_parse_exception', '[should] query malformed')"),
        [{"ok": True}],
    ]

    llm.complete.return_value = '{"query": {"bool": {"should": [{"match": {"message": "x"}}], "minimum_should_match": 1}}}'

    repair = IntelligentQueryRepair(db, llm)
    mem = _MemoryStub()
    repair.memory = mem

    success, results, _ = repair.repair_and_retry("idx", original_query, size=10)

    assert success is True
    assert results == [{"ok": True}]
    assert len(mem.saved) == 1


def test_query_repair_does_not_record_when_all_attempts_fail():
    db = MagicMock()
    llm = MagicMock()

    original_query = {"query": {"bool": {"should": "bad"}}}

    db.search.side_effect = QueryMalformedException(
        "idx",
        original_query,
        "RequestError(400, 'x_content_parse_exception', '[should] query malformed')",
    )
    llm.complete.return_value = "not json"

    repair = IntelligentQueryRepair(db, llm)
    mem = _MemoryStub()
    repair.memory = mem

    success, results, _ = repair.repair_and_retry("idx", original_query, size=10)

    assert success is False
    assert results is None
    assert mem.saved == []
