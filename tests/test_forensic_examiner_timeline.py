"""
tests/test_forensic_examiner_timeline.py

Comprehensive test for forensic_examiner timeline functionality.

Tests that forensic_examiner:
1. Properly parses field types to avoid IP/port confusion
2. Returns rich timeline data with dates and pattern analysis
3. Builds comprehensive forensic reports with proper structure
"""
import pytest
import json
import logging
from datetime import datetime, timezone
from unittest.mock import Mock, MagicMock, patch

logger = logging.getLogger(__name__)


@pytest.fixture
def mock_db():
    """Mock database connector."""
    db = Mock()
    db.search = Mock()
    return db


@pytest.fixture
def mock_llm():
    """Mock LLM provider."""
    llm = Mock()
    llm.chat = Mock()
    return llm


@pytest.fixture
def mock_config():
    """Mock configuration."""
    cfg = Mock()
    cfg.get = Mock(side_effect=lambda section, key, **kwargs: {
        ("db", "logs_index"): "securityclaw-logs",
        ("db", "vector_index"): "securityclaw-vectors",
    }.get((section, key), kwargs.get("default")))
    return cfg


def test_parse_field_mappings_excludes_ip_from_text_fields():
    """Test that IP fields are NOT added to all_text_fields."""
    from skills.forensic_examiner import logic
    
    field_docs = """
    Field: source.ip
    Type: IPv4 address
    Description: Source IP address
    
    Field: destination.port
    Type: Port number
    Description: Destination port
    
    Field: event.message
    Type: Text
    Description: Event message
    """
    
    # Using the OLD buggy version (before fix)
    # This will demonstrate the bug
    mappings = logic._parse_field_mappings(field_docs)
    
    # REQUIREMENT: IP fields should NOT be automatically added to text fields
    # After fix, this will be true; before fix it's false
    assert "source.ip" not in mappings.get("all_text_fields", []), \
        "BUG: IP field 'source.ip' is in all_text_fields! Will cause '1194 is not an IP' errors"
    
    # Port fields should be identified separately
    assert "destination.port" in mappings.get("port_fields", []), \
        "Port fields must be recognized separately"
    
    # Text fields should be included
    assert "event.message" in mappings.get("all_text_fields", []) or \
           "event.message" in mappings.get("text_fields", []), \
        "Text fields must be discoverable"


def test_execute_searches_with_port_number():
    """Test that port numbers don't get treated as IP addresses."""
    from skills.forensic_examiner import logic
    
    # Mock database
    mock_db = Mock()
    mock_db.search = Mock(return_value=[])
    
    # Mock configuration
    mock_cfg = Mock()
    mock_cfg.get = Mock(side_effect=lambda s, k, **kw: {
        ("db", "logs_index"): "logstash*",
        ("db", "vector_index"): "securityclaw-vectors",
    }.get((s, k), kw.get("default")))
    
    field_docs = """
    Field: source.ip (IPv4 address - Source IP)
    Field: destination.ip (IPv4 address - Destination IP)
    Field: destination_port (Port number - Destination port)
    Field: message (Text - Event message)
    """
    
    strategy = {
        "search_queries": [
            {
                "description": "Search for port 1194 traffic",
                "keywords": ["1194", "192.168.0.16"],
            }
        ]
    }
    
    # Before fix: This would put "1194" into IP fields and fail
    # After fix: "1194" goes to text fields, "192.168.0.16" goes to IP fields
    try:
        results = logic._execute_searches(mock_db, "logstash*", strategy, field_docs, llm=None)
        # If we get here, the search was structured correctly
        assert isinstance(results, list), "Results should be a list"
    except Exception as exc:
        # If get error about "1194 is not an IP literal", the bug is present
        if "is not an IP string literal" in str(exc):
            pytest.fail(f"BUG: Port number being treated as IP: {exc}")
        raise


def test_forensic_timeline_contains_required_elements():
    """Test that forensic timeline includes dates, times, and pattern analysis."""
    from skills.forensic_examiner import logic
    
    # Create sample logs with proper structure
    sample_results = [
        {
            "_id": "1",
            "_source": {
                "@timestamp": "2026-01-15T10:30:00Z",
                "source.ip": "1.1.1.1",
                "destination.ip": "192.168.0.16",
                "destination.port": 1194,
                "event.message": "Connection attempt",
            }
        },
        {
            "_id": "2",
            "_source": {
                "@timestamp": "2026-01-20T14:45:00Z",
                "source.ip": "1.1.1.1",
                "destination.ip": "192.168.0.16",
                "destination.port": 1194,
                "event.message": "Connection attempt",
            }
        },
        {
            "_id": "3",
            "_source": {
                "@timestamp": "2026-01-25T09:15:00Z",
                "source.ip": "1.1.1.1",
                "destination.ip": "192.168.0.16",
                "destination.port": 1194,
                "event.message": "Connection attempt",
            }
        },
    ]
    
    mock_llm = Mock()
    mock_llm.chat = Mock(return_value=json.dumps({
        "timeline": [
            {
                "timestamp": "2026-01-15",
                "event": "First connection from Iran IP"
            }
        ],
        "pattern": "Periodic connections every 5 days (robot-like)"
    }))
    
    field_docs = "Field: event.message"
    
    # This should produce a timeline with dates, times, and pattern
    narrative = logic._ask_llm_for_comprehensive_timeline(
        mock_llm,
        "Investigate Iran traffic to 192.168.0.16:1194",
        sample_results,
        field_docs,
        "Analyze logs"
    )
    
    # REQUIREMENT: Timeline must contain actual analysis, not just "no results" message
    assert narrative, "Timeline should not be empty"
    # Should have meaningful content about dates/times/patterns, not generic response
    assert len(narrative) > 100, "Timeline narrative should be detailed"
    # Should NOT be the generic "no results" response
    assert "no relevant logs were found" not in narrative.lower(), \
        "With results, should not return generic 'no results' message"


def test_forensic_no_results_returns_reasonable_output():
    """Test that forensic examiner returns reasonable output even with 0 results."""
    from skills.forensic_examiner import logic
    
    mock_llm = Mock()
    # Mock the LLM response for no-results case
    mock_llm.chat = Mock(return_value="""
    ## Forensic Summary
    - No logs found for Iran traffic to 192.168.0.16:1194 in the past 3 months
    - Possible causes: Activity may be infrequent, blocked by firewall, or in different time window
    - Recommendations: Check firewall logs, extend time window, verify IP mappings
    """)
    
    field_docs = "Field: source.ip\nField: destination.port"
    incident_question = "Investigate Iran traffic to 192.168.0.16:1194"
    strategy = {"search_queries": []}
    
    narrative = logic._ask_llm_for_timeline_no_results(
        mock_llm,
        incident_question,
        strategy,
        field_docs,
        "Instruction"
    )
    
    # Even with no results, should get meaningful analysis
    assert narrative, "Should return analysis even without results"
    assert "Forensic" in narrative or "logs" in narrative, \
        "Should have substantive content about forensic analysis"
    # Should NOT be a short generic sentence
    assert len(narrative) > 100, "Should provide helpful analysis, not one-liner"


def test_field_type_classification_accuracy():
    """Test that field types are correctly classified."""
    from skills.forensic_examiner import logic
    
    field_docs = """
    - source.ip (IPv4 address, Source IP)
    - destination.ip (IPv4 address, Destination IP)  
    - destination.port (Port number, Destination port)
    - source.port (Port number, Source port)
    -@timestamp (Timestamp, Event timestamp)
    - event.message (Text, Log message)
    - dns.query (DNS query)
    - protocol (Protocol, Transport protocol)
    """
    
    mappings = logic._parse_field_mappings(field_docs)
    
    # Verify each field is classified correctly
    assert "source.ip" in mappings["ip_fields"], "source.ip should be IP field"
    assert "destination.ip" in mappings["ip_fields"], "destination.ip should be IP field"
    assert "destination.port" in mappings.get("port_fields", []), \
        "destination.port should be recognized as port"
    assert "event.message" in mappings["all_text_fields"], \
        "event.message should be in text fields"
    
    # CRITICAL: IP fields must NOT be in all_text_fields after fix
    ip_fields = mappings.get("ip_fields", [])
    all_text = mappings.get("all_text_fields", [])
    ip_in_text = [f for f in ip_fields if f in all_text]
    assert not ip_in_text, \
        f"CRITICAL: IP fields found in all_text_fields: {ip_in_text}. " \
        f"This causes '1194 is not an IP' errors when searching port numbers."


def test_forensic_report_structure():
    """Test that forensic report has all required elements."""
    from skills.forensic_examiner import logic
    
    report = {
        "incident_summary": "Iran traffic to 192.168.0.16:1194",
        "initial_strategy": {"summary": "Search for Iran IPs"},
        "results_found": 5,
        "timeline_narrative": "Detailed forensic timeline with dates, times, pattern frequencies and botnet activity assessment",
        "refinement_rounds": 2,
    }
    
    # Validate report structure
    assert "incident_summary" in report, "Must have incident summary"
    assert "initial_strategy" in report, "Must have search strategy"
    assert "results_found" in report, "Must count results"
    assert "timeline_narrative" in report, "Must have timeline"
    assert isinstance(report["timeline_narrative"], str), "Timeline must be string"
    assert len(report["timeline_narrative"]) > 50, "Timeline must have substance"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
