"""
tests/test_forensic_examiner_integration.py

Integration test for forensic_examiner with realistic incident scenario.

This tests the full flow:
1. Parse field documentation
2. Extract search keywords
3. Build queries (without IP/port confusion)
4. Generate timeline narrative
"""
import pytest
import json
from unittest.mock import Mock, MagicMock, patch, call
from datetime import datetime


@pytest.fixture
def mock_db():
    """Mock database with sample Iran incident logs."""
    db = Mock()
    
    # Sample logs from Iran IP to 192.168.0.16:1194
    sample_logs = [
        {
            "_id": "log1",
            "_source": {
                "@timestamp": "2026-01-10T08:30:45Z",
                "source.ip": "1.1.1.100",
                "destination.ip": "192.168.0.16",
                "destination.port": 1194,
                "source.port": 52341,
                "protocol": "tcp",
                "geoip.country_code2": "IR",
                "event.message": "Connection attempt to VPN port",
            }
        },
        {
            "_id": "log2",
            "_source": {
                "@timestamp": "2026-01-15T14:22:10Z",
                "source.ip": "1.1.1.100",
                "destination.ip": "192.168.0.16",
                "destination.port": 1194,
                "source.port": 52342,
                "protocol": "tcp",
                "geoip.country_code2": "IR",
                "event.message": "Connection attempt to VPN port",
            }
        },
        {
            "_id": "log3",
            "_source": {
                "@timestamp": "2026-01-20T09:15:30Z",
                "source.ip": "1.1.1.100",
                "destination.ip": "192.168.0.16",
                "destination.port": 1194,
                "source.port": 52343,
                "protocol": "tcp",
                "geoip.country_code2": "IR",
                "event.message": "Connection attempt to VPN port",
            }
        },
    ]
    
    db.search = Mock(return_value=sample_logs)
    return db


@pytest.fixture
def mock_llm():
    """Mock LLM that returns structured timeline."""
    llm = Mock()
    
    def llm_side_effect(messages):
        # Check what the messages are asking for
        prompt = str(messages[-1].get("content", ""))
        
        if "Build a comprehensive forensic timeline" in prompt:
            return """## Forensic Timeline Analysis

### Timeline
- **2026-01-10 08:30:45 UTC**: First connection attempt from Iran (IP 1.1.1.100) to 192.168.0.16:1194
- **2026-01-15 14:22:10 UTC**: Second connection attempt, 5 days later
- **2026-01-20 09:15:30 UTC**: Third connection attempt, 5 days later

### Pattern Analysis
- **Frequency**: 3 connection attempts over 10 days (recurring every 5 days)
- **Pattern Type**: Regular/Periodic - indicates automated bot or scheduled scanning
- **Source**: Single Iranian IP (1.1.1.100) with incremental source port numbers
- **Destination**: Consistent target (192.168.0.16:1194 - likely VPN service)
- **Protocol**: All TCP, indicating connection attempts

### Risk Assessment
- This is likely **automated reconnaissance** (bot-like behavior)
- The periodic 5-day interval suggests cron job or periodic scanner
- The consistent target and port indicate targeted probing, not random scanning
- **Threat Level**: MEDIUM - Persistent reconnaissance activity from hostile nation

### Recommendations
1. Block the IP 1.1.1.100 at firewall
2. Implement rate limiting on VPN port 1194
3. Monitor for successful connections from this IP
4. Alert on further attempts from Iran"""
        
        elif "refined" in prompt.lower() or "follow-up" in prompt.lower():
            return json.dumps({
                "summary": "Expand search to related IPs and timeframes",
                "search_queries": [
                    {"description": "Other Iranian IPs", "keywords": ["Iran"]},
                    {"description": "Other VPN ports", "keywords": ["1194", "vpn"]},
                ],
                "rationale": "Determine if this is isolated or part of broader campaign"
            })
        
        elif "strategy" in prompt.lower():
            return json.dumps({
                "summary": "Search for Iran traffic to VPN server",
                "search_queries": [
                    {"description": "Iran to target IP on VPN port", 
                     "keywords": ["Iran", "1.1.1.1", "192.168.0.16", "1194"]},
                ],
                "time_window": "2026-01-01 to 2026-03-31",
                "reasoning": "Look for Iranian IPs connecting to known VPN infrastructure"
            })
        
        else:
            return json.dumps({
                "summary": "Generic search",
                "search_queries": [],
            })
    
    llm.chat = Mock(side_effect=llm_side_effect)
    return llm


@pytest.fixture
def mock_config():
    """Mock configuration."""
    cfg = Mock()
    cfg.get = Mock(side_effect=lambda section, key, **kwargs: {
        ("db", "logs_index"): "logstash*",
        ("db", "vector_index"): "securityclaw-vectors",
    }.get((section, key), kwargs.get("default")))
    return cfg


def test_forensic_examiner_iran_incident_produces_timeline(mock_db, mock_llm, mock_config):
    """Test that forensic_examiner generates rich timeline for Iran VPN incident."""
    from skills.forensic_examiner import logic
    
    context = {
        "db": mock_db,
        "llm": mock_llm,
        "config": mock_config,
        "parameters": {
            "question": "There is traffic from Iran to the destination IP 192.168.0.16 on port 1194 in the past 3 months. Do forensics on this."
        },
        "conversation_history": [],
    }
    
    # Mock field documentation from RAG
    field_docs = """
    - source.ip (IPv4 address): Source IP of connection
    - destination.ip (IPv4 address): Destination IP of connection
    - destination.port (Port number): Destination port
    - source.port (Port number): Source port
    - protocol (Protocol): Transport protocol (tcp, udp)
    - geoip.country_code2 (Text): Country code
    - @timestamp (Timestamp): Event timestamp
    - event.message (Text): Event description
    """
    
    with patch('skills.forensic_examiner.logic._fetch_field_documentation', return_value=field_docs):
        result = logic.run(context)
    
    # Verify result structure
    assert result["status"] == "ok", f"Should succeed, got {result}"
    assert "forensic_report" in result
    
    report = result["forensic_report"]
    
    # Verify report has all required elements
    assert "incident_summary" in report
    assert "timeline_narrative" in report
    assert "results_found" in report
    assert report["results_found"] > 0, "Should have found logs"
    
    # Verify timeline has rich content (not just generic text)
    timeline = report["timeline_narrative"].lower()
    
    # Check for timeline elements
    assert "2026-01" in report["timeline_narrative"] or "january" in timeline, \
        "Should include specific dates"
    assert "pattern" in timeline or "periodic" in timeline or "frequency" in timeline, \
        "Should analyze pattern"
    assert "iran" in timeline, "Should mention Iran"
    assert "1194" in report["timeline_narrative"] or "port" in timeline, \
        "Should mention port"
    assert "threat" in timeline or "risk" in timeline or "bot" in timeline, \
        "Should provide threat assessment"
    
    # Verify timeline is NOT generic one-liner
    assert len(report["timeline_narrative"]) > 200, \
        f"Timeline too short ({len(report['timeline_narrative'])} chars). Likely generic response"


def test_field_mapping_prevents_port_ip_confusion():
    """Test that port 1194 doesn't get searched in IP fields."""
    from skills.forensic_examiner import logic
    
    # Field docs with both IP and port fields
    field_docs = """
    - source.ip (IPv4): Source address
    - destination.ip (IPv4): Destination address
    - destination.port (Port): Destination port number
    """
    
    mappings = logic._parse_field_mappings(field_docs)
    
    # Verify separation
    assert "source.ip" in mappings["ip_fields"]
    assert "destination.ip" in mappings["ip_fields"]
    assert "destination.port" in mappings["port_fields"]
    
    # CRITICAL: No IP fields in text fields (prevents the bug)
    for ip_field in mappings["ip_fields"]:
        assert ip_field not in mappings.get("all_text_fields", []), \
            f"BUG: IP field {ip_field} shouldn't be in text_fields!"
    
    # Build search clauses with keywords including a port number
    strategy = {
        "search_queries": [
            {
                "description": "Search with port",
                "keywords": ["192.168.0.16", "1194"],
            }
        ]
    }
    
    # Mock db that would fail with bad query
    mock_db = Mock()
    call_count = [0]
    
    def search_side_effect(index, query, **kwargs):
        call_count[0] += 1
        # Simulate OpenSearch would fail if port went into IP field
        if call_count[0] == 1:
            # Check if query structure is correct
            bool_query = query.get("query", {}).get("bool", {})
            should_clauses = bool_query.get("should", [])
            
            # Look for any term queries with 1194 in IP fields
            for clause in should_clauses:
                if "term" in clause:
                    for field, value in clause["term"].items():
                        if value == "1194" and "ip" in field.lower():
                            # This would be the bug!
                            raise Exception("'1194' is not an IP string literal")
        
        return [{"_id": "1", "_source": {"@timestamp": "2026-01-10"}}]
    
    mock_db.search = Mock(side_effect=search_side_effect)
    mock_llm = Mock()
    
    # This should NOT raise the IP literal error
    results = logic._execute_searches(mock_db, "logstash*", strategy, field_docs, mock_llm)
    assert isinstance(results, list), "Should complete without IP literal error"
    assert call_count[0] == 1, "Should succeed on first try now (no query malformed error)"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
