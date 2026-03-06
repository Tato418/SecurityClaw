"""
tests/test_forensic_timeline_quality.py

Tests that forensic timeline output has the richness users expect:
- Dates and times
- Frequency analysis
- Human vs bot classification
- Timeline narrative (not generic garbage)
"""
import pytest
from unittest.mock import Mock, patch
import json


def test_timeline_includes_dates_and_times():
    """Test that timeline narrative includes specific timestamps."""
    from skills.forensic_examiner import logic
    
    sample_results = [
        {
            "_id": "1",
            "_source": {
                "@timestamp": "2026-01-10T08:30:45Z",
                "source.ip": "1.1.1.100",
                "event.message": "Connection attempt",
            }
        },
        {
            "_id": "2",
            "_source": {
                "@timestamp": "2026-01-15T14:22:10Z",
                "source.ip": "1.1.1.100",
                "event.message": "Connection attempt",
            }
        },
    ]
    
    mock_llm = Mock()
    mock_llm.chat = Mock(return_value="""
    Timeline of Events:
    - **2026-01-10 08:30:45 UTC**: First connection from Iran IP 1.1.1.100
    - **2026-01-15 14:22:10 UTC**: Second connection attempt
    
    Frequency: 2 attempts over 5 days
    Pattern: Regular periodic activity (every 5 days) - indicates bot/automated scanning
    """)
    
    field_docs = "field: timestamp"
    instruction = "Be precise"
    
    narrative = logic._ask_llm_for_comprehensive_timeline(
        mock_llm,
        "Investigate Iran traffic",
        sample_results,
        field_docs,
        instruction
    )
    
    # MUST have actual dates/times
    assert "2026-01-10" in narrative or "10 january" in narrative.lower(), \
        "Must include specific dates from logs"
    assert "2026-01-15" in narrative or "15 january" in narrative.lower(), \
        "Must include second date"
    # Can have time or just date
    assert "08:30" in narrative or "14:22" in narrative or "UTC" in narrative, \
        "Should include time information or timezone"


def test_timeline_includes_frequency_analysis():
    """Test that timeline includes frequency analysis."""
    from skills.forensic_examiner import logic
    
    # Create 10 events over 30 days showing regular pattern
    sample_results = [
        {
            "_id": str(i),
            "_source": {
                "@timestamp": f"2026-01-{10 + i*3:02d}T10:00:00Z",
                "source.ip": "1.1.1.100",
                "destination.port": 1194,
                "event.message": "Connection",
            }
        }
        for i in range(10)
    ]
    
    mock_llm = Mock()
    mock_llm.chat = Mock(return_value="""
    Frequency Analysis:
    - Total Events: 10 connection attempts
    - Time Span: 30 days (Jan 10 - Feb 9, 2026)  
    - Frequency: ~1 attempt every 3 days (regular interval)
    - Pattern: PERIODIC/REGULAR - indicates automated bot or scheduled job
    - Consistency: Events occur at consistent times (10:00 UTC daily)
    - Non-human Indicators:
      * Exact 3-day intervals
      * Same time of day
      * Consistent source port increments
      * No weekend/weekday variation
    
    Conclusion: This is ROBOT/BOT activity, not human operator
    """)
    
    field_docs = "@timestamp field"
    
    narrative = logic._ask_llm_for_comprehensive_timeline(
        mock_llm,
        "Analyzed Iran connections",
        sample_results,
        field_docs,
        "Detailed"
    )
    
    # Must mention frequency
    lower = narrative.lower()
    frequency_keywords = ["frequency", "per day", "interval", "every", "periodic", "regular", "pattern"]
    has_frequency = any(kw in lower for kw in frequency_keywords)
    assert has_frequency, \
        f"Must mention frequency. Got: {narrative[:200]}"
    
    # Must distinguish human vs bot
    bot_indicators = ["bot", "automated", "robot", "periodic", "scheduled", "regular", "script"]
    has_classification = any(ind in lower for ind in bot_indicators)
    assert has_classification, \
        "Must classify as human or bot activity"


def test_timeline_not_generic_garbage():
    """Test that timeline is substantive, not generic one-liner."""
    from skills.forensic_examiner import logic
    
    results = [{"_id": "1", "_source": {"@timestamp": "2026-01-10T10:00:00Z"}}]
    
    mock_llm = Mock()
    # Return substantive analysis
    mock_llm.chat = Mock(return_value="""
    # Forensic Analysis Report
    
    ## Timeline
    - 2026-01-10: Event detected
    
    ## Entities
    - Source: Iranian IP range 1.1.1.0/24
    - Destination: 192.168.0.16:1194 (VPN endpoint)
    
    ## Pattern Analysis  
    Single event on Jan 10. Insufficient for pattern analysis.
    
    ## Recommendations
    - Enable logging for all VPN connection attempts
    - Implement geo-blocking for Iranian IP ranges
    - Alert on any future connection from this source
    """)
    
    narrative = logic._ask_llm_for_comprehensive_timeline(
        mock_llm,
        "Iran incident",
        results,
        "field docs",
        "instruction"
    )
    
    # Substantive narrative should be > 300 chars
    assert len(narrative) > 300, \
        f"Timeline too short ({len(narrative)} chars). Likely generic/garbage response"
    
    # Must NOT be generic one-liner about no data
    generic_garbage = [
        "no relevant logs were found",
        "no data available",
        "unable to analyze",
        "insufficient information",
    ]
    
    for garbage in generic_garbage:
        assert garbage.lower() not in narrative.lower(), \
            f"Timeline returned generic response with '{garbage}'"


def test_no_results_doesn_not_return_useless_sentence():
    """Test that even with no results, response is comprehensive."""
    from skills.forensic_examiner import logic
    
    mock_llm = Mock()
    mock_llm.chat = Mock(return_value="""
    No logs found for Iran traffic to 192.168.0.16:1194.
    
    Possible Explanations:
    1. **Firewall Blocked**: VPN server may be blocking Iranian IPs before logging
    2. **Log Rotation**: Events may have been older than current log retention (e.g., 90 days)
    3. **Wrong Field Mapping**: Search may not have matched actual field names
    4. **Timing**: Activity may occur during windows not yet ingested into logs
    
    Forensic Implications:
    - The ABSENCE of logs suggests either successful blocking or activity outside timeframe
    - Firewall/IDS may be more trustworthy source than application logs
    
    Recommended Next Steps:
    1. Check firewall/proxy logs for blocked connections from Iran
    2. Extend log retention query to 6+ months ago
    3. Examine VPN server logs directly
    4. Consult network admin about traffic shaping policies
    5. Review IDS alerts during this period
    """)
    
    strategy = {"search_queries": []}
    
    narrative = logic._ask_llm_for_timeline_no_results(
        mock_llm,
        "Iran incident",
        strategy,
        "field docs",
        "instruction"
    )
    
    # Should NOT be single sentence
    sentence_count = narrative.count(".")
    assert sentence_count > 5, \
        f"No-results response too short ({sentence_count} sentences). Should give helpful analysis"
    
    # Should be > 200 chars
    assert len(narrative) > 200, \
        f"Analysis too brief ({len(narrative)} chars). Should provide guidance"
    
    # Should NOT say "Unable to analyze" or similar cop-out
    assert "unable" not in narrative.lower(), \
        "Should not give up with 'unable to analyze'"
    assert "error" not in narrative.lower() or "error logs" in narrative.lower(), \
        "Avoid generic error messages"


def test_parses_multiple_dates_from_results():
    """Test that timeline extracts multiple dates from results."""
    from skills.forensic_examiner import logic
    
    # Three events on consecutive days
    results = [
        {
            "_id": "1",
            "_source": {
                "@timestamp": "2026-01-10T10:00:00Z",
                "source.ip": "1.1.1.100",
            }
        },
        {
            "_id": "2",
            "_source": {
                "@timestamp": "2026-01-11T14:30:00Z",
                "source.ip": "1.1.1.100",
            }
        },
        {
            "_id": "3",
            "_source": {
                "@timestamp": "2026-01-12T09:15:00Z",
                "source.ip": "1.1.1.100",
            }
        },
    ]
    
    mock_llm = Mock()
    mock_llm.chat = Mock(return_value="""
    Timeline:
    - Jan 10 10:00 UTC - Event 1
    - Jan 11 14:30 UTC - Event 2  
    - Jan 12 09:15 UTC - Event 3
    
    Pattern: Events on consecutive days from same source
    Frequency: Daily activity on Jan 10-12
    Trend: Consistent across 3-day window
    """)
    
    narrative = logic._ask_llm_for_comprehensive_timeline(
        mock_llm,
        None,
        results,
        "fields",
        "instruction"
    )
    
    # Must mention all dates
    date_count = sum(1 for date in ["jan 10", "jan 11", "jan 12", "10", "11", "12"] 
                    if date.lower() in narrative.lower())
    assert date_count >= 3, \
        f"Should mention all 3 dates. Found {date_count} date references"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
