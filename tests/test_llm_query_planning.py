"""
tests/test_llm_query_planning.py

Test that LLM query planning is data-agnostic:
- LLM extracts intent (search terms, time range)
- Python discovers fields and builds OpenSearch query
- No knowledge of specific field names in LLM prompt
"""
import json
from unittest.mock import MagicMock, patch
import pytest


class TestLLMQueryPlanning:
    """Test LLM-based query planning for data-agnostic searches."""
    
    def test_llm_plans_port_traffic_query_february(self):
        """
        Test: User asks "traffic on port 1194 in february"
        Expected: LLM extracts port 1194, February time range
        Ensure: LLM doesn't know field names, Python discovers them
        """
        # Mock the LLM response
        mock_llm = MagicMock()
        mock_llm.complete.return_value = json.dumps({
            "reasoning": "User asking for traffic on port 1194 in February",
            "detected_time_range": "february (last month, approximately)",
            "time_range": "now-2M",
            "search_terms": ["1194"],
            "skip_search": False
        })
        
        # Import after mocking
        from skills.rag_querier.logic import _plan_query_with_llm
        
        # Test the planning
        question = "any traffic on port 1194 in february?"
        conversation_history = []
        field_mappings = {}  # LLM doesn't use this anyway
        
        plan = _plan_query_with_llm(question, conversation_history, field_mappings, mock_llm)
        
        # Verify the plan
        assert plan["search_terms"] == ["1194"]
        assert plan["time_range"] == "now-2M"
        assert plan.get("skip_search") == False
        assert "1194" in plan["reasoning"]
        
        # Verify LLM was called (with NO field names in the prompt)
        mock_llm.complete.assert_called_once()
        prompt_used = mock_llm.complete.call_args[0][0]
        
        # The prompt should NOT mention specific field names
        assert "dest_port" not in prompt_used
        assert "destination.port" not in prompt_used
        assert "src_ip" not in prompt_used
        assert "geoip" not in prompt_used
        
        # But the prompt SHOULD mention the intent clearly
        assert "port" in prompt_used.lower()
        assert "search" in prompt_used.lower()
    
    def test_query_builder_uses_discovered_fields(self):
        """
        Test: Query builder discovers and uses actual fields
        Ensure: Python layer maps generic intent to instance-specific fields
        """
        from core.query_builder import build_keyword_query
        
        # Simulated field discovery (what would be returned by discover_field_mappings)
        field_mappings = {
            "port_fields": ["dest_port", "dst_port"],
            "ip_fields": ["src_ip", "source_ip"],
            "text_fields": ["message", "description"],
            "all_fields": ["src_ip", "dest_port", "@timestamp"]
        }
        
        # LLM extracted these generic terms
        search_terms = ["1194"]  # Port number extracted from user question
        
        # Build the query
        query, metadata = build_keyword_query(search_terms, field_mappings)
        
        # Verify query structure
        assert query is not None
        assert isinstance(query, dict)
        assert "query" in query
        assert "bool" in query["query"]
        
        # Verify the query uses discovered fields (text_fields if available, else all_fields)
        fields_used = metadata.get("fields_used", [])
        assert len(fields_used) > 0
        # Should use text fields since they're available
        assert all(f in field_mappings.get("text_fields", []) + field_mappings.get("all_fields", []) for f in fields_used)
    
    def test_iran_traffic_query_planning(self):
        """
        Test: User asks "traffic from Iran in past 3 months"
        Expected: LLM extracts "iran", time_range="now-3M"
        Ensure: No field knowledge leaked to LLM
        """
        mock_llm = MagicMock()
        mock_llm.complete.return_value = json.dumps({
            "reasoning": "User asking about traffic from Iran over past 3 months",
            "detected_time_range": "past 3 months",
            "time_range": "now-3M",
            "search_terms": ["iran"],
            "skip_search": False
        })
        
        from skills.rag_querier.logic import _plan_query_with_llm
        
        question = "traffic from iran in the past 3 months?"
        conversation_history = []
        field_mappings = {}
        
        plan = _plan_query_with_llm(question, conversation_history, field_mappings, mock_llm)
        
        assert plan["search_terms"] == ["iran"]
        assert plan["time_range"] == "now-3M"
        assert plan.get("skip_search") == False
        
        # Verify LLM prompt is data-agnostic
        prompt_used = mock_llm.complete.call_args[0][0]
        assert "geoip" not in prompt_used.lower()  # Specific field name
        assert "country_name" not in prompt_used.lower()  # Specific field name
        assert "iran" in prompt_used.lower()  # But intent IS clear


class TestDataAgnosticQueryBuilding:
    """Test that query building is data-agnostic."""
    
    def test_query_builder_handles_port_search_generically(self):
        """
        Test: Query builder receives generic search term "1194"
        Expected: Maps to discovered fields and builds OpenSearch query
        Ensure: No hardcoded field names in the logic
        """
        from core.query_builder import build_keyword_query
        
        # Generic search term extracted by LLM
        search_terms = ["1194"]  # Port number
        
        # Field mappings discovered by Python from schema
        field_mappings = {
            "port_fields": ["dest_port", "dst_port"],  # Actual instance fields
            "all_fields": ["src_ip", "dest_port", "@timestamp"]
        }
        
        # Build the query
        query, metadata = build_keyword_query(search_terms, field_mappings)
        
        # Verify query structure is valid OpenSearch DSL
        assert query is not None
        assert isinstance(query, dict)
        assert "query" in query
        assert "bool" in query["query"]
        
        # Verify query uses discovered fields (not hardcoded)
        fields_used = metadata.get("fields_used", [])
        assert len(fields_used) > 0
        # Should use fields from the mappings, not hardcoded names
        assert all(f in field_mappings.get("all_fields", []) for f in fields_used)
    
    def test_query_builder_with_different_schema(self):
        """
        Test: Same search term with different field names
        Expected: Query builder adapts to different schema
        Ensure: System is truly data-agnostic across schemas
        """
        from core.query_builder import build_keyword_query
        
        search_terms = ["1194"]
        
        # Different dataset with different field naming
        field_mappings_variant = {
            "port_fields": ["destination_port", "dport"],  # Different names!
            "all_fields": ["source_ip", "destination_port", "timestamp"]
        }
        
        query, metadata = build_keyword_query(search_terms, field_mappings_variant)
        
        assert query is not None
        fields_used = metadata.get("fields_used", [])
        # Should have adapted to new field names
        assert len(fields_used) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
