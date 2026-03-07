"""
Test that threat_analyst doesn't hallucinate about baseline context when none is found.

This prevents responses like "The baseline context also shows no relevant patterns"
when baseline_querier was never invoked and RAG found no relevant context.
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json

from skills.threat_analyst.logic import _analyze_finding


class TestThreatAnalystBaselineContextHandling:
    """Test that threat_analyst properly handles missing baseline context."""
    
    def test_excludes_baseline_section_when_no_context_found(self):
        """
        Baseline context section should NOT be included in LLM prompt when
        RAG engine returns "No relevant context found".
        
        This prevents the LLM from making up claims about baseline analysis.
        """
        # Mock RAG engine that returns "No relevant context found"
        mock_rag = Mock()
        mock_rag.build_context_string.return_value = "### Relevant Behavioral Context\n_No relevant context found._\n"
        
        # Mock LLM that captures what it receives
        mock_llm = Mock()
        llm_prompt_received = None
        
        def capture_prompt(messages):
            nonlocal llm_prompt_received
            llm_prompt_received = messages[1]["content"]
            # Return a valid verdict
            return json.dumps({
                "verdict": "BENIGN",
                "confidence": 0.9,
                "reasoning": "No suspicious activity detected"
            })
        
        mock_llm.chat.side_effect = capture_prompt
        
        # Run threat_analyst
        finding = "IPs 1.2.3.4 and 5.6.7.8 associated with policy alert"
        instruction = "Analyze the finding"
        
        result = _analyze_finding(
            finding,
            instruction,
            mock_rag,
            mock_llm,
            conversation_history=[]
        )
        
        # Verify baseline section is NOT in the prompt
        assert "**Baseline Context:**" not in llm_prompt_received
        assert "_No relevant context found._" not in llm_prompt_received
        
        # Verify reputation section IS present  
        assert "**Reputation Intelligence:**" in llm_prompt_received
        
        # Verify the result is still valid
        assert result["verdict"] == "BENIGN"
    
    def test_includes_baseline_section_when_context_found(self):
        """
        Baseline context section SHOULD be included when RAG finds relevant context.
        """
        # Mock RAG engine that returns actual context
        mock_rag = Mock()
        mock_rag.build_context_string.return_value = (
            "### Relevant Behavioral Context\n"
            "1. [network_baseline/network_baseliner] Normal traffic pattern includes IPs 1.2.3.0/24\n"
            "2. [network_baseline/network_baseliner] Port 443 is expected for this IP range\n"
        )
        
        # Mock LLM
        mock_llm = Mock()
        llm_prompt_received = None
        
        def capture_prompt(messages):
            nonlocal llm_prompt_received
            llm_prompt_received = messages[1]["content"]
            return json.dumps({
                "verdict": "BENIGN",
                "confidence": 0.95,
                "reasoning": "Activity matches baseline patterns"
            })
        
        mock_llm.chat.side_effect = capture_prompt
        
        # Run threat_analyst
        finding = "IPs 1.2.3.4 and 5.6.7.8 accessing port 443"
        instruction = "Analyze the finding"
        
        result = _analyze_finding(
            finding,
            instruction,
            mock_rag,
            mock_llm,
            conversation_history=[]
        )
        
        # Verify baseline section IS in the prompt when relevant context exists
        assert "**Baseline Context:**" in llm_prompt_received
        assert "Normal traffic pattern" in llm_prompt_received
        assert "Port 443 is expected" in llm_prompt_received
        
        # Make sure "No relevant context found" is NOT in there
        assert "_No relevant context found._" not in llm_prompt_received
        
        # Verify the result
        assert result["verdict"] == "BENIGN"
        assert "baseline patterns" in result["reasoning"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
