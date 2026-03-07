"""
tests/test_skill_onboarding.py — Tests for skill variable discovery and onboarding.
"""
import json
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from core.skill_onboarding import (
    discover_skill_requirements,
    get_missing_skill_variables,
    _load_onboarding_state,
    _save_onboarding_state,
)


class TestSkillRequirementDiscovery:
    """Test discovering skill-specific variable requirements."""

    def test_discover_skill_requirements(self):
        """Should discover required variables from skill manifest files."""
        requirements = discover_skill_requirements()
        
        # threat_analyst should have API key requirements
        assert "threat_analyst" in requirements
        threat_analyst_vars = requirements["threat_analyst"]
        assert "ABUSEIPDB_API_KEY" in threat_analyst_vars
        assert "ALIENVAULT_API_KEY" in threat_analyst_vars
        assert "VIRUSTOTAL_API_KEY" in threat_analyst_vars
        
        # Verify optional flag
        assert threat_analyst_vars["ABUSEIPDB_API_KEY"].get("optional") is True
        assert threat_analyst_vars["ABUSEIPDB_API_KEY"].get("is_secret") is True

    def test_discover_geoip_requirements(self):
        """Should discover MaxMind license key requirement for geoip_lookup."""
        requirements = discover_skill_requirements()
        
        assert "geoip_lookup" in requirements
        geoip_vars = requirements["geoip_lookup"]
        assert "MAXMIND_LICENSE_KEY" in geoip_vars
        
        # Verify required flag
        assert geoip_vars["MAXMIND_LICENSE_KEY"].get("optional") is False
        assert geoip_vars["MAXMIND_LICENSE_KEY"].get("is_secret") is True

    def test_discover_empty_for_skills_without_requirements(self):
        """Skills without required_env_vars in manifest should not appear."""
        requirements = discover_skill_requirements()
        
        # anomaly_triage doesn't declare requirements, so it shouldn't appear
        assert "anomaly_triage" not in requirements
        # forensic_examiner doesn't declare requirements
        assert "forensic_examiner" not in requirements

    def test_missing_variables_with_no_env_set(self):
        """Should report all variables as missing when environment is empty."""
        with patch.dict(os.environ, {}, clear=True):
            # Clear environment and reload dotenv
            with patch("core.skill_onboarding.load_dotenv"):
                missing = get_missing_skill_variables()
                
                # threat_analyst vars should appear as missing
                # (optional is only checked in ensure_skill_variables_onboarded)
                assert "threat_analyst" in missing
                assert "ABUSEIPDB_API_KEY" in missing["threat_analyst"]
                
                # geoip_lookup required var should appear as missing
                assert "geoip_lookup" in missing
                assert "MAXMIND_LICENSE_KEY" in missing["geoip_lookup"]

    def test_missing_variables_with_partial_env_set(self):
        """Should report only unset variables as missing."""
        # This test checks that only variables NOT in the environment are reported as missing.
        # Note: The actual .env file may have some values set, so we only test
        # that variables we explicitly set are not reported as missing.
        env = {
            "MAXMIND_LICENSE_KEY": "test-key-123",
            "ABUSEIPDB_API_KEY": "test-abuse-key",
        }
        with patch.dict(os.environ, env):
            with patch("core.skill_onboarding.load_dotenv"):
                missing = get_missing_skill_variables()
                
                # geoip_lookup should not appear (key is set)
                assert "geoip_lookup" not in missing
                # threat_analyst may or may not appear (depends on what's in .env)
                if "threat_analyst" in missing:
                    # But ABUSEIPDB_API_KEY shouldn't be in the list (it's set)
                    assert "ABUSEIPDB_API_KEY" not in missing["threat_analyst"]

    def test_all_variables_set_no_missing(self):
        """Should report no missing variables when all are set."""
        env = {
            "MAXMIND_LICENSE_KEY": "test-key",
            "ABUSEIPDB_API_KEY": "test",
            "ALIENVAULT_API_KEY": "test",
            "VIRUSTOTAL_API_KEY": "test",
            "TALOS_CLIENT_ID": "test",
            "TALOS_CLIENT_SECRET": "test",
        }
        with patch.dict(os.environ, env, clear=True):
            with patch("core.skill_onboarding.load_dotenv"):
                missing = get_missing_skill_variables()
                
                # Should be empty
                assert missing == {}


class TestOnboardingState:
    """Test onboarding state tracking."""

    def test_load_empty_state(self, tmp_path):
        """Should load empty dict if state file doesn't exist."""
        with patch(
            "core.skill_onboarding._ONBOARDING_STATE_PATH",
            tmp_path / ".onboarding_state.json"
        ):
            state = _load_onboarding_state()
            assert state == {}

    def test_save_and_load_state(self, tmp_path):
        """Should save and load onboarding state correctly."""
        state_file = tmp_path / ".onboarding_state.json"
        
        with patch("core.skill_onboarding._ONBOARDING_STATE_PATH", state_file):
            # Save a state
            test_state = {
                "skills_onboarded": ["threat_analyst", "geoip_lookup"],
                "timestamp": "2026-03-07T12:00:00Z",
            }
            _save_onboarding_state(test_state)
            
            # Load it back
            loaded = _load_onboarding_state()
            assert loaded == test_state

    def test_load_corrupted_state(self, tmp_path):
        """Should handle corrupted state files gracefully."""
        state_file = tmp_path / ".onboarding_state.json"
        state_file.write_text("{ invalid json }")
        
        with patch("core.skill_onboarding._ONBOARDING_STATE_PATH", state_file):
            state = _load_onboarding_state()
            assert state == {}


class TestVariableDescriptions:
    """Test that skill variables have useful descriptions."""

    def test_threat_analyst_descriptions(self):
        """threat_analyst variables should have descriptions."""
        requirements = discover_skill_requirements()
        threat_analyst = requirements.get("threat_analyst", {})
        
        for var_name, var_spec in threat_analyst.items():
            assert "description" in var_spec
            assert len(var_spec["description"]) > 0
            assert var_spec.get("env_key") == var_name

    def test_geoip_descriptions(self):
        """geoip_lookup variables should have descriptions."""
        requirements = discover_skill_requirements()
        geoip = requirements.get("geoip_lookup", {})
        
        for var_name, var_spec in geoip.items():
            assert "description" in var_spec
            assert len(var_spec["description"]) > 0
            assert var_spec.get("env_key") == var_name


class TestManifestValidation:
    """Test that manifest files are properly structured."""

    def test_threat_analyst_manifest_has_required_env_vars(self):
        """threat_analyst manifest should declare required_env_vars."""
        from pathlib import Path
        
        manifest_path = Path(__file__).parent.parent / "skills" / "threat_analyst" / "manifest.yaml"
        assert manifest_path.exists()
        
        import yaml
        manifest = yaml.safe_load(manifest_path.read_text())
        assert "required_env_vars" in manifest
        assert len(manifest["required_env_vars"]) > 0

    def test_geoip_manifest_has_required_env_vars(self):
        """geoip_lookup manifest should declare required_env_vars."""
        from pathlib import Path
        
        manifest_path = Path(__file__).parent.parent / "skills" / "geoip_lookup" / "manifest.yaml"
        assert manifest_path.exists()
        
        import yaml
        manifest = yaml.safe_load(manifest_path.read_text())
        assert "required_env_vars" in manifest
        assert len(manifest["required_env_vars"]) > 0
