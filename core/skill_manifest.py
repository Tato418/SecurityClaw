"""Load and manage skill manifests for modular supervisor routing."""

import logging
from pathlib import Path
from typing import Any
import yaml

logger = logging.getLogger(__name__)


class SkillManifestLoader:
    """Load skill manifests to enable modular supervisor decision-making."""

    def __init__(self, skills_dir: Path | str = None):
        """Initialize with path to skills directory."""
        if skills_dir is None:
            # Default to skills/ directory relative to this file
            skills_dir = Path(__file__).parent.parent / "skills"
        self.skills_dir = Path(skills_dir)

    def load_all_manifests(self) -> dict[str, dict[str, Any]]:
        """Load manifest.yaml from all skill directories.
        
        Returns:
            Dict mapping skill_name -> manifest content
        """
        manifests = {}
        
        if not self.skills_dir.exists():
            logger.warning("Skills directory not found: %s", self.skills_dir)
            return manifests
        
        for skill_dir in self.skills_dir.iterdir():
            if not skill_dir.is_dir():
                continue
            
            manifest_path = skill_dir / "manifest.yaml"
            if not manifest_path.exists():
                continue
            
            try:
                with open(manifest_path, "r", encoding="utf-8") as f:
                    manifest = yaml.safe_load(f)
                
                if not manifest:
                    logger.warning("Empty manifest in %s", skill_dir.name)
                    continue
                
                skill_name = manifest.get("name", skill_dir.name)
                manifests[skill_name] = manifest
                logger.debug("Loaded manifest for skill: %s", skill_name)
            
            except Exception as e:
                logger.warning("Failed to load manifest in %s: %s", skill_dir.name, e)
        
        return manifests

    def build_supervisor_context(self, manifests: dict[str, dict]) -> str:
        """Generate supervisor prompt context from manifests.
        
        This creates a structured guide the LLM can use to understand
        which skill to choose based on question keywords and intent.
        
        Args:
            manifests: Dict from load_all_manifests()
        
        Returns:
            Formatted string for inclusion in supervisor prompt
        """
        if not manifests:
            return ""
        
        lines = [
            "## Skill Capabilities (Dynamically Loaded from Manifests)\n",
            "### Can/Cannot Matrix\n",
        ]
        
        for skill_name, manifest in sorted(manifests.items()):
            lines.append(f"\n**{skill_name}**")
            
            can_answer = manifest.get("can_answer", [])
            if can_answer:
                lines.append(f"  - CAN: {', '.join(can_answer)}")
            
            cannot_answer = manifest.get("cannot_answer", [])
            if cannot_answer:
                lines.append(f"  - CANNOT: {', '.join(cannot_answer)}")
            
            priority_keywords = manifest.get("priority_keywords", [])
            if priority_keywords:
                lines.append(f"  - Priority keywords: {', '.join(priority_keywords)}")
            
            explicit_only = manifest.get("explicit_only", False)
            if explicit_only:
                lines.append(f"  - EXPLICIT ONLY: Requires explicit skill mention")
            
            min_context = manifest.get("min_prior_context", 0)
            if min_context > 0:
                lines.append(f"  - Works best with {min_context}+ prior results")
        
        lines.append("\n")
        return "\n".join(lines)


def get_skill_matching_instructions(manifests: dict[str, dict]) -> str:
    """Generate routing decision instructions based on manifests.
    
    Returns:
        Formatted instructions for the supervisor LLM
    """
    lines = [
        "## Skill Selection Algorithm (Manifest-Driven)\n",
        "1. Extract keywords from user question",
        "2. For each skill, check priority_keywords match",
        "3. If match found and skill.can_answer matches intent → rank 1 (primary)",
        "4. If match found but min_prior_context not met → rank 2 (secondary)",
        "5. If no match → use general purpose ordering",
        "6. Explicit-only skills only if explicitly mentioned\n",
    ]
    
    return "\n".join(lines)
