"""Scoring data models."""

from typing import List, Dict, Optional
from dataclasses import dataclass, field


@dataclass
class ScoreBreakdown:
    """Score breakdown model."""
    keywords_and_phrases: float = 0.0
    required_skills: float = 0.0
    responsibilities_alignment: float = 0.0
    seniority_and_scope: float = 0.0
    tools_and_systems: float = 0.0
    education_and_certifications: float = 0.0
    
    def total(self) -> float:
        """Calculate total score."""
        return (
            self.keywords_and_phrases +
            self.required_skills +
            self.responsibilities_alignment +
            self.seniority_and_scope +
            self.tools_and_systems +
            self.education_and_certifications
        )


@dataclass
class ScoringResult:
    """Scoring result model."""
    overall_score: float
    sub_scores: ScoreBreakdown
    penalties: Dict[str, float] = field(default_factory=dict)
    score_explanation: List[str] = field(default_factory=list)
    top_contributors: List[dict] = field(default_factory=list)
    top_penalties: List[dict] = field(default_factory=list)
