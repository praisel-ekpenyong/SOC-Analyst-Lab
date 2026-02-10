"""Scoring data models."""

from typing import List, Dict, Optional
from pydantic import BaseModel, Field


class ScoreBreakdown(BaseModel):
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


class ScoringResult(BaseModel):
    """Scoring result model."""
    overall_score: float
    sub_scores: ScoreBreakdown
    penalties: Dict[str, float] = Field(default_factory=dict)
    score_explanation: List[str] = Field(default_factory=list)
    top_contributors: List[dict] = Field(default_factory=list)
    top_penalties: List[dict] = Field(default_factory=list)
