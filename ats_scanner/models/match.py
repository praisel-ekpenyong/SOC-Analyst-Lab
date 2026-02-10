"""Matching and evidence data models."""

from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum


class MatchGrade(str, Enum):
    """Grade for requirement match."""
    DIRECT = "direct"
    EQUIVALENT = "equivalent"
    INDIRECT = "indirect"
    WEAK = "weak"
    MISSING = "missing"


class ConfidenceLevel(str, Enum):
    """Confidence level for match."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class DepthLevel(str, Enum):
    """Depth level inferred from verbs."""
    LED = "led"
    OWNED = "owned"
    DELIVERED = "delivered"
    USED = "used"
    UNKNOWN = "unknown"


class EvidenceSpan(BaseModel):
    """Evidence span model."""
    matched_text: str
    start_offset: int
    end_offset: int
    section: str
    source_type: str  # experience, projects, skills, education, other
    context: Optional[str] = None
    date_range: Optional[str] = None
    recency_weight: float = 0.5
    depth: DepthLevel = DepthLevel.UNKNOWN
    
    
class RequirementMatch(BaseModel):
    """Requirement match model."""
    requirement_text: str
    requirement_category: str
    requirement_importance: str
    grade: MatchGrade
    confidence: ConfidenceLevel
    evidence_spans: List[EvidenceSpan] = Field(default_factory=list)
    recency_weight: float = 0.5
    depth: DepthLevel = DepthLevel.UNKNOWN
    fix: Optional[str] = None
    suggested_keywords: List[str] = Field(default_factory=list)
    is_synonym_match: bool = False
    matched_via: Optional[str] = None  # tracks what alias/synonym matched


class MatchResult(BaseModel):
    """Overall match result model."""
    matched_keywords: List[dict] = Field(default_factory=list)
    missing_keywords: List[str] = Field(default_factory=list)
    requirements_map: List[RequirementMatch] = Field(default_factory=list)
    dealbreakers: List[str] = Field(default_factory=list)
    keyword_stuffing_detected: bool = False
    keyword_stuffing_score: float = 0.0
