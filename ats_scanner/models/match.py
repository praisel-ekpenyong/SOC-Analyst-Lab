"""Matching and evidence data models."""

from typing import List, Optional
from dataclasses import dataclass, field
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


@dataclass
class EvidenceSpan:
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
    matched_via: Optional[str] = None  # tracks what alias/synonym matched
    
    
@dataclass
class RequirementMatch:
    """Requirement match model."""
    requirement_text: str
    requirement_category: str
    requirement_importance: str
    grade: MatchGrade
    confidence: ConfidenceLevel
    evidence_spans: List[EvidenceSpan] = field(default_factory=list)
    recency_weight: float = 0.5
    depth: DepthLevel = DepthLevel.UNKNOWN
    fix: Optional[str] = None
    suggested_keywords: List[str] = field(default_factory=list)
    is_synonym_match: bool = False


@dataclass
class MatchResult:
    """Overall match result model."""
    matched_keywords: List[dict] = field(default_factory=list)
    missing_keywords: List[str] = field(default_factory=list)
    requirements_map: List[RequirementMatch] = field(default_factory=list)
    dealbreakers: List[str] = field(default_factory=list)
    keyword_stuffing_detected: bool = False
    keyword_stuffing_score: float = 0.0
