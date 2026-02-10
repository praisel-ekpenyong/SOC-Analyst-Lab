"""Data models for ATS Scanner."""

from .resume import Resume, ResumeSection, ContactInfo, ParsingWarning
from .job import JobPosting, JobRequirement
from .match import EvidenceSpan, RequirementMatch, MatchResult
from .scoring import ScoreBreakdown, ScoringResult
from .rewrite import RewriteSuggestion

__all__ = [
    "Resume",
    "ResumeSection",
    "ContactInfo",
    "ParsingWarning",
    "JobPosting",
    "JobRequirement",
    "EvidenceSpan",
    "RequirementMatch",
    "MatchResult",
    "ScoreBreakdown",
    "ScoringResult",
    "RewriteSuggestion",
]
