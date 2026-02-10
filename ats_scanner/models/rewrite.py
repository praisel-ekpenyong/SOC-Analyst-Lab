"""Rewrite suggestion data models."""

from typing import List, Optional
from dataclasses import dataclass, field


@dataclass
class RewriteSuggestion:
    """Rewrite suggestion model."""
    suggested_text: str
    reason: str
    supported_by_evidence: bool
    original_span: Optional[str] = None
    proof_needed: List[str] = field(default_factory=list)
    impact: str = "medium"  # low, medium, high
    requirement_addressed: Optional[str] = None
