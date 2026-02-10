"""Rewrite suggestion data models."""

from typing import List, Optional
from pydantic import BaseModel, Field


class RewriteSuggestion(BaseModel):
    """Rewrite suggestion model."""
    original_span: Optional[str] = None
    suggested_text: str
    reason: str
    supported_by_evidence: bool
    proof_needed: List[str] = Field(default_factory=list)
    impact: str = "medium"  # low, medium, high
    requirement_addressed: Optional[str] = None
