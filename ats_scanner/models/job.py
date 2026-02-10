"""Job posting data models."""

from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum


class RequirementCategory(str, Enum):
    """Category of job requirement."""
    SKILL = "skill"
    TOOL = "tool"
    RESPONSIBILITY = "responsibility"
    DOMAIN = "domain"
    EDUCATION = "education"
    CERTIFICATION = "certification"
    YEARS = "years"
    SOFT = "soft"


class RequirementImportance(str, Enum):
    """Importance level of requirement."""
    MUST_HAVE = "must_have"
    REQUIRED = "required"
    PREFERRED = "preferred"
    RESPONSIBILITY = "responsibility"
    OTHER = "other"


class JobRequirement(BaseModel):
    """Job requirement model."""
    text: str
    category: RequirementCategory
    importance: RequirementImportance
    original_span: str
    start_offset: int
    end_offset: int
    keywords: List[str] = Field(default_factory=list)


class JobPosting(BaseModel):
    """Job posting model."""
    raw_text: str
    requirements: List[JobRequirement] = Field(default_factory=list)
    title: Optional[str] = None
    company: Optional[str] = None
    
    def get_must_haves(self) -> List[JobRequirement]:
        """Get must-have requirements."""
        return [r for r in self.requirements if r.importance == RequirementImportance.MUST_HAVE]
    
    def get_required(self) -> List[JobRequirement]:
        """Get required requirements."""
        return [r for r in self.requirements if r.importance == RequirementImportance.REQUIRED]
    
    def get_preferred(self) -> List[JobRequirement]:
        """Get preferred requirements."""
        return [r for r in self.requirements if r.importance == RequirementImportance.PREFERRED]
