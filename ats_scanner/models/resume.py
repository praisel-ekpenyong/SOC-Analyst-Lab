"""Resume data models."""

from typing import List, Optional, Tuple
from pydantic import BaseModel, Field
from enum import Enum


class SeverityLevel(str, Enum):
    """Severity level for parsing warnings."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class SectionType(str, Enum):
    """Resume section types."""
    SUMMARY = "summary"
    EXPERIENCE = "experience"
    PROJECTS = "projects"
    SKILLS = "skills"
    EDUCATION = "education"
    CERTIFICATIONS = "certifications"
    OTHER = "other"


class ParsingWarning(BaseModel):
    """Parsing warning model."""
    message: str
    severity: SeverityLevel
    example: Optional[str] = None
    location: Optional[str] = None


class ContactInfo(BaseModel):
    """Contact information model."""
    email: Optional[str] = None
    phone: Optional[str] = None
    linkedin: Optional[str] = None
    github: Optional[str] = None
    website: Optional[str] = None


class ResumeSection(BaseModel):
    """Resume section model."""
    type: SectionType
    text: str
    start_offset: int
    end_offset: int
    heading: Optional[str] = None


class Resume(BaseModel):
    """Resume model."""
    full_text: str
    sections: List[ResumeSection] = Field(default_factory=list)
    contact_info: ContactInfo = Field(default_factory=ContactInfo)
    page_boundaries: List[int] = Field(default_factory=list)
    parsing_warnings: List[ParsingWarning] = Field(default_factory=list)
    file_type: Optional[str] = None
    
    def get_section_text(self, section_type: SectionType) -> str:
        """Get text from a specific section type."""
        sections = [s for s in self.sections if s.type == section_type]
        return "\n".join(s.text for s in sections)
