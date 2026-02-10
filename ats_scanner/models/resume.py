"""Resume data models."""

from typing import List, Optional, Tuple
from dataclasses import dataclass, field
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


@dataclass
class ParsingWarning:
    """Parsing warning model."""
    message: str
    severity: SeverityLevel
    example: Optional[str] = None
    location: Optional[str] = None


@dataclass
class ContactInfo:
    """Contact information model."""
    email: Optional[str] = None
    phone: Optional[str] = None
    linkedin: Optional[str] = None
    github: Optional[str] = None
    website: Optional[str] = None


@dataclass
class ResumeSection:
    """Resume section model."""
    type: SectionType
    text: str
    start_offset: int
    end_offset: int
    heading: Optional[str] = None


@dataclass
class Resume:
    """Resume model."""
    full_text: str
    sections: List[ResumeSection] = field(default_factory=list)
    contact_info: ContactInfo = field(default_factory=ContactInfo)
    page_boundaries: List[int] = field(default_factory=list)
    parsing_warnings: List[ParsingWarning] = field(default_factory=list)
    file_type: Optional[str] = None
    
    def get_section_text(self, section_type: SectionType) -> str:
        """Get text from a specific section type."""
        sections = [s for s in self.sections if s.type == section_type]
        return "\n".join(s.text for s in sections)
