"""Resume parser orchestrator."""

import os
import re
from typing import Optional
from ..models.resume import Resume, ContactInfo, ParsingWarning, SeverityLevel
from .pdf_parser import PDFParser
from .docx_parser import DOCXParser
from .text_parser import TextParser
from ..extractors.section_extractor import SectionExtractor


class ResumeParser:
    """Main resume parser that orchestrates parsing."""
    
    def __init__(self):
        self.pdf_parser = PDFParser()
        self.docx_parser = DOCXParser()
        self.text_parser = TextParser()
        self.section_extractor = SectionExtractor()
    
    def parse_file(self, file_path: str) -> Resume:
        """Parse resume file and return Resume object."""
        if not os.path.exists(file_path):
            return Resume(
                full_text="",
                parsing_warnings=[ParsingWarning(
                    message=f"File not found: {file_path}",
                    severity=SeverityLevel.HIGH,
                    example=None
                )]
            )
        
        # Determine file type and parse
        file_ext = os.path.splitext(file_path)[1].lower()
        
        if file_ext == '.pdf':
            text, page_boundaries, warnings = self.pdf_parser.parse(file_path)
            file_type = "pdf"
        elif file_ext in ['.docx', '.doc']:
            text, warnings = self.docx_parser.parse(file_path)
            page_boundaries = []
            file_type = "docx"
        else:
            text, warnings = self.text_parser.parse(file_path)
            page_boundaries = []
            file_type = "txt"
        
        # Extract contact info
        contact_info = self._extract_contact_info(text, warnings)
        
        # Extract sections
        sections = self.section_extractor.extract_sections(text)
        
        resume = Resume(
            full_text=text,
            sections=sections,
            contact_info=contact_info,
            page_boundaries=page_boundaries,
            parsing_warnings=warnings,
            file_type=file_type
        )
        
        return resume
    
    def parse_text(self, text: str) -> Resume:
        """Parse resume from raw text."""
        # Normalize text
        text = self.text_parser._normalize_text(text)
        
        # Extract contact info
        warnings = []
        contact_info = self._extract_contact_info(text, warnings)
        
        # Extract sections
        sections = self.section_extractor.extract_sections(text)
        
        resume = Resume(
            full_text=text,
            sections=sections,
            contact_info=contact_info,
            parsing_warnings=warnings,
            file_type="text"
        )
        
        return resume
    
    def _extract_contact_info(self, text: str, warnings: list) -> ContactInfo:
        """Extract contact information from resume text."""
        contact_info = ContactInfo()
        
        # Extract email
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        email_match = re.search(email_pattern, text)
        if email_match:
            contact_info.email = email_match.group()
        
        # Extract phone
        phone_pattern = r'(\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'
        phone_match = re.search(phone_pattern, text)
        if phone_match:
            contact_info.phone = phone_match.group()
        
        # Extract LinkedIn
        linkedin_pattern = r'linkedin\.com/in/[\w\-]+'
        linkedin_match = re.search(linkedin_pattern, text, re.IGNORECASE)
        if linkedin_match:
            contact_info.linkedin = linkedin_match.group()
        
        # Extract GitHub
        github_pattern = r'github\.com/[\w\-]+'
        github_match = re.search(github_pattern, text, re.IGNORECASE)
        if github_match:
            contact_info.github = github_match.group()
        
        # Validate contact info
        if not contact_info.email:
            warnings.append(ParsingWarning(
                message="Email address not found",
                severity=SeverityLevel.MEDIUM,
                example="Consider adding your email for contact"
            ))
        
        if not contact_info.phone:
            warnings.append(ParsingWarning(
                message="Phone number not found",
                severity=SeverityLevel.MEDIUM,
                example="Consider adding your phone number for contact"
            ))
        
        return contact_info
