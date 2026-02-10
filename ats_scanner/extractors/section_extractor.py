"""Section extractor for resumes."""

import re
from typing import List, Tuple
from ..models.resume import ResumeSection, SectionType


class SectionExtractor:
    """Extract sections from resume text."""
    
    # Section heading variants
    SECTION_PATTERNS = {
        SectionType.SUMMARY: [
            r'\b(summary|profile|about|objective|professional summary)\b',
        ],
        SectionType.EXPERIENCE: [
            r'\b(experience|work experience|work history|employment|professional experience|career history)\b',
        ],
        SectionType.PROJECTS: [
            r'\b(projects|portfolio|key projects|selected projects)\b',
        ],
        SectionType.SKILLS: [
            r'\b(skills|technical skills|core competencies|technologies|competencies|expertise)\b',
        ],
        SectionType.EDUCATION: [
            r'\b(education|academic background|qualifications)\b',
        ],
        SectionType.CERTIFICATIONS: [
            r'\b(certifications|certificates|licenses|credentials)\b',
        ],
    }
    
    def extract_sections(self, text: str) -> List[ResumeSection]:
        """Extract sections from resume text."""
        sections = []
        
        # Find all section headers
        headers = self._find_section_headers(text)
        
        if not headers:
            # No headers found, use heuristics
            sections = self._extract_by_heuristics(text)
        else:
            # Split by headers
            sections = self._split_by_headers(text, headers)
        
        return sections
    
    def _find_section_headers(self, text: str) -> List[Tuple[str, SectionType, int]]:
        """Find section headers in text."""
        headers = []
        lines = text.split('\n')
        char_pos = 0
        
        for line in lines:
            line_stripped = line.strip()
            if line_stripped:
                # Check if line is a section header
                for section_type, patterns in self.SECTION_PATTERNS.items():
                    for pattern in patterns:
                        if re.match(pattern, line_stripped, re.IGNORECASE):
                            headers.append((line_stripped, section_type, char_pos))
                            break
            char_pos += len(line) + 1  # +1 for newline
        
        return headers
    
    def _split_by_headers(self, text: str, headers: List[Tuple[str, SectionType, int]]) -> List[ResumeSection]:
        """Split text into sections based on headers."""
        sections = []
        
        for i, (heading, section_type, start) in enumerate(headers):
            # Find end position
            if i < len(headers) - 1:
                end = headers[i + 1][2]
            else:
                end = len(text)
            
            # Extract section text
            section_text = text[start:end].strip()
            
            # Remove the heading from the text
            section_text = re.sub(
                re.escape(heading) + r'\s*',
                '',
                section_text,
                count=1,
                flags=re.IGNORECASE
            ).strip()
            
            if section_text:
                sections.append(ResumeSection(
                    type=section_type,
                    text=section_text,
                    start_offset=start,
                    end_offset=end,
                    heading=heading
                ))
        
        return sections
    
    def _extract_by_heuristics(self, text: str) -> List[ResumeSection]:
        """Extract sections using heuristics when headers are not clear."""
        sections = []
        
        # Try to find experience blocks with dates
        experience_blocks = self._find_experience_blocks(text)
        if experience_blocks:
            for start, end, block_text in experience_blocks:
                sections.append(ResumeSection(
                    type=SectionType.EXPERIENCE,
                    text=block_text,
                    start_offset=start,
                    end_offset=end,
                    heading=None
                ))
        
        # Try to find skills blocks (lists)
        skills_blocks = self._find_skills_blocks(text)
        if skills_blocks:
            for start, end, block_text in skills_blocks:
                sections.append(ResumeSection(
                    type=SectionType.SKILLS,
                    text=block_text,
                    start_offset=start,
                    end_offset=end,
                    heading=None
                ))
        
        # If no sections found, treat entire text as OTHER
        if not sections:
            sections.append(ResumeSection(
                type=SectionType.OTHER,
                text=text,
                start_offset=0,
                end_offset=len(text),
                heading=None
            ))
        
        return sections
    
    def _find_experience_blocks(self, text: str) -> List[Tuple[int, int, str]]:
        """Find experience blocks by looking for date ranges and job titles."""
        blocks = []
        
        # Pattern for date ranges
        date_pattern = r'\b(\d{1,2}/\d{4}|\d{4}|[A-Z][a-z]+ \d{4})\s*[-–]\s*(\d{1,2}/\d{4}|\d{4}|[A-Z][a-z]+ \d{4}|Present|Current)\b'
        
        # Find all date matches
        for match in re.finditer(date_pattern, text, re.IGNORECASE):
            # Extract context around the date (likely a job entry)
            start = max(0, match.start() - 200)
            end = min(len(text), match.end() + 500)
            block_text = text[start:end].strip()
            blocks.append((start, end, block_text))
        
        return blocks
    
    def _find_skills_blocks(self, text: str) -> List[Tuple[int, int, str]]:
        """Find skills blocks by looking for lists of comma-separated items."""
        blocks = []
        
        # Look for lines with many commas (likely skill lists)
        lines = text.split('\n')
        char_pos = 0
        
        for line in lines:
            line_stripped = line.strip()
            # If line has 3+ commas and is not too long, likely a skill list
            if line_stripped.count(',') >= 3 and len(line_stripped) < 300:
                blocks.append((char_pos, char_pos + len(line), line_stripped))
            char_pos += len(line) + 1
        
        return blocks
