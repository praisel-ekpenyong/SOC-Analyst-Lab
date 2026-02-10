"""PDF parsing with pdfplumber."""

import re
from typing import List, Tuple
from collections import Counter
from ..models.resume import ParsingWarning, SeverityLevel

# Try to import pdfplumber, but provide fallback
try:
    import pdfplumber
    HAS_PDFPLUMBER = True
except ImportError:
    HAS_PDFPLUMBER = False


class PDFParser:
    """PDF parser using pdfplumber."""
    
    def __init__(self):
        self.warnings: List[ParsingWarning] = []
        self.page_boundaries: List[int] = []
    
    def parse(self, file_path: str) -> Tuple[str, List[int], List[ParsingWarning]]:
        """Parse PDF file and return text, page boundaries, and warnings."""
        self.warnings = []
        self.page_boundaries = []
        
        if not HAS_PDFPLUMBER:
            self.warnings.append(ParsingWarning(
                message="pdfplumber not available - PDF parsing not supported",
                severity=SeverityLevel.HIGH,
                example="Install pdfplumber to parse PDF files"
            ))
            return "", [], self.warnings
        
        all_text = []
        char_count = 0
        page_texts = []
        
        try:
            with pdfplumber.open(file_path) as pdf:
                for page_num, page in enumerate(pdf.pages, 1):
                    text = page.extract_text() or ""
                    page_texts.append(text)
                    all_text.append(text)
                    char_count += len(text)
                    self.page_boundaries.append(char_count)
        except Exception as e:
            self.warnings.append(ParsingWarning(
                message=f"Error parsing PDF: {str(e)}",
                severity=SeverityLevel.HIGH,
                example=None
            ))
            return "", [], self.warnings
        
        full_text = "\n".join(all_text)
        
        # Run quality checks
        self._check_parsing_quality(full_text, page_texts)
        
        # Normalize text
        normalized_text = self._normalize_text(full_text)
        
        return normalized_text, self.page_boundaries, self.warnings
    
    def _check_parsing_quality(self, full_text: str, page_texts: List[str]):
        """Check for parsing quality issues."""
        # Check for low text extraction (possible image-based PDF)
        if len(full_text.strip()) < 100:
            self.warnings.append(ParsingWarning(
                message="Very little text extracted - PDF may be image-based",
                severity=SeverityLevel.HIGH,
                example=full_text[:50] if full_text else None
            ))
        
        # Check for excessive special characters
        special_chars = re.findall(r'[^\w\s\-\.,;:()@/]', full_text)
        if len(special_chars) > len(full_text) * 0.1:
            self.warnings.append(ParsingWarning(
                message="Excessive special characters detected - may indicate parsing issues",
                severity=SeverityLevel.MEDIUM,
                example=f"Found {len(special_chars)} special characters in {len(full_text)} chars"
            ))
        
        # Check for table or multi-column layout
        if self._detect_table_layout(full_text):
            self.warnings.append(ParsingWarning(
                message="Possible table or multi-column layout detected",
                severity=SeverityLevel.MEDIUM,
                example=None
            ))
        
        # Check for duplicated headers/footers
        duplicates = self._detect_duplicated_lines(page_texts)
        if duplicates:
            self.warnings.append(ParsingWarning(
                message="Duplicated header/footer text detected across pages",
                severity=SeverityLevel.LOW,
                example=f"Repeated: '{duplicates[0][:50]}...'"
            ))
        
        # Check for missing common section headers
        if not self._has_common_sections(full_text):
            self.warnings.append(ParsingWarning(
                message="Missing common resume section headers",
                severity=SeverityLevel.MEDIUM,
                example="Expected sections like Experience, Education, Skills not found"
            ))
    
    def _detect_table_layout(self, text: str) -> bool:
        """Detect if text might contain tables."""
        lines = text.split('\n')
        short_lines = sum(1 for line in lines if 0 < len(line.strip()) < 20)
        return short_lines > len(lines) * 0.3
    
    def _detect_duplicated_lines(self, page_texts: List[str]) -> List[str]:
        """Detect lines that appear in multiple pages (headers/footers)."""
        if len(page_texts) < 2:
            return []
        
        # Get first and last lines of each page
        page_lines = []
        for text in page_texts:
            lines = [l.strip() for l in text.split('\n') if l.strip()]
            if lines:
                page_lines.append((lines[0], lines[-1] if len(lines) > 1 else ""))
        
        # Count occurrences
        first_lines = [p[0] for p in page_lines]
        last_lines = [p[1] for p in page_lines]
        
        duplicates = []
        for line, count in Counter(first_lines).items():
            if count > 1 and len(line) > 5:
                duplicates.append(line)
        for line, count in Counter(last_lines).items():
            if count > 1 and len(line) > 5 and line not in duplicates:
                duplicates.append(line)
        
        return duplicates
    
    def _has_common_sections(self, text: str) -> bool:
        """Check if text contains common resume sections."""
        text_lower = text.lower()
        common_sections = [
            'experience', 'education', 'skills', 'work history',
            'employment', 'professional', 'summary', 'objective'
        ]
        return any(section in text_lower for section in common_sections)
    
    def _normalize_text(self, text: str) -> str:
        """Normalize whitespace and fix line wraps."""
        # Fix hyphenated line breaks
        text = re.sub(r'(\w)-\s*\n\s*(\w)', r'\1\2', text)
        
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text)
        text = re.sub(r'\n\s*\n\s*\n+', '\n\n', text)
        
        return text.strip()
