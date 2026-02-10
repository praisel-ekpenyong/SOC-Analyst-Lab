"""Text file parsing."""

import re
from typing import List, Tuple
from ..models.resume import ParsingWarning, SeverityLevel


class TextParser:
    """Plain text parser."""
    
    def __init__(self):
        self.warnings: List[ParsingWarning] = []
    
    def parse(self, file_path: str) -> Tuple[str, List[ParsingWarning]]:
        """Parse text file and return text and warnings."""
        self.warnings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                text = f.read()
        except UnicodeDecodeError:
            # Try with different encoding
            try:
                with open(file_path, 'r', encoding='latin-1') as f:
                    text = f.read()
                self.warnings.append(ParsingWarning(
                    message="File encoding is not UTF-8, used fallback encoding",
                    severity=SeverityLevel.LOW,
                    example=None
                ))
            except Exception as e:
                self.warnings.append(ParsingWarning(
                    message=f"Error reading file: {str(e)}",
                    severity=SeverityLevel.HIGH,
                    example=None
                ))
                return "", self.warnings
        except Exception as e:
            self.warnings.append(ParsingWarning(
                message=f"Error reading file: {str(e)}",
                severity=SeverityLevel.HIGH,
                example=None
            ))
            return "", self.warnings
        
        # Run quality checks
        self._check_parsing_quality(text)
        
        # Normalize text
        normalized_text = self._normalize_text(text)
        
        return normalized_text, self.warnings
    
    def _check_parsing_quality(self, text: str):
        """Check for parsing quality issues."""
        # Check for low text extraction
        if len(text.strip()) < 100:
            self.warnings.append(ParsingWarning(
                message="Very little text in file",
                severity=SeverityLevel.HIGH,
                example=text[:50] if text else None
            ))
        
        # Check for excessive special characters
        special_chars = re.findall(r'[^\w\s\-\.,;:()@/]', text)
        if len(special_chars) > len(text) * 0.1:
            self.warnings.append(ParsingWarning(
                message="Excessive special characters detected",
                severity=SeverityLevel.MEDIUM,
                example=f"Found {len(special_chars)} special characters"
            ))
        
        # Check for missing common section headers
        if not self._has_common_sections(text):
            self.warnings.append(ParsingWarning(
                message="Missing common resume section headers",
                severity=SeverityLevel.MEDIUM,
                example="Expected sections like Experience, Education, Skills not found"
            ))
    
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
        
        # Normalize whitespace within lines but keep line breaks
        lines = text.split('\n')
        lines = [re.sub(r'\s+', ' ', line.strip()) for line in lines]
        text = '\n'.join(lines)
        
        # Reduce multiple blank lines to max 2
        text = re.sub(r'\n\s*\n\s*\n+', '\n\n', text)
        
        return text.strip()
