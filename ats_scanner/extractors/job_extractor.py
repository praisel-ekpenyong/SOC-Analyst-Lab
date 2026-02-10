"""Job requirement extractor."""

import re
from typing import List
from ..models.job import JobPosting, JobRequirement, RequirementCategory, RequirementImportance


class JobExtractor:
    """Extract structured requirements from job postings."""
    
    # Importance cues
    MUST_HAVE_CUES = [
        r'\bmust\s+have\b',
        r'\brequired\b',
        r'\bmust\b',
        r'\bmandatory\b',
        r'\bessential\b',
        r'\bneed\s+to\s+have\b',
    ]
    
    REQUIRED_CUES = [
        r'\bshould\s+have\b',
        r'\bminimum\b',
        r'\bqualified\s+candidates\b',
        r'\byou\s+have\b',
    ]
    
    PREFERRED_CUES = [
        r'\bpreferred\b',
        r'\bnice\s+to\s+have\b',
        r'\bplus\b',
        r'\bbonus\b',
        r'\bdesirable\b',
    ]
    
    RESPONSIBILITY_CUES = [
        r'\byou\s+will\b',
        r'\bresponsibilities\s+include\b',
        r'\bresponsible\s+for\b',
        r'\bduties\b',
    ]
    
    def extract(self, text: str) -> JobPosting:
        """Extract job posting requirements."""
        requirements = []
        
        # Split into bullets and sentences
        items = self._split_into_items(text)
        
        # Process each item
        for item_text, start_offset in items:
            req = self._process_item(item_text, start_offset)
            if req:
                requirements.append(req)
        
        # Merge near duplicates
        requirements = self._merge_duplicates(requirements)
        
        job_posting = JobPosting(
            raw_text=text,
            requirements=requirements
        )
        
        return job_posting
    
    def _split_into_items(self, text: str) -> List[tuple]:
        """Split text into processable items (bullets and sentences)."""
        items = []
        
        # Find bullet points
        bullet_pattern = r'^[\s]*[•\-\*]\s+(.+?)(?=^[\s]*[•\-\*]|$)'
        bullets = re.finditer(bullet_pattern, text, re.MULTILINE | re.DOTALL)
        
        for match in bullets:
            items.append((match.group(1).strip(), match.start()))
        
        # If no bullets, split by sentences
        if not items:
            sentences = re.split(r'[.!?]\s+', text)
            char_pos = 0
            for sentence in sentences:
                sentence = sentence.strip()
                if len(sentence) > 20:  # Skip very short sentences
                    items.append((sentence, char_pos))
                char_pos += len(sentence) + 2  # +2 for delimiter and space
        
        return items
    
    def _process_item(self, text: str, start_offset: int) -> JobRequirement:
        """Process a single item and extract requirement."""
        if len(text.strip()) < 10:
            return None
        
        # Determine importance
        importance = self._determine_importance(text)
        
        # Determine category
        category = self._determine_category(text)
        
        # Extract keywords
        keywords = self._extract_keywords(text)
        
        req = JobRequirement(
            text=text,
            category=category,
            importance=importance,
            original_span=text,
            start_offset=start_offset,
            end_offset=start_offset + len(text),
            keywords=keywords
        )
        
        return req
    
    def _determine_importance(self, text: str) -> RequirementImportance:
        """Determine importance level from text."""
        text_lower = text.lower()
        
        # Check for must-have cues
        for cue in self.MUST_HAVE_CUES:
            if re.search(cue, text_lower):
                return RequirementImportance.MUST_HAVE
        
        # Check for responsibility cues
        for cue in self.RESPONSIBILITY_CUES:
            if re.search(cue, text_lower):
                return RequirementImportance.RESPONSIBILITY
        
        # Check for preferred cues
        for cue in self.PREFERRED_CUES:
            if re.search(cue, text_lower):
                return RequirementImportance.PREFERRED
        
        # Check for required cues
        for cue in self.REQUIRED_CUES:
            if re.search(cue, text_lower):
                return RequirementImportance.REQUIRED
        
        # Default to other
        return RequirementImportance.OTHER
    
    def _determine_category(self, text: str) -> RequirementCategory:
        """Determine category from text."""
        text_lower = text.lower()
        
        # Education patterns
        if re.search(r'\b(degree|bachelor|master|phd|mba|bs|ba|ms|ma)\b', text_lower):
            return RequirementCategory.EDUCATION
        
        # Certification patterns
        if re.search(r'\b(certification|certified|certificate|credential)\b', text_lower):
            return RequirementCategory.CERTIFICATION
        
        # Years/experience patterns
        if re.search(r'\b\d+\+?\s*(years?|yrs?)\b', text_lower):
            return RequirementCategory.YEARS
        
        # Responsibility patterns
        if re.search(r'\b(you will|responsible for|duties include|manage|lead|develop|build|implement|design|create)\b', text_lower):
            return RequirementCategory.RESPONSIBILITY
        
        # Tool patterns (common tools)
        tool_keywords = ['python', 'java', 'sql', 'aws', 'azure', 'docker', 'kubernetes', 'git', 'jira', 'tableau', 'power bi']
        if any(tool in text_lower for tool in tool_keywords):
            return RequirementCategory.TOOL
        
        # Soft skill patterns
        if re.search(r'\b(communication|teamwork|leadership|problem solving|analytical|organizational)\b', text_lower):
            return RequirementCategory.SOFT
        
        # Default to skill
        return RequirementCategory.SKILL
    
    def _extract_keywords(self, text: str) -> List[str]:
        """Extract key technical terms from text."""
        keywords = []
        
        # Common technical keywords pattern
        # Extract capitalized words, acronyms, and technical terms
        tech_patterns = [
            r'\b[A-Z]{2,}(?:/[A-Z]{2,})*\b',  # Acronyms like AWS, CI/CD
            r'\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b',  # Capitalized phrases
            r'\b(?:Python|Java|JavaScript|TypeScript|SQL|NoSQL|AWS|Azure|GCP|Docker|Kubernetes|Git|Linux|Windows|React|Angular|Vue|Node\.js|Django|Flask|Spring|Hibernate|MongoDB|PostgreSQL|MySQL|Redis|Kafka|RabbitMQ|Jenkins|CircleCI|Terraform|Ansible|Chef|Puppet)\b',
        ]
        
        for pattern in tech_patterns:
            matches = re.findall(pattern, text)
            keywords.extend(matches)
        
        # Remove duplicates while preserving order
        seen = set()
        keywords = [k for k in keywords if not (k in seen or seen.add(k))]
        
        return keywords[:10]  # Limit to 10 keywords per requirement
    
    def _merge_duplicates(self, requirements: List[JobRequirement]) -> List[JobRequirement]:
        """Merge near-duplicate requirements."""
        if not requirements:
            return requirements
        
        merged = []
        seen_texts = set()
        
        for req in requirements:
            # Simple duplicate check based on text similarity
            text_normalized = req.text.lower().strip()
            if text_normalized not in seen_texts:
                seen_texts.add(text_normalized)
                merged.append(req)
        
        return merged
