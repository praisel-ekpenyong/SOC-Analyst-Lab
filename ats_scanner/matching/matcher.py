"""Main matching engine with evidence tracking."""

import re
from typing import List, Optional
from rapidfuzz import fuzz
from ..models.resume import Resume, SectionType
from ..models.job import JobPosting, JobRequirement
from ..models.match import (
    MatchResult, RequirementMatch, EvidenceSpan,
    MatchGrade, ConfidenceLevel, DepthLevel
)
from ..extractors.date_extractor import DateExtractor
from .synonym_handler import SynonymHandler


class Matcher:
    """Match job requirements against resume with evidence."""
    
    # Depth inference patterns
    DEPTH_PATTERNS = {
        DepthLevel.LED: [r'\b(led|managed|mentored|drove|directed|oversaw)\b'],
        DepthLevel.OWNED: [r'\b(owned|designed|architected|responsible for|established|created)\b'],
        DepthLevel.DELIVERED: [r'\b(built|implemented|shipped|automated|developed|deployed|delivered|launched)\b'],
        DepthLevel.USED: [r'\b(used|assisted|supported|helped|worked with|utilized|leveraged)\b'],
    }
    
    def __init__(self, synonym_handler: Optional[SynonymHandler] = None):
        """Initialize matcher."""
        self.synonym_handler = synonym_handler or SynonymHandler()
        self.date_extractor = DateExtractor()
    
    def match(self, resume: Resume, job_posting: JobPosting) -> MatchResult:
        """Match job requirements against resume."""
        result = MatchResult()
        
        # Extract date ranges from resume
        date_ranges = self.date_extractor.extract_all_date_ranges(resume.full_text)
        
        # Match each requirement
        for req in job_posting.requirements:
            req_match = self._match_requirement(resume, req, date_ranges)
            result.requirements_map.append(req_match)
            
            # Track dealbreakers
            if req.importance.value == 'must_have' and req_match.grade == MatchGrade.MISSING:
                result.dealbreakers.append(req.text)
        
        # Extract matched and missing keywords
        self._extract_keywords_summary(result, job_posting, resume)
        
        # Detect keyword stuffing
        result.keyword_stuffing_detected, result.keyword_stuffing_score = \
            self._detect_keyword_stuffing(resume)
        
        return result
    
    def _match_requirement(
        self,
        resume: Resume,
        requirement: JobRequirement,
        date_ranges: list
    ) -> RequirementMatch:
        """Match a single requirement against resume."""
        evidence_spans = []
        
        # Extract key terms from requirement
        key_terms = self._extract_key_terms(requirement.text)
        
        # Search for matches in resume
        for term in key_terms:
            spans = self._search_term(resume, term, date_ranges)
            evidence_spans.extend(spans)
        
        # Also search for the full requirement text
        full_spans = self._search_term(resume, requirement.text, date_ranges)
        evidence_spans.extend(full_spans)
        
        # Deduplicate spans
        evidence_spans = self._deduplicate_spans(evidence_spans)
        
        # Grade the match
        grade, confidence = self._grade_match(evidence_spans, requirement)
        
        # Calculate overall recency and depth
        recency_weight = self._calculate_overall_recency(evidence_spans)
        depth = self._calculate_overall_depth(evidence_spans)
        
        # Generate fix suggestions
        fix, suggested_keywords = self._generate_fix(requirement, evidence_spans, resume)
        
        return RequirementMatch(
            requirement_text=requirement.text,
            requirement_category=requirement.category.value,
            requirement_importance=requirement.importance.value,
            grade=grade,
            confidence=confidence,
            evidence_spans=evidence_spans,
            recency_weight=recency_weight,
            depth=depth,
            fix=fix,
            suggested_keywords=suggested_keywords
        )
    
    def _extract_key_terms(self, text: str) -> List[str]:
        """Extract key terms from requirement text."""
        # Remove common words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for',
                      'of', 'with', 'by', 'from', 'up', 'about', 'into', 'through', 'during'}
        
        # Extract words
        words = re.findall(r'\b\w+\b', text.lower())
        
        # Filter and return significant terms
        key_terms = [w for w in words if len(w) > 3 and w not in stop_words]
        
        # Add full phrases (2-3 words)
        phrases = re.findall(r'\b\w+\s+\w+(?:\s+\w+)?\b', text)
        key_terms.extend([p for p in phrases if len(p) > 8])
        
        return list(set(key_terms))[:10]  # Limit to 10 key terms
    
    def _search_term(
        self,
        resume: Resume,
        term: str,
        date_ranges: list
    ) -> List[EvidenceSpan]:
        """Search for a term in resume and return evidence spans."""
        spans = []
        text = resume.full_text.lower()
        term_lower = term.lower()
        
        # Exact match search
        for match in re.finditer(re.escape(term_lower), text):
            span = self._create_evidence_span(
                resume, match.start(), match.end(),
                term, date_ranges, is_exact=True
            )
            if span:
                spans.append(span)
        
        # Fuzzy match search (for typos)
        if len(term_lower) > 5:
            words = text.split()
            for i, word in enumerate(words):
                similarity = fuzz.ratio(term_lower, word)
                if similarity > 85:  # High similarity threshold
                    # Find position in original text
                    word_start = text.find(word, sum(len(w) + 1 for w in words[:i]))
                    if word_start != -1:
                        span = self._create_evidence_span(
                            resume, word_start, word_start + len(word),
                            word, date_ranges, is_exact=False
                        )
                        if span:
                            spans.append(span)
        
        # Synonym match search
        synonyms = self.synonym_handler.find_synonyms(term)
        for synonym in synonyms:
            if synonym.lower() != term_lower:
                for match in re.finditer(re.escape(synonym.lower()), text):
                    span = self._create_evidence_span(
                        resume, match.start(), match.end(),
                        synonym, date_ranges, is_exact=False, is_synonym=True
                    )
                    if span:
                        span.matched_via = f"synonym of {term}"
                        spans.append(span)
        
        return spans
    
    def _create_evidence_span(
        self,
        resume: Resume,
        start: int,
        end: int,
        matched_text: str,
        date_ranges: list,
        is_exact: bool = True,
        is_synonym: bool = False
    ) -> Optional[EvidenceSpan]:
        """Create evidence span with context and metadata."""
        # Determine which section this span is in
        section_type = "other"
        for section in resume.sections:
            if section.start_offset <= start <= section.end_offset:
                section_type = section.type.value
                break
        
        # Get context (surrounding text)
        context_start = max(0, start - 100)
        context_end = min(len(resume.full_text), end + 100)
        context = resume.full_text[context_start:context_end]
        
        # Find nearest date range
        date_range = None
        recency_weight = 0.5  # default
        for dr in date_ranges:
            if abs(dr['position'] - start) < 500:  # Within 500 chars
                date_range = dr['text']
                recency_weight = self.date_extractor.calculate_recency_weight(
                    dr['start'], dr['end']
                )
                break
        
        # Infer depth from context
        depth = self._infer_depth(context)
        
        return EvidenceSpan(
            matched_text=matched_text,
            start_offset=start,
            end_offset=end,
            section=section_type,
            source_type=section_type,
            context=context[:200],  # Limit context length
            date_range=date_range,
            recency_weight=recency_weight,
            depth=depth
        )
    
    def _infer_depth(self, context: str) -> DepthLevel:
        """Infer depth level from context."""
        context_lower = context.lower()
        
        for depth_level, patterns in self.DEPTH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, context_lower):
                    return depth_level
        
        return DepthLevel.UNKNOWN
    
    def _deduplicate_spans(self, spans: List[EvidenceSpan]) -> List[EvidenceSpan]:
        """Remove duplicate or overlapping spans."""
        if not spans:
            return spans
        
        # Sort by start offset
        spans.sort(key=lambda s: s.start_offset)
        
        # Remove overlapping spans
        deduplicated = [spans[0]]
        for span in spans[1:]:
            last = deduplicated[-1]
            # If spans don't overlap, add
            if span.start_offset >= last.end_offset:
                deduplicated.append(span)
            # If overlapping, keep the longer one
            elif (span.end_offset - span.start_offset) > (last.end_offset - last.start_offset):
                deduplicated[-1] = span
        
        return deduplicated
    
    def _grade_match(
        self,
        evidence_spans: List[EvidenceSpan],
        requirement: JobRequirement
    ) -> tuple:
        """Grade the match quality and confidence."""
        if not evidence_spans:
            return MatchGrade.MISSING, ConfidenceLevel.LOW
        
        # Count evidence by section
        experience_count = sum(1 for s in evidence_spans if s.source_type == 'experience')
        projects_count = sum(1 for s in evidence_spans if s.source_type == 'projects')
        skills_count = sum(1 for s in evidence_spans if s.source_type == 'skills')
        
        # Determine grade
        if experience_count > 0 or projects_count > 0:
            # Check for synonyms
            has_synonym = any(hasattr(s, 'matched_via') and s.matched_via for s in evidence_spans)
            if has_synonym:
                grade = MatchGrade.EQUIVALENT
            else:
                grade = MatchGrade.DIRECT
        elif skills_count > 0:
            grade = MatchGrade.WEAK
        else:
            grade = MatchGrade.INDIRECT
        
        # Determine confidence
        # High confidence: action + tool + outcome context
        # Medium confidence: action + tool
        # Low confidence: tool mention only
        has_action_context = any(s.depth in [DepthLevel.LED, DepthLevel.OWNED, DepthLevel.DELIVERED] 
                                 for s in evidence_spans)
        
        if experience_count > 1 and has_action_context:
            confidence = ConfidenceLevel.HIGH
        elif (experience_count > 0 or projects_count > 0) and has_action_context:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW
        
        return grade, confidence
    
    def _calculate_overall_recency(self, evidence_spans: List[EvidenceSpan]) -> float:
        """Calculate overall recency weight from evidence spans."""
        if not evidence_spans:
            return 0.5
        
        weights = [s.recency_weight for s in evidence_spans if s.recency_weight]
        return max(weights) if weights else 0.5
    
    def _calculate_overall_depth(self, evidence_spans: List[EvidenceSpan]) -> DepthLevel:
        """Calculate overall depth from evidence spans."""
        if not evidence_spans:
            return DepthLevel.UNKNOWN
        
        # Return the highest depth level found
        depth_priority = {
            DepthLevel.LED: 4,
            DepthLevel.OWNED: 3,
            DepthLevel.DELIVERED: 2,
            DepthLevel.USED: 1,
            DepthLevel.UNKNOWN: 0
        }
        
        best_depth = max(evidence_spans, key=lambda s: depth_priority.get(s.depth, 0)).depth
        return best_depth
    
    def _generate_fix(
        self,
        requirement: JobRequirement,
        evidence_spans: List[EvidenceSpan],
        resume: Resume
    ) -> tuple:
        """Generate fix suggestion and keywords."""
        if evidence_spans:
            # Has some evidence, suggest improvement
            if len(evidence_spans) == 1 and evidence_spans[0].source_type == 'skills':
                fix = "Add concrete examples in experience section demonstrating this skill"
                keywords = self._extract_key_terms(requirement.text)
            else:
                fix = None
                keywords = []
        else:
            # No evidence, suggest addition
            fix = "Consider adding this skill/experience if you have it"
            keywords = self._extract_key_terms(requirement.text)
        
        return fix, keywords[:5]
    
    def _extract_keywords_summary(
        self,
        result: MatchResult,
        job_posting: JobPosting,
        resume: Resume
    ):
        """Extract matched and missing keywords summary."""
        all_keywords = set()
        for req in job_posting.requirements:
            all_keywords.update(req.keywords)
        
        resume_text_lower = resume.full_text.lower()
        
        for keyword in all_keywords:
            if keyword.lower() in resume_text_lower:
                # Find where it's mentioned
                sections = []
                for section in resume.sections:
                    if keyword.lower() in section.text.lower():
                        sections.append(section.type.value)
                
                result.matched_keywords.append({
                    'keyword': keyword,
                    'found_in': list(set(sections))
                })
            else:
                result.missing_keywords.append(keyword)
    
    def _detect_keyword_stuffing(self, resume: Resume) -> tuple:
        """Detect keyword stuffing in resume."""
        # Get skills section
        skills_text = resume.get_section_text(SectionType.SKILLS)
        
        if not skills_text:
            return False, 0.0
        
        # Count comma-separated lists
        comma_count = skills_text.count(',')
        
        # Count verbs (action words)
        action_verbs = ['built', 'developed', 'implemented', 'designed', 'created',
                       'led', 'managed', 'improved', 'increased', 'decreased']
        verb_count = sum(1 for verb in action_verbs if verb in skills_text.lower())
        
        # Calculate ratio
        if len(skills_text) < 100:
            return False, 0.0
        
        # High comma count with low verb count suggests keyword stuffing
        if comma_count > 20 and verb_count < 3:
            stuffing_score = min(1.0, comma_count / 30)
            return True, stuffing_score
        
        # Check for repeated keywords
        words = re.findall(r'\b\w+\b', skills_text.lower())
        word_freq = {}
        for word in words:
            if len(word) > 4:  # Only check meaningful words
                word_freq[word] = word_freq.get(word, 0) + 1
        
        # If any word appears more than 5 times, it's likely stuffing
        max_freq = max(word_freq.values()) if word_freq else 0
        if max_freq > 5:
            stuffing_score = min(1.0, max_freq / 10)
            return True, stuffing_score
        
        return False, 0.0
