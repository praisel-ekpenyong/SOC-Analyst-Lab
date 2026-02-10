"""Unit tests for matcher."""

import pytest
from ats_scanner.parsers.resume_parser import ResumeParser
from ats_scanner.extractors.job_extractor import JobExtractor
from ats_scanner.matching.matcher import Matcher
from ats_scanner.models.match import MatchGrade
from tests.ats_scanner.fixtures.samples import SAMPLE_JOB_POSTING, SAMPLE_RESUME


def test_matcher_basic():
    """Test basic matching."""
    parser = ResumeParser()
    resume = parser.parse_text(SAMPLE_RESUME)
    
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    matcher = Matcher()
    result = matcher.match(resume, job_posting)
    
    assert len(result.requirements_map) > 0


def test_evidence_spans():
    """Test that evidence spans have correct offsets."""
    parser = ResumeParser()
    resume = parser.parse_text(SAMPLE_RESUME)
    
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    matcher = Matcher()
    result = matcher.match(resume, job_posting)
    
    # Check that at least some matches have evidence spans
    with_evidence = [m for m in result.requirements_map if m.evidence_spans]
    assert len(with_evidence) > 0
    
    # Verify offsets are valid
    for req_match in with_evidence:
        for span in req_match.evidence_spans:
            assert span.start_offset >= 0
            assert span.end_offset > span.start_offset
            assert span.end_offset <= len(resume.full_text)


def test_match_grades():
    """Test that matches are properly graded."""
    parser = ResumeParser()
    resume = parser.parse_text(SAMPLE_RESUME)
    
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    matcher = Matcher()
    result = matcher.match(resume, job_posting)
    
    # Check that we have various grades
    grades = {m.grade for m in result.requirements_map}
    assert len(grades) > 0  # Should have at least one type of grade


def test_keyword_summary():
    """Test keyword summary extraction."""
    parser = ResumeParser()
    resume = parser.parse_text(SAMPLE_RESUME)
    
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    matcher = Matcher()
    result = matcher.match(resume, job_posting)
    
    # Should have matched and/or missing keywords
    assert len(result.matched_keywords) > 0 or len(result.missing_keywords) > 0
