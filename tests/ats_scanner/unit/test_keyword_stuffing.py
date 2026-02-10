"""Unit tests for keyword stuffing detection."""

import pytest
from ats_scanner.parsers.resume_parser import ResumeParser
from ats_scanner.extractors.job_extractor import JobExtractor
from ats_scanner.matching.matcher import Matcher
from tests.ats_scanner.fixtures.samples import SAMPLE_JOB_POSTING, KEYWORD_STUFFING_RESUME


def test_keyword_stuffing_detection():
    """Test that keyword stuffing is detected."""
    parser = ResumeParser()
    resume = parser.parse_text(KEYWORD_STUFFING_RESUME)
    
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    matcher = Matcher()
    result = matcher.match(resume, job_posting)
    
    # Should detect keyword stuffing
    assert result.keyword_stuffing_detected is True
    assert result.keyword_stuffing_score > 0


def test_no_keyword_stuffing_on_normal_resume():
    """Test that normal resumes don't trigger keyword stuffing."""
    from tests.ats_scanner.fixtures.samples import SAMPLE_RESUME
    
    parser = ResumeParser()
    resume = parser.parse_text(SAMPLE_RESUME)
    
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    matcher = Matcher()
    result = matcher.match(resume, job_posting)
    
    # Normal resume should not trigger keyword stuffing
    # (or have very low score)
    assert result.keyword_stuffing_score < 0.5
