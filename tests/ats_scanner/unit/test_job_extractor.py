"""Unit tests for job extractor."""

import pytest
from ats_scanner.extractors.job_extractor import JobExtractor
from ats_scanner.models.job import RequirementImportance, RequirementCategory
from tests.ats_scanner.fixtures.samples import SAMPLE_JOB_POSTING


def test_job_extractor_basic():
    """Test basic job extraction."""
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    assert len(job_posting.requirements) > 0
    assert job_posting.raw_text == SAMPLE_JOB_POSTING


def test_must_have_detection():
    """Test must-have requirement detection."""
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    must_haves = [r for r in job_posting.requirements 
                  if r.importance == RequirementImportance.MUST_HAVE]
    
    assert len(must_haves) > 0


def test_required_detection():
    """Test required requirement detection."""
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    required = [r for r in job_posting.requirements 
                if r.importance == RequirementImportance.REQUIRED]
    
    assert len(required) > 0


def test_preferred_detection():
    """Test preferred requirement detection."""
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    preferred = [r for r in job_posting.requirements 
                 if r.importance == RequirementImportance.PREFERRED]
    
    assert len(preferred) > 0


def test_category_detection():
    """Test requirement category detection."""
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    # Check for various categories
    categories = {r.category for r in job_posting.requirements}
    
    # Should detect at least skills and responsibilities
    assert RequirementCategory.SKILL in categories or RequirementCategory.TOOL in categories


def test_keyword_extraction():
    """Test keyword extraction from requirements."""
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    # At least some requirements should have keywords
    with_keywords = [r for r in job_posting.requirements if r.keywords]
    assert len(with_keywords) > 0
