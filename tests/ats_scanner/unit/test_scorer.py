"""Unit tests for scorer."""

import pytest
from ats_scanner.parsers.resume_parser import ResumeParser
from ats_scanner.extractors.job_extractor import JobExtractor
from ats_scanner.matching.matcher import Matcher
from ats_scanner.scoring.scorer import Scorer
from tests.ats_scanner.fixtures.samples import SAMPLE_JOB_POSTING, SAMPLE_RESUME


def test_scorer_basic():
    """Test basic scoring."""
    parser = ResumeParser()
    resume = parser.parse_text(SAMPLE_RESUME)
    
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    matcher = Matcher()
    match_result = matcher.match(resume, job_posting)
    
    scorer = Scorer()
    scoring_result = scorer.score(match_result, job_posting, resume)
    
    # Score should be between 0 and 100
    assert 0 <= scoring_result.overall_score <= 100


def test_sub_scores():
    """Test that sub-scores are calculated."""
    parser = ResumeParser()
    resume = parser.parse_text(SAMPLE_RESUME)
    
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    matcher = Matcher()
    match_result = matcher.match(resume, job_posting)
    
    scorer = Scorer()
    scoring_result = scorer.score(match_result, job_posting, resume)
    
    # All sub-scores should be >= 0
    assert scoring_result.sub_scores.keywords_and_phrases >= 0
    assert scoring_result.sub_scores.required_skills >= 0
    assert scoring_result.sub_scores.responsibilities_alignment >= 0
    assert scoring_result.sub_scores.seniority_and_scope >= 0
    assert scoring_result.sub_scores.tools_and_systems >= 0
    assert scoring_result.sub_scores.education_and_certifications >= 0


def test_penalties():
    """Test that penalties are applied correctly."""
    parser = ResumeParser()
    resume = parser.parse_text(SAMPLE_RESUME)
    
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    matcher = Matcher()
    match_result = matcher.match(resume, job_posting)
    
    scorer = Scorer()
    scoring_result = scorer.score(match_result, job_posting, resume)
    
    # Penalties dict should exist
    assert isinstance(scoring_result.penalties, dict)
    
    # All penalties should be positive
    for penalty_value in scoring_result.penalties.values():
        assert penalty_value >= 0


def test_score_explanation():
    """Test that score explanation is generated."""
    parser = ResumeParser()
    resume = parser.parse_text(SAMPLE_RESUME)
    
    extractor = JobExtractor()
    job_posting = extractor.extract(SAMPLE_JOB_POSTING)
    
    matcher = Matcher()
    match_result = matcher.match(resume, job_posting)
    
    scorer = Scorer()
    scoring_result = scorer.score(match_result, job_posting, resume)
    
    # Should have explanation
    assert len(scoring_result.score_explanation) > 0
