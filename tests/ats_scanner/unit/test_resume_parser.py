"""Unit tests for resume parser."""

import pytest
from ats_scanner.parsers.resume_parser import ResumeParser
from tests.ats_scanner.fixtures.samples import SAMPLE_RESUME


def test_resume_parser_text():
    """Test parsing resume from text."""
    parser = ResumeParser()
    resume = parser.parse_text(SAMPLE_RESUME)
    
    assert resume.full_text
    assert len(resume.full_text) > 100


def test_contact_info_extraction():
    """Test contact info extraction."""
    parser = ResumeParser()
    resume = parser.parse_text(SAMPLE_RESUME)
    
    assert resume.contact_info.email == "john.doe@email.com"
    assert resume.contact_info.phone is not None


def test_section_extraction():
    """Test section extraction."""
    parser = ResumeParser()
    resume = parser.parse_text(SAMPLE_RESUME)
    
    # Should extract at least some sections
    assert len(resume.sections) > 0


def test_parsing_warnings():
    """Test parsing warnings."""
    parser = ResumeParser()
    resume = parser.parse_text("Too short")
    
    # Should have warnings for short text and missing contact info
    assert len(resume.parsing_warnings) > 0
