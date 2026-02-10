# ATS Scanner - Quick Start Guide

## Installation & Setup

### Prerequisites
- Python 3.11 or higher
- Standard Python libraries (included by default)

### Optional Dependencies
For full functionality, install these packages:
```bash
pip install pdfplumber python-docx rapidfuzz typer rich pytest
```

However, the tool works without them using built-in fallbacks.

## Basic Usage

### 1. Scan a Resume Against a Job Posting

```bash
cd /home/runner/work/SOC-Analyst-Lab/SOC-Analyst-Lab
python -m ats_scanner scan --job examples/job_posting.txt --resume examples/resume.txt --out report.json
```

**Output:**
```
ATS Scanner v1.0.0

📄 Loading job posting...
📄 Parsing resume...
🔍 Matching requirements...
📊 Calculating scores...
💡 Generating suggestions...
📝 Generating report...
✅ JSON report saved to: report.json

✓ Scan complete!
Overall Score: 90.8/100
Total time: 0.08s
```

### 2. Generate Both JSON and Text Reports

```bash
python -m ats_scanner scan --job examples/job_posting.txt --resume examples/resume.txt --format both --out report
```

This creates:
- `report` (JSON format)
- `report` (text format)

### 3. Debug Mode

```bash
python -m ats_scanner scan --job examples/job_posting.txt --resume examples/resume.txt --debug
```

Shows intermediate results:
- Number of requirements extracted
- Sections found
- Contact information
- Match statistics

### 4. Strict Mode

```bash
python -m ats_scanner scan --job examples/job_posting.txt --resume examples/resume.txt --strict
```

Fails if parsing quality is too low (useful for automated pipelines).

## Example Output

### Text Report (Excerpt)
```
================================================================================
ATS SCANNER REPORT
================================================================================

OVERALL MATCH SCORE: 90.8/100

SUB-SCORES:
  • Keywords and Phrases:         10.8/20
  • Required Skills:              25.0/25
  • Responsibilities Alignment:   20.0/20
  • Seniority and Scope:          15.0/15
  • Tools and Systems:            10.0/10
  • Education and Certifications: 10.0/10

SCORE BREAKDOWN:
  • Required Skills: +25.0 points
  • Responsibilities Alignment: +20.0 points
  • Seniority and Scope: +15.0 points

✓ TOP STRENGTHS:
  1. Must have 5+ years of software development experience
     Evidence: "software development experience..."
  2. Required: Strong proficiency in Python and Go
     Evidence: "Python and FastAPI..."
```

### JSON Report Structure
```json
{
  "overall_score": 90.83,
  "sub_scores": {
    "keywords_and_phrases": 10.83,
    "required_skills": 25.0,
    "responsibilities_alignment": 20.0,
    "seniority_and_scope": 15.0,
    "tools_and_systems": 10.0,
    "education_and_certifications": 10.0
  },
  "dealbreakers": [],
  "matched_keywords": [
    {
      "keyword": "Python",
      "found_in": ["experience", "skills"]
    }
  ],
  "missing_keywords": ["Terraform", "Kubernetes"],
  "requirements_map": [
    {
      "requirement": "Must have 5+ years of software development experience",
      "category": "years",
      "importance": "must_have",
      "grade": "direct",
      "confidence": "high",
      "recency_weight": 1.0,
      "depth": "unknown",
      "evidence_spans": [
        {
          "matched_text": "software",
          "start_offset": 119,
          "end_offset": 127,
          "section": "summary",
          "source_type": "summary",
          "context": "Senior Software Engineer with 6 years...",
          "date_range": null,
          "recency_weight": 1.0,
          "depth": "unknown"
        }
      ]
    }
  ],
  "parsing_warnings": [],
  "rewrite_suggestions": [],
  "meta": {
    "scan_timestamp": "2026-02-10T23:27:40.123456",
    "resume_file_type": "txt",
    "timings": {
      "job_extraction": 0.002,
      "resume_parsing": 0.002,
      "matching": 0.073,
      "scoring": 0.000,
      "suggestions": 0.000,
      "report_generation": 0.001
    },
    "version": "1.0.0"
  }
}
```

## Understanding the Scores

### Sub-Scores (Total 100 points)
- **Keywords and Phrases (20)**: Matches of key terms from job posting
- **Required Skills (25)**: Technical skills and tools required
- **Responsibilities Alignment (20)**: Match with job responsibilities
- **Seniority and Scope (15)**: Leadership and experience level
- **Tools and Systems (10)**: Specific technology stack
- **Education and Certifications (10)**: Academic and professional credentials

### Match Grades
- **DIRECT**: Exact match in experience or projects section
- **EQUIVALENT**: Synonym or equivalent tool (e.g., MySQL ↔ PostgreSQL)
- **INDIRECT**: Found in other sections
- **WEAK**: Only mentioned in skills list without context
- **MISSING**: Not found in resume

### Confidence Levels
- **HIGH**: Action verb + tool + outcome in same context
- **MEDIUM**: Action verb + tool
- **LOW**: Tool mentioned without context

### Penalties
- **Missing must-have**: -15 points each (max -30)
- **Parsing issues**: up to -10 points
- **Keyword stuffing**: up to -10 points
- **Low confidence**: up to -10 points

## Advanced Features

### Custom Synonyms

Create a `synonyms.json` file:
```json
{
  "canonical_map": {
    "python": ["python", "py", "python3"],
    "javascript": ["javascript", "js", "ecmascript"]
  },
  "equivalents": {
    "mysql": {"postgresql": 0.7, "mariadb": 0.9}
  }
}
```

Use it:
```bash
python -m ats_scanner scan --job job.txt --resume resume.txt --synonyms synonyms.json
```

### Raw Text Input

You can pass raw text instead of files:
```bash
python -m ats_scanner scan \
  --job "Senior Engineer. Required: Python, AWS, 5+ years." \
  --resume "John Doe. 6 years Python and AWS experience." \
  --out report.json
```

## Key Features

✅ **Evidence-Based**: Every match includes exact text spans with character offsets  
✅ **Date-Aware**: Recency weighting based on when experience occurred  
✅ **Depth Analysis**: Infers level of involvement from action verbs  
✅ **Anti-Stuffing**: Detects and penalizes keyword-stuffed resumes  
✅ **Stable Scoring**: Small wording changes don't cause big score swings  
✅ **Actionable**: Provides specific suggestions for improvement  

## Performance

Typical execution times:
- Small resume (~1 page): ~0.08s
- Medium resume (~2 pages): ~0.15s
- Large resume (~3+ pages): ~0.25s

## Troubleshooting

### "pdfplumber not available"
- PDF parsing requires pdfplumber
- Install with: `pip install pdfplumber`
- Or use .txt format instead

### "python-docx not available"
- DOCX parsing requires python-docx
- Install with: `pip install python-docx`
- Or convert to .txt format

### Low Parsing Quality
- Use `--debug` to see parsing warnings
- Check for image-based PDFs
- Try converting to text format
- Use `--strict` mode to enforce quality

## Complete Example Workflow

```bash
# 1. Navigate to project directory
cd /home/runner/work/SOC-Analyst-Lab/SOC-Analyst-Lab

# 2. Run scan with both output formats
python -m ats_scanner scan \
  --job examples/job_posting.txt \
  --resume examples/resume.txt \
  --format both \
  --out my_report

# 3. View text report
cat my_report

# 4. View JSON report (formatted)
python -m json.tool my_report > my_report_formatted.json
cat my_report_formatted.json

# 5. Extract specific scores
python -c "import json; print(json.load(open('my_report'))['overall_score'])"
```

## Next Steps

1. Review the `ATS_SCANNER_README.md` for detailed documentation
2. Check `ATS_SCANNER_IMPLEMENTATION.md` for technical details
3. Explore the `examples/` directory for sample files
4. Run tests: `python -m pytest tests/` (if pytest installed)
5. Customize synonyms in `ats_scanner/matching/synonym_handler.py`

## Support

For questions or issues:
- Review documentation in repository
- Check example files in `examples/`
- Examine test cases in `tests/`

---

**Version**: 1.0.0  
**Python**: 3.11+  
**License**: See LICENSE file in repository
