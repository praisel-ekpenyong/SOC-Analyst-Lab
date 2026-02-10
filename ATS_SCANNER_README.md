# ATS Scanner

A comprehensive Python tool that analyzes resumes against job postings and produces scored, evidence-backed reports. This tool helps job seekers optimize their resumes by identifying gaps, suggesting improvements, and providing actionable insights.

## Features

- **Multi-format Support**: Parses PDF, DOCX, and plain text resumes
- **Intelligent Matching**: Uses fuzzy matching and synonym handling for robust keyword detection
- **Evidence-Based Analysis**: Every match is backed by exact text spans and offsets
- **Date-Aware Scoring**: Applies recency weighting based on experience dates
- **Depth Inference**: Analyzes action verbs to infer level of involvement (led, owned, delivered, used)
- **Anti-Keyword Stuffing**: Detects and penalizes keyword-stuffed resumes
- **Comprehensive Reports**: Generates both JSON (for programmatic use) and human-readable reports
- **Rewrite Suggestions**: Provides actionable suggestions with guardrails

## Installation

### Prerequisites

- Python 3.11 or higher
- pip package manager

### Install Dependencies

```bash
cd /home/runner/work/SOC-Analyst-Lab/SOC-Analyst-Lab
pip install -r requirements.txt
```

## Project Structure

```
ats_scanner/
├── __init__.py
├── cli.py                      # Command-line interface
├── models/                     # Pydantic data models
│   ├── __init__.py
│   ├── resume.py              # Resume models
│   ├── job.py                 # Job posting models
│   ├── match.py               # Match result models
│   ├── scoring.py             # Scoring models
│   └── rewrite.py             # Rewrite suggestion models
├── parsers/                    # Document parsers
│   ├── __init__.py
│   ├── resume_parser.py       # Main resume parser
│   ├── pdf_parser.py          # PDF parsing
│   ├── docx_parser.py         # DOCX parsing
│   └── text_parser.py         # Text parsing
├── extractors/                 # Data extractors
│   ├── __init__.py
│   ├── section_extractor.py   # Resume section extraction
│   ├── job_extractor.py       # Job requirement extraction
│   └── date_extractor.py      # Date parsing and recency
├── matching/                   # Matching engine
│   ├── __init__.py
│   ├── matcher.py             # Main matching logic
│   └── synonym_handler.py     # Synonym and canonicalization
├── scoring/                    # Scoring engine
│   ├── __init__.py
│   └── scorer.py              # Score calculation
└── reporting/                  # Report generation
    ├── __init__.py
    ├── report_generator.py    # JSON and text reports
    └── rewrite_generator.py   # Rewrite suggestions

tests/
├── __init__.py
└── ats_scanner/
    ├── __init__.py
    ├── fixtures/
    │   ├── __init__.py
    │   └── samples.py         # Test data
    └── unit/
        ├── __init__.py
        ├── test_job_extractor.py
        ├── test_resume_parser.py
        ├── test_matcher.py
        ├── test_scorer.py
        └── test_keyword_stuffing.py
```

## Usage

### Basic Command

```bash
python -m ats_scanner.cli scan --job <job_file> --resume <resume_file> --out output.json
```

### Command Options

- `--job`: Path to job posting file or raw text
- `--resume`: Path to resume file (.pdf, .docx, .txt) or raw text
- `--out`: Output file path (default: out.json)
- `--format`: Output format - `json`, `text`, or `both` (default: json)
- `--strict`: Fail if parsing quality is too low
- `--synonyms`: Path to custom synonyms JSON file
- `--debug`: Print intermediate extraction results

### Examples

#### Basic scan with JSON output
```bash
python -m ats_scanner.cli scan \
  --job examples/job_posting.txt \
  --resume examples/resume.pdf \
  --out report.json
```

#### Generate both JSON and text reports
```bash
python -m ats_scanner.cli scan \
  --job examples/job_posting.txt \
  --resume examples/resume.pdf \
  --out report.json \
  --format both
```

#### Debug mode
```bash
python -m ats_scanner.cli scan \
  --job examples/job_posting.txt \
  --resume examples/resume.pdf \
  --out report.json \
  --debug
```

#### Strict parsing mode
```bash
python -m ats_scanner.cli scan \
  --job examples/job_posting.txt \
  --resume examples/resume.pdf \
  --out report.json \
  --strict
```

### Using Raw Text Input

You can also pass job postings and resumes as raw text:

```bash
python -m ats_scanner.cli scan \
  --job "Senior Software Engineer. Required: Python, AWS, 5+ years experience." \
  --resume "John Doe, Software Engineer with 6 years Python and AWS experience." \
  --out report.json
```

## Architecture

### Data Flow

```
┌─────────────┐
│  Job Post   │
│   (Text)    │
└──────┬──────┘
       │
       v
┌──────────────────┐      ┌─────────────┐
│ Job Requirement  │      │   Resume    │
│   Extractor      │      │   (PDF/     │
└────────┬─────────┘      │  DOCX/TXT)  │
         │                └──────┬──────┘
         │                       │
         │                       v
         │              ┌────────────────┐
         │              │ Resume Parser  │
         │              └────────┬───────┘
         │                       │
         │                       v
         │              ┌────────────────┐
         │              │    Section     │
         │              │   Extractor    │
         │              └────────┬───────┘
         │                       │
         v                       v
    ┌────────────────────────────────┐
    │      Matching Engine           │
    │  - Synonym Handling            │
    │  - Fuzzy Matching              │
    │  - Evidence Tracking           │
    │  - Date-Aware Weighting        │
    └───────────┬────────────────────┘
                │
                v
    ┌───────────────────────┐
    │   Scoring Engine      │
    │  - Sub-scores         │
    │  - Penalties          │
    │  - Stability          │
    └───────────┬───────────┘
                │
                v
    ┌───────────────────────┐
    │  Report Generation    │
    │  - JSON Output        │
    │  - Human Report       │
    │  - Rewrite Suggestions│
    └───────────────────────┘
```

### Scoring Model

**Total: 100 points**

- Keywords and Phrases: 20 points
- Required Skills: 25 points
- Responsibilities Alignment: 20 points
- Seniority and Scope: 15 points
- Tools and Systems: 10 points
- Education and Certifications: 10 points

**Penalties:**

- Missing must-have: -15 each (capped at -30)
- High severity parsing issues: -10
- Keyword stuffing: -10
- Low confidence evidence: -10

### Match Grades

- **Direct**: Exact match in experience/projects
- **Equivalent**: Synonym or equivalent tool match
- **Indirect**: Match in other sections
- **Weak**: Only in skills list without context
- **Missing**: No match found

### Confidence Levels

- **High**: Action + tool + outcome in context
- **Medium**: Action + tool
- **Low**: Tool mention only or skills list only

## Output Format

### JSON Output

The JSON output contains:

- `overall_score`: 0-100 score
- `sub_scores`: Breakdown by category
- `dealbreakers`: List of missing must-haves
- `matched_keywords`: Keywords found with locations
- `missing_keywords`: Keywords not found
- `requirements_map`: Detailed match for each requirement with evidence
- `parsing_warnings`: Issues found during parsing
- `rewrite_suggestions`: Actionable improvement suggestions
- `penalties`: Applied penalties
- `score_explanation`: Human-readable score breakdown
- `meta`: Metadata including timings

### Text Output

The human-readable report includes:

- Overall score and sub-scores
- Critical gaps (deal-breakers)
- Top strengths with evidence quotes
- Top gaps
- Top 10 missing keywords
- Parsing warnings
- Top 5 highest impact edits

## Running Tests

```bash
# Run all tests
pytest tests/

# Run with coverage
pytest --cov=ats_scanner tests/

# Run specific test file
pytest tests/ats_scanner/unit/test_matcher.py

# Run with verbose output
pytest -v tests/
```

## Test Coverage

The test suite includes:

- Job requirement extraction tests
- Resume parsing tests
- Evidence span validation tests
- Scoring penalty tests
- Keyword stuffing detection tests
- Match grade tests

## Customization

### Custom Synonyms

Create a JSON file with custom synonyms:

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

Use it with:

```bash
python -m ats_scanner.cli scan \
  --job job.txt \
  --resume resume.pdf \
  --synonyms custom_synonyms.json \
  --out report.json
```

## Key Features Explained

### Evidence-Based Matching

Every match includes:
- Exact matched text
- Start and end character offsets
- Section where found (experience, projects, skills, etc.)
- Context (surrounding text)
- Date range if available
- Recency weight
- Depth level (led, owned, delivered, used)

### Date-Aware Recency

Experience is weighted by recency:
- 0-12 months: 1.0x
- 1-3 years: 0.7x
- 3+ years: 0.4x
- No date found: 0.5x (with warning)

### Keyword Stuffing Detection

Detects and penalizes:
- Long comma-separated lists without context
- Repeated keywords beyond threshold
- Large skills sections with minimal experience evidence

### Stable Scoring

- Capped contributions prevent single keywords from dominating
- Multiple evidence sources increase confidence
- Small wording changes don't cause large score swings

### Rewrite Suggestions Guardrails

- Suggestions linked to evidence have `supported_by_evidence: true`
- Unsupported suggestions marked as "add if true"
- Never invents metrics - uses placeholders like `[metric]`
- Lists required proof when suggesting additions

## Parsing Quality Checks

The tool checks for:

- Low extracted text (image-based PDFs)
- Table or multi-column layouts
- Excessive special characters
- Missing common section headers
- Inconsistent date formats
- Duplicated headers/footers

## Contributing

This tool is part of a portfolio project. For questions or suggestions, contact the repository owner.

## License

See LICENSE file in repository root.

## Version

1.0.0

---

**Note**: This tool is designed for educational and portfolio purposes. All test data is synthetic and for demonstration only.
