"""Command-line interface for ATS Scanner."""

import os
import sys
import time
from pathlib import Path
from typing import Optional
import typer
from rich.console import Console
from rich.progress import Progress

from ..parsers import ResumeParser
from ..extractors import JobExtractor
from ..matching import Matcher, SynonymHandler
from ..scoring import Scorer
from ..reporting import ReportGenerator, RewriteGenerator
from ..models.job import JobPosting

app = typer.Typer(help="ATS Scanner - Resume and Job Posting Analysis Tool")
console = Console()


@app.command()
def scan(
    job: str = typer.Option(..., help="Job posting file path or text"),
    resume: str = typer.Option(..., help="Resume file path (.pdf, .docx, .txt) or text"),
    out: str = typer.Option("out.json", help="Output file path"),
    format: str = typer.Option("json", help="Output format: json, text, or both"),
    strict: bool = typer.Option(False, help="Fail if parsing quality is too low"),
    synonyms: Optional[str] = typer.Option(None, help="Path to custom synonyms JSON file"),
    debug: bool = typer.Option(False, help="Print intermediate extraction results"),
):
    """
    Scan a resume against a job posting and generate a match report.
    
    Example:
        python -m ats_scanner.cli scan --job job.txt --resume resume.pdf --out report.json
    """
    console.print("[bold blue]ATS Scanner v1.0.0[/bold blue]")
    console.print()
    
    timings = {}
    
    # Parse job posting
    console.print("📄 Loading job posting...")
    start_time = time.time()
    
    if os.path.exists(job):
        with open(job, 'r') as f:
            job_text = f.read()
    else:
        job_text = job
    
    job_extractor = JobExtractor()
    job_posting = job_extractor.extract(job_text)
    
    timings['job_extraction'] = time.time() - start_time
    
    if debug:
        console.print(f"  Extracted {len(job_posting.requirements)} requirements")
        for req in job_posting.requirements[:3]:
            console.print(f"    - [{req.importance.value}] {req.text[:60]}...")
    
    # Parse resume
    console.print("📄 Parsing resume...")
    start_time = time.time()
    
    resume_parser = ResumeParser()
    
    if os.path.exists(resume):
        resume_obj = resume_parser.parse_file(resume)
    else:
        resume_obj = resume_parser.parse_text(resume)
    
    timings['resume_parsing'] = time.time() - start_time
    
    if debug:
        console.print(f"  Extracted {len(resume_obj.sections)} sections")
        console.print(f"  Contact: Email={resume_obj.contact_info.email}, Phone={resume_obj.contact_info.phone}")
        console.print(f"  Warnings: {len(resume_obj.parsing_warnings)}")
    
    # Check parsing quality in strict mode
    if strict:
        high_severity_warnings = [w for w in resume_obj.parsing_warnings if w.severity.value == 'high']
        if high_severity_warnings:
            console.print("[bold red]❌ Parsing quality too low (strict mode)[/bold red]")
            for warning in high_severity_warnings:
                console.print(f"  • {warning.message}")
            sys.exit(1)
    
    # Match requirements
    console.print("🔍 Matching requirements...")
    start_time = time.time()
    
    synonym_handler = SynonymHandler(synonyms) if synonyms else SynonymHandler()
    matcher = Matcher(synonym_handler)
    match_result = matcher.match(resume_obj, job_posting)
    
    timings['matching'] = time.time() - start_time
    
    if debug:
        console.print(f"  Matched keywords: {len(match_result.matched_keywords)}")
        console.print(f"  Missing keywords: {len(match_result.missing_keywords)}")
        console.print(f"  Dealbreakers: {len(match_result.dealbreakers)}")
    
    # Calculate scores
    console.print("📊 Calculating scores...")
    start_time = time.time()
    
    scorer = Scorer()
    scoring_result = scorer.score(match_result, job_posting, resume_obj)
    
    timings['scoring'] = time.time() - start_time
    
    # Generate rewrite suggestions
    console.print("💡 Generating suggestions...")
    start_time = time.time()
    
    rewrite_generator = RewriteGenerator()
    rewrite_suggestions = rewrite_generator.generate(match_result, resume_obj)
    
    timings['suggestions'] = time.time() - start_time
    
    # Generate reports
    console.print("📝 Generating report...")
    start_time = time.time()
    
    report_generator = ReportGenerator()
    
    if format in ['json', 'both']:
        json_report = report_generator.generate_json_report(
            resume_obj,
            job_posting,
            match_result,
            scoring_result,
            rewrite_suggestions,
            timings
        )
        
        json_path = out if format == 'json' else out.replace('.', '_json.')
        report_generator.save_report(json_report, json_path, 'json')
        console.print(f"✅ JSON report saved to: {json_path}")
    
    if format in ['text', 'both']:
        text_report = report_generator.generate_text_report(
            resume_obj,
            job_posting,
            match_result,
            scoring_result,
            rewrite_suggestions
        )
        
        text_path = out.replace('.json', '.txt') if format == 'both' else out
        report_generator.save_report(text_report, text_path, 'text')
        console.print(f"✅ Text report saved to: {text_path}")
    
    timings['report_generation'] = time.time() - start_time
    
    # Print summary
    console.print()
    console.print("[bold green]✓ Scan complete![/bold green]")
    console.print(f"Overall Score: [bold]{scoring_result.overall_score:.1f}/100[/bold]")
    
    if match_result.dealbreakers:
        console.print(f"[bold red]⚠️  {len(match_result.dealbreakers)} deal-breaker(s) found[/bold red]")
    
    total_time = sum(timings.values())
    console.print(f"Total time: {total_time:.2f}s")


@app.command()
def version():
    """Show version information."""
    console.print("ATS Scanner v1.0.0")
    console.print("A comprehensive resume analysis tool")


if __name__ == "__main__":
    app()
