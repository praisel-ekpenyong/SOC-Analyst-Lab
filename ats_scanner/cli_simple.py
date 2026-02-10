"""Command-line interface for ATS Scanner."""

import os
import sys
import time
import argparse
from pathlib import Path
from typing import Optional

try:
    from rich.console import Console
    HAS_RICH = True
except ImportError:
    HAS_RICH = False
    # Simple console fallback
    class Console:
        def print(self, *args, **kwargs):
            if args:
                print(args[0])

from ats_scanner.parsers import ResumeParser
from ats_scanner.extractors import JobExtractor
from ats_scanner.matching import Matcher, SynonymHandler
from ats_scanner.scoring import Scorer
from ats_scanner.reporting import ReportGenerator, RewriteGenerator
from ats_scanner.models.job import JobPosting

console = Console()


def scan_command(args):
    """
    Scan a resume against a job posting and generate a match report.
    """
    console.print("[ATS Scanner v1.0.0]" if not HAS_RICH else "[bold blue]ATS Scanner v1.0.0[/bold blue]")
    console.print("")
    
    timings = {}
    
    # Parse job posting
    console.print("📄 Loading job posting...")
    start_time = time.time()
    
    if os.path.exists(args.job):
        with open(args.job, 'r') as f:
            job_text = f.read()
    else:
        job_text = args.job
    
    job_extractor = JobExtractor()
    job_posting = job_extractor.extract(job_text)
    
    timings['job_extraction'] = time.time() - start_time
    
    if args.debug:
        console.print(f"  Extracted {len(job_posting.requirements)} requirements")
        for req in job_posting.requirements[:3]:
            console.print(f"    - [{req.importance.value}] {req.text[:60]}...")
    
    # Parse resume
    console.print("📄 Parsing resume...")
    start_time = time.time()
    
    resume_parser = ResumeParser()
    
    if os.path.exists(args.resume):
        resume_obj = resume_parser.parse_file(args.resume)
    else:
        resume_obj = resume_parser.parse_text(args.resume)
    
    timings['resume_parsing'] = time.time() - start_time
    
    if args.debug:
        console.print(f"  Extracted {len(resume_obj.sections)} sections")
        console.print(f"  Contact: Email={resume_obj.contact_info.email}, Phone={resume_obj.contact_info.phone}")
        console.print(f"  Warnings: {len(resume_obj.parsing_warnings)}")
    
    # Check parsing quality in strict mode
    if args.strict:
        high_severity_warnings = [w for w in resume_obj.parsing_warnings if w.severity.value == 'high']
        if high_severity_warnings:
            console.print("[ERROR] Parsing quality too low (strict mode)" if not HAS_RICH else "[bold red]❌ Parsing quality too low (strict mode)[/bold red]")
            for warning in high_severity_warnings:
                console.print(f"  • {warning.message}")
            sys.exit(1)
    
    # Match requirements
    console.print("🔍 Matching requirements...")
    start_time = time.time()
    
    synonym_handler = SynonymHandler(args.synonyms) if args.synonyms else SynonymHandler()
    matcher = Matcher(synonym_handler)
    match_result = matcher.match(resume_obj, job_posting)
    
    timings['matching'] = time.time() - start_time
    
    if args.debug:
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
    
    if args.format in ['json', 'both']:
        json_report = report_generator.generate_json_report(
            resume_obj,
            job_posting,
            match_result,
            scoring_result,
            rewrite_suggestions,
            timings
        )
        
        json_path = args.out if args.format == 'json' else args.out.replace('.', '_json.')
        report_generator.save_report(json_report, json_path, 'json')
        console.print(f"✅ JSON report saved to: {json_path}")
    
    if args.format in ['text', 'both']:
        text_report = report_generator.generate_text_report(
            resume_obj,
            job_posting,
            match_result,
            scoring_result,
            rewrite_suggestions
        )
        
        text_path = args.out.replace('.json', '.txt') if args.format == 'both' else args.out
        report_generator.save_report(text_report, text_path, 'text')
        console.print(f"✅ Text report saved to: {text_path}")
    
    timings['report_generation'] = time.time() - start_time
    
    # Print summary
    console.print("")
    console.print("[SUCCESS] Scan complete!" if not HAS_RICH else "[bold green]✓ Scan complete![/bold green]")
    score_text = f"Overall Score: {scoring_result.overall_score:.1f}/100"
    console.print(score_text if not HAS_RICH else f"Overall Score: [bold]{scoring_result.overall_score:.1f}/100[/bold]")
    
    if match_result.dealbreakers:
        console.print(f"[WARNING] {len(match_result.dealbreakers)} deal-breaker(s) found" if not HAS_RICH else f"[bold red]⚠️  {len(match_result.dealbreakers)} deal-breaker(s) found[/bold red]")
    
    total_time = sum(timings.values())
    console.print(f"Total time: {total_time:.2f}s")


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="ATS Scanner - Resume and Job Posting Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Example:
  python -m ats_scanner.cli scan --job job.txt --resume resume.pdf --out report.json
  python -m ats_scanner.cli scan --job job.txt --resume resume.txt --format both
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan resume against job posting')
    scan_parser.add_argument('--job', required=True, help='Job posting file path or text')
    scan_parser.add_argument('--resume', required=True, help='Resume file path (.pdf, .docx, .txt) or text')
    scan_parser.add_argument('--out', default='out.json', help='Output file path (default: out.json)')
    scan_parser.add_argument('--format', default='json', choices=['json', 'text', 'both'],
                           help='Output format: json, text, or both (default: json)')
    scan_parser.add_argument('--strict', action='store_true',
                           help='Fail if parsing quality is too low')
    scan_parser.add_argument('--synonyms', help='Path to custom synonyms JSON file')
    scan_parser.add_argument('--debug', action='store_true',
                           help='Print intermediate extraction results')
    
    # Version command
    version_parser = subparsers.add_parser('version', help='Show version information')
    
    args = parser.parse_args()
    
    if args.command == 'scan':
        scan_command(args)
    elif args.command == 'version':
        console.print("ATS Scanner v1.0.0")
        console.print("A comprehensive resume analysis tool")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
