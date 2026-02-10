"""Report generator for JSON and human-readable formats."""

import json
from datetime import datetime
from typing import Dict
from ..models.resume import Resume
from ..models.job import JobPosting
from ..models.match import MatchResult
from ..models.scoring import ScoringResult
from ..models.rewrite import RewriteSuggestion


class ReportGenerator:
    """Generate reports in JSON and human-readable formats."""
    
    def generate_json_report(
        self,
        resume: Resume,
        job_posting: JobPosting,
        match_result: MatchResult,
        scoring_result: ScoringResult,
        rewrite_suggestions: list,
        timings: dict
    ) -> Dict:
        """Generate complete JSON report."""
        report = {
            "overall_score": scoring_result.overall_score,
            "sub_scores": {
                "keywords_and_phrases": scoring_result.sub_scores.keywords_and_phrases,
                "required_skills": scoring_result.sub_scores.required_skills,
                "responsibilities_alignment": scoring_result.sub_scores.responsibilities_alignment,
                "seniority_and_scope": scoring_result.sub_scores.seniority_and_scope,
                "tools_and_systems": scoring_result.sub_scores.tools_and_systems,
                "education_and_certifications": scoring_result.sub_scores.education_and_certifications,
            },
            "dealbreakers": match_result.dealbreakers,
            "matched_keywords": match_result.matched_keywords,
            "missing_keywords": match_result.missing_keywords,
            "requirements_map": [
                {
                    "requirement": m.requirement_text,
                    "category": m.requirement_category,
                    "importance": m.requirement_importance,
                    "grade": m.grade.value,
                    "confidence": m.confidence.value,
                    "recency_weight": m.recency_weight,
                    "depth": m.depth.value,
                    "evidence_spans": [
                        {
                            "matched_text": e.matched_text,
                            "start_offset": e.start_offset,
                            "end_offset": e.end_offset,
                            "section": e.section,
                            "source_type": e.source_type,
                            "context": e.context,
                            "date_range": e.date_range,
                            "recency_weight": e.recency_weight,
                            "depth": e.depth.value
                        }
                        for e in m.evidence_spans
                    ],
                    "fix": m.fix,
                    "suggested_keywords": m.suggested_keywords
                }
                for m in match_result.requirements_map
            ],
            "parsing_warnings": [
                {
                    "message": w.message,
                    "severity": w.severity.value,
                    "example": w.example,
                    "location": w.location
                }
                for w in resume.parsing_warnings
            ],
            "rewrite_suggestions": [
                {
                    "original_span": s.original_span,
                    "suggested_text": s.suggested_text,
                    "reason": s.reason,
                    "supported_by_evidence": s.supported_by_evidence,
                    "proof_needed": s.proof_needed,
                    "impact": s.impact,
                    "requirement_addressed": s.requirement_addressed
                }
                for s in rewrite_suggestions
            ],
            "penalties": scoring_result.penalties,
            "score_explanation": scoring_result.score_explanation,
            "meta": {
                "scan_timestamp": datetime.now().isoformat(),
                "resume_file_type": resume.file_type,
                "timings": timings,
                "version": "1.0.0"
            }
        }
        
        return report
    
    def generate_text_report(
        self,
        resume: Resume,
        job_posting: JobPosting,
        match_result: MatchResult,
        scoring_result: ScoringResult,
        rewrite_suggestions: list
    ) -> str:
        """Generate human-readable text report."""
        lines = []
        
        # Header
        lines.append("=" * 80)
        lines.append("ATS SCANNER REPORT")
        lines.append("=" * 80)
        lines.append("")
        
        # Overall score
        lines.append(f"OVERALL MATCH SCORE: {scoring_result.overall_score:.1f}/100")
        lines.append("")
        
        # Sub-scores
        lines.append("SUB-SCORES:")
        lines.append(f"  • Keywords and Phrases:         {scoring_result.sub_scores.keywords_and_phrases:.1f}/20")
        lines.append(f"  • Required Skills:              {scoring_result.sub_scores.required_skills:.1f}/25")
        lines.append(f"  • Responsibilities Alignment:   {scoring_result.sub_scores.responsibilities_alignment:.1f}/20")
        lines.append(f"  • Seniority and Scope:          {scoring_result.sub_scores.seniority_and_scope:.1f}/15")
        lines.append(f"  • Tools and Systems:            {scoring_result.sub_scores.tools_and_systems:.1f}/10")
        lines.append(f"  • Education and Certifications: {scoring_result.sub_scores.education_and_certifications:.1f}/10")
        lines.append("")
        
        # Score explanation
        if scoring_result.score_explanation:
            lines.append("SCORE BREAKDOWN:")
            for explanation in scoring_result.score_explanation:
                lines.append(f"  • {explanation}")
            lines.append("")
        
        # Dealbreakers
        if match_result.dealbreakers:
            lines.append("⚠️  CRITICAL GAPS (Deal-breakers):")
            for db in match_result.dealbreakers:
                lines.append(f"  ✗ {db}")
            lines.append("")
        
        # Top strengths
        lines.append("✓ TOP STRENGTHS:")
        strengths = self._extract_top_strengths(match_result)
        for i, strength in enumerate(strengths[:5], 1):
            lines.append(f"  {i}. {strength['text']}")
            if strength.get('evidence'):
                lines.append(f"     Evidence: \"{strength['evidence'][:100]}...\"")
        lines.append("")
        
        # Top gaps
        lines.append("✗ TOP GAPS:")
        gaps = self._extract_top_gaps(match_result)
        for i, gap in enumerate(gaps[:5], 1):
            lines.append(f"  {i}. {gap}")
        lines.append("")
        
        # Missing keywords
        if match_result.missing_keywords:
            lines.append("MISSING KEYWORDS (Top 10):")
            for keyword in match_result.missing_keywords[:10]:
                lines.append(f"  • {keyword}")
            lines.append("")
        
        # Parsing warnings
        if resume.parsing_warnings:
            lines.append("⚠️  PARSING WARNINGS:")
            for warning in resume.parsing_warnings:
                lines.append(f"  • [{warning.severity.value.upper()}] {warning.message}")
                if warning.example:
                    lines.append(f"    Example: {warning.example[:80]}")
            lines.append("")
        
        # High-impact edits
        if rewrite_suggestions:
            lines.append("💡 TOP 5 HIGHEST IMPACT EDITS:")
            for i, suggestion in enumerate(rewrite_suggestions[:5], 1):
                lines.append(f"  {i}. [{suggestion.impact.upper()}] {suggestion.reason}")
                lines.append(f"     Suggestion: {suggestion.suggested_text[:150]}")
                if not suggestion.supported_by_evidence and suggestion.proof_needed:
                    lines.append(f"     ⚠️  Add if true - Proof needed: {', '.join(suggestion.proof_needed[:3])}")
                lines.append("")
        
        # Footer
        lines.append("=" * 80)
        lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("=" * 80)
        
        return "\n".join(lines)
    
    def _extract_top_strengths(self, match_result: MatchResult) -> list:
        """Extract top strengths from matches."""
        strengths = []
        
        for req_match in match_result.requirements_map:
            if req_match.grade.value in ['direct', 'equivalent'] and req_match.confidence.value in ['high', 'medium']:
                evidence_text = ""
                if req_match.evidence_spans:
                    evidence_text = req_match.evidence_spans[0].matched_text
                
                strengths.append({
                    'text': req_match.requirement_text,
                    'evidence': evidence_text,
                    'grade': req_match.grade.value,
                    'confidence': req_match.confidence.value
                })
        
        # Sort by grade and confidence
        grade_order = {'direct': 2, 'equivalent': 1}
        conf_order = {'high': 2, 'medium': 1}
        
        strengths.sort(
            key=lambda s: (grade_order.get(s['grade'], 0), conf_order.get(s['confidence'], 0)),
            reverse=True
        )
        
        return strengths
    
    def _extract_top_gaps(self, match_result: MatchResult) -> list:
        """Extract top gaps from missing requirements."""
        gaps = []
        
        for req_match in match_result.requirements_map:
            if req_match.grade == 'missing' or req_match.grade.value == 'missing':
                # Prioritize by importance
                importance_order = {'must_have': 3, 'required': 2, 'preferred': 1}
                priority = importance_order.get(req_match.requirement_importance, 0)
                gaps.append({
                    'text': req_match.requirement_text,
                    'priority': priority
                })
        
        gaps.sort(key=lambda g: g['priority'], reverse=True)
        return [g['text'] for g in gaps]
    
    def save_report(self, report_data: Dict, output_path: str, format: str = 'json'):
        """Save report to file."""
        if format == 'json':
            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2)
        elif format == 'text':
            with open(output_path, 'w') as f:
                f.write(report_data)
