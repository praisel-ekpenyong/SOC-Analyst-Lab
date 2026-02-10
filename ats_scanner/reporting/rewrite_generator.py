"""Rewrite suggestion generator."""

from typing import List
from ..models.match import MatchResult, RequirementMatch, MatchGrade, ConfidenceLevel
from ..models.rewrite import RewriteSuggestion
from ..models.resume import Resume


class RewriteGenerator:
    """Generate rewrite suggestions based on matches."""
    
    def generate(
        self,
        match_result: MatchResult,
        resume: Resume
    ) -> List[RewriteSuggestion]:
        """Generate rewrite suggestions."""
        suggestions = []
        
        # Generate suggestions for missing must-haves
        for req_match in match_result.requirements_map:
            if req_match.grade == MatchGrade.MISSING:
                sugg = self._suggest_for_missing(req_match)
                if sugg:
                    suggestions.append(sugg)
            elif req_match.grade == MatchGrade.WEAK:
                sugg = self._suggest_for_weak(req_match)
                if sugg:
                    suggestions.append(sugg)
        
        # Sort by impact
        impact_order = {'high': 3, 'medium': 2, 'low': 1}
        suggestions.sort(key=lambda s: impact_order.get(s.impact, 0), reverse=True)
        
        return suggestions[:10]  # Return top 10
    
    def _suggest_for_missing(self, req_match: RequirementMatch) -> RewriteSuggestion:
        """Generate suggestion for missing requirement."""
        # Determine impact based on importance
        if req_match.requirement_importance in ['must_have', 'required']:
            impact = 'high'
        elif req_match.requirement_importance == 'preferred':
            impact = 'medium'
        else:
            impact = 'low'
        
        # Generate suggestion text
        suggested_text = f"Add experience or projects demonstrating: {req_match.requirement_text}"
        
        # Extract proof needed
        proof_needed = req_match.suggested_keywords or ["relevant experience or certification"]
        
        return RewriteSuggestion(
            original_span=None,
            suggested_text=suggested_text,
            reason=f"Missing {req_match.requirement_importance} requirement",
            supported_by_evidence=False,
            proof_needed=proof_needed,
            impact=impact,
            requirement_addressed=req_match.requirement_text
        )
    
    def _suggest_for_weak(self, req_match: RequirementMatch) -> RewriteSuggestion:
        """Generate suggestion for weak match."""
        if not req_match.evidence_spans:
            return None
        
        # Find evidence in skills section
        skills_evidence = [e for e in req_match.evidence_spans if e.source_type == 'skills']
        
        if not skills_evidence:
            return None
        
        # Get the original span
        evidence = skills_evidence[0]
        original = evidence.matched_text
        
        # Generate improved text
        suggested_text = f"[Describe how you used {original} in a project or work experience with specific outcomes, e.g., 'Built X using {original} which resulted in Y']"
        
        return RewriteSuggestion(
            original_span=original,
            suggested_text=suggested_text,
            reason="Skill mentioned only in skills section without concrete examples",
            supported_by_evidence=True,
            proof_needed=[],
            impact='medium',
            requirement_addressed=req_match.requirement_text
        )
