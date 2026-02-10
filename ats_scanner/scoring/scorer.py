"""Main scoring engine."""

from typing import List
from ..models.match import MatchResult, MatchGrade, ConfidenceLevel, DepthLevel
from ..models.scoring import ScoringResult, ScoreBreakdown
from ..models.job import JobPosting, RequirementCategory, RequirementImportance
from ..models.resume import Resume, SeverityLevel


class Scorer:
    """Calculate scores based on matches."""
    
    # Score weights
    MAX_KEYWORDS_SCORE = 20
    MAX_REQUIRED_SKILLS_SCORE = 25
    MAX_RESPONSIBILITIES_SCORE = 20
    MAX_SENIORITY_SCORE = 15
    MAX_TOOLS_SCORE = 10
    MAX_EDUCATION_SCORE = 10
    
    # Penalties
    MUST_HAVE_PENALTY = 15
    MAX_MUST_HAVE_PENALTY = 30
    MAX_PARSING_PENALTY = 10
    MAX_KEYWORD_STUFFING_PENALTY = 10
    MAX_LOW_CONFIDENCE_PENALTY = 10
    
    def __init__(self):
        """Initialize scorer."""
        pass
    
    def score(
        self,
        match_result: MatchResult,
        job_posting: JobPosting,
        resume: Resume
    ) -> ScoringResult:
        """Calculate overall score."""
        # Calculate sub-scores
        sub_scores = ScoreBreakdown()
        
        # Keywords and phrases score
        sub_scores.keywords_and_phrases = self._score_keywords(match_result, job_posting)
        
        # Required skills score
        sub_scores.required_skills = self._score_required_skills(match_result, job_posting)
        
        # Responsibilities alignment score
        sub_scores.responsibilities_alignment = self._score_responsibilities(match_result, job_posting)
        
        # Seniority and scope score
        sub_scores.seniority_and_scope = self._score_seniority(match_result, job_posting)
        
        # Tools and systems score
        sub_scores.tools_and_systems = self._score_tools(match_result, job_posting)
        
        # Education and certifications score
        sub_scores.education_and_certifications = self._score_education(match_result, job_posting)
        
        # Calculate base score
        base_score = sub_scores.total()
        
        # Calculate penalties
        penalties = {}
        
        # Missing must-haves penalty
        must_have_penalty = self._calculate_must_have_penalty(match_result)
        if must_have_penalty > 0:
            penalties['missing_must_haves'] = must_have_penalty
        
        # Parsing quality penalty
        parsing_penalty = self._calculate_parsing_penalty(resume)
        if parsing_penalty > 0:
            penalties['parsing_quality'] = parsing_penalty
        
        # Keyword stuffing penalty
        if match_result.keyword_stuffing_detected:
            keyword_penalty = match_result.keyword_stuffing_score * self.MAX_KEYWORD_STUFFING_PENALTY
            penalties['keyword_stuffing'] = keyword_penalty
        
        # Low confidence penalty
        low_confidence_penalty = self._calculate_low_confidence_penalty(match_result)
        if low_confidence_penalty > 0:
            penalties['low_confidence_evidence'] = low_confidence_penalty
        
        # Calculate final score
        total_penalty = sum(penalties.values())
        overall_score = max(0, min(100, base_score - total_penalty))
        
        # Generate explanation
        score_explanation, top_contributors, top_penalties = self._generate_explanation(
            sub_scores, penalties, match_result
        )
        
        return ScoringResult(
            overall_score=overall_score,
            sub_scores=sub_scores,
            penalties=penalties,
            score_explanation=score_explanation,
            top_contributors=top_contributors,
            top_penalties=top_penalties
        )
    
    def _score_keywords(self, match_result: MatchResult, job_posting: JobPosting) -> float:
        """Score based on keyword matches."""
        total_keywords = len(match_result.matched_keywords) + len(match_result.missing_keywords)
        if total_keywords == 0:
            return 0.0
        
        matched_count = len(match_result.matched_keywords)
        match_rate = matched_count / total_keywords
        
        # Apply capped contribution
        score = match_rate * self.MAX_KEYWORDS_SCORE
        return round(score, 2)
    
    def _score_required_skills(self, match_result: MatchResult, job_posting: JobPosting) -> float:
        """Score based on required skills matches."""
        skill_reqs = [m for m in match_result.requirements_map 
                     if m.requirement_category in ['skill', 'tool']]
        
        if not skill_reqs:
            return 0.0
        
        # Weight by match grade
        grade_weights = {
            MatchGrade.DIRECT: 1.0,
            MatchGrade.EQUIVALENT: 0.8,
            MatchGrade.INDIRECT: 0.5,
            MatchGrade.WEAK: 0.3,
            MatchGrade.MISSING: 0.0
        }
        
        total_weight = 0.0
        for req_match in skill_reqs:
            weight = grade_weights.get(req_match.grade, 0.0)
            # Boost weight for high confidence
            if req_match.confidence == ConfidenceLevel.HIGH:
                weight *= 1.2
            elif req_match.confidence == ConfidenceLevel.LOW:
                weight *= 0.8
            
            # Boost weight for recency
            weight *= req_match.recency_weight
            
            total_weight += weight
        
        # Normalize
        max_possible = len(skill_reqs) * 1.2  # max possible with boosts
        score = (total_weight / max_possible) * self.MAX_REQUIRED_SKILLS_SCORE
        
        return round(min(score, self.MAX_REQUIRED_SKILLS_SCORE), 2)
    
    def _score_responsibilities(self, match_result: MatchResult, job_posting: JobPosting) -> float:
        """Score based on responsibilities alignment."""
        resp_reqs = [m for m in match_result.requirements_map 
                    if m.requirement_category == 'responsibility']
        
        if not resp_reqs:
            return 0.0
        
        # Weight by depth level
        depth_weights = {
            DepthLevel.LED: 1.0,
            DepthLevel.OWNED: 0.8,
            DepthLevel.DELIVERED: 0.6,
            DepthLevel.USED: 0.4,
            DepthLevel.UNKNOWN: 0.2
        }
        
        total_weight = 0.0
        for req_match in resp_reqs:
            if req_match.grade != MatchGrade.MISSING:
                weight = depth_weights.get(req_match.depth, 0.2)
                total_weight += weight
        
        # Normalize
        max_possible = len(resp_reqs)
        score = (total_weight / max_possible) * self.MAX_RESPONSIBILITIES_SCORE
        
        return round(min(score, self.MAX_RESPONSIBILITIES_SCORE), 2)
    
    def _score_seniority(self, match_result: MatchResult, job_posting: JobPosting) -> float:
        """Score based on seniority and scope indicators."""
        # Check for leadership depth
        led_count = sum(1 for m in match_result.requirements_map 
                       if m.depth == DepthLevel.LED)
        owned_count = sum(1 for m in match_result.requirements_map 
                         if m.depth == DepthLevel.OWNED)
        
        # Check for years requirements
        years_reqs = [m for m in match_result.requirements_map 
                     if m.requirement_category == 'years']
        years_matched = sum(1 for m in years_reqs if m.grade != MatchGrade.MISSING)
        
        # Calculate score
        leadership_score = min(10, (led_count * 2 + owned_count) * 2)
        years_score = 5 if years_matched > 0 else 0
        
        score = leadership_score + years_score
        return round(min(score, self.MAX_SENIORITY_SCORE), 2)
    
    def _score_tools(self, match_result: MatchResult, job_posting: JobPosting) -> float:
        """Score based on tools and systems."""
        tool_reqs = [m for m in match_result.requirements_map 
                    if m.requirement_category == 'tool']
        
        if not tool_reqs:
            return 0.0
        
        matched_count = sum(1 for m in tool_reqs if m.grade != MatchGrade.MISSING)
        match_rate = matched_count / len(tool_reqs)
        
        score = match_rate * self.MAX_TOOLS_SCORE
        return round(score, 2)
    
    def _score_education(self, match_result: MatchResult, job_posting: JobPosting) -> float:
        """Score based on education and certifications."""
        edu_reqs = [m for m in match_result.requirements_map 
                   if m.requirement_category in ['education', 'certification']]
        
        if not edu_reqs:
            # No requirements, give full score
            return self.MAX_EDUCATION_SCORE
        
        matched_count = sum(1 for m in edu_reqs if m.grade != MatchGrade.MISSING)
        match_rate = matched_count / len(edu_reqs)
        
        score = match_rate * self.MAX_EDUCATION_SCORE
        return round(score, 2)
    
    def _calculate_must_have_penalty(self, match_result: MatchResult) -> float:
        """Calculate penalty for missing must-haves."""
        missing_count = len(match_result.dealbreakers)
        penalty = min(missing_count * self.MUST_HAVE_PENALTY, self.MAX_MUST_HAVE_PENALTY)
        return penalty
    
    def _calculate_parsing_penalty(self, resume: Resume) -> float:
        """Calculate penalty for parsing quality issues."""
        high_severity = sum(1 for w in resume.parsing_warnings 
                          if w.severity == SeverityLevel.HIGH)
        medium_severity = sum(1 for w in resume.parsing_warnings 
                            if w.severity == SeverityLevel.MEDIUM)
        
        penalty = (high_severity * 5 + medium_severity * 2)
        return min(penalty, self.MAX_PARSING_PENALTY)
    
    def _calculate_low_confidence_penalty(self, match_result: MatchResult) -> float:
        """Calculate penalty for concentration of low confidence evidence."""
        total_matches = len([m for m in match_result.requirements_map 
                           if m.grade != MatchGrade.MISSING])
        
        if total_matches == 0:
            return 0.0
        
        low_confidence = sum(1 for m in match_result.requirements_map 
                           if m.confidence == ConfidenceLevel.LOW and m.grade != MatchGrade.MISSING)
        
        low_conf_rate = low_confidence / total_matches
        
        if low_conf_rate > 0.5:  # More than half are low confidence
            penalty = (low_conf_rate - 0.5) * 20  # Scale penalty
            return min(penalty, self.MAX_LOW_CONFIDENCE_PENALTY)
        
        return 0.0
    
    def _generate_explanation(
        self,
        sub_scores: ScoreBreakdown,
        penalties: dict,
        match_result: MatchResult
    ) -> tuple:
        """Generate score explanation."""
        explanation = []
        
        # Top contributors
        contributors = [
            {'category': 'Keywords and Phrases', 'points': sub_scores.keywords_and_phrases},
            {'category': 'Required Skills', 'points': sub_scores.required_skills},
            {'category': 'Responsibilities Alignment', 'points': sub_scores.responsibilities_alignment},
            {'category': 'Seniority and Scope', 'points': sub_scores.seniority_and_scope},
            {'category': 'Tools and Systems', 'points': sub_scores.tools_and_systems},
            {'category': 'Education and Certifications', 'points': sub_scores.education_and_certifications},
        ]
        contributors.sort(key=lambda x: x['points'], reverse=True)
        top_contributors = contributors[:3]
        
        for contrib in top_contributors:
            explanation.append(f"{contrib['category']}: +{contrib['points']:.1f} points")
        
        # Top penalties
        penalty_list = [{'reason': k, 'points': v} for k, v in penalties.items()]
        penalty_list.sort(key=lambda x: x['points'], reverse=True)
        top_penalties = penalty_list[:3]
        
        for penalty in top_penalties:
            explanation.append(f"{penalty['reason'].replace('_', ' ').title()}: -{penalty['points']:.1f} points")
        
        return explanation, top_contributors, top_penalties
