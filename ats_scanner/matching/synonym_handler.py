"""Synonym and canonicalization handler."""

import json
from typing import Dict, List, Optional, Tuple


class SynonymHandler:
    """Handle skill synonyms and canonical names."""
    
    def __init__(self, synonyms_path: Optional[str] = None):
        """Initialize with optional custom synonyms file."""
        self.canonical_map = {}
        self.equivalents = {}
        
        if synonyms_path:
            self._load_synonyms(synonyms_path)
        else:
            self._load_default_synonyms()
    
    def _load_default_synonyms(self):
        """Load default synonyms and equivalents."""
        # Canonical skill mappings
        self.canonical_map = {
            'ci/cd': ['ci/cd', 'cicd', 'continuous integration', 'continuous deployment', 'continuous delivery'],
            'postgresql': ['postgresql', 'postgres', 'psql'],
            'mysql': ['mysql', 'my sql'],
            'javascript': ['javascript', 'js', 'ecmascript'],
            'typescript': ['typescript', 'ts'],
            'python': ['python', 'py'],
            'docker': ['docker', 'containerization'],
            'kubernetes': ['kubernetes', 'k8s'],
            'amazon web services': ['aws', 'amazon web services'],
            'google cloud platform': ['gcp', 'google cloud', 'google cloud platform'],
            'microsoft azure': ['azure', 'microsoft azure'],
            'machine learning': ['machine learning', 'ml'],
            'artificial intelligence': ['artificial intelligence', 'ai'],
            'natural language processing': ['nlp', 'natural language processing'],
        }
        
        # Reverse mapping for lookup
        self.alias_to_canonical = {}
        for canonical, aliases in self.canonical_map.items():
            for alias in aliases:
                self.alias_to_canonical[alias.lower()] = canonical
        
        # Equivalent tools (partial match strength)
        self.equivalents = {
            'tableau': {'power bi': 0.8, 'looker': 0.7, 'qlik': 0.7},
            'power bi': {'tableau': 0.8, 'looker': 0.7, 'qlik': 0.7},
            'mysql': {'postgresql': 0.7, 'mariadb': 0.9, 'sql server': 0.6},
            'postgresql': {'mysql': 0.7, 'sql server': 0.6},
            'aws': {'azure': 0.7, 'gcp': 0.7},
            'azure': {'aws': 0.7, 'gcp': 0.7},
            'gcp': {'aws': 0.7, 'azure': 0.7},
            'react': {'vue': 0.6, 'angular': 0.6},
            'vue': {'react': 0.6, 'angular': 0.6},
            'angular': {'react': 0.6, 'vue': 0.6},
        }
    
    def _load_synonyms(self, path: str):
        """Load synonyms from JSON file."""
        try:
            with open(path, 'r') as f:
                data = json.load(f)
                self.canonical_map = data.get('canonical_map', {})
                self.equivalents = data.get('equivalents', {})
                
                # Build reverse mapping
                self.alias_to_canonical = {}
                for canonical, aliases in self.canonical_map.items():
                    for alias in aliases:
                        self.alias_to_canonical[alias.lower()] = canonical
        except Exception as e:
            print(f"Warning: Could not load synonyms file: {e}")
            self._load_default_synonyms()
    
    def get_canonical(self, term: str) -> str:
        """Get canonical form of a term."""
        term_lower = term.lower()
        return self.alias_to_canonical.get(term_lower, term)
    
    def find_synonyms(self, term: str) -> List[str]:
        """Find all synonyms for a term."""
        canonical = self.get_canonical(term)
        return self.canonical_map.get(canonical, [term])
    
    def find_equivalents(self, term: str) -> Dict[str, float]:
        """Find equivalent terms with their match strength."""
        canonical = self.get_canonical(term)
        return self.equivalents.get(canonical, {})
    
    def is_synonym_match(self, term1: str, term2: str) -> Tuple[bool, Optional[str]]:
        """Check if two terms are synonyms."""
        canonical1 = self.get_canonical(term1)
        canonical2 = self.get_canonical(term2)
        
        if canonical1 == canonical2:
            return True, canonical1
        
        return False, None
    
    def is_equivalent_match(self, term1: str, term2: str) -> Tuple[bool, float]:
        """Check if two terms are equivalents and return strength."""
        canonical1 = self.get_canonical(term1)
        canonical2 = self.get_canonical(term2)
        
        equivalents = self.equivalents.get(canonical1, {})
        if canonical2 in equivalents:
            return True, equivalents[canonical2]
        
        return False, 0.0
