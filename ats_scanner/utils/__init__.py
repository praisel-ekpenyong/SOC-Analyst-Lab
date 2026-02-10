"""Simple fuzzy matching utilities."""


def simple_fuzzy_ratio(s1: str, s2: str) -> float:
    """Calculate simple fuzzy match ratio between two strings."""
    s1_lower = s1.lower().strip()
    s2_lower = s2.lower().strip()
    
    # Exact match
    if s1_lower == s2_lower:
        return 100.0
    
    # Substring match
    if s1_lower in s2_lower or s2_lower in s1_lower:
        return 90.0
    
    # Calculate simple similarity based on common characters
    common_chars = set(s1_lower) & set(s2_lower)
    all_chars = set(s1_lower) | set(s2_lower)
    
    if not all_chars:
        return 0.0
    
    char_similarity = (len(common_chars) / len(all_chars)) * 100
    
    # Boost for similar length
    len_diff = abs(len(s1_lower) - len(s2_lower))
    len_factor = max(0, 1 - (len_diff / max(len(s1_lower), len(s2_lower))))
    
    return char_similarity * (0.7 + 0.3 * len_factor)


def ratio(s1: str, s2: str) -> float:
    """Alias for simple_fuzzy_ratio for compatibility."""
    return simple_fuzzy_ratio(s1, s2)
