"""Date extraction and recency calculation."""

import re
from datetime import datetime
from typing import Optional, Tuple
from dateutil import parser as date_parser
from dateutil.relativedelta import relativedelta


class DateExtractor:
    """Extract and analyze dates from text."""
    
    def extract_date_range(self, text: str) -> Optional[Tuple[datetime, Optional[datetime]]]:
        """Extract date range from text."""
        # Common date range patterns
        patterns = [
            r'(\d{1,2}/\d{4})\s*[-–]\s*(\d{1,2}/\d{4}|Present|Current)',
            r'(\d{4})\s*[-–]\s*(\d{4}|Present|Current)',
            r'([A-Z][a-z]+\s+\d{4})\s*[-–]\s*([A-Z][a-z]+\s+\d{4}|Present|Current)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                start_str = match.group(1)
                end_str = match.group(2)
                
                try:
                    start_date = self._parse_date(start_str)
                    end_date = self._parse_date(end_str) if end_str.lower() not in ['present', 'current'] else None
                    return (start_date, end_date)
                except:
                    continue
        
        return None
    
    def _parse_date(self, date_str: str) -> datetime:
        """Parse date string to datetime."""
        # Try dateutil parser
        try:
            return date_parser.parse(date_str, fuzzy=True)
        except:
            # Try manual parsing for common formats
            if re.match(r'^\d{4}$', date_str):
                return datetime(int(date_str), 1, 1)
            elif re.match(r'^\d{1,2}/\d{4}$', date_str):
                month, year = date_str.split('/')
                return datetime(int(year), int(month), 1)
            raise ValueError(f"Cannot parse date: {date_str}")
    
    def calculate_recency_weight(self, start_date: datetime, end_date: Optional[datetime]) -> float:
        """Calculate recency weight based on date range."""
        # If no end date, assume current
        if end_date is None:
            end_date = datetime.now()
        
        # Calculate months since end date
        months_ago = relativedelta(datetime.now(), end_date).months + \
                     (relativedelta(datetime.now(), end_date).years * 12)
        
        # Apply recency weights
        if months_ago <= 12:
            return 1.0
        elif months_ago <= 36:
            return 0.7
        else:
            return 0.4
    
    def extract_all_date_ranges(self, text: str) -> list:
        """Extract all date ranges from text with their positions."""
        date_ranges = []
        
        # Pattern for date ranges
        pattern = r'(\d{1,2}/\d{4}|\d{4}|[A-Z][a-z]+\s+\d{4})\s*[-–]\s*(\d{1,2}/\d{4}|\d{4}|[A-Z][a-z]+\s+\d{4}|Present|Current)'
        
        for match in re.finditer(pattern, text, re.IGNORECASE):
            try:
                start_date = self._parse_date(match.group(1))
                end_str = match.group(2)
                end_date = self._parse_date(end_str) if end_str.lower() not in ['present', 'current'] else None
                
                date_ranges.append({
                    'start': start_date,
                    'end': end_date,
                    'text': match.group(0),
                    'position': match.start()
                })
            except:
                continue
        
        return date_ranges
