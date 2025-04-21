"""
Response Parser Utility

Provides standardized methods for parsing structured responses from LLMs.
This ensures consistent parsing logic across different agents and components.
"""

import re
import logging
from typing import Dict, List, Optional, Any, Tuple, Union

logger = logging.getLogger(__name__)

class ResponseParser:
    """Utility class for parsing structured responses from LLMs."""

    @staticmethod
    def extract_section(text: str, section_name: str) -> Optional[str]:
        """
        Extract a labeled section from text.
        
        Args:
            text: The text to parse
            section_name: The section name to look for (e.g., "IDENTIFIED_PROJECT_TYPE")
            
        Returns:
            The extracted section content or None if not found
        """
        if not text or not section_name:
            return None
            
        pattern = re.compile(
            r"(?:^|\n)" + re.escape(section_name) + r":\s*(.*?)(?:\n\w+:|$)",
            re.DOTALL | re.IGNORECASE
        )
        match = pattern.search(text)
        
        if match:
            return match.group(1).strip()
        return None

    @staticmethod
    def extract_bulleted_list(text: str) -> List[str]:
        """
        Extract a bulleted list from text.
        
        Args:
            text: The text containing a bulleted list
            
        Returns:
            List of extracted items
        """
        if not text:
            return []
            
        # Match items starting with -, *, or • bullet points
        items = re.findall(r"(?:^|\n)(?:[-*•])[ \t]*(.*?)(?=(?:\n[-*•])|$)", text, re.DOTALL)
        return [item.strip() for item in items if item.strip()]

    @staticmethod
    def extract_numbered_list(text: str) -> List[str]:
        """
        Extract a numbered list from text.
        
        Args:
            text: The text containing a numbered list
            
        Returns:
            List of extracted items
        """
        if not text:
            return []
            
        # Match items starting with numbers followed by . or )
        items = re.findall(r"(?:^|\n)(?:\d+[.)]|[a-z][.)])[ \t]*(.*?)(?=(?:\n\d+[.)]|\n[a-z][.])|$)", text, re.DOTALL)
        return [item.strip() for item in items if item.strip()]

    @staticmethod
    def extract_json(text: str) -> Optional[Dict[str, Any]]:
        """
        Extract a JSON object from text.
        
        Args:
            text: The text containing a JSON object
            
        Returns:
            Parsed JSON object or None if not found/invalid
        """
        import json
        
        # Find JSON between curly braces
        match = re.search(r"\{.*\}", text, re.DOTALL)
        if not match:
            return None
            
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            return None

    @staticmethod
    def extract_code_blocks(text: str, language: Optional[str] = None) -> List[str]:
        """
        Extract code blocks from markdown text.
        
        Args:
            text: The text containing code blocks
            language: Optional language specifier to filter blocks
            
        Returns:
            List of extracted code blocks
        """
        if not text:
            return []
            
        # Pattern to match markdown code blocks
        if language:
            pattern = r"```(?:" + re.escape(language) + r")\n(.*?)```"
        else:
            pattern = r"```(?:\w*)\n(.*?)```"
            
        blocks = re.findall(pattern, text, re.DOTALL)
        return [block.strip() for block in blocks]

    @staticmethod
    def categorize_severity(text: str) -> str:
        """
        Categorize severity from text description.
        
        Args:
            text: Text containing severity description
            
        Returns:
            Standardized severity level: "Critical", "High", "Medium", "Low", or "Unknown"
        """
        text_lower = text.lower()
        
        if any(term in text_lower for term in ["critical", "severe", "very high"]):
            return "Critical"
        elif "high" in text_lower:
            return "High"
        elif "medium" in text_lower or "moderate" in text_lower:
            return "Medium"
        elif "low" in text_lower or "minor" in text_lower:
            return "Low"
        else:
            return "Unknown"

    @staticmethod
    def extract_key_value_pairs(text: str) -> Dict[str, str]:
        """
        Extract key-value pairs from text.
        
        Args:
            text: Text containing key-value pairs
            
        Returns:
            Dictionary of extracted key-value pairs
        """
        if not text:
            return {}
            
        # Pattern to match "Key: Value" pairs
        pairs = re.findall(r"^([^:]+):\s*(.*?)$", text, re.MULTILINE)
        return {key.strip(): value.strip() for key, value in pairs}

    @staticmethod
    def extract_vulnerability_details(text: str) -> Dict[str, Any]:
        """
        Extract structured vulnerability details from text.
        
        Args:
            text: Text containing vulnerability details
            
        Returns:
            Dictionary with structured vulnerability information
        """
        details = {
            "title": "",
            "description": "",
            "severity": "Unknown",
            "impact": "",
            "recommendation": "",
            "code_snippets": []
        }
        
        # Extract title (first line or section)
        first_line = text.split('\n')[0].strip() if text else ""
        if first_line:
            details["title"] = first_line
        
        # Extract sections
        for section_name, key in [
            ("Description", "description"),
            ("Impact", "impact"),
            ("Severity", "severity"),
            ("Recommendation", "recommendation"),
            ("Remediation", "recommendation"),
            ("Fix", "recommendation")
        ]:
            content = ResponseParser.extract_section(text, section_name)
            if content:
                if key == "severity":
                    details[key] = ResponseParser.categorize_severity(content)
                else:
                    details[key] = content
        
        # Extract code snippets
        details["code_snippets"] = ResponseParser.extract_code_blocks(text, "solidity")
        
        return details

    @staticmethod
    def extract_all_sections(text: str) -> Dict[str, str]:
        """Extract all sections from a structured response
        
        Args:
            text: The LLM response text
            
        Returns:
            A dictionary of section names to section content
        """
        # Pattern to find sections like "SECTION_NAME: content"
        pattern = r'([A-Z_]+):?\s*(.*?)(?=\n\n[A-Z_]+:|\Z)'
        matches = re.findall(pattern, text, re.DOTALL)
        
        result = {}
        for section_name, content in matches:
            result[section_name] = content.strip()
        
        return result
    
    @staticmethod
    def parse_vulnerability(text: str) -> Dict[str, Any]:
        """Parse vulnerability information into a structured format
        
        Args:
            text: The text containing vulnerability information
            
        Returns:
            A dictionary with parsed vulnerability details
        """
        vulnerability = {}
        
        # Extract title (may be the first line or explicit "Title:" section)
        title_match = re.search(r'^(.*?)(?:\n|$)', text.strip())
        if title_match:
            vulnerability['title'] = title_match.group(1).strip()
        
        # Extract common vulnerability fields
        for field, patterns in {
            'title': [r'(?:^|\n)Title:?\s*(.*?)(?:\n|$)', r'(?:^|\n)Vulnerability:?\s*(.*?)(?:\n|$)'],
            'type': [r'(?:^|\n)Type:?\s*(.*?)(?:\n|$)', r'(?:^|\n)Vulnerability Type:?\s*(.*?)(?:\n|$)'],
            'severity': [r'(?:^|\n)Severity:?\s*(.*?)(?:\n|$)'],
            'location': [r'(?:^|\n)Location:?\s*(.*?)(?:\n|$)', r'(?:^|\n)Affected:?\s*(.*?)(?:\n|$)'],
            'description': [r'(?:^|\n)Description:?\s*(.*?)(?:\n(?:[A-Z][a-z]+ ?[A-Z][a-z]+:|\Z))', r'(?:^|\n)Issue:?\s*(.*?)(?:\n(?:[A-Z][a-z]+ ?[A-Z][a-z]+:|\Z))'],
            'impact': [r'(?:^|\n)Impact:?\s*(.*?)(?:\n(?:[A-Z][a-z]+ ?[A-Z][a-z]+:|\Z))', r'(?:^|\n)Potential Impact:?\s*(.*?)(?:\n(?:[A-Z][a-z]+ ?[A-Z][a-z]+:|\Z))'],
            'recommendation': [r'(?:^|\n)Recommendation:?\s*(.*?)(?:\n(?:[A-Z][a-z]+ ?[A-Z][a-z]+:|\Z))', r'(?:^|\n)Remediation:?\s*(.*?)(?:\n(?:[A-Z][a-z]+ ?[A-Z][a-z]+:|\Z))'],
            'code_snippet': [r'(?:^|\n)Code Snippet:?\s*(.*?)(?:\n(?:[A-Z][a-z]+ ?[A-Z][a-z]+:|\Z))', r'(?:^|\n)Code:?\s*(.*?)(?:\n(?:[A-Z][a-z]+ ?[A-Z][a-z]+:|\Z))'],
        }.items():
            for pattern in patterns:
                match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
                if match and match.group(1).strip():
                    vulnerability[field] = match.group(1).strip()
                    break
        
        # Extract or infer severity level
        if 'severity' in vulnerability:
            severity_text = vulnerability['severity'].lower()
            if 'critical' in severity_text:
                vulnerability['severity_level'] = 'critical'
            elif 'high' in severity_text:
                vulnerability['severity_level'] = 'high'
            elif 'medium' in severity_text:
                vulnerability['severity_level'] = 'medium'
            elif 'low' in severity_text:
                vulnerability['severity_level'] = 'low'
            else:
                vulnerability['severity_level'] = 'unknown'
        
        return vulnerability
    
    @staticmethod
    def parse_yes_no_question(text: str, question_pattern: str) -> Tuple[bool, str]:
        """Parse a yes/no question response
        
        Args:
            text: The text containing the response
            question_pattern: The regex pattern to identify the question
            
        Returns:
            A tuple of (is_yes, reasoning)
        """
        # Find the question and answer in the text
        match = re.search(question_pattern, text, re.IGNORECASE | re.DOTALL)
        if not match:
            logger.warning(f"Could not find question matching pattern: {question_pattern}")
            return (False, "Unable to determine answer")
        
        # Check if the answer is affirmative
        answer_text = match.group(1) if len(match.groups()) >= 1 else text
        
        # Keywords indicating affirmative or negative responses
        yes_keywords = ['yes', 'affirmative', 'correct', 'indeed', 'true', 'agreed']
        no_keywords = ['no', 'negative', 'incorrect', 'false', 'disagree']
        
        # Check for keywords in the answer text
        is_yes = any(keyword in answer_text.lower() for keyword in yes_keywords)
        is_no = any(keyword in answer_text.lower() for keyword in no_keywords)
        
        # If clearly yes or no, return accordingly
        if is_yes and not is_no:
            return (True, answer_text)
        elif is_no and not is_yes:
            return (False, answer_text)
        
        # If unclear, do more analysis
        yes_count = sum(1 for keyword in yes_keywords if keyword in answer_text.lower())
        no_count = sum(1 for keyword in no_keywords if keyword in answer_text.lower())
        
        # Return based on which has more matches, preferring "no" in case of ties
        return (yes_count > no_count, answer_text)
    
    @staticmethod
    def format_with_newlines(text: str) -> str:
        """Ensure text has proper newline formatting
        
        Args:
            text: The text to format
            
        Returns:
            The formatted text
        """
        # Replace escaped newlines with actual newlines
        text = text.replace('\\n', '\n')
        
        # Ensure sections are separated by double newlines
        text = re.sub(r'([A-Z_]+:)\s*', r'\n\1 ', text)
        
        # Remove excessive newlines
        text = re.sub(r'\n{3,}', '\n\n', text)
        
        return text.strip() 