"""
Helper Utilities

This module provides common helper functions used throughout the LLM Audit system.
These utilities handle text processing, input validation, and other common tasks.
"""

import logging
import os
import re
import json
from typing import List, Dict, Any, Union, Optional, Tuple, Set

logger = logging.getLogger(__name__)

# Text processing utilities

def truncate_text(text: str, max_length: int, add_ellipsis: bool = True) -> str:
    """
    Truncate text to a maximum length.
    
    Args:
        text: The text to truncate
        max_length: Maximum length in characters
        add_ellipsis: Whether to add "..." at the end of truncated text
        
    Returns:
        Truncated text
    """
    if not text or len(text) <= max_length:
        return text
        
    result = text[:max_length]
    if add_ellipsis:
        result = result.rstrip() + "..."
        
    return result

def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """
    Extract JSON from a text string.
    
    Args:
        text: Text that may contain JSON
        
    Returns:
        Extracted JSON as dict or None if no valid JSON found
    """
    # Look for JSON patterns in the text
    json_pattern = r'```json\s*([\s\S]*?)\s*```|{[\s\S]*}'
    matches = re.findall(json_pattern, text)
    
    for match in matches:
        if match:
            # Clean up the match
            cleaned = match.strip()
            
            # Ensure it starts with {
            if not cleaned.startswith('{'):
                continue
                
            try:
                return json.loads(cleaned)
            except json.JSONDecodeError:
                logger.debug(f"Failed to parse JSON: {cleaned[:100]}...")
                
    logger.warning("No valid JSON found in text")
    return None

def parse_structured_response(text: str, default_fields: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Parse a structured response from an LLM output.
    
    Args:
        text: Text response from LLM
        default_fields: Default field values to use if parsing fails
        
    Returns:
        Dictionary with parsed fields
    """
    if default_fields is None:
        default_fields = {}
        
    # First try to extract JSON
    json_data = extract_json_from_text(text)
    if json_data:
        # Update default fields with extracted JSON
        result = default_fields.copy()
        result.update(json_data)
        return result
        
    # If JSON extraction fails, try field-by-field extraction
    result = default_fields.copy()
    
    # Common field patterns
    field_patterns = {
        "project_type": r'(?:PROJECT_TYPE|Project Type|project type)[\s:]+([^\n]+)',
        "confidence": r'(?:CONFIDENCE|Confidence|confidence)[\s:]+([^\n]+)',
        "need_more_info": r'(?:NEED_MORE_INFO|Need More Info|need more info)[\s:]+([^\n]+)',
        "have_enough_info": r'(?:HAVE_ENOUGH_INFO|Have Enough Info|have enough info)[\s:]+([^\n]+)',
        "questions": r'(?:QUESTIONS|Questions|questions|SPECIFIC_QUESTIONS)[\s:]+([^\n]*(?:\n\s*-[^\n]+)*)',
        "vulnerabilities": r'(?:VULNERABILITIES|Vulnerabilities|vulnerabilities)[\s:]+([^\n]*(?:\n\s*-[^\n]+)*)',
        "reasoning": r'(?:REASONING|Reasoning|reasoning)[\s:]+([^\n]*(?:\n[^\n]+)*)',
    }
    
    for field, pattern in field_patterns.items():
        match = re.search(pattern, text, re.IGNORECASE)
        if match and match.group(1).strip():
            value = match.group(1).strip()
            
            # Convert boolean strings to actual booleans
            if value.lower() in ('yes', 'true', 'y'):
                value = True
            elif value.lower() in ('no', 'false', 'n'):
                value = False
                
            # Special handling for list fields
            if field in ('questions', 'vulnerabilities'):
                # Extract list items
                if '\n' in value:
                    value = [item.strip('- ').strip() for item in value.split('\n') if item.strip()]
                else:
                    value = [value]
                    
            result[field] = value
            
    return result

def parse_boolean_from_text(text: str, default: bool = False) -> bool:
    """
    Parse a boolean value from text.
    
    Args:
        text: Text to parse
        default: Default value if parsing fails
        
    Returns:
        Boolean value
    """
    if not text:
        return default
        
    text = text.lower().strip()
    if text in ('yes', 'true', 'y', '1'):
        return True
    elif text in ('no', 'false', 'n', '0'):
        return False
    
    return default

def split_into_chunks(text: str, max_chunk_size: int, overlap: int = 0) -> List[str]:
    """
    Split text into chunks of maximum size.
    
    Args:
        text: Text to split
        max_chunk_size: Maximum chunk size in characters
        overlap: Number of characters to overlap between chunks
        
    Returns:
        List of text chunks
    """
    if not text:
        return []
        
    if len(text) <= max_chunk_size:
        return [text]
        
    chunks = []
    start = 0
    
    while start < len(text):
        end = min(start + max_chunk_size, len(text))
        
        # If we're not at the end, try to break at a newline or period
        if end < len(text):
            # Look for a good breaking point (newline, period, space)
            for break_char in ['\n', '.', ' ']:
                last_break = text.rfind(break_char, start, end)
                if last_break > start:
                    end = last_break + 1
                    break
        
        chunks.append(text[start:end])
        start = end - overlap if overlap > 0 else end
        
    return chunks

# File and path utilities

def normalize_path(path: str) -> str:
    """
    Normalize a file path.
    
    Args:
        path: File path to normalize
        
    Returns:
        Normalized path
    """
    return os.path.normpath(path)

def is_valid_file_extension(filename: str, allowed_extensions: List[str]) -> bool:
    """
    Check if a file has a valid extension.
    
    Args:
        filename: Filename to check
        allowed_extensions: List of allowed extensions (e.g., ['.sol', '.js'])
        
    Returns:
        True if file has a valid extension
    """
    _, ext = os.path.splitext(filename)
    return ext.lower() in allowed_extensions

def list_files_in_directory(directory: str, 
                           allowed_extensions: List[str] = None, 
                           excluded_dirs: List[str] = None) -> List[str]:
    """
    List all files in a directory with optional filtering.
    
    Args:
        directory: Directory to scan
        allowed_extensions: List of allowed file extensions
        excluded_dirs: List of directory names to exclude
        
    Returns:
        List of file paths
    """
    if excluded_dirs is None:
        excluded_dirs = ["node_modules", ".git", "build", "dist"]
        
    result = []
    
    for root, dirs, files in os.walk(directory):
        # Exclude directories in-place
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        
        for file in files:
            if allowed_extensions is None or is_valid_file_extension(file, allowed_extensions):
                result.append(os.path.join(root, file))
                
    return result

def get_file_content(file_path: str, max_size_mb: float = 10) -> Optional[str]:
    """
    Get the content of a file with size checking.
    
    Args:
        file_path: Path to the file
        max_size_mb: Maximum file size in MB
        
    Returns:
        File content or None if file is too large or cannot be read
    """
    try:
        # Check file size
        file_size = os.path.getsize(file_path) / (1024 * 1024)  # Convert to MB
        if file_size > max_size_mb:
            logger.warning(f"File {file_path} is too large ({file_size:.2f} MB > {max_size_mb} MB)")
            return None
            
        # Read file content
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")
        return None

# Data processing utilities

def estimate_token_count(text: str, tokens_per_char: float = 0.25) -> int:
    """
    Estimate the number of tokens in a text.
    This is a rough estimate and not intended to be exact.
    
    Args:
        text: Text to estimate token count for
        tokens_per_char: Tokens per character ratio
        
    Returns:
        Estimated token count
    """
    if not text:
        return 0
        
    # Simple estimation based on character count
    return int(len(text) * tokens_per_char)

def merge_dictionaries(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge two dictionaries.
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary
        
    Returns:
        Merged dictionary
    """
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = merge_dictionaries(result[key], value)
        else:
            result[key] = value
            
    return result

def flatten_list(nested_list: List) -> List:
    """
    Flatten a nested list.
    
    Args:
        nested_list: Nested list
        
    Returns:
        Flattened list
    """
    result = []
    
    for item in nested_list:
        if isinstance(item, list):
            result.extend(flatten_list(item))
        else:
            result.append(item)
            
    return result

def deduplicate_list(items: List) -> List:
    """
    Remove duplicates from a list while preserving order.
    
    Args:
        items: List to deduplicate
        
    Returns:
        Deduplicated list
    """
    seen = set()
    result = []
    
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
            
    return result

# Validation utilities

def validate_severity_level(level: str, 
                           allowed_levels: List[str] = None) -> Optional[str]:
    """
    Validate severity level.
    
    Args:
        level: Severity level to validate
        allowed_levels: List of allowed severity levels
        
    Returns:
        Normalized severity level or None if invalid
    """
    if allowed_levels is None:
        allowed_levels = ["Critical", "High", "Medium", "Low", "Informational"]
        
    # Normalize level
    normalized = level.strip().title()
    
    # Check if normalized level is in allowed levels
    if normalized in allowed_levels:
        return normalized
        
    # Special case handling
    if normalized == "Info":
        return "Informational"
        
    # Handle numerical representations
    if normalized in ["1", "2", "3", "4", "5"]:
        index = int(normalized) - 1
        if 0 <= index < len(allowed_levels):
            return allowed_levels[index]
            
    logger.warning(f"Invalid severity level: {level}")
    return None

def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid.
    
    Args:
        url: URL to validate
        
    Returns:
        True if URL is valid
    """
    url_pattern = re.compile(
        r'^(?:http|https)://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
    return bool(url_pattern.match(url)) 