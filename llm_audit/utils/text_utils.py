"""
Text Processing Utilities

This module provides helper functions for text processing, formatting, parsing,
and other common text manipulation operations used throughout the LLM Audit system.
"""

import logging
import re
import os
import json
from typing import List, Dict, Any, Optional, Tuple, Set, Union

logger = logging.getLogger(__name__)

def truncate_text(text: str, max_length: int, add_ellipsis: bool = True) -> str:
    """
    Truncate text to a specified maximum length.
    
    Args:
        text: Text to truncate
        max_length: Maximum length in characters
        add_ellipsis: Whether to add "..." to the end of truncated text
        
    Returns:
        Truncated text
    """
    if not text or len(text) <= max_length:
        return text
        
    truncated = text[:max_length]
    
    # Try to truncate at a sentence or word boundary
    for boundary in ['. ', '? ', '! ', '\n', ' ']:
        last_boundary = truncated.rfind(boundary)
        if last_boundary > max_length * 0.8:  # Only use if boundary is not too early
            truncated = truncated[:last_boundary + len(boundary)]
            break
            
    # Add ellipsis if requested
    if add_ellipsis and len(text) > max_length:
        if truncated.endswith((' ', '\n', '.', '?', '!')):
            truncated = truncated.rstrip(' \n.?!')
        truncated += "..."
        
    return truncated

def split_into_chunks(text: str, max_chunk_size: int, overlap: int = 0) -> List[str]:
    """
    Split text into chunks of a specified maximum size.
    
    Args:
        text: Text to split
        max_chunk_size: Maximum chunk size in characters
        overlap: Number of characters to overlap between chunks
        
    Returns:
        List of text chunks
    """
    if not text or len(text) <= max_chunk_size:
        return [text] if text else []
        
    chunks = []
    start = 0
    
    while start < len(text):
        # Calculate end position
        end = start + max_chunk_size
        
        # Adjust end to avoid cutting in the middle of a word/sentence
        if end < len(text):
            # Try to find a good breaking point
            for break_char in ['\n\n', '\n', '. ', '? ', '! ', ', ', ' ']:
                last_break = text.rfind(break_char, start, end)
                if last_break > start:
                    end = last_break + len(break_char)
                    break
        else:
            end = len(text)
            
        # Extract chunk
        chunks.append(text[start:end])
        
        # Update start position for next chunk
        start = end - overlap
        
    return chunks

def normalize_whitespace(text: str) -> str:
    """
    Normalize whitespace in text.
    
    Args:
        text: Text to normalize
        
    Returns:
        Normalized text
    """
    if not text:
        return text
        
    # Replace multiple whitespace with a single space
    normalized = re.sub(r'\s+', ' ', text)
    
    # Trim leading/trailing whitespace
    normalized = normalized.strip()
    
    return normalized

def clean_text(text: str, preserve_newlines: bool = False) -> str:
    """
    Clean text by removing unwanted characters and normalizing whitespace.
    
    Args:
        text: Text to clean
        preserve_newlines: Whether to preserve newline characters
        
    Returns:
        Cleaned text
    """
    if not text:
        return text
        
    # Remove control characters except newlines if requested
    if preserve_newlines:
        cleaned = re.sub(r'[\x00-\x09\x0b\x0c\x0e-\x1f\x7f]', '', text)
    else:
        cleaned = re.sub(r'[\x00-\x1f\x7f]', '', text)
        
    # Normalize whitespace
    if preserve_newlines:
        # Normalize spaces while preserving newlines
        lines = cleaned.split('\n')
        lines = [normalize_whitespace(line) for line in lines]
        cleaned = '\n'.join(lines)
    else:
        cleaned = normalize_whitespace(cleaned)
        
    return cleaned

def extract_json_from_text(text: str) -> Optional[Dict[str, Any]]:
    """
    Extract JSON from a text string.
    
    Args:
        text: Text to extract JSON from
        
    Returns:
        Extracted JSON as a dictionary, or None if no valid JSON found
    """
    if not text:
        return None
        
    # Try to find JSON in code blocks
    json_block_pattern = r'```(?:json)?\s*([\s\S]*?)\s*```'
    json_block_matches = re.findall(json_block_pattern, text)
    
    for match in json_block_matches:
        try:
            return json.loads(match)
        except:
            pass
            
    # Try to find JSON objects in the text
    json_pattern = r'({[\s\S]*?})'
    json_matches = re.findall(json_pattern, text)
    
    for match in json_matches:
        try:
            return json.loads(match)
        except:
            pass
            
    # Try to extract the entire text as JSON
    try:
        return json.loads(text)
    except:
        pass
        
    return None

def parse_structured_response(text: str, default_fields: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Parse a structured response from LLM output.
    
    Args:
        text: Text to parse
        default_fields: Default field values
        
    Returns:
        Parsed structured response as a dictionary
    """
    if default_fields is None:
        default_fields = {}
        
    result = default_fields.copy()
    
    # Try to parse as JSON first
    json_data = extract_json_from_text(text)
    if json_data:
        result.update(json_data)
        return result
        
    # Fall back to regex-based field extraction
    field_pattern = r'(?:^|\n)([A-Z][A-Za-z0-9_\s]*?):\s*(.*?)(?=\n[A-Z][A-Za-z0-9_\s]*?:|$)'
    matches = re.findall(field_pattern, text, re.DOTALL)
    
    for field, value in matches:
        field_key = field.strip().lower().replace(' ', '_')
        result[field_key] = value.strip()
        
    return result

def parse_boolean_from_text(text: str, default: bool = False) -> bool:
    """
    Parse a boolean value from text.
    
    Args:
        text: Text to parse
        default: Default value if parsing fails
        
    Returns:
        Parsed boolean value
    """
    if not text:
        return default
        
    text = text.strip().lower()
    
    # Check for true-like values
    if text in ['true', 'yes', 'y', '1', 'ok', 'sure', 'definitely', 'absolutely', 'correct']:
        return True
        
    # Check for false-like values
    if text in ['false', 'no', 'n', '0', 'nope', 'never', 'incorrect']:
        return False
        
    # Default
    return default

def estimate_token_count(text: str, tokens_per_char: float = 0.25) -> int:
    """
    Estimate the number of tokens in a text.
    
    Args:
        text: Text to estimate token count for
        tokens_per_char: Estimated number of tokens per character
        
    Returns:
        Estimated token count
    """
    if not text:
        return 0
        
    # A simple estimation based on character count
    return int(len(text) * tokens_per_char)

def normalize_path(path: str) -> str:
    """
    Normalize a file path.
    
    Args:
        path: File path to normalize
        
    Returns:
        Normalized path
    """
    if not path:
        return path
        
    # Expand user directory (e.g., ~/)
    expanded_path = os.path.expanduser(path)
    
    # Normalize path separators and resolve relative paths
    normalized_path = os.path.normpath(expanded_path)
    
    return normalized_path

def is_valid_file_extension(filename: str, allowed_extensions: List[str]) -> bool:
    """
    Check if a file has a valid extension.
    
    Args:
        filename: Filename to check
        allowed_extensions: List of allowed extensions (e.g., ['.py', '.js'])
        
    Returns:
        True if the file has a valid extension, False otherwise
    """
    if not filename or not allowed_extensions:
        return False
        
    _, ext = os.path.splitext(filename.lower())
    
    return ext in allowed_extensions

def list_files_in_directory(directory: str, 
                           allowed_extensions: List[str] = None,
                           excluded_dirs: List[str] = None) -> List[str]:
    """
    List files in a directory.
    
    Args:
        directory: Directory to list files from
        allowed_extensions: List of allowed extensions (e.g., ['.py', '.js'])
        excluded_dirs: List of directory names to exclude
        
    Returns:
        List of file paths
    """
    if not directory or not os.path.isdir(directory):
        return []
        
    if excluded_dirs is None:
        excluded_dirs = ['.git', 'node_modules', '__pycache__', 'venv', '.env']
        
    result = []
    
    for root, dirs, files in os.walk(directory):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in excluded_dirs]
        
        for file in files:
            if allowed_extensions is None or is_valid_file_extension(file, allowed_extensions):
                result.append(os.path.join(root, file))
                
    return result

def get_file_content(file_path: str, max_size_mb: float = 10) -> Optional[str]:
    """
    Get the content of a file.
    
    Args:
        file_path: Path to the file
        max_size_mb: Maximum file size in MB
        
    Returns:
        File content as a string, or None if file cannot be read
    """
    if not file_path or not os.path.isfile(file_path):
        return None
        
    # Check file size
    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    if file_size_mb > max_size_mb:
        logger.warning(f"File {file_path} is too large ({file_size_mb:.2f} MB > {max_size_mb} MB)")
        return None
        
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except Exception as e:
        logger.error(f"Error reading file {file_path}: {str(e)}")
        return None

def merge_dictionaries(dict1: Dict[str, Any], dict2: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively merge two dictionaries.
    
    Args:
        dict1: First dictionary
        dict2: Second dictionary
        
    Returns:
        Merged dictionary
    """
    if not dict1:
        return dict2.copy() if dict2 else {}
        
    if not dict2:
        return dict1.copy()
        
    result = dict1.copy()
    
    for key, value in dict2.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            # Recursively merge nested dictionaries
            result[key] = merge_dictionaries(result[key], value)
        else:
            # Override or add value
            result[key] = value
            
    return result

def flatten_list(nested_list: List) -> List:
    """
    Flatten a nested list.
    
    Args:
        nested_list: Nested list to flatten
        
    Returns:
        Flattened list
    """
    if not nested_list:
        return []
        
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
        items: List of items
        
    Returns:
        Deduplicated list
    """
    if not items:
        return []
        
    seen = set()
    result = []
    
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
            
    return result

def validate_severity_level(level: str, allowed_levels: List[str] = None) -> Optional[str]:
    """
    Validate a severity level against allowed levels.
    
    Args:
        level: Severity level to validate
        allowed_levels: List of allowed severity levels
        
    Returns:
        Validated severity level, or None if invalid
    """
    if not level:
        return None
        
    if allowed_levels is None:
        allowed_levels = ['critical', 'high', 'medium', 'low', 'informational']
        
    level = level.lower().strip()
    
    # Check exact matches
    if level in allowed_levels:
        return level
        
    # Check aliases
    aliases = {
        'severe': 'critical',
        'important': 'high',
        'moderate': 'medium',
        'minor': 'low',
        'info': 'informational',
        'note': 'informational'
    }
    
    if level in aliases and aliases[level] in allowed_levels:
        return aliases[level]
        
    return None

def is_valid_url(url: str) -> bool:
    """
    Check if a URL is valid.
    
    Args:
        url: URL to check
        
    Returns:
        True if the URL is valid, False otherwise
    """
    if not url:
        return False
        
    # Basic URL pattern
    url_pattern = r'^(https?|ftp)://[^\s/$.?#].[^\s]*$'
    
    return bool(re.match(url_pattern, url)) 