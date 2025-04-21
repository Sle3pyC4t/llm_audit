"""
LLM Utilities

This module provides helper functions for interacting with language models.
It handles common operations like prompt creation, message formatting, and response processing.
"""

import logging
import re
import json
from typing import List, Dict, Any, Union, Optional, Tuple

logger = logging.getLogger(__name__)

# Message formatting utilities

def format_system_prompt(base_prompt: str, additional_context: str = None) -> str:
    """
    Format a system prompt by adding additional context if provided.
    
    Args:
        base_prompt: Base system prompt
        additional_context: Additional context to add
        
    Returns:
        Formatted system prompt
    """
    if not additional_context:
        return base_prompt
        
    return f"{base_prompt}\n\nAdditional Context:\n{additional_context}"

def format_user_message(content: str, include_formatting: bool = True) -> str:
    """
    Format a user message.
    
    Args:
        content: Message content
        include_formatting: Whether to include markdown formatting
        
    Returns:
        Formatted user message
    """
    if not include_formatting:
        return content
        
    # Add markdown formatting for better readability
    return content

def format_code_block(code: str, language: str = "") -> str:
    """
    Format code as a markdown code block.
    
    Args:
        code: Code to format
        language: Programming language for syntax highlighting
        
    Returns:
        Formatted code block
    """
    return f"```{language}\n{code}\n```"

def format_structured_output_prompt(fields: List[str], 
                                   format_description: str = None) -> str:
    """
    Create a prompt that instructs the LLM to return a structured output.
    
    Args:
        fields: List of fields to include in the structured output
        format_description: Description of the output format
        
    Returns:
        Structured output prompt
    """
    if format_description is None:
        format_description = "Please provide your response in the following structured format"
    
    fields_str = "\n".join([f"- {field}" for field in fields])
    
    return f"""
{format_description}:

{fields_str}

You can provide your response in JSON format or as a structured text with the field names as headers.
"""

# Response parsing utilities

def extract_code_blocks(text: str, language: str = None) -> List[str]:
    """
    Extract code blocks from a text.
    
    Args:
        text: Text to extract code blocks from
        language: Optional language specifier to filter by
        
    Returns:
        List of extracted code blocks
    """
    if language:
        pattern = f"```(?:{language})?\n(.*?)```"
    else:
        pattern = "```(?:[a-zA-Z]*)?\n(.*?)```"
        
    matches = re.findall(pattern, text, re.DOTALL)
    return matches

def extract_list_items(text: str) -> List[str]:
    """
    Extract list items from a text.
    
    Args:
        text: Text to extract list items from
        
    Returns:
        List of extracted items
    """
    # Look for markdown list items
    list_pattern = r'(?:^|\n)[ \t]*(?:-|\*|\d+\.)[ \t]+(.*?)(?=(?:\n[ \t]*(?:-|\*|\d+\.))|$)'
    matches = re.findall(list_pattern, text, re.DOTALL)
    
    # Clean up matches
    return [item.strip() for item in matches if item.strip()]

def extract_sections(text: str) -> Dict[str, str]:
    """
    Extract sections from a text based on markdown headers.
    
    Args:
        text: Text to extract sections from
        
    Returns:
        Dictionary of section name to section content
    """
    # Find all headers
    header_pattern = r'(?:^|\n)#{1,6} +(.*?)(?=\n)'
    headers = re.findall(header_pattern, text)
    
    # Split text by headers
    sections = re.split(r'(?:^|\n)#{1,6} +.*?(?=\n)', text)
    
    # First element is everything before the first header
    sections = sections[1:]
    
    # Create dictionary of header to content
    result = {}
    for i, header in enumerate(headers):
        if i < len(sections):
            result[header.strip()] = sections[i].strip()
            
    return result

def extract_structured_data(text: str, 
                          expected_fields: List[str], 
                          default_values: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Extract structured data from a text.
    
    Args:
        text: Text to extract structured data from
        expected_fields: List of expected field names
        default_values: Dictionary of default values for fields
        
    Returns:
        Dictionary of extracted data
    """
    if default_values is None:
        default_values = {}
        
    # Try to parse as JSON first
    try:
        # Find JSON blocks
        json_match = re.search(r'```json\s*([\s\S]*?)\s*```|{[\s\S]*}', text)
        if json_match:
            json_text = json_match.group(1) if json_match.group(1) else json_match.group(0)
            data = json.loads(json_text)
            
            # Ensure all expected fields are present
            result = default_values.copy()
            for field in expected_fields:
                if field in data:
                    result[field] = data[field]
                    
            return result
    except Exception as e:
        logger.debug(f"Failed to parse JSON: {str(e)}")
    
    # Fall back to section-based parsing
    result = default_values.copy()
    sections = extract_sections(text)
    
    for field in expected_fields:
        # Try different variations of the field name
        for field_variant in [field, field.lower(), field.upper(), field.title()]:
            if field_variant in sections:
                result[field] = sections[field_variant]
                break
                
        # If not found in sections, try line-based parsing
        if field not in result:
            pattern = f"(?:^|\n)(?:{field}|{field.lower()}|{field.upper()}|{field.title()})\\s*:?\\s*(.*?)(?=\n|$)"
            match = re.search(pattern, text)
            if match:
                result[field] = match.group(1).strip()
                
    return result

# LLM interaction utilities

def create_chat_completion_messages(system_prompt: str, 
                                  user_messages: List[str], 
                                  assistant_messages: List[str] = None) -> List[Dict[str, str]]:
    """
    Create a list of messages for chat completion.
    
    Args:
        system_prompt: System prompt
        user_messages: List of user messages
        assistant_messages: List of assistant messages
        
    Returns:
        List of messages for chat completion
    """
    if assistant_messages is None:
        assistant_messages = []
        
    # Ensure the lists have the same length
    while len(assistant_messages) < len(user_messages) - 1:
        assistant_messages.append("")
        
    # Create the messages list
    messages = [{"role": "system", "content": system_prompt}]
    
    # Alternate between user and assistant messages
    for i, user_msg in enumerate(user_messages):
        messages.append({"role": "user", "content": user_msg})
        
        # Add assistant message if available
        if i < len(assistant_messages):
            if assistant_messages[i]:  # Only add if not empty
                messages.append({"role": "assistant", "content": assistant_messages[i]})
                
    return messages

def format_few_shot_examples(examples: List[Dict[str, str]], 
                           input_key: str = "input", 
                           output_key: str = "output") -> str:
    """
    Format few-shot examples for inclusion in a prompt.
    
    Args:
        examples: List of examples, each with input and output keys
        input_key: Key for input in the examples
        output_key: Key for output in the examples
        
    Returns:
        Formatted few-shot examples
    """
    formatted = []
    
    for i, example in enumerate(examples):
        formatted.append(f"Example {i+1}:")
        formatted.append(f"Input: {example[input_key]}")
        formatted.append(f"Output: {example[output_key]}")
        formatted.append("")  # Add empty line between examples
        
    return "\n".join(formatted)

def create_extraction_prompt(text: str, 
                           extraction_instruction: str, 
                           output_format: str = None) -> str:
    """
    Create a prompt for extracting information from text.
    
    Args:
        text: Text to extract information from
        extraction_instruction: Instruction for the extraction
        output_format: Description of the expected output format
        
    Returns:
        Extraction prompt
    """
    prompt = f"""
{extraction_instruction}

Text to analyze:
{text}
"""
    
    if output_format:
        prompt += f"\n\nProvide your output in the following format:\n{output_format}"
        
    return prompt

def create_analysis_prompt(code: str, 
                         analysis_instruction: str, 
                         additional_context: str = None,
                         output_format: str = None) -> str:
    """
    Create a prompt for analyzing code.
    
    Args:
        code: Code to analyze
        analysis_instruction: Instruction for the analysis
        additional_context: Additional context for the analysis
        output_format: Description of the expected output format
        
    Returns:
        Analysis prompt
    """
    prompt = f"""
{analysis_instruction}

Code to analyze:
```
{code}
```
"""
    
    if additional_context:
        prompt += f"\n\nAdditional context:\n{additional_context}"
        
    if output_format:
        prompt += f"\n\nProvide your analysis in the following format:\n{output_format}"
        
    return prompt

def chunk_prompt(prompt: str, 
                max_chunk_size: int, 
                overlap: int = 100,
                include_instruction_in_each_chunk: bool = True,
                instruction: str = None) -> List[str]:
    """
    Split a prompt into chunks for processing long texts.
    
    Args:
        prompt: Prompt to chunk
        max_chunk_size: Maximum chunk size in characters
        overlap: Number of characters to overlap between chunks
        include_instruction_in_each_chunk: Whether to include instruction in each chunk
        instruction: Instruction to include in each chunk
        
    Returns:
        List of prompt chunks
    """
    if len(prompt) <= max_chunk_size:
        return [prompt]
        
    # Extract instruction if not provided explicitly
    if include_instruction_in_each_chunk and not instruction:
        # Try to identify the instruction part (usually at the beginning)
        instruction_end = prompt.find("\n\n")
        if instruction_end > 0:
            instruction = prompt[:instruction_end]
        else:
            # If no clear separation, use the first 100 characters
            instruction = prompt[:min(100, len(prompt))]
            
    # Determine content to chunk
    content = prompt
    if include_instruction_in_each_chunk and instruction:
        # Remove instruction from content to avoid duplication
        if content.startswith(instruction):
            content = content[len(instruction):].lstrip()
            
    # Split content into chunks
    chunks = []
    start = 0
    while start < len(content):
        # Calculate end position
        end = start + max_chunk_size
        if include_instruction_in_each_chunk and instruction:
            end = start + max_chunk_size - len(instruction) - 10  # Reserve space for instruction and some padding
            
        # Adjust end to avoid cutting in the middle of a word/sentence
        if end < len(content):
            # Look for a good breaking point (newline, period, space)
            for break_char in ['\n\n', '\n', '.', ' ']:
                last_break = content.rfind(break_char, start, end)
                if last_break > start:
                    end = last_break + len(break_char)
                    break
        else:
            end = len(content)
            
        # Extract chunk
        chunk = content[start:end]
        
        # Add instruction if needed
        if include_instruction_in_each_chunk and instruction:
            chunk = f"{instruction}\n\n{chunk}"
            
        chunks.append(chunk)
        
        # Update start position for next chunk
        start = end - overlap
        
    return chunks 