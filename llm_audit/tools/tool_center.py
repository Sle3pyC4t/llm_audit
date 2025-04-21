"""
Tool Center for LLM Audit

Provides tools for:
- Knowledge base connection
- Report generation
- System tool calls
- Internet access
"""

import os
import logging
import subprocess
from typing import Dict, List, Optional, Any

import requests
from langchain.tools import Tool
from langchain_core.tools import BaseTool

from ..config import Config

logger = logging.getLogger(__name__)


class ToolCenter:
    """Provides a central repository of tools available to agents"""
    
    def __init__(self, config: Config):
        self.config = config
        self.tools: Dict[str, BaseTool] = {}
        self._initialize_tools()
        
    def _initialize_tools(self):
        """Initialize all available tools"""
        # File system tools
        self.tools["read_file"] = Tool(
            name="read_file",
            func=self.read_file,
            description="Read the contents of a file from the codebase being audited"
        )
        
        self.tools["list_directory"] = Tool(
            name="list_directory",
            func=self.list_directory,
            description="List the contents of a directory in the codebase being audited"
        )
        
        # Knowledge base tools
        self.tools["search_knowledge_base"] = Tool(
            name="search_knowledge_base",
            func=self.search_knowledge_base,
            description="Search the knowledge base for information about security vulnerabilities"
        )
        
        # Report tools
        self.tools["add_to_report"] = Tool(
            name="add_to_report",
            func=self.add_to_report,
            description="Add information to the audit report"
        )
        
        # System tools
        self.tools["run_command"] = Tool(
            name="run_command",
            func=self.run_command,
            description="Run a shell command and return the output"
        )
        
        # Internet tools
        self.tools["web_search"] = Tool(
            name="web_search",
            func=self.web_search,
            description="Search the web for information"
        )
        
    def get_tools(self, tool_names: Optional[List[str]] = None) -> List[BaseTool]:
        """Get a list of tools by name
        
        Args:
            tool_names: Optional list of tool names to retrieve. If None, all tools are returned.
            
        Returns:
            List of tools
        """
        if tool_names is None:
            return list(self.tools.values())
        
        return [self.tools[name] for name in tool_names if name in self.tools]
    
    # File system tools
    def read_file(self, file_path: str) -> str:
        """Read the contents of a file
        
        Args:
            file_path: Path to the file, relative to the codebase root
            
        Returns:
            Contents of the file
        """
        full_path = os.path.join(self.config.codebase_path, file_path)
        
        try:
            with open(full_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            logger.error(f"Error reading file {full_path}: {str(e)}")
            return f"Error reading file: {str(e)}"
    
    def list_directory(self, dir_path: str) -> List[str]:
        """List the contents of a directory
        
        Args:
            dir_path: Path to the directory, relative to the codebase root
            
        Returns:
            List of files and directories
        """
        full_path = os.path.join(self.config.codebase_path, dir_path)
        
        try:
            return os.listdir(full_path)
        except Exception as e:
            logger.error(f"Error listing directory {full_path}: {str(e)}")
            return [f"Error listing directory: {str(e)}"]
    
    # Knowledge base tools
    def search_knowledge_base(self, query: str) -> str:
        """Search the knowledge base for information
        
        Args:
            query: Search query
            
        Returns:
            Search results
        """
        try:
            logger.info(f"Searching knowledge base for: {query}")
            
            # Determine which subdirectory to search based on query
            kb_dir = self.config.knowledge_base_path
            
            # Default to solidity directory for smart contract audits
            if "solidity" in query.lower():
                kb_dir = os.path.join(kb_dir, "solidity")
            
            # Check if knowledge base directory exists
            if not os.path.exists(kb_dir):
                logger.warning(f"Knowledge base directory not found: {kb_dir}")
                return f"Knowledge base directory not found: {kb_dir}"
            
            # Get list of all markdown files in the directory
            md_files = []
            for root, _, files in os.walk(kb_dir):
                for file in files:
                    if file.endswith('.md'):
                        md_files.append(os.path.join(root, file))
            
            if not md_files:
                logger.warning(f"No knowledge base files found in: {kb_dir}")
                return f"No knowledge base files found in: {kb_dir}"
            
            # Simple keyword-based search for now
            # Split query into keywords
            keywords = [k.lower() for k in query.split() if len(k) > 3]
            
            # Search each file for keywords
            results = []
            for md_file in md_files:
                try:
                    with open(md_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                        
                    file_relevance = 0
                    for keyword in keywords:
                        if keyword in content.lower():
                            file_relevance += content.lower().count(keyword)
                    
                    if file_relevance > 0:
                        # Extract file name for the result
                        file_name = os.path.basename(md_file)
                        # Add to results with relevance score
                        results.append((file_name, file_relevance, content))
                except Exception as e:
                    logger.error(f"Error reading knowledge base file {md_file}: {str(e)}")
            
            # Sort results by relevance score (descending)
            results.sort(key=lambda x: x[1], reverse=True)
            
            if not results:
                logger.warning(f"No relevant knowledge base entries found for query: {query}")
                return f"No relevant knowledge base entries found for query: {query}"
            
            # Format and return results (limit to top 3 for clarity)
            formatted_results = []
            for file_name, score, content in results[:3]:
                formatted_results.append(f"## Knowledge Base: {file_name} (Relevance: {score})\n\n{content}\n\n")
            
            return "\n".join(formatted_results)
        except Exception as e:
            logger.error(f"Error searching knowledge base: {str(e)}")
            return f"Error searching knowledge base: {str(e)}"
    
    # Report tools
    def add_to_report(self, section: str, content: str) -> str:
        """Add information to the audit report
        
        Args:
            section: Report section to add to
            content: Content to add
            
        Returns:
            Confirmation message
        """
        # In a real implementation, this would update a report object
        # For now, we'll just log it
        logger.info(f"Adding to report section '{section}': {content[:100]}...")
        return f"Added content to report section: {section}"
    
    # System tools
    def run_command(self, command: str) -> str:
        """Run a shell command and return the output
        
        Args:
            command: Command to run
            
        Returns:
            Command output
        """
        try:
            # Set cwd to the codebase path to run commands relative to it
            result = subprocess.run(
                command,
                shell=True,
                cwd=self.config.codebase_path,
                capture_output=True,
                text=True,
                timeout=30  # Timeout after 30 seconds
            )
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return "Command timed out after 30 seconds"
        except Exception as e:
            logger.error(f"Error running command {command}: {str(e)}")
            return f"Error running command: {str(e)}"
    
    # Internet tools
    def web_search(self, query: str) -> str:
        """Search the web for information
        
        Args:
            query: Search query
            
        Returns:
            Search results
        """
        # In a real implementation, this would use a proper search API
        # For now, we'll just return a placeholder
        return f"Web search results for query: {query}" 