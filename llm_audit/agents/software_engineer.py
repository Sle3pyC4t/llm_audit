"""
Software Engineer Agent

Responsible for understanding the target Solidity smart contract codebase,
answering questions about its structure, and identifying potential paths for vulnerabilities.
"""

import os
import logging
from typing import Any, List, Optional

from langchain_core.language_models import BaseChatModel

from .base_agent import BaseAgent
from ..config import Config
from ..tools.tool_center import ToolCenter
from ..llm_providers import LLMProviderFactory

logger = logging.getLogger(__name__)


class SoftwareEngineerAgent(BaseAgent):
    """Software Engineer agent for understanding the smart contract codebase"""
    
    def __init__(
        self,
        config: Config,
        tool_center: ToolCenter,
        model: Optional[BaseChatModel] = None,
        system_prompt: Optional[str] = None
    ):
        # Initialize the model if not provided
        if model is None:
            model = LLMProviderFactory.create_llm(
                provider_name=config.llm_provider,
                model_name=config.software_engineer_model,
                api_key=config.get_api_key(),
                temperature=0.1
            )
        
        super().__init__(
            name="SoftwareEngineer",
            config=config,
            tool_center=tool_center,
            model=model,
            system_prompt=system_prompt
        )
        
        # Tools specific to this agent
        self.tools = tool_center.get_tools([
            "read_file",
            "list_directory",
            "run_command"
        ])
    
    def _get_default_system_prompt(self) -> str:
        """Get the default system prompt for this agent"""
        return f"""You are a Software Engineer agent in a multi-agent LLM code auditing system specialized in Solidity smart contracts.

Your primary responsibility is to understand the target Solidity codebase as if you were one of its developers.
You should be able to answer questions about the codebase's structure, architecture, and execution flow.

The smart contract codebase you are analyzing is located at: {self.config.codebase_path}

Your tasks include:
1. Analyzing the structure of the Solidity contracts to understand their organization
2. Identifying key components, interfaces, libraries, and their relationships
3. Mapping potential execution paths, especially those that might lead to security vulnerabilities
4. Answering questions from other agents about how the smart contracts work

When analyzing Solidity code, pay special attention to:
- Contract inheritance hierarchies
- State variables and their visibility
- Function modifiers and access controls
- External calls to other contracts
- Ether handling logic
- Gas optimization patterns

When asked questions, be thorough and precise in your responses. Provide code snippets and file paths
when relevant. If you're unsure about something, acknowledge the uncertainty rather than making assumptions.

You have access to the following tools:
- read_file: Read the contents of a file in the codebase
- list_directory: List the contents of a directory in the codebase
- run_command: Run a shell command and return its output

Respond in a clear, professional manner, focusing on providing accurate technical information about Solidity smart contracts.
"""
    
    async def analyze_codebase(self) -> str:
        """Perform an initial analysis of the codebase structure"""
        try:
            # List the root directory to start understanding the structure
            root_files = self.tool_center.list_directory(".")
            
            # Check for common project files to understand the type of project
            analysis = "Initial Solidity codebase analysis:\n\n"
            
            # Look for package management and config files
            package_files = [f for f in root_files if f in [
                "package.json", "hardhat.config.js", "truffle-config.js", "foundry.toml",
                "remappings.txt", "brownie-config.yaml"
            ]]
            
            if package_files:
                analysis += f"Found blockchain development files: {', '.join(package_files)}\n"
                
                # For each package file, read its contents to understand the project setup
                for pkg_file in package_files:
                    pkg_content = self.tool_center.read_file(pkg_file)
                    analysis += f"\n{pkg_file} content:\n{pkg_content}\n"
            
            # Look for README or documentation
            readme_files = [f for f in root_files if f.lower().startswith("readme")]
            if readme_files:
                readme_content = self.tool_center.read_file(readme_files[0])
                analysis += f"\nREADME content:\n{readme_content}\n"
            
            # Find source code directories
            src_dirs = [d for d in root_files if d in [
                "src", "contracts", "sources", "solidity"
            ] and os.path.isdir(os.path.join(self.config.codebase_path, d))]
            
            # If no typical Solidity directories found, look for .sol files in the root
            if not src_dirs:
                sol_files = [f for f in root_files if f.endswith(".sol")]
                if sol_files:
                    analysis += "\nFound Solidity files in root directory:\n"
                    for sol_file in sol_files:
                        sol_content = self.tool_center.read_file(sol_file)
                        analysis += f"\n{sol_file}:\n```solidity\n{sol_content}\n```\n"
            else:
                # Analyze each source directory
                for src_dir in src_dirs:
                    src_files = self.tool_center.list_directory(src_dir)
                    sol_files = [f for f in src_files if f.endswith(".sol")]
                    analysis += f"\nSource directory '{src_dir}' contains {len(sol_files)} Solidity files: {', '.join(sol_files[:10])}"
                    if len(sol_files) > 10:
                        analysis += f" and {len(sol_files) - 10} more files"
                    
                    # Analyze a few key Solidity files
                    for sol_file in sol_files[:3]:  # Limit to first 3 files to avoid overwhelming
                        file_path = os.path.join(src_dir, sol_file)
                        sol_content = self.tool_center.read_file(file_path)
                        analysis += f"\n\nAnalyzing {file_path}:\n```solidity\n{sol_content}\n```\n"
            
            # Look for test files to understand test coverage
            test_dirs = [d for d in root_files if d in ["test", "tests"] and os.path.isdir(os.path.join(self.config.codebase_path, d))]
            if test_dirs:
                for test_dir in test_dirs:
                    test_files = self.tool_center.list_directory(test_dir)
                    analysis += f"\nTest directory '{test_dir}' contains: {', '.join(test_files[:10])}"
                    if len(test_files) > 10:
                        analysis += f" and {len(test_files) - 10} more files"
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing codebase: {str(e)}")
            return f"Failed to analyze codebase: {str(e)}"
    
    async def find_execution_paths(self, source: str, target: str) -> List[str]:
        """Find potential execution paths from source to target
        
        Args:
            source: Starting point (e.g., "public function")
            target: End point (e.g., "ether transfer")
            
        Returns:
            List of potential execution paths
        """
        message = f"""I need to find all possible execution paths from {source} to {target} in the Solidity codebase.
        
Please analyze how control flow could pass from {source} to {target}, considering:
1. Direct function calls
2. Inheritance relationships
3. Library usage
4. Event emissions
5. Modifier effects
6. External contract interactions

For each potential path, provide:
- The contract and function names involved
- Any conditions that must be satisfied
- Potential security implications
"""
        response = await self.process_message(message)
        return [response.content]
    
    async def answer_question(self, question: str) -> str:
        """Answer a question about the codebase
        
        Args:
            question: Question about the codebase
            
        Returns:
            Answer to the question
        """
        response = await self.process_message(question)
        return response.content
    
    async def run(self) -> Any:
        """Run the Software Engineer agent's main functionality"""
        try:
            # Perform initial analysis
            analysis = await self.analyze_codebase()
            
            # Add the analysis to the report
            self.tool_center.add_to_report(
                "Smart Contract Analysis",
                f"# Smart Contract Analysis\n\n{analysis}"
            )
            
            return analysis
        except Exception as e:
            logger.error(f"Error running Software Engineer agent: {str(e)}")
            return f"Failed to run Software Engineer agent: {str(e)}" 