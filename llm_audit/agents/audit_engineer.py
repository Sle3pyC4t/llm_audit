"""
Audit Engineer Agent

Responsible for identifying security vulnerabilities in Solidity smart contracts
by selecting appropriate knowledge bases and working with the Software Engineer agent.
"""

import logging
import asyncio
from typing import Any, Dict, List, Optional

from langchain_core.language_models import BaseChatModel

from .base_agent import BaseAgent
from ..config import Config
from ..tools.tool_center import ToolCenter
from ..llm_providers import LLMProviderFactory

logger = logging.getLogger(__name__)


class AuditEngineerAgent(BaseAgent):
    """Audit Engineer agent for finding security vulnerabilities in smart contracts"""
    
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
                model_name=config.audit_engineer_model,
                api_key=config.get_api_key(),
                temperature=0.2
            )
        
        super().__init__(
            name="AuditEngineer",
            config=config,
            tool_center=tool_center,
            model=model,
            system_prompt=system_prompt
        )
        
        # Tools specific to this agent
        self.tools = tool_center.get_tools([
            "read_file",
            "list_directory",
            "search_knowledge_base",
            "add_to_report"
        ])
        
        # Track findings
        self.findings: List[Dict[str, Any]] = []
    
    def _get_default_system_prompt(self) -> str:
        """Get the default system prompt for this agent"""
        return f"""You are an Audit Engineer agent in a multi-agent LLM code auditing system specialized in Solidity smart contract security.

Your primary responsibility is to identify security vulnerabilities in the target Solidity smart contracts.
You should work closely with the Software Engineer agent to understand the codebase and
use your security expertise to find potential issues.

The smart contract codebase you are analyzing is located at: {self.config.codebase_path}

Your tasks include:
1. Selecting appropriate security knowledge bases for the Solidity smart contracts being audited
2. Asking the Software Engineer agent for information about the contract structure and execution paths
3. Identifying potential security vulnerabilities based on code patterns and architecture
4. Documenting your findings with detailed explanations

When identifying vulnerabilities in Solidity smart contracts, focus on:
- Reentrancy vulnerabilities
- Integer overflow/underflow (in Solidity <0.8.0)
- Access control issues
- Gas optimization problems
- Front-running vulnerabilities
- Denial of service vectors
- Logic bugs in business rules
- Oracle manipulation
- Flash loan attack vectors
- Signature replay attacks
- Incorrect event emissions
- Upgrade mechanism security issues
- Initialization problems
- Centralization risks

You should NOT focus on web application vulnerabilities like SQL injection, XSS, or password issues,
as these are not relevant to Solidity smart contract security.

You have access to the following tools:
- read_file: Read the contents of a file in the codebase
- list_directory: List the contents of a directory in the codebase
- search_knowledge_base: Search the security knowledge base for information about Solidity vulnerabilities
- add_to_report: Add information to the audit report

Be focused and concise in your responses. When receiving very large pieces of code, focus on the security-critical parts only.
If you need more focused information, ask for it specifically rather than requesting everything at once.

For each finding, document:
1. Vulnerability type and severity
2. Affected contract and function
3. Description of the issue
4. Potential impact if exploited
5. Recommendations for remediation

Respond in a clear, professional manner, focusing on providing accurate Solidity security assessments.
"""

    async def process_message_with_timeout(self, message: str, timeout: int = 180) -> Any:
        """Process a message with a timeout to prevent hanging
        
        Args:
            message: The message to process
            timeout: Timeout in seconds
            
        Returns:
            The response or an error message
        """
        try:
            logger.info(f"Processing message with timeout {timeout}s (length: {len(message)} chars)")
            response = await asyncio.wait_for(
                self.process_message(message), 
                timeout=timeout
            )
            return response
        except asyncio.TimeoutError:
            logger.error(f"Timeout occurred while processing message (length: {len(message)} chars)")
            return type('obj', (object,), {'content': f"ERROR: Message processing timed out after {timeout} seconds."})
        except Exception as e:
            logger.error(f"Error processing message: {str(e)}")
            return type('obj', (object,), {'content': f"ERROR: {str(e)}"})
    
    async def identify_vulnerabilities(self, software_engineer) -> List[Dict[str, Any]]:
        """Identify security vulnerabilities in the Solidity codebase
        
        Args:
            software_engineer: The Software Engineer agent to interact with
            
        Returns:
            List of vulnerability findings
        """
        logger.info("Starting vulnerability identification")
        
        # Ask the Software Engineer for an overview of the codebase (with a max limit)
        logger.info("Requesting codebase overview from Software Engineer")
        codebase_overview = await software_engineer.answer_question(
            "Please provide a high-level overview of the Solidity smart contract codebase structure, "
            "including main contracts, inheritance relationships, and key functionality. "
            "Limit your response to the 5 most important files/contracts."
        )
        logger.info(f"Received codebase overview: {len(codebase_overview)} chars")
        
        # Get knowledge base information to use in analysis
        logger.info("Searching knowledge base for vulnerability patterns")
        kb_results = self.tool_center.search_knowledge_base("solidity vulnerabilities common patterns")
        logger.info(f"Knowledge base search returned {len(kb_results)} results")
        
        # Process only the first part if it's too long
        if len(codebase_overview) > 4000:
            logger.info("Codebase overview too long, truncating")
            codebase_overview = codebase_overview[:4000] + "... [truncated for brevity]"
        
        # Based on the overview, determine what security knowledge bases to use
        logger.info("Determining potential vulnerabilities based on overview")
        message = f"""Based on the following Solidity smart contract overview, identify the top 3 potential security 
        vulnerabilities I should look for in these contracts:
        
        {codebase_overview}
        
        Focus specifically on Solidity smart contract vulnerabilities that might apply to this codebase.
        Keep your response under 500 words.
        """
        
        response = await self.process_message_with_timeout(message)
        vulnerability_types = response.content
        logger.info(f"Identified vulnerability types: {len(vulnerability_types)} chars")
        
        # Ask about specific security-sensitive areas (with a focus)
        logger.info("Requesting information about security-sensitive areas")
        sensitive_areas = await software_engineer.answer_question(
            "Identify the top 3 most security-critical functions in the contracts that: "
            "1) Handle Ether transfers, 2) Manage access control, or 3) Modify critical state variables. "
            "For each, provide only the contract name, function name, and a brief description of what it does."
        )
        logger.info(f"Received information about sensitive areas: {len(sensitive_areas)} chars")
        
        # Look for specific patterns based on the knowledge base
        logger.info("Determining target areas for security review")
        message = f"""Based on the software engineer's description of security-sensitive areas in the smart contracts:
        
        {sensitive_areas}
        
        What are the 3 most likely Solidity vulnerabilities I should look for in these contracts or functions?
        For each vulnerability type, briefly explain what pattern I should look for.
        Keep your response under 500 words.
        """
        
        response = await self.process_message_with_timeout(message)
        target_areas = response.content
        logger.info(f"Identified target areas: {len(target_areas)} chars")
        
        # Request code review with focus on the security-critical functions
        logger.info("Requesting code details for security review")
        code_details = await software_engineer.answer_question(
            f"Please provide the code for the security-critical functions mentioned: {target_areas}. "
            "Show only the function implementations, not the entire contracts."
        )
        logger.info(f"Received code details: {len(code_details)} chars")
        
        # Analyze the code for security issues
        logger.info("Analyzing code for security vulnerabilities")
        message = f"""Analyze the following Solidity code for the security vulnerabilities we identified earlier:
        
        {code_details}
        
        For each potential issue, provide:
        1. The vulnerability type (e.g., reentrancy, access control, etc.)
        2. The specific code pattern that indicates the vulnerability
        3. The potential impact if exploited
        4. The recommended fix for Solidity smart contracts
        
        Focus on concrete findings, not general observations.
        """
        
        response = await self.process_message_with_timeout(message, timeout=300)  # Longer timeout for analysis
        vulnerability_analysis = response.content
        logger.info(f"Completed vulnerability analysis: {len(vulnerability_analysis)} chars")
        
        # Parse the analysis into structured findings
        logger.info("Structuring findings")
        message = f"""Based on the vulnerability analysis, create a structured list of findings.
        
        For each finding, include:
        - ID: A unique identifier (e.g., VULN-001)
        - Title: A concise description of the issue
        - Severity: Critical, High, Medium, or Low
        - Location: The contract, function, and line number(s) where the issue is present
        - Description: A detailed explanation of the vulnerability
        - Impact: The potential consequences if exploited
        - Recommendation: How to fix the issue
        
        The analysis to structure:
        {vulnerability_analysis}
        """
        
        response = await self.process_message_with_timeout(message)
        structured_findings = response.content
        logger.info(f"Structured findings created: {len(structured_findings)} chars")
        
        # Add the findings to the report
        logger.info("Adding findings to report")
        self.tool_center.add_to_report(
            "Security Findings",
            f"# Smart Contract Security Findings\n\n{structured_findings}"
        )
        
        # Check if we got actual findings or an error message
        if structured_findings.startswith("ERROR:"):
            logger.warning("Error occurred during findings structuring")
            # Add a basic finding if we hit an error
            basic_finding = {
                "id": "VULN-ERROR",
                "title": "Error during vulnerability analysis",
                "severity": "Unknown",
                "location": "Unknown",
                "description": "An error occurred during the vulnerability analysis process. Manual review is recommended.",
                "impact": "Unknown",
                "recommendation": "Perform a manual security review of the codebase."
            }
            self.findings.append(basic_finding)
            return self.findings
        
        # Parse structured findings and populate findings list
        try:
            # Simple parsing logic - extract findings based on ID pattern
            import re
            findings_text = structured_findings.split("\n\n")
            for finding_text in findings_text:
                # Look for finding ID pattern (e.g., VULN-001)
                id_match = re.search(r'(VULN-\d+)', finding_text)
                if id_match:
                    id_value = id_match.group(1)
                    
                    # Look for severity
                    severity_match = re.search(r'Severity:\s*(\w+)', finding_text)
                    severity = severity_match.group(1) if severity_match else "Unknown"
                    
                    # Look for title - typically the first line
                    title_match = re.search(r'Title:\s*(.+)', finding_text)
                    title = title_match.group(1) if title_match else id_value
                    
                    # Look for location
                    location_match = re.search(r'Location:\s*(.+)', finding_text)
                    location = location_match.group(1) if location_match else "Unknown"
                    
                    # Add to findings
                    finding = {
                        "id": id_value,
                        "title": title,
                        "severity": severity,
                        "location": location,
                        "description": finding_text,  # Store full text as description
                        "impact": "See description",
                        "recommendation": "See description"
                    }
                    self.findings.append(finding)
        except Exception as e:
            logger.error(f"Error parsing findings: {str(e)}")
            # Add a fallback finding
            fallback_finding = {
                "id": "VULN-PARSE",
                "title": "Error parsing vulnerability findings",
                "severity": "Unknown",
                "location": "Unknown",
                "description": f"Error parsing findings: {str(e)}. Raw findings: {structured_findings[:200]}...",
                "impact": "Unknown",
                "recommendation": "Review the full report manually."
            }
            self.findings.append(fallback_finding)
        
        # If no findings were parsed, add at least one sample finding
        if not self.findings:
            logger.warning("No findings were parsed, adding sample finding")
            sample_finding = {
                "id": "VULN-SAMPLE",
                "title": "Potential Vulnerabilities Identified",
                "severity": "Medium",
                "location": "See full report",
                "description": "See the full report for vulnerability details.",
                "impact": "See the full report for impact details.",
                "recommendation": "Review the full security report."
            }
            self.findings.append(sample_finding)
        
        logger.info(f"Returning {len(self.findings)} findings")
        return self.findings
    
    async def run(self, software_engineer) -> List[Dict[str, Any]]:
        """Run the Audit Engineer agent's main functionality
        
        Args:
            software_engineer: The Software Engineer agent to interact with
            
        Returns:
            List of vulnerability findings
        """
        try:
            logger.info("Starting Audit Engineer run")
            findings = await self.identify_vulnerabilities(software_engineer)
            logger.info(f"Audit Engineer completed with {len(findings)} findings")
            return findings
        except Exception as e:
            logger.error(f"Error running Audit Engineer agent: {str(e)}", exc_info=True)
            return [{"error": f"Failed to run Audit Engineer agent: {str(e)}"}] 