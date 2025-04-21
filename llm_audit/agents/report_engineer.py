"""
Report Engineer Agent

Responsible for collecting information from other agents and
generating a comprehensive Solidity smart contract audit report.
"""

import os
import logging
from typing import Any, Dict, List, Optional

from langchain_core.language_models import BaseChatModel

from .base_agent import BaseAgent
from ..config import Config
from ..tools.tool_center import ToolCenter
from ..llm_providers import LLMProviderFactory

logger = logging.getLogger(__name__)


class ReportEngineerAgent(BaseAgent):
    """Report Engineer agent for generating Solidity audit reports"""
    
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
                model_name=config.report_engineer_model,
                api_key=config.get_api_key(),
                temperature=0.1
            )
        
        super().__init__(
            name="ReportEngineer",
            config=config,
            tool_center=tool_center,
            model=model,
            system_prompt=system_prompt
        )
        
        # Tools specific to this agent
        self.tools = tool_center.get_tools([
            "read_file",
            "list_directory"
        ])
        
        # Report sections
        self.report_sections: Dict[str, str] = {
            "Executive Summary": "",
            "Smart Contract Analysis": "",
            "Security Findings": "",
            "Proof of Concept Exploits": "",
            "Unconfirmed Findings": "",
            "Recommendations": "",
            "Conclusion": ""
        }
    
    def _get_default_system_prompt(self) -> str:
        """Get the default system prompt for this agent"""
        return f"""You are a Report Engineer agent in a multi-agent LLM code auditing system specialized in Solidity smart contract security.

Your primary responsibility is to collect information from other agents and
generate a comprehensive, well-structured smart contract audit report.

The smart contract codebase you are analyzing is located at: {self.config.codebase_path}

Your tasks include:
1. Collecting information from other agents (Software Engineer, Audit Engineer, Penetration Engineer)
2. Organizing the information into a coherent, professional report
3. Ensuring all security findings are clearly documented with appropriate severity ratings
4. Providing practical, actionable recommendations for Solidity contract remediation
5. Generating the final report in the requested format

When creating the report:
- Use clear, professional language appropriate for blockchain developers
- Structure the report logically with appropriate sections and subsections
- Include an executive summary for project stakeholders
- Prioritize findings by severity
- Link findings to specific contract files and functions
- Include proof-of-concept examples where available
- Provide specific, actionable remediation steps for Solidity developers

The report should include the following sections:
1. Executive Summary
2. Smart Contract Analysis
3. Security Findings
4. Proof of Concept Exploits
5. Unconfirmed Findings
6. Recommendations
7. Conclusion

You have access to the following tools:
- read_file: Read the contents of a file in the codebase
- list_directory: List the contents of a directory in the codebase

Respond in a clear, professional manner, focusing on producing high-quality documentation for smart contract security audits.
"""
    
    def add_to_section(self, section: str, content: str) -> None:
        """Add content to a report section
        
        Args:
            section: The section name
            content: The content to add
        """
        if section in self.report_sections:
            if self.report_sections[section]:
                self.report_sections[section] += f"\n\n{content}"
            else:
                self.report_sections[section] = content
            logger.debug(f"Added content to report section: {section}")
        else:
            logger.warning(f"Unknown report section: {section}")
    
    async def generate_executive_summary(self, findings: List[Dict[str, Any]]) -> str:
        """Generate an executive summary based on the findings
        
        Args:
            findings: List of validated findings
            
        Returns:
            Executive summary text
        """
        # Count findings by severity
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
        for finding in findings:
            severity = finding.get("severity", "Unknown")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Generate the summary
        message = f"""Please generate an executive summary for a Solidity smart contract security audit report based on the following information:

1. The audit was conducted on the smart contracts at: {self.config.codebase_path}
2. The following vulnerabilities were identified:
   - Critical: {severity_counts.get("Critical", 0)}
   - High: {severity_counts.get("High", 0)}
   - Medium: {severity_counts.get("Medium", 0)}
   - Low: {severity_counts.get("Low", 0)}
   - Unknown severity: {severity_counts.get("Unknown", 0)}

The executive summary should be concise (2-3 paragraphs) and:
1. Briefly describe the purpose and scope of the smart contract audit
2. Summarize the key findings and their potential impact on the blockchain
3. Provide a high-level overview of recommended actions for the smart contract developers

The executive summary is intended for both technical and non-technical blockchain project stakeholders.
Use appropriate terminology for blockchain and Solidity context.
"""
        
        response = await self.process_message(message)
        return response.content
    
    async def generate_recommendations(self, findings: List[Dict[str, Any]]) -> str:
        """Generate recommendations based on the findings
        
        Args:
            findings: List of validated findings
            
        Returns:
            Recommendations text
        """
        # Extract recommendations from findings
        recommendations = []
        for finding in findings:
            if "recommendation" in finding:
                recommendations.append({
                    "id": finding.get("id", "Unknown"),
                    "title": finding.get("title", "Unknown"),
                    "severity": finding.get("severity", "Unknown"),
                    "recommendation": finding.get("recommendation", "")
                })
        
        # Generate comprehensive recommendations
        message = f"""Please generate a comprehensive set of recommendations for Solidity smart contract security based on the following specific recommendations from the audit findings:

{recommendations}

The recommendations should:
1. Be organized by priority/severity
2. Include both specific fixes for the identified issues and general smart contract security best practices
3. Be practical and actionable for Solidity developers
4. Reference specific Solidity patterns or established standards (like OpenZeppelin) where appropriate
5. Include implementation considerations like gas optimization and security-performance tradeoffs

Format the recommendations section with appropriate headings, bullet points, and explanations.
Include code examples in Solidity where helpful.
"""
        
        response = await self.process_message(message)
        return response.content
    
    async def generate_conclusion(self) -> str:
        """Generate a conclusion for the report
        
        Returns:
            Conclusion text
        """
        message = """Please generate a conclusion section for the Solidity smart contract security audit report.

The conclusion should:
1. Summarize the overall security posture of the smart contracts
2. Highlight the most critical areas that need attention
3. Provide perspective on the findings in the context of the blockchain ecosystem
4. End with a forward-looking statement about continuing security improvement in smart contract development

Keep the conclusion to 1-2 paragraphs and maintain a professional, balanced tone appropriate for a blockchain security audit report.
"""
        
        response = await self.process_message(message)
        return response.content
    
    async def generate_full_report(self, validated_findings: List[Dict[str, Any]]) -> str:
        """Generate the full audit report
        
        Args:
            validated_findings: List of validated findings
            
        Returns:
            Complete report text
        """
        # Generate executive summary
        executive_summary = await self.generate_executive_summary(validated_findings)
        self.add_to_section("Executive Summary", executive_summary)
        
        # Generate recommendations
        recommendations = await self.generate_recommendations(validated_findings)
        self.add_to_section("Recommendations", recommendations)
        
        # Generate conclusion
        conclusion = await self.generate_conclusion()
        self.add_to_section("Conclusion", conclusion)
        
        # Combine all sections into a full report
        report = f"# Solidity Smart Contract Security Audit Report\n\n"
        report += f"## Executive Summary\n\n{self.report_sections['Executive Summary']}\n\n"
        report += f"## Smart Contract Analysis\n\n{self.report_sections['Smart Contract Analysis']}\n\n"
        report += f"## Security Findings\n\n{self.report_sections['Security Findings']}\n\n"
        
        if self.report_sections['Proof of Concept Exploits']:
            report += f"## Proof of Concept Exploits\n\n{self.report_sections['Proof of Concept Exploits']}\n\n"
        
        if self.report_sections['Unconfirmed Findings']:
            report += f"## Unconfirmed Findings\n\n{self.report_sections['Unconfirmed Findings']}\n\n"
        
        report += f"## Recommendations\n\n{self.report_sections['Recommendations']}\n\n"
        report += f"## Conclusion\n\n{self.report_sections['Conclusion']}\n\n"
        
        return report
    
    async def save_report(self, report: str) -> str:
        """Save the report to a file
        
        Args:
            report: The report content
            
        Returns:
            Path to the saved report file
        """
        # Determine file extension based on format
        extensions = {
            "markdown": "md",
            "html": "html",
            "pdf": "pdf"  # Note: actual PDF generation would require additional libraries
        }
        ext = extensions.get(self.config.report_format, "md")
        
        # Create filename with timestamp
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"solidity_audit_report_{timestamp}.{ext}"
        filepath = os.path.join(self.config.output_dir, filename)
        
        # Save the report
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Report saved to: {filepath}")
            return filepath
        except Exception as e:
            logger.error(f"Error saving report: {str(e)}")
            return f"Error saving report: {str(e)}"
    
    async def run(self, validated_findings: List[Dict[str, Any]]) -> str:
        """Run the Report Engineer agent's main functionality
        
        Args:
            validated_findings: List of validated findings
            
        Returns:
            Path to the saved report file
        """
        try:
            # Generate the full report
            report = await self.generate_full_report(validated_findings)
            
            # Save the report to a file
            report_path = await self.save_report(report)
            
            return report_path
        except Exception as e:
            logger.error(f"Error running Report Engineer agent: {str(e)}")
            return f"Failed to run Report Engineer agent: {str(e)}" 