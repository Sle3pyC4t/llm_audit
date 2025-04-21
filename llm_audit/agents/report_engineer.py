"""
Report Engineer Agent

Responsible for collecting information from other agents and
generating a comprehensive Solidity smart contract audit report.
"""

import os
import logging
import re
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
    
    async def generate_recommendations(self, findings: List[Dict[str, Any]], additional_recommendations: Optional[str] = None) -> str:
        """Generate recommendations based on the findings
        
        Args:
            findings: List of validated findings
            additional_recommendations: Optional additional recommendations to include
            
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
        message = """Please generate a comprehensive set of recommendations for Solidity smart contract security based on the following specific recommendations from the audit findings:

{}

{}

The recommendations should:
1. Be organized by priority/severity
2. Include both specific fixes for the identified issues and general smart contract security best practices
3. Be practical and actionable for Solidity developers
4. Reference specific Solidity patterns or established standards (like OpenZeppelin) where appropriate
5. Include implementation considerations like gas optimization and security-performance tradeoffs

Format the recommendations section with appropriate headings, bullet points, and explanations.
Include code examples in Solidity where helpful.
""".format(
            recommendations,
            "Additional security recommendations from experts:\n\n" + additional_recommendations if additional_recommendations else ""
        )
        
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
        # Define regex patterns as constants to avoid backslash issues in f-strings
        import re
        NUMBERED_LIST_PATTERN = r'^\d+\.'
        EXPLOIT_PATTERN = r'exploit|poc|proof|reproduce'
        CODE_PATTERN = r'code|implementation|function|contract'
        
        # Helper function to get the first line of project type or the full text
        def get_project_type_display(project_type_text):
            if '\n' in project_type_text:
                return project_type_text.split('\n')[0]
            return project_type_text
        
        # Generate executive summary
        executive_summary = await self.generate_executive_summary(validated_findings)
        self.add_to_section("Executive Summary", executive_summary)
        
        # Decide if we need more information about any findings
        finding_gaps_message = """I'm generating a security audit report. For each finding, I need to decide if I have sufficient information or if I should request additional details from other agents. What questions should I ask about each finding to ensure the report is comprehensive? Consider:

1. Code context that might be missing
2. Technical impact details that may need clarification
3. Exploitation difficulty assessment
4. Remediation complexity
5. Business impact

Provide a general checklist of questions I should review for each finding to ensure completeness.
"""
        
        response = await self.process_message(finding_gaps_message)
        finding_checklist = response.content
        
        # Process the checklist into actual questions
        checklist_items = []
        for line in finding_gaps_message.split('\n'):
            if line.strip().startswith('-') or ('?' in line) or re.match(NUMBERED_LIST_PATTERN, line):
                checklist_items.append(line.strip())
        
        # For each finding, check if we need more information
        for i, finding in enumerate(validated_findings):
            if i < 5:  # Limit to first 5 findings to avoid too many iterations
                finding_assessment_message = f"""For this finding, assess if I have sufficient information for a complete report or if I should request more details:
                
                ID: {finding.get('id', 'Unknown')}
                Title: {finding.get('title', 'Unknown')}
                Severity: {finding.get('severity', 'Unknown')}
                Description: {finding.get('description', 'Unknown')}
                Location: {finding.get('location', 'Unknown')}
                
                Using the checklist:
                {finding_checklist}
                
                Respond with:
                SUFFICIENT_INFO: <Yes/No>
                MISSING_DETAILS: <List what's missing>
                QUESTIONS_FOR_AGENTS: <Questions to ask, if needed>
                """
                
                response = await self.process_message(finding_assessment_message)
                finding_assessment = response.content
                
                need_more_info = "SUFFICIENT_INFO: No" in finding_assessment
                
                if need_more_info:
                    # Extract questions
                    questions = []
                    in_questions = False
                    for line in finding_assessment.split('\n'):
                        if line.startswith('QUESTIONS_FOR_AGENTS:'):
                            in_questions = True
                            continue
                        if in_questions and line.strip():
                            questions.append(line.strip())
                    
                    if questions:
                        # Determine which agent to ask based on the questions
                        target_agent = "audit_engineer"  # Default
                        if any(re.search(EXPLOIT_PATTERN, q, re.IGNORECASE) for q in questions):
                            target_agent = "penetration_engineer"
                        elif any(re.search(CODE_PATTERN, q, re.IGNORECASE) for q in questions):
                            target_agent = "software_engineer"
                        
                        questions_text = "\n".join([f"- {q}" for q in questions[:3]])  # Limit to 3 questions
                        query = f"""I'm preparing the audit report section for this finding and need additional information:
                        
                        Finding: {finding.get('title', 'Unknown')} ({finding.get('id', 'Unknown')})
                        
                        Please provide more details on:
                        {questions_text}
                        
                        This will help me create a more comprehensive and accurate report section.
                        """
                        
                        additional_info = await self.communicate(target_agent, query)
                        logger.info(f"Received additional information for finding {finding.get('id', 'Unknown')}")
                        
                        # Add the information to the finding
                        validated_findings[i]["additional_report_info"] = additional_info
        
        # Get project type information from findings if available
        project_type = None
        for finding in validated_findings:
            if "project_type" in finding:
                project_type = finding.get("project_type")
                break
        
        # If project type not found in findings, determine it ourselves
        if not project_type:
            # Ask if we should request project type information
            determine_project_type_message = """I'm generating a security audit report and need to determine the project type. Should I:
            
            1. Ask the Audit Engineer for project type information
            2. Ask the Software Engineer directly to analyze the codebase
            3. Try to infer it from the findings we already have
            
            Which approach would give me the most accurate information for the report?
            """
            
            response = await self.process_message(determine_project_type_message)
            project_type_approach = response.content
            
            if "ask the audit engineer" in project_type_approach.lower():
                project_type_response = await self.communicate(
                    "audit_engineer",
                    "Based on your analysis of the codebase, what type of Solidity project is this? "
                    "Please provide a concise, structured summary including project type, standards used, and key features."
                )
                project_type = project_type_response
            elif "ask the software engineer" in project_type_approach.lower():
                project_type_response = await self.communicate(
                    "software_engineer",
                    "Please analyze this codebase and tell me what type of Solidity project this is. "
                    "Include the primary project category (DeFi, NFT, etc.), any standards it implements, "
                    "and key architectural patterns. I need this for the security audit report."
                )
                project_type = project_type_response
            else:
                # Try to infer from findings
                infer_project_type_message = f"""Based on these security findings, what type of Solidity project is this likely to be?
                
                Findings:
                {[f"{f.get('id', 'Unknown')}: {f.get('title', 'Unknown')}" for f in validated_findings[:5]]}
                
                Please provide a structured analysis that includes:
                1. Likely project type (DeFi, NFT, DAO, etc.)
                2. Potential standards or protocols used
                3. Confidence level in this assessment
                """
                
                response = await self.process_message(infer_project_type_message)
                project_type = response.content
        
        # Get project-specific audit checkpoints
        if project_type:
            logger.info(f"Generating project-specific audit checkpoints for {project_type}")
            checkpoint_message = f"""Generate a comprehensive list of security audit checkpoints specific to this type of Solidity project:
            
            Project Type: {project_type}
            
            The checkpoints should:
            1. Be tailored specifically to this project type
            2. Cover the key security concerns for this project category
            3. Include project-specific vulnerability patterns
            4. Reference relevant industry standards or best practices
            
            Format the checkpoints as a markdown list with clear categories and subcategories.
            Be specific and technical, not generic.
            """
            
            checkpoints_response = await self.process_message(checkpoint_message)
            project_specific_checkpoints = checkpoints_response.content
        else:
            # Fallback to generic checkpoints
            project_specific_checkpoints = """
            - **DeFi-Specific Checks:** Slippage protection, price oracle manipulation, flash loan vulnerabilities
            - **Token Implementation Checks:** ERC20/ERC721/ERC1155 compliance, safe minting/burning mechanisms
            - **Access Control Verification:** Role-based permission systems, privilege escalation vectors
            - **Economic Security Model Analysis:** Game theory incentives, MEV protection measures
            """
            
        # Ask if we need additional recommendations beyond what's in the findings
        additional_recommendations_query = """Do we need additional security recommendations beyond addressing the specific findings? 
        
        Consider:
        1. Are there architectural improvements that should be suggested?
        2. Are there testing processes that should be implemented?
        3. Should we recommend specific security tools or frameworks?
        4. Are there best practices for this type of project that should be highlighted?
        
        If yes, which agent would be best to ask for these recommendations?
        """
        
        response = await self.process_message(additional_recommendations_query)
        recommendations_assessment = response.content
        
        if "yes" in recommendations_assessment.lower():
            # Determine who to ask based on the response
            ask_audit = "audit engineer" in recommendations_assessment.lower()
            ask_penetration = "penetration engineer" in recommendations_assessment.lower()
            
            if ask_audit:
                additional_recommendations = await self.communicate(
                    "audit_engineer",
                    "Beyond the specific findings, what additional security recommendations would you make for this project? "
                    "Please focus on architectural improvements, security best practices, testing methodologies, "
                    "and any specific tools or frameworks that would enhance security."
                )
                
                # Generate recommendations based on findings and additional input
                recommendations = await self.generate_recommendations(validated_findings, additional_recommendations)
            elif ask_penetration:
                additional_recommendations = await self.communicate(
                    "penetration_engineer",
                    "Beyond the specific vulnerabilities identified, what additional security recommendations would you make? "
                    "Please focus on defensive coding practices, security testing, and hardening measures "
                    "that would help prevent similar issues in the future."
                )
                
                # Generate recommendations based on findings and additional input
                recommendations = await self.generate_recommendations(validated_findings, additional_recommendations)
            else:
                # Just use the findings
                recommendations = await self.generate_recommendations(validated_findings)
        else:
            # Just use the findings
            recommendations = await self.generate_recommendations(validated_findings)
            
        self.add_to_section("Recommendations", recommendations)
        
        # Generate conclusion
        conclusion = await self.generate_conclusion()
        self.add_to_section("Conclusion", conclusion)
        
        # Combine all sections into a full report
        report = f"# Solidity Smart Contract Security Audit Report\n\n"
        report += f"## Executive Summary\n\n{self.report_sections['Executive Summary']}\n\n"
        report += f"## Audit Methodology\n\n"
        report += f"### Project Type\n\n"
        report += "This audit was conducted on a {} project, which informed our security assessment approach and focus areas.\n\n".format(get_project_type_display(project_type))
        report += f"### Audit Checkpoints\n\n"
        report += "This audit was conducted using a systematic approach that includes the following checkpoints:\n\n"
        report += "#### Standard Security Checkpoints\n\n"
        report += "- **Code Quality & Standards:** Review of code quality, adherence to Solidity standards, and best practices\n"
        report += "- **Architecture Review:** Evaluation of smart contract architecture, inheritance patterns, and component interactions\n"
        report += "- **Business Logic Review:** Analysis of business logic implementation and potential flaws\n"
        report += "- **Security Vulnerability Assessment:** Identification of common and contract-specific security vulnerabilities\n"
        report += "- **Gas Optimization:** Analysis of gas usage and optimization opportunities\n"
        report += "- **Exploit Scenario Testing:** Validation of vulnerabilities through proof-of-concept exploits\n\n"
        report += f"#### Project-Specific Security Checkpoints\n\n{project_specific_checkpoints}\n\n"
        report += f"## Smart Contract Analysis\n\n{self.report_sections['Smart Contract Analysis']}\n\n"
        report += f"## Security Findings\n\n"
        
        # Generate detailed findings section with code snippets
        if validated_findings:
            for finding in validated_findings:
                report += f"### [{finding.get('severity', 'Unknown')}] {finding.get('id', 'Unknown')}: {finding.get('title', 'Unknown')}\n\n"
                report += f"**Description:**\n\n{finding.get('description', 'No description provided.')}\n\n"
                
                if "location" in finding:
                    report += f"**Location:** `{finding.get('location', 'Unknown')}`\n\n"
                
                # Include code snippet if available
                if "code_snippet" in finding:
                    report += f"**Vulnerable Code Snippet:**\n\n```solidity\n{finding.get('code_snippet', '')}\n```\n\n"
                
                # Include impact assessment
                if "impact" in finding:
                    report += f"**Impact:**\n\n{finding.get('impact', 'No impact assessment provided.')}\n\n"
                
                # Include recommendation
                if "recommendation" in finding:
                    report += f"**Recommendation:**\n\n{finding.get('recommendation', 'No recommendation provided.')}\n\n"
                
                # Include validation details
                if "validation" in finding:
                    report += f"**Validation:**\n\n{finding.get('validation', 'Not validated.')}\n\n"
                
                # Include additional information gathered during report generation if available
                if "additional_report_info" in finding:
                    report += f"**Additional Technical Details:**\n\n{finding.get('additional_report_info')}\n\n"
                
                report += "---\n\n"
        else:
            report += "No validated findings in this audit.\n\n"
        
        if self.report_sections['Proof of Concept Exploits']:
            report += f"## Proof of Concept Exploits\n\n"
            # Enhanced PoC section
            for finding in validated_findings:
                if "proof_of_concept" in finding and finding.get("status") == "Confirmed":
                    report += f"### PoC for {finding.get('id', 'Unknown')}: {finding.get('title', 'Unknown')}\n\n"
                    report += "**Steps to Reproduce:**\n\n"
                    
                    poc_content = finding.get('proof_of_concept', '')
                    
                    # Try to extract steps to reproduce if they exist
                    if "Step" in poc_content and ":" in poc_content:
                        lines = poc_content.split("\n")
                        in_steps = False
                        steps = []
                        
                        for line in lines:
                            if line.strip().startswith("Step") or line.strip().startswith("1."):
                                in_steps = True
                            
                            if in_steps:
                                steps.append(line)
                                
                                if not line.strip() and steps:  # Empty line after steps
                                    break
                        
                        if steps:
                            report += "\n".join(steps) + "\n\n"
                    
                    # Add the PoC code itself
                    if "```" in poc_content:
                        # Extract code blocks
                        import re
                        code_blocks = re.findall(r"```(?:solidity)?(.*?)```", poc_content, re.DOTALL)
                        
                        if code_blocks:
                            report += "**Exploit Code:**\n\n"
                            for code in code_blocks:
                                report += f"```solidity\n{code.strip()}\n```\n\n"
                        else:
                            report += poc_content + "\n\n"
                    else:
                        report += poc_content + "\n\n"
                    
                    # Expected outcome
                    report += "**Expected Outcome:**\n\n"
                    if "Expected outcome" in poc_content:
                        outcome_start = poc_content.find("Expected outcome")
                        outcome_end = poc_content.find("\n\n", outcome_start)
                        if outcome_end == -1:
                            outcome_end = len(poc_content)
                        
                        expected_outcome = poc_content[outcome_start:outcome_end].strip()
                        report += expected_outcome + "\n\n"
                    else:
                        report += "Successful exploitation of the vulnerability.\n\n"
                    
                    report += "---\n\n"
        
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