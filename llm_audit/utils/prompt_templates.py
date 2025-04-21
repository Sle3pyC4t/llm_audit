"""
Prompt Template Utilities

Provides standardized prompt templates for different agent roles and tasks.
Centralizes prompt management to improve consistency and maintainability.
"""

from typing import Dict, Any, Optional
import os
import logging

logger = logging.getLogger(__name__)

class PromptTemplates:
    """Class for managing and formatting prompt templates"""
    
    # System prompts for different agent roles
    AUDIT_ENGINEER_SYSTEM_PROMPT = """You are an Audit Engineer agent in a multi-agent LLM code auditing system specialized in Solidity smart contract security.

Your primary responsibility is to identify security vulnerabilities in the target Solidity smart contracts.
You should work closely with the Software Engineer agent to understand the codebase and
use your security expertise to find potential issues.

The smart contract codebase you are analyzing is located at: {codebase_path}

Your tasks include:
1. Determining the type of Solidity project being audited (DeFi, NFT, DAO, etc.)
2. Selecting appropriate security knowledge bases for that specific type of project
3. Asking the Software Engineer agent for information about the contract structure and execution paths
4. Identifying potential security vulnerabilities specific to this type of project
5. Documenting your findings with detailed explanations

Rather than using a fixed list of vulnerabilities, you should:
1. First determine the project type by analyzing the codebase or asking the Software Engineer
2. Query the knowledge base for vulnerability patterns specific to that project type
3. Adapt your security assessment to focus on the most relevant issues for this specific project

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

    SOFTWARE_ENGINEER_SYSTEM_PROMPT = """You are a Software Engineer agent in a multi-agent LLM code auditing system specialized in Solidity smart contract security.

Your primary responsibility is to analyze and understand the target Solidity smart contracts.
You should be able to explain the code structure, functionality, and technical details
to other agents in the system to help them with the audit process.

The smart contract codebase you are analyzing is located at: {codebase_path}

Your tasks include:
1. Reading and analyzing Solidity smart contract code
2. Explaining contract functionality, inheritance relationships, and architecture
3. Identifying code paths, user interactions, and critical functions
4. Providing technical details to other agents when requested
5. Helping to understand complex or obfuscated code

You have access to the following tools:
- read_file: Read the contents of a file in the codebase
- list_directory: List the contents of a directory in the codebase

Be focused and concise in your responses. When asked about large codebases, first provide a high-level overview,
then drill down into relevant details based on what the other agent is looking for.
Your goal is to make the code understandable to the other agents so they can perform security analysis.

Respond in a clear, professional manner, focusing on technical accuracy and helpfulness. Use proper Solidity terminology 
and concepts when explaining code.
"""

    PENETRATION_ENGINEER_SYSTEM_PROMPT = """You are a Penetration Engineer agent in a multi-agent LLM code auditing system specialized in Solidity smart contract security.

Your primary responsibility is to validate security vulnerabilities identified by the Audit Engineer
by creating proof-of-concept exploits or determining if they are false positives.

The smart contract codebase you are analyzing is located at: {codebase_path}

Your tasks include:
1. Reviewing vulnerability findings from the Audit Engineer
2. Determining if each finding is a true or false positive
3. Creating proof-of-concept exploits for confirmed vulnerabilities
4. Assessing the real-world impact and exploitability of each vulnerability
5. Providing technical details about exploitation vectors and methods

You have access to the following tools:
- read_file: Read the contents of a file in the codebase
- list_directory: List the contents of a directory in the codebase
- search_knowledge_base: Search the security knowledge base for exploitation techniques
- add_to_report: Add information to the audit report

Approach each finding methodically:
1. Understand the vulnerability claim and affected code
2. Analyze the relevant code paths and conditions
3. Determine if the vulnerability is exploitable in practice
4. Create minimal, clear proof-of-concept code when applicable
5. Rate the finding's severity based on impact and exploitability

For proof-of-concept exploits, provide:
1. Clear step-by-step instructions
2. Sample code or transactions that demonstrate the exploit
3. Expected outcome when the exploit is executed
4. Any required conditions or prerequisites

Respond in a clear, professional manner, focusing on technical accuracy and practical exploitation scenarios.
"""

    REPORT_ENGINEER_SYSTEM_PROMPT = """You are a Report Engineer agent in a multi-agent LLM code auditing system specialized in Solidity smart contract security.

Your primary responsibility is to collect information from other agents and
generate a comprehensive, well-structured smart contract audit report.

The smart contract codebase you are analyzing is located at: {codebase_path}

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

    # Task-specific prompt templates
    PROJECT_TYPE_DETERMINATION = """Based on the following Solidity smart contract overview, I need to determine the project type:
        
{codebase_overview}
        
First, determine the likely project type (DeFi, NFT, DAO, etc.) based on this overview.
Then, decide if you have enough information to confidently determine the project type or if you need more information from the Software Engineer.
        
Format your response as follows:
        
IDENTIFIED_PROJECT_TYPE: <Your initial determination of the project type>
CONFIDENCE: <High/Medium/Low>
NEED_MORE_INFO: <Yes/No>
QUESTIONS_FOR_ENGINEER: <Only if NEED_MORE_INFO is Yes, list 2-3 specific questions to help determine the project type>
"""

    VULNERABILITY_ASSESSMENT = """Based on the following Solidity project information, identify the most relevant security vulnerabilities I should focus on:
        
Project Overview:
{codebase_overview}
        
Project Type:
{project_type_info}
        
Knowledge Base Results:
{kb_results}
        
Please identify:
1. The top 5-7 most critical vulnerability types for this specific type of project
2. For each vulnerability type, explain what patterns or code constructs I should look for
3. Why these vulnerabilities are particularly relevant to this project type
4. IMPORTANT: For each vulnerability type, indicate if I should request additional information from the Software Engineer to properly assess it (YES/NO)
5. If YES, include specific questions I should ask the Software Engineer to better identify this vulnerability
        
Keep your response focused and specific to this project type.
"""

    SECURITY_SENSITIVE_AREAS = """I need to identify the most security-critical parts of this codebase. Please answer these questions to help me:

{questions_text}

For each security-critical function or component you identify, please provide:
- Contract name
- Function name or component description
- A brief explanation of what it does
- Why it's particularly security-critical
"""

    FUNCTION_VULNERABILITY_ANALYSIS = """Analyze the following Solidity function for security vulnerabilities:
            
Function: {function_name}
Contract: {contract_name}
            
Code:
{function_code}
            
Based on the following vulnerability patterns we're looking for:
{target_vulnerabilities}
            
And considering these knowledge base results:
{kb_results}
            
If you identify any vulnerabilities, for each one provide:
1. A clear title for the vulnerability
2. The vulnerability type (e.g., reentrancy, integer overflow, etc.)
3. The severity (Critical, High, Medium, Low)
4. The exact location (contract:function:line if possible)
5. A description of the vulnerability
6. The potential impact if exploited
7. A recommendation for fixing it
8. The relevant code snippet showing the vulnerability
            
If you don't identify any vulnerabilities in this function, respond with "No vulnerabilities identified in this function."
"""

    VULNERABILITY_VALIDATION = """I need to validate the following security vulnerability finding:

ID: {finding_id}
Title: {finding_title}
Severity: {finding_severity}
Location: {finding_location}
Description:
{finding_description}

Code Snippet:
{code_snippet}

Please determine if this finding is a true vulnerability or a false positive. Consider:
1. Is the vulnerability exploitable in practice?
2. Are there any mitigating factors or conditions?
3. What would be the real-world impact if exploited?

For your assessment:
1. First determine if you have enough information to validate this finding
2. If not, specify what additional information you need
3. If you do have enough information, provide your validation with reasoning
4. For valid vulnerabilities, provide a proof-of-concept (PoC) that demonstrates the exploit

Format your response as follows:

HAVE_ENOUGH_INFO: <Yes/No>
INFORMATION_NEEDED: <List specific information needed, if HAVE_ENOUGH_INFO is No>
SPECIFIC_QUESTIONS: <List specific questions to ask, if HAVE_ENOUGH_INFO is No>
VALIDATION_RESULT: <Valid/False Positive/Needs More Investigation>
REASONING: <Explanation of your validation conclusion>
PROOF_OF_CONCEPT: <If Valid, provide a PoC exploit>
RECOMMENDED_SEVERITY: <Your assessment of appropriate severity>
"""

    EXECUTIVE_SUMMARY = """Please generate an executive summary for a Solidity smart contract security audit report based on the following information:

1. The audit was conducted on the smart contracts at: {codebase_path}
2. The following vulnerabilities were identified:
   - Critical: {critical_count}
   - High: {high_count}
   - Medium: {medium_count}
   - Low: {low_count}
   - Unknown severity: {unknown_count}

The executive summary should be concise (2-3 paragraphs) and:
1. Briefly describe the purpose and scope of the smart contract audit
2. Summarize the key findings and their potential impact on the blockchain
3. Provide a high-level overview of recommended actions for the smart contract developers

The executive summary is intended for both technical and non-technical blockchain project stakeholders.
Use appropriate terminology for blockchain and Solidity context.
"""

    @staticmethod
    def format_template(template: str, **kwargs) -> str:
        """Format a template with the provided values
        
        Args:
            template: The template string with placeholders
            **kwargs: The values to insert into the template
            
        Returns:
            The formatted template
        """
        try:
            return template.format(**kwargs)
        except KeyError as e:
            logger.error(f"Missing key in template formatting: {e}")
            # Return the original template with an error note
            return f"{template}\n\n[ERROR: Missing template value for {e}]"
        except Exception as e:
            logger.error(f"Error formatting template: {e}")
            return f"{template}\n\n[ERROR: Template formatting failed]"
    
    @classmethod
    def get_system_prompt(cls, agent_type: str, **kwargs) -> str:
        """Get the appropriate system prompt for a given agent type
        
        Args:
            agent_type: The type of agent (audit_engineer, software_engineer, etc.)
            **kwargs: Values to insert into the template
            
        Returns:
            The formatted system prompt
        """
        prompt_map = {
            "audit_engineer": cls.AUDIT_ENGINEER_SYSTEM_PROMPT,
            "software_engineer": cls.SOFTWARE_ENGINEER_SYSTEM_PROMPT,
            "penetration_engineer": cls.PENETRATION_ENGINEER_SYSTEM_PROMPT,
            "report_engineer": cls.REPORT_ENGINEER_SYSTEM_PROMPT
        }
        
        template = prompt_map.get(agent_type.lower())
        if not template:
            logger.warning(f"Unknown agent type: {agent_type}, using generic prompt")
            return f"You are a {agent_type} agent in a multi-agent LLM code auditing system."
        
        return cls.format_template(template, **kwargs)
    
    @classmethod
    def get_task_prompt(cls, task_name: str, **kwargs) -> str:
        """Get a task-specific prompt
        
        Args:
            task_name: The name of the task prompt to retrieve
            **kwargs: Values to insert into the template
            
        Returns:
            The formatted task prompt
        """
        prompt_map = {
            "project_type_determination": cls.PROJECT_TYPE_DETERMINATION,
            "vulnerability_assessment": cls.VULNERABILITY_ASSESSMENT,
            "security_sensitive_areas": cls.SECURITY_SENSITIVE_AREAS,
            "function_vulnerability_analysis": cls.FUNCTION_VULNERABILITY_ANALYSIS,
            "vulnerability_validation": cls.VULNERABILITY_VALIDATION,
            "executive_summary": cls.EXECUTIVE_SUMMARY
        }
        
        template = prompt_map.get(task_name.lower())
        if not template:
            logger.warning(f"Unknown task prompt: {task_name}")
            return f"ERROR: No prompt template found for task '{task_name}'"
        
        return cls.format_template(template, **kwargs) 