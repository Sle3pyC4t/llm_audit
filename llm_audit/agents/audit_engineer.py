"""
Audit Engineer Agent

Responsible for identifying security vulnerabilities in Solidity smart contracts
by selecting appropriate knowledge bases and working with the Software Engineer agent.
"""

import logging
import asyncio
import re
import hashlib
from typing import Any, Dict, List, Optional, Tuple

from langchain_core.language_models import BaseChatModel

from .base_agent import BaseAgent
from ..config import Config
from ..tools.tool_center import ToolCenter
from ..llm_providers import LLMProviderFactory
from ..utils.knowledge_base import KnowledgeBase
from ..utils.response_parser import ResponseParser

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
        # Define regex patterns as constants to avoid backslash issues in f-strings
        CONTRACT_PATTERN = r'([A-Za-z0-9_]+)\s*contract'
        FUNCTION_PATTERN = r'([A-Za-z0-9_]+)\s*function'
        NUMBER_PREFIX_PATTERN = r'\d+\.\s*'
        NUMBERED_LIST_PATTERN = r'^\d+\.'
        
        # Define newline constant to avoid backslash in f-strings
        NEWLINE = "\n"
        
        # Initialize findings list
        findings = []
        
        # Helper function for building strings with newlines
        def format_with_newlines(template, *args, **kwargs):
            """Format a string with newlines without using f-strings"""
            return template.format(*args, **kwargs)
        
        logger.info("Starting vulnerability identification")
        
        # Step 1: Ask the Software Engineer for an overview of the codebase
        logger.info("Requesting codebase overview from Software Engineer")
        codebase_overview = await software_engineer.answer_question(
            "Please provide a high-level overview of the Solidity smart contract codebase structure, "
            "including main contracts, inheritance relationships, and key functionality. "
            "Limit your response to the 5 most important files/contracts."
        )
        logger.info(f"Received codebase overview: {len(codebase_overview)} chars")
        
        # Process only the first part if it's too long
        if len(codebase_overview) > 4000:
            logger.info("Codebase overview too long, truncating")
            codebase_overview = codebase_overview[:4000] + "... [truncated for brevity]"
        
        # Step 2: Determine the project type using the agent's self-determination capability
        logger.info("Determining project type and whether more information is needed")
        determine_project_type_message = f"""Based on the following Solidity smart contract overview, I need to determine the project type:
        
        {codebase_overview}
        
        First, determine the likely project type (DeFi, NFT, DAO, etc.) based on this overview.
        Then, decide if you have enough information to confidently determine the project type or if you need more information from the Software Engineer.
        
        Format your response as follows:
        
        IDENTIFIED_PROJECT_TYPE: <Your initial determination of the project type>
        CONFIDENCE: <High/Medium/Low>
        NEED_MORE_INFO: <Yes/No>
        QUESTIONS_FOR_ENGINEER: <Only if NEED_MORE_INFO is Yes, list 2-3 specific questions to help determine the project type>
        """
        
        response = await self.process_message_with_timeout(determine_project_type_message)
        project_type_assessment = response.content
        
        # Parse the response to extract information
        identified_project_type = ResponseParser.extract_section(project_type_assessment, "IDENTIFIED_PROJECT_TYPE")
        need_more_info_section = ResponseParser.extract_section(project_type_assessment, "NEED_MORE_INFO")
        need_more_info = need_more_info_section and "yes" in need_more_info_section.lower()
        questions_section = ResponseParser.extract_section(project_type_assessment, "QUESTIONS_FOR_ENGINEER")
        questions_for_engineer = ResponseParser.extract_bulleted_list(questions_section) if questions_section else []
        
        project_type_info = identified_project_type or "Unknown"
        
        # If needed, get more information from the Software Engineer
        if need_more_info and questions_for_engineer:
            logger.info("Requesting more information to determine project type")
            questions_text = "\n".join([f"{i+1}. {q}" for i, q in enumerate(questions_for_engineer)])
            project_type_query = f"""I'm trying to determine what type of Solidity project this is. Based on my initial analysis, I think it might be {identified_project_type}, but I need more information. Could you please answer these questions:

{questions_text}

Also, please categorize this project as specifically as possible (e.g., DeFi lending platform, NFT marketplace, 
DAO governance, token bridge, stablecoin, AMM DEX, yield aggregator, etc.) and identify any specific standards or protocols used.
"""
            
            # Use the communicate method for dynamic agent-to-agent interaction
            additional_info = await self.communicate("software_engineer", project_type_query)
            logger.info(f"Received additional project type information from Software Engineer")
            
            # Update project type based on additional information
            refine_project_type_message = f"""Based on my initial analysis, I identified this project as: {identified_project_type}
            
            I asked the Software Engineer for more information, and got this response:
            
            {additional_info}
            
            Please provide an updated and more specific project type classification based on this additional information. 
            Format your response as:
            
            PROJECT_TYPE: <Specific project type>
            STANDARDS: <Standards/protocols used>
            DESIGN_PATTERNS: <Notable design patterns>
            """
            
            response = await self.process_message_with_timeout(refine_project_type_message)
            refined_project_type = response.content
            project_type_info = refined_project_type
        
        logger.info(f"Project type determined: {project_type_info[:100]}...")
        
        # Step 3: Use the KnowledgeBase to get project-specific vulnerabilities
        parsed_project_type = project_type_info.split('\n')[0] if '\n' in project_type_info else project_type_info
        parsed_project_type = parsed_project_type.replace("PROJECT_TYPE:", "").strip()
        
        vulnerability_categories = KnowledgeBase.get_vulnerability_categories(parsed_project_type)
        logger.info(f"Found {len(vulnerability_categories)} vulnerability categories for project type {parsed_project_type}")
        
        # Get vulnerability patterns from the KnowledgeBase
        vulnerability_patterns = KnowledgeBase.get_vulnerability_patterns(parsed_project_type)
        
        # Format the vulnerability information for the prompt
        kb_results = ""
        for category in vulnerability_categories:
            vuln_info = KnowledgeBase.get_vulnerability_description(category)
            kb_results += f"## {category}\n"
            kb_results += f"Description: {vuln_info.get('description', 'No description available')}\n"
            kb_results += f"Severity: {vuln_info.get('severity', 'Unknown')}\n"
            kb_results += f"Patterns to look for:\n"
            for pattern in vuln_info.get('patterns', []):
                kb_results += f"- {pattern}\n"
            kb_results += f"Recommendation: {vuln_info.get('recommendation', 'No recommendation available')}\n\n"
        
        # Get security patterns for the project type
        security_patterns = KnowledgeBase.get_security_patterns(parsed_project_type)
        if security_patterns:
            kb_results += "## Security Patterns\n"
            for pattern_name, description in security_patterns.items():
                kb_results += f"- {pattern_name}: {description}\n"
        
        logger.info(f"Knowledge base results prepared: {len(kb_results)} chars")
        
        # Step 4: Generate project-specific vulnerability patterns to look for
        logger.info("Generating project-specific vulnerability patterns")
        message = f"""Based on the following Solidity project information, identify the most relevant security vulnerabilities I should focus on:
        
        Project Overview:
        {codebase_overview}
        
        Project Type:
        {project_type_info}
        
        Knowledge Base Results:
        {kb_results[:1500] if len(kb_results) > 1500 else kb_results}
        
        Please identify:
        1. The top 5-7 most critical vulnerability types for this specific type of project
        2. For each vulnerability type, explain what patterns or code constructs I should look for
        3. Why these vulnerabilities are particularly relevant to this project type
        4. IMPORTANT: For each vulnerability type, indicate if I should request additional information from the Software Engineer to properly assess it (YES/NO)
        5. If YES, include specific questions I should ask the Software Engineer to better identify this vulnerability
        
        Keep your response focused and specific to this project type.
        """
        
        response = await self.process_message_with_timeout(message)
        project_specific_vulnerabilities = response.content
        logger.info(f"Identified project-specific vulnerabilities: {len(project_specific_vulnerabilities)} chars")
        
        # Step 5: Parse the vulnerability patterns and decide which require additional information
        # Extract vulnerability sections using the ResponseParser
        vulnerability_sections = []
        vulnerability_list = ResponseParser.extract_numbered_list(project_specific_vulnerabilities)
        
        # 确保vulnerability_list不是None或空列表
        if not vulnerability_list:
            # 尝试其他提取方法
            vulnerability_list = ResponseParser.extract_bulleted_list(project_specific_vulnerabilities)
            if not vulnerability_list:
                # 如果仍然为空，使用整个文本作为回退
                logger.warning("Could not extract structured vulnerability list, using full text")
                vulnerability_list = [project_specific_vulnerabilities]
        
        for vuln_item in vulnerability_list:
            # 确保vuln_item是字符串
            if not isinstance(vuln_item, str):
                continue
                
            # 用正则表达式检查是否包含关键词
            if re.search(r"vulnerability|issue|attack|exploit", vuln_item.lower()):
                title = vuln_item.strip()
                # Find this item's full content in the original text
                pattern = re.escape(title) + r"(.*?)(?=\d+\.|\Z)"
                match = re.search(pattern, project_specific_vulnerabilities, re.DOTALL)
                content = match.group(1).strip() if match else ""
                
                vulnerability_sections.append({
                    "title": title,
                    "content": content
                })
        
        # For each vulnerability section, check if additional information is needed
        need_additional_info = {}
        for section in vulnerability_sections:
            if not isinstance(section, dict) or "content" not in section:
                continue
                
            section_content = section.get("content", "")
            if not isinstance(section_content, str):
                continue
                
            if "YES" in section_content and (
                "question" in section_content.lower() or 
                "ask" in section_content.lower()
            ):
                # Extract questions to ask the Software Engineer
                questions = []
                # Try to extract the questions section
                question_section = re.search(r"(?:questions?|ask).*?:(.*?)(?=\n\n|\Z)", section_content, re.IGNORECASE | re.DOTALL)
                if question_section:
                    question_text = question_section.group(1).strip()
                    questions = ResponseParser.extract_bulleted_list(question_text)
                    if not questions:  # Try numbered list if bulleted list fails
                        questions = ResponseParser.extract_numbered_list(question_text)
                
                if questions:
                    need_additional_info[section["title"]] = questions
        
        # Get additional information for vulnerabilities that need it
        additional_vulnerability_info = {}
        for vulnerability, questions in need_additional_info.items():
            if questions:
                logger.info(f"Requesting additional information for: {vulnerability}")
                questions_text = "\n".join([f"- {q}" for q in questions])
                query = """I'm analyzing this codebase for potential {} vulnerabilities. 
                To properly assess this, I need your assistance with the following specific questions:
                
                {}
                
                Please provide detailed responses from your understanding of the code.
                """.format(vulnerability, questions_text)
                
                additional_info = await self.communicate("software_engineer", query)
                logger.info(f"Received additional information for {vulnerability}")
                
                additional_vulnerability_info[vulnerability] = additional_info
        
        # Step 6: Ask the agent if it needs to ask specific questions about security-sensitive areas
        logger.info("Determining what security-sensitive areas to investigate")
        what_to_ask_message = """Based on the project type ({}) 
        and potential vulnerabilities identified, I need to determine what specific security-sensitive areas to ask the Software Engineer about.
        
        What are the most important questions I should ask to identify security-critical functions for this type of project?
        
        Format your response as a list of 3-5 specific questions that will help me identify:
        1. Functions that handle assets/value transfers
        2. Access control mechanisms
        3. Critical state variables
        4. Project-specific security concerns
        
        For each question, explain why it's important for this project type.
        """.format(parsed_project_type)
        
        response = await self.process_message_with_timeout(what_to_ask_message)
        security_questions = response.content
        
        # Extract questions to ask the Software Engineer using ResponseParser
        questions_to_ask = ResponseParser.extract_bulleted_list(security_questions)
        if not questions_to_ask:
            questions_to_ask = ResponseParser.extract_numbered_list(security_questions)
        
        # Filter out explanations (lines without question marks) if needed
        questions_to_ask = [q for q in questions_to_ask if '?' in q]
        
        # Ask security-sensitive questions if we have any
        if questions_to_ask:
            logger.info("Requesting information about security-sensitive areas")
            questions_text = "\n".join(questions_to_ask[:5])  # Limit to 5 questions
            sensitive_areas_query = """I need to identify the most security-critical parts of this codebase. Please answer these questions to help me:

{}

For each security-critical function or component you identify, please provide:
- Contract name
- Function name or component description
- A brief explanation of what it does
- Why it's particularly security-critical
""".format(questions_text)
            
            sensitive_areas = await self.communicate("software_engineer", sensitive_areas_query)
            logger.info(f"Received information about sensitive areas: {len(sensitive_areas)} chars")
        else:
            # Fallback to a more generic question if we couldn't generate specific questions
            sensitive_areas_query = """Given that this appears to be a {} project:
            
            Please identify the top 3-5 most security-critical functions in the contracts that: 
            1) Handle assets/value transfers
            2) Manage access control
            3) Modify critical state variables
            4) Implement key business logic specific to this project type
            
            For each function, provide:
            - Contract name
            - Function name
            - A brief description of what it does
            - Why it's particularly security-critical
            """.format(parsed_project_type)
            
            sensitive_areas = await self.communicate("software_engineer", sensitive_areas_query)
            logger.info(f"Received information about sensitive areas: {len(sensitive_areas)} chars")
        
        # Step 7: Determine target vulnerabilities with all gathered information
        logger.info("Determining target areas for security review")
        combined_info = """Project Type Information:
{}

Project-Specific Vulnerabilities:
{}

Security-Sensitive Areas:
{}
""".format(project_type_info, project_specific_vulnerabilities, sensitive_areas)
        
        # Add any additional vulnerability information we gathered
        if additional_vulnerability_info:
            combined_info += "\nAdditional Information on Specific Vulnerabilities:\n"
            for vuln, info in additional_vulnerability_info.items():
                combined_info += "\n### {}\n{}\n".format(vuln, info)
        
        message = """Based on all the information I've gathered about this project, what are the most likely Solidity vulnerabilities I should look for in these specific contracts and functions?

{}

For each vulnerability type:
1. Specify which contract and function might be affected
2. Explain what pattern I should look for
3. Describe why this particular code is vulnerable
4. Provide an approach for validating if the vulnerability exists

Focus on being specific to this codebase rather than general vulnerability descriptions.
Limit your response to the 5 most critical potential vulnerabilities.
""".format(combined_info)
        
        response = await self.process_message_with_timeout(message)
        target_vulnerabilities = response.content
        logger.info(f"Determined target vulnerabilities: {len(target_vulnerabilities)} chars")
        
        # Continue with the rest of the function (parsing sensitive areas, analyzing functions, etc.)
        # Look for specific patterns based on the knowledge base
        logger.info("Determining target areas for security review")
        message = """Based on the software engineer's description of security-sensitive areas in the smart contracts:
        
        {}
        
        And considering these project-specific vulnerability patterns:
        
        {}
        
        What are the most likely Solidity vulnerabilities I should look for in these contracts or functions?
        For each vulnerability type, briefly explain what pattern I should look for.
        Keep your response under 500 words.
        """.format(sensitive_areas, project_specific_vulnerabilities)
        
        response = await self.process_message_with_timeout(message)
        target_vulnerabilities = response.content
        logger.info(f"Determined target vulnerabilities: {len(target_vulnerabilities)} chars")
        
        # Parse the sensitive areas to extract contract and function names
        sensitive_functions = []
        
        # Simple parsing - this could be improved with better regex or structure
        for line in sensitive_areas.split('\n'):
            if ':' in line and ('function' in line.lower() or 'contract' in line.lower()):
                contract_match = re.search(CONTRACT_PATTERN, line, re.IGNORECASE)
                function_match = re.search(FUNCTION_PATTERN, line, re.IGNORECASE)
                
                contract = contract_match.group(1) if contract_match else None
                function = function_match.group(1) if function_match else None
                
                if contract or function:
                    sensitive_functions.append((contract, function))
        
        if not sensitive_functions:
            # If parsing fails, fallback to requesting the information directly
            message = """Based on your previous response about security-sensitive areas, please list the 
            exact contract names and function names in the following format:
            
            1. ContractName: functionName
            2. ContractName: functionName
            3. ContractName: functionName
            
            Only list the names, nothing else.
            """
            
            response = await software_engineer.answer_question(message)
            
            for line in response.split('\n'):
                if ':' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        contract = parts[0].strip().replace('.', '')
                        function = parts[1].strip()
                        
                        if re.search(NUMBER_PREFIX_PATTERN, contract):
                            contract = re.sub(NUMBER_PREFIX_PATTERN, '', contract)
                        
                        sensitive_functions.append((contract, function))
        
        # For each security-sensitive function, get the code and analyze it
        for contract_name, function_name in sensitive_functions:
            if not contract_name or not function_name:
                continue
                
            logger.info(f"Analyzing {contract_name}.{function_name}")
            
            # Get the function code
            code_query = "Please provide the full code of the function `{}` in the contract `{}`, including any relevant modifiers, inheritance, or state variables it uses. Format it as a proper Solidity code snippet.".format(function_name, contract_name)
            
            function_code = await software_engineer.answer_question(code_query)
            
            # Check if the response contains a code block
            if "```" not in function_code:
                function_code = "```solidity\n" + function_code + "\n```"
            
            # Get relevant vulnerability knowledge
            kb_query = f"solidity vulnerability {contract_name} {function_name} {target_vulnerabilities}"
            kb_results = self.tool_center.search_knowledge_base(kb_query)
            
            # Ask the model to analyze this specific function for vulnerabilities
            message = format_with_newlines("""Analyze the following Solidity function for security vulnerabilities:
            
            Function: {0}
            Contract: {1}
            
            Code:
            {2}
            
            Based on the following vulnerability patterns we're looking for:
            {3}
            
            And considering these knowledge base results:
            {4}
            
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
            """, function_name, contract_name, function_code, target_vulnerabilities, kb_results[:1000] if len(kb_results) > 1000 else kb_results)
            
            response = await self.process_message_with_timeout(message, timeout=240)
            analysis = response.content
            
            if "no vulnerabilities identified" not in analysis.lower():
                # Parse the vulnerabilities from the analysis
                current_section = ""
                current_content = ""
                vulnerability = {}
                
                sections = {
                    "title": ["title", "vulnerability title"],
                    "type": ["vulnerability type", "type"],
                    "severity": ["severity"],
                    "location": ["location", "exact location"],
                    "description": ["description"],
                    "impact": ["impact", "potential impact"],
                    "recommendation": ["recommendation", "fix"],
                    "code_snippet": ["code snippet", "relevant code", "vulnerable code"]
                }
                
                for line in analysis.split('\n'):
                    line = line.strip()
                    
                    # Skip empty lines
                    if not line:
                        continue
                    
                    # Check if this line starts a new section
                    new_section = None
                    for section, keywords in sections.items():
                        for keyword in keywords:
                            if line.lower().startswith(f"{keyword}:") or line.lower().startswith(f"{keyword.title()}:"):
                                if current_section and current_content:
                                    vulnerability[current_section] = current_content.strip()
                                new_section = section
                                current_content = line.split(':', 1)[1].strip() if ':' in line else ""
                                break
                        if new_section:
                            break
                    
                    if new_section:
                        current_section = new_section
                    elif current_section:
                        # Continue adding to the current section
                        current_content += f"\n{line}"
                
                # Add the last section
                if current_section and current_content:
                    vulnerability[current_section] = current_content.strip()
                
                # Clean up code snippets
                if "code_snippet" in vulnerability:
                    code = vulnerability["code_snippet"]
                    if "```" in code:
                        code_blocks = re.findall(r"```(?:solidity)?(.*?)```", code, re.DOTALL)
                        if code_blocks:
                            vulnerability["code_snippet"] = code_blocks[0].strip()
        
        return findings
