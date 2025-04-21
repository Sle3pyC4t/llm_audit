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
        import re
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
        identified_project_type = None
        need_more_info = False
        questions_for_engineer = []
        in_questions = False
        
        for line in project_type_assessment.split('\n'):
            if line.startswith('IDENTIFIED_PROJECT_TYPE:'):
                identified_project_type = line.replace('IDENTIFIED_PROJECT_TYPE:', '').strip()
            elif line.startswith('NEED_MORE_INFO:') and 'yes' in line.lower():
                need_more_info = True
            elif line.startswith('QUESTIONS_FOR_ENGINEER:'):
                in_questions = True
            elif in_questions:
                if line.strip() and not line.startswith('CONFIDENCE:'):
                    questions_for_engineer.append(line.strip())
        
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
        
        # Step 3: Query the knowledge base for project-specific vulnerabilities
        logger.info("Querying knowledge base for project-specific vulnerabilities")
        kb_query = f"solidity vulnerabilities {project_type_info}"
        kb_results = self.tool_center.search_knowledge_base(kb_query)
        logger.info(f"Knowledge base search returned {len(kb_results)} results")
        
        # If knowledge base results are limited, also get common Solidity vulnerabilities
        if len(kb_results) < 500:
            logger.info("Limited project-specific knowledge found, adding common vulnerabilities")
            common_kb_results = self.tool_center.search_knowledge_base("solidity vulnerabilities common patterns")
            kb_results = kb_results + "\n\n" + common_kb_results
            logger.info(f"Combined knowledge base results: {len(kb_results)} chars")
        
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
        # This allows the agent to decide when to communicate with other agents based on need
        need_additional_info = {}
        vulnerability_sections = []
        current_section = ""
        current_content = []
        
        # Parse the response to extract individual vulnerability descriptions
        for line in project_specific_vulnerabilities.split('\n'):
            if re.match(NUMBERED_LIST_PATTERN, line) and (
                "vulnerability" in line.lower() or 
                "issue" in line.lower() or 
                "attack" in line.lower() or
                "exploit" in line.lower()
            ):
                # Save the previous section if it exists
                if current_section and current_content:
                    vulnerability_sections.append({
                        "title": current_section,
                        "content": '\n'.join(current_content)
                    })
                
                # Start a new section
                current_section = line.strip()
                current_content = []
            elif current_section:
                current_content.append(line)
        
        # Add the last section
        if current_section and current_content:
            vulnerability_sections.append({
                "title": current_section,
                "content": '\n'.join(current_content)
            })
        
        # For each vulnerability section, check if additional information is needed
        for section in vulnerability_sections:
            if "YES" in section["content"] and (
                "question" in section["content"].lower() or 
                "ask" in section["content"].lower()
            ):
                # Extract questions to ask the Software Engineer
                questions = []
                in_questions = False
                for line in section["content"].split('\n'):
                    if "question" in line.lower() or "ask" in line.lower():
                        in_questions = True
                        continue
                    if in_questions and line.strip() and not line.startswith("YES") and not line.startswith("NO"):
                        questions.append(line.strip())
                
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
        """.format(project_type_info.split('\n')[0] if '\n' in project_type_info else project_type_info)
        
        response = await self.process_message_with_timeout(what_to_ask_message)
        security_questions = response.content
        
        # Extract questions to ask the Software Engineer
        questions_to_ask = []
        for line in security_questions.split('\n'):
            if line.strip() and ('?' in line or line.startswith('-') or re.match(NUMBERED_LIST_PATTERN, line)):
                if not line.startswith('Why'):  # Skip explanation lines
                    questions_to_ask.append(line.strip())
        
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
            """.format(project_type_info.split('\n')[0] if '\n' in project_type_info else project_type_info)
            
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
                        import re
                        code_blocks = re.findall(r"```(?:solidity)?(.*?)```", code, re.DOTALL)
                        if code_blocks:
                            vulnerability["code_snippet"] = code_blocks[0].strip()
                
                # If we have a valid vulnerability with at least title and description
                if "title" in vulnerability and "description" in vulnerability:
                    # Generate a unique ID for the finding
                    import hashlib
                    import time
                    
                    title_hash = hashlib.md5(vulnerability.get("title", "").encode()).hexdigest()[:6]
                    finding_id = f"ISSUE-{title_hash}"
                    
                    finding = {
                        "id": finding_id,
                        "title": vulnerability.get("title", "Unknown Vulnerability"),
                        "type": vulnerability.get("type", "Unknown"),
                        "severity": vulnerability.get("severity", "Medium"),
                        "location": vulnerability.get("location", f"{contract_name}:{function_name}"),
                        "description": vulnerability.get("description", "No description provided"),
                        "impact": vulnerability.get("impact", "No impact provided"),
                        "recommendation": vulnerability.get("recommendation", "No recommendation provided"),
                        "code_snippet": vulnerability.get("code_snippet", "No code snippet provided"),
                        "status": "Pending Validation"
                    }
                    
                    findings.append(finding)
                    
                    # Add to report with enhanced formatting
                    self.tool_center.add_to_report(
                        "Security Findings",
                        "### [{}] {}: {}\n\n"
                        "**Description:** {}\n\n"
                        "**Location:** `{}`\n\n"
                        "**Impact:** {}\n\n"
                        "**Recommendation:** {}\n\n"
                        "**Code Snippet:**\n```solidity\n{}\n```\n\n"
                        .format(
                            finding['severity'],
                            finding['id'],
                            finding['title'],
                            finding['description'],
                            finding['location'],
                            finding['impact'],
                            finding['recommendation'],
                            finding['code_snippet']
                        )
                    )
        
        # If no findings yet, look for general patterns across the codebase
        if not findings:
            logger.info("No specific findings yet, performing general codebase analysis")
            
            # Get the software engineer to provide key contracts for analysis
            key_contracts = await software_engineer.answer_question(
                "What are the 3 most important Solidity contracts in this codebase that should be thoroughly reviewed for security? " 
                "For each, provide the contract name and a brief explanation of why it's security-critical."
            )
            
            # Analyze each key contract
            for line in key_contracts.split('\n'):
                if ':' in line or '-' in line:
                    contract_name = None
                    
                    if ':' in line:
                        contract_name = line.split(':')[0].strip()
                    elif '-' in line:
                        contract_name = line.split('-')[0].strip()
                    
                    if contract_name and any(c.isalpha() for c in contract_name):
                        # Clean up contract name in case it has numbers or other markers
                        import re
                        contract_name = re.sub(r'^\d+\.\s*', '', contract_name)
                        contract_name = contract_name.strip()
                        
                        contract_code = await software_engineer.answer_question(
                            f"Please provide the full code of the contract `{contract_name}`. "
                            f"If it's too large, provide the key functions that handle assets, access control, or other security-critical operations."
                        )
                        
                        # Analyze contract for vulnerabilities
                        message = f"""Analyze the following Solidity contract for security vulnerabilities:
                        
                        Contract: {contract_name}
                        
                        Code:
                        {contract_code}
                        
                        Based on common Solidity vulnerabilities and the following knowledge base results:
                        {kb_results[:1000] if len(kb_results) > 1000 else kb_results}
                        
                        If you identify any vulnerabilities, for each one provide:
                        1. A clear title for the vulnerability
                        2. The vulnerability type (e.g., reentrancy, integer overflow, etc.)
                        3. The severity (Critical, High, Medium, Low)
                        4. The exact location (contract:function:line if possible)
                        5. A description of the vulnerability
                        6. The potential impact if exploited
                        7. A recommendation for fixing it
                        8. The relevant code snippet showing the vulnerability
                        
                        If you don't identify any vulnerabilities in this contract, respond with "No vulnerabilities identified in this contract."
                        """
                        
                        response = await self.process_message_with_timeout(message, timeout=300)
                        analysis = response.content
                        
                        if "no vulnerabilities identified" not in analysis.lower():
                            # Similar parsing logic as above
                            # ... [The parsing logic is the same as above, so not duplicating it here]
                            # Instead of duplicating the parsing code, we should refactor it to a separate function
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
                                    import re
                                    code_blocks = re.findall(r"```(?:solidity)?(.*?)```", code, re.DOTALL)
                                    if code_blocks:
                                        vulnerability["code_snippet"] = code_blocks[0].strip()
                            
                            # If we have a valid vulnerability with at least title and description
                            if "title" in vulnerability and "description" in vulnerability:
                                # Generate a unique ID for the finding
                                import hashlib
                                
                                title_hash = hashlib.md5(vulnerability.get("title", "").encode()).hexdigest()[:6]
                                finding_id = f"ISSUE-{title_hash}"
                                
                                finding = {
                                    "id": finding_id,
                                    "title": vulnerability.get("title", "Unknown Vulnerability"),
                                    "type": vulnerability.get("type", "Unknown"),
                                    "severity": vulnerability.get("severity", "Medium"),
                                    "location": vulnerability.get("location", f"{contract_name}"),
                                    "description": vulnerability.get("description", "No description provided"),
                                    "impact": vulnerability.get("impact", "No impact provided"),
                                    "recommendation": vulnerability.get("recommendation", "No recommendation provided"),
                                    "code_snippet": vulnerability.get("code_snippet", "No code snippet provided"),
                                    "status": "Pending Validation"
                                }
                                
                                findings.append(finding)
                                
                                # Add to report with enhanced formatting
                                self.tool_center.add_to_report(
                                    "Security Findings",
                                    "### [{}] {}: {}\n\n"
                                    "**Description:** {}\n\n"
                                    "**Location:** `{}`\n\n"
                                    "**Impact:** {}\n\n"
                                    "**Recommendation:** {}\n\n"
                                    "**Code Snippet:**\n```solidity\n{}\n```\n\n"
                                    .format(
                                        finding['severity'],
                                        finding['id'],
                                        finding['title'],
                                        finding['description'],
                                        finding['location'],
                                        finding['impact'],
                                        finding['recommendation'],
                                        finding['code_snippet']
                                    )
                                )
        
        logger.info(f"Identified {len(findings)} potential vulnerabilities")
        return findings
    
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