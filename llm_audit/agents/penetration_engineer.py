"""
Penetration Engineer Agent

Responsible for validating vulnerabilities found by the Audit Engineer
and creating proof-of-concept exploits for Solidity smart contracts when possible.
"""

import logging
from typing import Any, Dict, List, Optional

from langchain_core.language_models import BaseChatModel

from .base_agent import BaseAgent
from ..config import Config
from ..tools.tool_center import ToolCenter
from ..llm_providers import LLMProviderFactory

logger = logging.getLogger(__name__)


class PenetrationEngineerAgent(BaseAgent):
    """Penetration Engineer agent for validating smart contract vulnerabilities and creating PoCs"""
    
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
                model_name=config.penetration_engineer_model,
                api_key=config.get_api_key(),
                temperature=0.3
            )
        
        super().__init__(
            name="PenetrationEngineer",
            config=config,
            tool_center=tool_center,
            model=model,
            system_prompt=system_prompt
        )
        
        # Tools specific to this agent
        self.tools = tool_center.get_tools([
            "read_file",
            "list_directory",
            "run_command",
            "add_to_report"
        ])
        
        # Track validated findings
        self.validated_findings: List[Dict[str, Any]] = []
    
    def _get_default_system_prompt(self) -> str:
        """Get the default system prompt for this agent"""
        return f"""You are a Penetration Engineer agent in a multi-agent LLM code auditing system specialized in Solidity smart contract security.

Your primary responsibility is to validate the vulnerabilities identified by the Audit Engineer
and to create proof-of-concept (PoC) exploits for Solidity smart contracts when possible.

The smart contract codebase you are analyzing is located at: {self.config.codebase_path}

Your tasks include:
1. Reviewing vulnerability findings from the Audit Engineer
2. Determining which findings are true positives versus false positives in the Solidity code
3. Creating proof-of-concept exploits for validated Solidity vulnerabilities
4. Documenting exploitation steps and potential impact on the blockchain

When validating Solidity vulnerabilities:
- Carefully analyze the contract code to understand if the issue is actually exploitable
- Consider practical constraints like gas limits, access controls, or validations that might prevent exploitation
- Think creatively about how to bypass protections or chain multiple issues together
- Consider blockchain-specific contexts such as transaction ordering, block manipulation, etc.

When creating PoCs for Solidity vulnerabilities:
- Write clear, non-destructive code that demonstrates the vulnerability (in Solidity, JavaScript/TypeScript with ethers.js, etc.)
- Provide step-by-step instructions for reproducing the issue
- Document the expected outcome when the exploit is successful
- Consider different blockchain environments (mainnet, testnet, local fork)
- Include transaction sequences and required preconditions

You have access to the following tools:
- read_file: Read the contents of a file in the codebase
- list_directory: List the contents of a directory in the codebase
- run_command: Run a shell command and return its output
- add_to_report: Add information to the audit report

For each validated finding, document:
1. Your assessment of the vulnerability (confirmed, potential, or false positive)
2. The proof-of-concept code or steps to reproduce
3. The observed or expected outcome on-chain
4. Any additional notes on exploitability or impact

Respond in a clear, professional manner, focusing on providing accurate technical assessments of Solidity smart contract security.
Ethics note: Your PoCs should be for educational and validation purposes only, not for malicious use.
"""
    
    async def validate_findings(self, findings: List[Dict[str, Any]], software_engineer) -> List[Dict[str, Any]]:
        """Validate Solidity vulnerability findings and create PoCs
        
        Args:
            findings: List of vulnerability findings from the Audit Engineer
            software_engineer: The Software Engineer agent to interact with
            
        Returns:
            List of validated findings with PoCs where applicable
        """
        validated_findings = []
        
        for finding in findings:
            # Skip if this is an error message rather than a finding
            if "error" in finding:
                continue
            
            # First, determine if we need more information to validate this finding
            logger.info(f"Analyzing finding: {finding.get('id', 'Unknown')} - {finding.get('title', 'Unknown')}")
            
            # Ask the agent itself if it needs more information to proceed
            need_info_message = f"""I need to validate the following Solidity vulnerability finding:
            
            ID: {finding.get('id', 'Unknown')}
            Title: {finding.get('title', 'Unknown')}
            Type: {finding.get('type', 'Unknown')}
            Severity: {finding.get('severity', 'Unknown')}
            Location: {finding.get('location', 'Unknown')}
            Description: {finding.get('description', 'Unknown')}
            
            Based on this information, decide if I have enough information to validate this finding or if I need to request additional details.
            Format your response as follows:
            
            HAVE_ENOUGH_INFO: <Yes/No>
            INFORMATION_NEEDED: <If No, specify what information I need from the Software Engineer>
            SPECIFIC_QUESTIONS: <List 2-4 specific questions to ask>
            """
            
            response = await self.process_message(need_info_message)
            info_assessment = response.content
            
            # Parse the response
            need_more_info = "HAVE_ENOUGH_INFO: No" in info_assessment
            specific_questions = []
            in_questions = False
            
            for line in info_assessment.split('\n'):
                if line.startswith('SPECIFIC_QUESTIONS:'):
                    in_questions = True
                    continue
                if in_questions and line.strip():
                    specific_questions.append(line.strip())
            
            # Get more context if needed
            if need_more_info and specific_questions:
                logger.info(f"Requesting additional information for finding {finding.get('id', 'Unknown')}")
                questions_text = "\n".join([f"- {q}" for q in specific_questions])
                query = f"""I'm validating a potential vulnerability in your code and need additional information to properly assess it:
                
                Vulnerability: {finding.get('title', 'Unknown')} ({finding.get('id', 'Unknown')})
                Location: {finding.get('location', 'Unknown')}
                
                To properly validate this finding, please answer these specific questions:
                {questions_text}
                
                Please provide detailed, technical responses based on your understanding of the code.
                """
                
                code_context = await self.communicate("software_engineer", query)
                logger.info(f"Received additional context for finding {finding.get('id', 'Unknown')}")
            else:
                # Get standard code context if we don't need specific information
                if "location" in finding:
                    file_path = finding["location"].split(":")[0]
                    function_name = finding["location"].split(":")[1] if ":" in finding["location"] else None
                    
                    code_context = await software_engineer.answer_question(
                        f"Please provide the Solidity code context around {finding['location']} "
                        f"and explain how this code works in the overall contract flow, focusing on potential "
                        f"security implications. Include any relevant modifiers, inheritance, or state variables."
                    )
                else:
                    code_context = "No specific location provided for this finding."
            
            # Ask the software engineer for additional relevant information
            additional_context_query = f"""For the vulnerability '{finding.get('title', 'Unknown')}' at {finding.get('location', 'Unknown')}, 
            please provide:
            1. Any related functions or contract state variables that interact with this code
            2. The full execution path that could trigger this vulnerability
            3. Any protective measures or checks that are currently in place
            4. Access control mechanisms governing this functionality
            """
            
            additional_context = await self.communicate("software_engineer", additional_context_query)
            
            # Ask the model to validate the finding with the enhanced context
            message = f"""I need to validate the following Solidity smart contract vulnerability finding:
            
            ID: {finding.get('id', 'Unknown')}
            Title: {finding.get('title', 'Unknown')}
            Severity: {finding.get('severity', 'Unknown')}
            Location: {finding.get('location', 'Unknown')}
            Description: {finding.get('description', 'Unknown')}
            Type: {finding.get('type', 'Unknown')}
            
            Code snippet:
            ```solidity
            {finding.get('code_snippet', 'No code snippet provided')}
            ```
            
            Here is the context from the Software Engineer:
            {code_context}
            
            Additional context:
            {additional_context}
            
            Based on this information:
            1. Is this a true positive, potential vulnerability, or false positive in this Solidity contract?
            2. What specific conditions need to be true for this vulnerability to be exploitable on-chain?
            3. How could I create a proof-of-concept to demonstrate this vulnerability?
            4. Are there any blockchain-specific considerations (like gas costs, transaction ordering, etc.) that might affect exploitability?
            """
            
            response = await self.process_message(message)
            validation_result = response.content
            
            # Decide whether to create a PoC or not based on validation
            is_confirmed = any(phrase in validation_result.lower() for phrase in [
                "true positive", "confirmed", "is valid", "exploitable", "vulnerability exists",
                "can be exploited", "is vulnerable"
            ])
            
            should_create_poc = is_confirmed and not any(phrase in validation_result.lower() for phrase in [
                "difficult to exploit", "theoretical", "not practical", "requires privileged access",
                "highly unlikely", "edge case", "cannot be exploited"
            ])
            
            if should_create_poc:
                # First ask the agent if it needs specific information to create a good PoC
                poc_info_query = f"""To create an effective proof-of-concept exploit for this vulnerability:
                
                Vulnerability: {finding.get('title', 'Unknown')}
                Location: {finding.get('location', 'Unknown')}
                
                What specific information do I need from the Software Engineer about:
                1. Contract deployment parameters and initialization
                2. State requirements for the vulnerability
                3. Transaction sequence needed for exploitation
                4. Account permissions or ETH balances needed
                
                Please list specific questions I should ask about implementation details.
                """
                
                response = await self.process_message(poc_info_query)
                poc_questions = response.content
                
                # Extract specific questions about PoC creation
                poc_specific_questions = []
                for line in poc_questions.split('\n'):
                    if ('?' in line or (line.strip().startswith('-') and len(line.strip()) > 2)):
                        poc_specific_questions.append(line.strip())
                
                # Get information needed for PoC creation from Software Engineer
                if poc_specific_questions:
                    questions_text = "\n".join(poc_specific_questions[:5])  # Limit to 5 questions
                    poc_prep_query = f"""I'm creating a proof-of-concept exploit for the '{finding.get('title', 'Unknown')}' vulnerability and need specific technical details:

{questions_text}

Please provide detailed answers based on the actual implementation in the code.
"""
                    
                    poc_prep_info = await self.communicate("software_engineer", poc_prep_query)
                else:
                    # Fallback to standard questions
                    poc_prep_query = f"""To create a proof-of-concept exploit for the vulnerability '{finding.get('title', 'Unknown')}', 
                    I need the following information:
                    1. The constructor parameters and initialization values needed to deploy the contract
                    2. The minimum set of functions and state needed to reproduce the issue
                    3. Any preconditions that need to be set up (like account balances, permissions, etc.)
                    4. The expected normal behavior vs. the exploited behavior
                    
                    Please provide this information in a structured format suitable for creating a test case.
                    """
                    
                    poc_prep_info = await self.communicate("software_engineer", poc_prep_query)
                
                # Create the PoC with all gathered information
                message = f"""Please create a detailed proof-of-concept (PoC) exploit for the following Solidity vulnerability:
                
                ID: {finding.get('id', 'Unknown')}
                Title: {finding.get('title', 'Unknown')}
                Description: {finding.get('description', 'Unknown')}
                Location: {finding.get('location', 'Unknown')}
                
                Validation: {validation_result}
                
                Contract Setup Information:
                {poc_prep_info}
                
                Code Snippet:
                ```solidity
                {finding.get('code_snippet', 'No code snippet provided')}
                ```
                
                Please create:
                
                1. A complete Solidity-based exploit demonstrating the vulnerability with a testing contract
                that includes:
                   - The vulnerable contract (simplified if possible)
                   - A function that demonstrates the exploit
                   - Comments explaining each step of the attack
                
                2. Step-by-step instructions to execute the exploit, including:
                   - Required setup (e.g., network, accounts, initial states)
                   - Sequence of transactions or function calls with exact parameters
                   - The state before and after the exploit
                
                3. Expected outcome if successful, with clear indicators of what constitutes a successful exploit
                
                4. Any prerequisites or assumptions necessary for the exploit to work
                
                5. Explanation of the blockchain mechanism or Solidity feature being exploited
                """
                
                response = await self.process_message(message)
                poc = response.content
                
                # Ask if we want to verify the PoC or if we're confident in it
                verify_query = f"""I've created a proof-of-concept exploit for the '{finding.get('title', 'Unknown')}' vulnerability. Do I need the Software Engineer to validate the technical accuracy of this PoC? Consider factors like:

1. Implementation complexity of the exploit
2. Whether the PoC assumes certain contract behaviors
3. If there might be protective measures I've missed
4. If the exploit requires certain state conditions to work

Should I ask for verification (Yes/No) and why?
"""
                response = await self.process_message(verify_query)
                need_verification = "yes" in response.content.lower()
                
                # Get verification if needed
                if need_verification:
                    poc_verification_query = f"""Please review this proof-of-concept exploit for technical accuracy:
                    
                    Vulnerability: {finding.get('title', 'Unknown')}
                    
                    PoC:
                    {poc}
                    
                    Please verify:
                    1. Would this PoC successfully demonstrate the vulnerability?
                    2. Are there any technical errors or missing steps?
                    3. Are there any ways this PoC could be made more convincing or accurate?
                    """
                    
                    poc_verification = await self.communicate("software_engineer", poc_verification_query)
                else:
                    poc_verification = "The penetration engineer determined that this PoC is technically accurate and does not require additional verification."
                
                # Add validation and PoC to the finding
                validated_finding = finding.copy()
                validated_finding["validation"] = validation_result
                validated_finding["proof_of_concept"] = poc
                validated_finding["poc_verification"] = poc_verification
                validated_finding["status"] = "Confirmed"
                
                validated_findings.append(validated_finding)
                
                # Add to report with enhanced formatting
                self.tool_center.add_to_report(
                    "Proof of Concept Exploits",
                    f"## PoC for {finding.get('id', 'Unknown')}: {finding.get('title', 'Unknown')}\n\n"
                    f"### Vulnerability Summary\n\n"
                    f"**Location:** `{finding.get('location', 'Unknown')}`\n"
                    f"**Severity:** {finding.get('severity', 'Unknown')}\n"
                    f"**Vulnerability Type:** {finding.get('type', 'Unknown')}\n\n"
                    f"### Validation Analysis\n\n{validation_result}\n\n"
                    f"### Proof of Concept\n\n{poc}\n\n"
                    f"### Technical Verification\n\n{poc_verification}\n\n"
                    f"---\n\n"
                )
            else:
                # For findings that can't be confirmed
                
                # Determine why this finding couldn't be confirmed
                reason_query = f"""This vulnerability was assessed as a false positive or unconfirmed:
                
                Title: {finding.get('title', 'Unknown')}
                Description: {finding.get('description', 'Unknown')}
                
                Based on my validation analysis, specifically explain:
                1. Why this was flagged as a potential issue
                2. What evidence suggests it's not a valid vulnerability
                3. Are there any specific protections or constraints that prevent exploitation
                
                Should I ask the software engineer for additional information to confirm why this is not exploitable? (Yes/No)
                """
                
                response = await self.process_message(reason_query)
                reason_analysis = response.content
                
                need_engineer_perspective = "yes" in reason_analysis.lower()
                
                if need_engineer_perspective:
                    potential_fix_query = f"""For the vulnerability '{finding.get('title', 'Unknown')}' that I've assessed as a 
                    false positive or unconfirmed, please provide your analysis:
                    
                    1. Why might this have been flagged as a potential issue?
                    2. What existing protections or constraints prevent this from being exploitable?
                    3. Are there any conditions under which this could become a real vulnerability in the future?
                    """
                    
                    potential_fix = await self.communicate("software_engineer", potential_fix_query)
                else:
                    potential_fix = "Based on my analysis, additional confirmation from the software engineer is not needed."
                
                validated_finding = finding.copy()
                validated_finding["validation"] = validation_result
                validated_finding["status"] = "Unconfirmed"
                validated_finding["potential_fix"] = potential_fix
                validated_finding["analysis"] = reason_analysis
                
                validated_findings.append(validated_finding)
                
                # Add to the unconfirmed findings section
                self.tool_center.add_to_report(
                    "Unconfirmed Findings",
                    f"### Unconfirmed: {finding.get('id', 'Unknown')}: {finding.get('title', 'Unknown')}\n\n"
                    f"**Location:** `{finding.get('location', 'Unknown')}`\n"
                    f"**Severity:** {finding.get('severity', 'Unknown')}\n\n"
                    f"**Description:** {finding.get('description', 'No description provided')}\n\n"
                    f"**Validation:** {validation_result}\n\n"
                    f"**Analysis from Software Engineer:**\n\n{potential_fix}\n\n"
                    f"---\n\n"
                )
        
        self.validated_findings = validated_findings
        return validated_findings
    
    async def run(self, findings: List[Dict[str, Any]], software_engineer) -> List[Dict[str, Any]]:
        """Run the Penetration Engineer agent's main functionality
        
        Args:
            findings: List of vulnerability findings from the Audit Engineer
            software_engineer: The Software Engineer agent to interact with
            
        Returns:
            List of validated findings with PoCs where applicable
        """
        try:
            validated_findings = await self.validate_findings(findings, software_engineer)
            return validated_findings
        except Exception as e:
            logger.error(f"Error running Penetration Engineer agent: {str(e)}")
            return [{"error": f"Failed to run Penetration Engineer agent: {str(e)}"}] 