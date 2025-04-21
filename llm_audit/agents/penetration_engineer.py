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
                
            # Get more context about the vulnerability location
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
            
            # Ask the model to validate the finding
            message = f"""I need to validate the following Solidity smart contract vulnerability finding:
            
            ID: {finding.get('id', 'Unknown')}
            Title: {finding.get('title', 'Unknown')}
            Severity: {finding.get('severity', 'Unknown')}
            Location: {finding.get('location', 'Unknown')}
            Description: {finding.get('description', 'Unknown')}
            
            Here is the context from the Software Engineer:
            {code_context}
            
            Based on this information:
            1. Is this a true positive, potential vulnerability, or false positive in this Solidity contract?
            2. What specific conditions need to be true for this vulnerability to be exploitable on-chain?
            3. How could I create a proof-of-concept to demonstrate this vulnerability?
            4. Are there any blockchain-specific considerations (like gas costs, transaction ordering, etc.) that might affect exploitability?
            """
            
            response = await self.process_message(message)
            validation_result = response.content
            
            # Generate a PoC if the vulnerability is confirmed
            if "true positive" in validation_result.lower() or "confirmed" in validation_result.lower():
                message = f"""Please create a proof-of-concept (PoC) exploit for the following Solidity vulnerability:
                
                ID: {finding.get('id', 'Unknown')}
                Title: {finding.get('title', 'Unknown')}
                Description: {finding.get('description', 'Unknown')}
                Location: {finding.get('location', 'Unknown')}
                
                Validation: {validation_result}
                
                Please create:
                
                1. A complete Solidity-based exploit demonstrating the vulnerability
                (You can create a test contract and function that exploits the vulnerability)
                
                2. Step-by-step instructions to execute the exploit, including:
                   - Required setup (e.g., network, accounts, initial states)
                   - Sequence of transactions or function calls
                   - Parameter values to use
                
                3. Expected outcome if successful
                
                4. Any prerequisites or assumptions necessary for the exploit to work
                """
                
                response = await self.process_message(message)
                poc = response.content
                
                # Add validation and PoC to the finding
                validated_finding = finding.copy()
                validated_finding["validation"] = validation_result
                validated_finding["proof_of_concept"] = poc
                validated_finding["status"] = "Confirmed"
                
                validated_findings.append(validated_finding)
                
                # Add to report
                self.tool_center.add_to_report(
                    "Proof of Concept Exploits",
                    f"## PoC for {finding.get('id', 'Unknown')}: {finding.get('title', 'Unknown')}\n\n"
                    f"### Validation\n\n{validation_result}\n\n"
                    f"### Proof of Concept\n\n{poc}\n\n"
                )
            else:
                # For findings that can't be confirmed
                validated_finding = finding.copy()
                validated_finding["validation"] = validation_result
                validated_finding["status"] = "Unconfirmed or False Positive"
                
                validated_findings.append(validated_finding)
                
                # Add to report
                self.tool_center.add_to_report(
                    "Unconfirmed Findings",
                    f"## Assessment of {finding.get('id', 'Unknown')}: {finding.get('title', 'Unknown')}\n\n"
                    f"{validation_result}\n\n"
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