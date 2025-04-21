"""
Knowledge Base Utility

Provides centralized access to security knowledge bases for smart contract auditing.
This ensures consistent knowledge retrieval across different agents.
"""

import logging
import os
import json
from typing import Dict, List, Optional, Any, Union
import re

logger = logging.getLogger(__name__)

class KnowledgeBase:
    """Utility class for retrieving security knowledge from various sources."""
    
    # Common vulnerability categories for all Solidity projects
    COMMON_VULNERABILITY_CATEGORIES = [
        "Reentrancy",
        "Integer Overflow/Underflow",
        "Front-Running",
        "Access Control Issues",
        "Denial of Service",
        "Logic Errors",
        "Oracle Manipulation",
        "Flashloan Attacks"
    ]
    
    # Mapping of project types to vulnerability categories
    PROJECT_VULNERABILITY_MAPPING = {
        "erc20": [
            "Integer Overflow/Underflow",
            "Access Control Issues",
            "Logic Errors",
            "Approval Race Conditions",
            "Transfer Logic Flaws"
        ],
        "defi": [
            "Reentrancy",
            "Oracle Manipulation",
            "Flashloan Attacks",
            "Price Manipulation",
            "Slippage Issues",
            "Front-Running",
            "Logic Errors"
        ],
        "nft": [
            "Signature Replay",
            "Metadata Manipulation",
            "Access Control Issues",
            "Enumeration Vulnerabilities",
            "Royalty Bypassing"
        ],
        "dao": [
            "Voting Manipulation",
            "Governance Attacks",
            "Front-Running",
            "Access Control Issues",
            "Logic Errors"
        ],
        "lending": [
            "Collateral Value Manipulation",
            "Interest Rate Calculation Flaws",
            "Liquidation Vulnerabilities",
            "Oracle Manipulation",
            "Flashloan Attacks"
        ],
        "amm": [
            "Price Manipulation",
            "Slippage Issues",
            "Front-Running",
            "Flash Loan Exploits",
            "Impermanent Loss Manipulation"
        ],
        "staking": [
            "Reward Calculation Flaws",
            "Unstaking Vulnerabilities",
            "Access Control Issues",
            "Logic Errors"
        ]
    }
    
    # Detailed descriptions of vulnerabilities
    VULNERABILITY_DESCRIPTIONS = {
        "Reentrancy": {
            "description": "Allows attackers to repeatedly enter a contract before previous calls complete",
            "patterns": ["call.value", "transfer", "send", "external calls before state updates"],
            "severity": "High",
            "recommendation": "Implement checks-effects-interactions pattern and use ReentrancyGuard"
        },
        "Integer Overflow/Underflow": {
            "description": "Arithmetic operations reach the maximum or minimum size of the type",
            "patterns": ["arithmetic operations", "SafeMath not used", "unchecked arithmetic"],
            "severity": "High",
            "recommendation": "Use SafeMath library or Solidity 0.8+ with built-in overflow checks"
        },
        "Front-Running": {
            "description": "Transactions can be seen in mempool and exploited by observers",
            "patterns": ["commit-reveal", "timestamps for ordering", "valuable transactions"],
            "severity": "Medium",
            "recommendation": "Implement commit-reveal schemes or use private mempools"
        },
        "Access Control Issues": {
            "description": "Improper validation of who can call certain functions",
            "patterns": ["onlyOwner", "missing modifiers", "weak access controls"],
            "severity": "High",
            "recommendation": "Use OpenZeppelin AccessControl or custom role-based modifiers"
        },
        "Oracle Manipulation": {
            "description": "Price feeds or other oracle data can be manipulated",
            "patterns": ["price oracles", "single data source", "time-weighted average price not used"],
            "severity": "High",
            "recommendation": "Use multiple oracles, TWAP, and Chainlink decentralized oracles"
        },
        "Flashloan Attacks": {
            "description": "Exploits using loans that are borrowed and repaid in same transaction",
            "patterns": ["price calculations", "liquidity pools", "token swaps"],
            "severity": "High",
            "recommendation": "Check token balances before and after operations, use TWAP prices"
        }
    }
    
    # Security patterns by project type
    SECURITY_PATTERNS = {
        "defi": {
            "price_manipulation": "Check for price manipulation in liquidity pools",
            "flash_loan_protection": "Protect against flash loan attacks",
            "slippage_checking": "Implement proper slippage checks",
            "oracle_safety": "Use multiple oracles for critical operations"
        },
        "nft": {
            "signature_verification": "Implement secure signature verification",
            "metadata_protection": "Secure metadata from manipulation",
            "enumeration_safety": "Avoid expensive enumeration operations",
            "royalty_enforcement": "Ensure royalties cannot be bypassed"
        },
        "dao": {
            "voting_security": "Implement secure voting mechanisms",
            "proposal_timelocks": "Use timelocks for proposals",
            "quorum_management": "Implement proper quorum requirements"
        }
    }

    def __init__(self, tool_center=None):
        """
        Initialize the KnowledgeBase.
        
        Args:
            tool_center: The tool center for accessing external tools (optional)
        """
        self.tool_center = tool_center
        self._common_vulnerabilities = self._load_common_vulnerabilities()
        
    def _load_common_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Load common vulnerabilities from a local resource.
        
        Returns:
            List of common vulnerability definitions
        """
        # This is a fallback list of common vulnerabilities
        return [
            {
                "name": "Reentrancy",
                "description": "Allows attackers to repeatedly enter a contract before previous calls complete",
                "severity": "High",
                "patterns": ["call.value", "transfer", "send", "external calls before state updates"]
            },
            {
                "name": "Integer Overflow/Underflow",
                "description": "Arithmetic operations reach the maximum or minimum size of the type",
                "severity": "High",
                "patterns": ["arithmetic operations", "SafeMath not used", "unchecked arithmetic"]
            },
            {
                "name": "Front-Running",
                "description": "Transactions can be seen in mempool and exploited by observers",
                "severity": "Medium",
                "patterns": ["commit-reveal", "timestamps for ordering", "valuable transactions"]
            },
            {
                "name": "Access Control Issues",
                "description": "Improper validation of who can call certain functions",
                "severity": "High",
                "patterns": ["onlyOwner", "missing modifiers", "weak access controls"]
            },
            {
                "name": "Denial of Service",
                "description": "Contract functions can be made unavailable",
                "severity": "Medium",
                "patterns": ["loops with unbounded operations", "gas limits", "external calls that may fail"]
            },
            {
                "name": "Logic Errors",
                "description": "Flaws in business logic of the contract",
                "severity": "Variable",
                "patterns": ["complex calculations", "edge cases", "incorrect assumptions"]
            },
            {
                "name": "Oracle Manipulation",
                "description": "Price feeds or other oracle data can be manipulated",
                "severity": "High",
                "patterns": ["price oracles", "single data source", "time-weighted average price not used"]
            },
            {
                "name": "Flashloan Attacks",
                "description": "Exploits using loans that are borrowed and repaid in same transaction",
                "severity": "High",
                "patterns": ["price calculations", "liquidity pools", "token swaps"]
            }
        ]

    def get_vulnerabilities_by_project_type(self, project_type: str) -> List[Dict[str, Any]]:
        """
        Get vulnerabilities specific to a project type.
        
        Args:
            project_type: The type of project (DeFi, NFT, etc.)
            
        Returns:
            List of vulnerability definitions relevant to the project type
        """
        logger.info(f"Retrieving vulnerabilities for project type: {project_type}")
        
        # Try to get vulnerabilities from the tool center if available
        if self.tool_center:
            try:
                # Prepare a query for project-specific vulnerabilities
                query = f"What are the common security vulnerabilities in {project_type} projects? " \
                        f"Please include specific vulnerability names, descriptions, and code patterns to look for."
                
                response = self.tool_center.query_knowledge_base(query)
                
                if response and len(response) > 50:  # Simple check that we got meaningful content
                    logger.info(f"Retrieved vulnerability information from knowledge base")
                    return self._parse_vulnerabilities_response(response, project_type)
            except Exception as e:
                logger.warning(f"Error querying knowledge base: {str(e)}")
        
        # Fallback to common vulnerabilities with project-specific filtering
        logger.info("Using fallback common vulnerabilities")
        return self._filter_vulnerabilities_for_project(project_type)
    
    def _parse_vulnerabilities_response(self, response: str, project_type: str) -> List[Dict[str, Any]]:
        """
        Parse vulnerabilities from knowledge base response.
        
        Args:
            response: The response from the knowledge base
            project_type: The project type for context
            
        Returns:
            List of parsed vulnerability definitions
        """
        from .response_parser import ResponseParser
        
        vulnerabilities = []
        
        # Try to extract bulleted or numbered lists
        items = ResponseParser.extract_bulleted_list(response)
        if not items:
            items = ResponseParser.extract_numbered_list(response)
        
        # If we found structured items, process them
        if items:
            for item in items:
                # Try to extract a vulnerability name from the first line or bold text
                name_match = item.split('\n')[0].strip()
                name = name_match.replace('**', '').replace('__', '').strip()
                
                # Get description from the rest of the item
                description = item.strip()
                if name and len(name) < 100:  # Simple validation that we have a reasonable name
                    vulnerability = {
                        "name": name,
                        "description": description,
                        "severity": self._estimate_severity(description),
                        "patterns": self._extract_patterns(description),
                        "project_type": project_type
                    }
                    vulnerabilities.append(vulnerability)
        
        # If we couldn't parse structured items, try a more generic approach
        if not vulnerabilities:
            # Look for potential vulnerability names using common terminology
            names = [m.group(0) for m in 
                    re.finditer(r"(?i)(?:vulnerability|attack|exploit|issue):?\s*([^\n.]+)", response)]
            
            for name in names:
                vulnerability = {
                    "name": name.strip(),
                    "description": self._find_context(response, name, 200),
                    "severity": "Medium",  # Default when we can't determine
                    "patterns": [],
                    "project_type": project_type
                }
                vulnerabilities.append(vulnerability)
        
        # If we still don't have any vulnerabilities, merge with common ones
        if not vulnerabilities:
            logger.warning("Failed to parse vulnerabilities from response")
            vulnerabilities = self._filter_vulnerabilities_for_project(project_type)
        
        return vulnerabilities
    
    def _estimate_severity(self, description: str) -> str:
        """
        Estimate severity from vulnerability description.
        
        Args:
            description: Vulnerability description
            
        Returns:
            Estimated severity level
        """
        description_lower = description.lower()
        
        if any(term in description_lower for term in 
               ["critical", "severe", "catastrophic", "very high"]):
            return "Critical"
        elif any(term in description_lower for term in 
                ["high", "serious", "significant"]):
            return "High"
        elif any(term in description_lower for term in 
                ["medium", "moderate", "important"]):
            return "Medium"
        elif any(term in description_lower for term in 
                ["low", "minor", "small"]):
            return "Low"
        else:
            return "Medium"  # Default to medium if can't determine
    
    def _extract_patterns(self, description: str) -> List[str]:
        """
        Extract potential code patterns from description.
        
        Args:
            description: Vulnerability description
            
        Returns:
            List of extracted patterns
        """
        patterns = []
        
        # Look for code examples
        from .response_parser import ResponseParser
        code_blocks = ResponseParser.extract_code_blocks(description)
        if code_blocks:
            patterns.extend([block.strip() for block in code_blocks if len(block.strip()) < 100])
        
        # Look for phrases that might indicate patterns
        pattern_indicators = [
            "watch for", "look for", "pattern", "example", "such as", "e.g.", "like",
            "vulnerable", "check if", "avoid", "prevent", "function", "solidity"
        ]
        
        for indicator in pattern_indicators:
            if indicator in description.lower():
                context = self._find_context(description.lower(), indicator, 50)
                if context and len(context) < 100:
                    patterns.append(context)
        
        return patterns[:5]  # Limit to 5 most relevant patterns
    
    def _find_context(self, text: str, term: str, context_size: int) -> str:
        """
        Find context around a term in text.
        
        Args:
            text: The text to search
            term: The term to find context for
            context_size: The number of characters of context to include
            
        Returns:
            Context string around the term
        """
        term_index = text.lower().find(term.lower())
        if term_index == -1:
            return ""
        
        start = max(0, term_index - context_size // 2)
        end = min(len(text), term_index + len(term) + context_size // 2)
        
        # Adjust to start at word boundary
        while start > 0 and text[start].isalnum():
            start -= 1
        
        # Adjust to end at word boundary
        while end < len(text) - 1 and text[end].isalnum():
            end += 1
            
        return text[start:end].strip()
    
    def _filter_vulnerabilities_for_project(self, project_type: str) -> List[Dict[str, Any]]:
        """
        Filter common vulnerabilities for relevance to project type.
        
        Args:
            project_type: The type of project
            
        Returns:
            Filtered list of vulnerabilities
        """
        project_type_lower = project_type.lower()
        
        # Make a copy of the common vulnerabilities
        vulnerabilities = self._common_vulnerabilities.copy()
        
        # Add project-specific vulnerabilities
        if "defi" in project_type_lower or "finance" in project_type_lower:
            vulnerabilities.extend([
                {
                    "name": "Price Manipulation",
                    "description": "Price feeds can be manipulated through flash loans or other means",
                    "severity": "Critical",
                    "patterns": ["price calculation", "liquidity pool", "oracle"]
                },
                {
                    "name": "Slippage Issues",
                    "description": "Improper handling of slippage in token swaps",
                    "severity": "Medium",
                    "patterns": ["swap", "slippage", "deadline", "price impact"]
                }
            ])
        elif "nft" in project_type_lower:
            vulnerabilities.extend([
                {
                    "name": "Signature Replay",
                    "description": "NFT signatures can be reused multiple times",
                    "severity": "High",
                    "patterns": ["signature", "ecrecover", "nonce not used"]
                },
                {
                    "name": "Metadata Manipulation",
                    "description": "NFT metadata can be changed after minting",
                    "severity": "Medium",
                    "patterns": ["metadata", "tokenURI", "baseURI"]
                }
            ])
        elif "dao" in project_type_lower or "governance" in project_type_lower:
            vulnerabilities.extend([
                {
                    "name": "Voting Manipulation",
                    "description": "Votes can be manipulated through flash loans or similar",
                    "severity": "High",
                    "patterns": ["voting", "quorum", "snapshot", "proposal"]
                }
            ])
        elif "lending" in project_type_lower:
            vulnerabilities.extend([
                {
                    "name": "Collateral Value Manipulation",
                    "description": "Collateral value can be manipulated to drain funds",
                    "severity": "Critical",
                    "patterns": ["collateral", "liquidation", "loan to value", "oracle"]
                }
            ])
        
        return vulnerabilities

    def get_security_patterns(self, project_type: str, vulnerability: str = None) -> List[Dict[str, Any]]:
        """
        Get security patterns to look for based on project type and optional vulnerability.
        
        Args:
            project_type: The type of project
            vulnerability: Optional specific vulnerability to get patterns for
            
        Returns:
            List of security patterns to check
        """
        logger.info(f"Retrieving security patterns for {project_type}")
        
        patterns = []
        
        # Get vulnerabilities first
        vulnerabilities = self.get_vulnerabilities_by_project_type(project_type)
        
        # Filter by specific vulnerability if provided
        if vulnerability:
            vulnerabilities = [v for v in vulnerabilities 
                              if vulnerability.lower() in v["name"].lower()]
        
        # Extract patterns from vulnerabilities
        for vuln in vulnerabilities:
            for pattern in vuln.get("patterns", []):
                patterns.append({
                    "vulnerability": vuln["name"],
                    "severity": vuln["severity"],
                    "pattern": pattern,
                    "description": vuln["description"]
                })
        
        # Add general security patterns for the project type
        patterns.extend(self._get_general_security_patterns(project_type))
        
        return patterns
    
    def _get_general_security_patterns(self, project_type: str) -> List[Dict[str, Any]]:
        """
        Get general security patterns for a project type.
        
        Args:
            project_type: The type of project
            
        Returns:
            List of general security patterns
        """
        project_type_lower = project_type.lower()
        
        patterns = [
            {
                "vulnerability": "General Security",
                "severity": "Medium",
                "pattern": "selfdestruct",
                "description": "Contracts using selfdestruct can be destroyed, potentially locking funds"
            },
            {
                "vulnerability": "General Security",
                "severity": "Medium",
                "pattern": "tx.origin",
                "description": "Using tx.origin for authentication is vulnerable to phishing attacks"
            },
            {
                "vulnerability": "General Security",
                "severity": "Medium",
                "pattern": "block.timestamp",
                "description": "block.timestamp can be manipulated by miners within a certain range"
            },
            {
                "vulnerability": "General Security",
                "severity": "High",
                "pattern": "assembly",
                "description": "Inline assembly bypasses Solidity safety features"
            }
        ]
        
        # Add project-specific patterns
        if "defi" in project_type_lower or "finance" in project_type_lower:
            patterns.extend([
                {
                    "vulnerability": "General Security",
                    "severity": "High",
                    "pattern": "token balance before/after",
                    "description": "Check token balances before and after operations to prevent attacks"
                }
            ])
        elif "nft" in project_type_lower:
            patterns.extend([
                {
                    "vulnerability": "General Security",
                    "severity": "Medium",
                    "pattern": "tokenURI",
                    "description": "Ensure tokenURI cannot be manipulated after minting"
                }
            ])
        
        return patterns

    def get_security_best_practices(self, project_type: str) -> List[str]:
        """
        Get security best practices for a project type.
        
        Args:
            project_type: The type of project
            
        Returns:
            List of security best practices
        """
        logger.info(f"Retrieving security best practices for {project_type}")
        
        # Common best practices
        practices = [
            "Use OpenZeppelin's SafeMath or Solidity 0.8+ for arithmetic operations",
            "Follow the checks-effects-interactions pattern to prevent reentrancy",
            "Use specific functions like safeTransfer instead of transfer for ERC20 tokens",
            "Implement proper access control with role-based permissions",
            "Add emergency pause functionality for critical functions",
            "Use events to log important state changes and operations",
            "Avoid using block.timestamp for critical timing logic",
            "Limit the gas used in loops to prevent DOS attacks",
            "Use pull-over-push pattern for payment distribution"
        ]
        
        # Project-specific best practices
        project_type_lower = project_type.lower()
        
        if "defi" in project_type_lower or "finance" in project_type_lower:
            practices.extend([
                "Use time-weighted average prices (TWAP) for price oracles",
                "Implement slippage protection for token swaps",
                "Add checks for minimum/maximum values in financial calculations",
                "Use multiple independent price oracles for critical operations"
            ])
        elif "nft" in project_type_lower:
            practices.extend([
                "Implement EIP-712 for secure signature verification",
                "Use an incrementing nonce for each address to prevent signature replay",
                "Store metadata on IPFS or similar decentralized storage",
                "Implement royalty mechanisms following EIP-2981"
            ])
        elif "dao" in project_type_lower or "governance" in project_type_lower:
            practices.extend([
                "Implement timelock for governance proposals",
                "Use token snapshots to prevent flash loan governance attacks",
                "Require proposal submission deposits to prevent spam"
            ])
        
        return practices

    @classmethod
    def get_vulnerability_categories(cls, project_type: str) -> List[str]:
        """Get vulnerability categories for a specific project type
        
        Args:
            project_type: The type of project (e.g., 'solidity', 'defi')
            
        Returns:
            List of vulnerability categories relevant to the project type
        """
        project_type = project_type.lower()
        
        # Check for direct matches
        if project_type in cls.PROJECT_VULNERABILITY_MAPPING:
            return cls.PROJECT_VULNERABILITY_MAPPING[project_type]
        
        # Check for partial matches
        for key in cls.PROJECT_VULNERABILITY_MAPPING:
            if key in project_type or project_type in key:
                return cls.PROJECT_VULNERABILITY_MAPPING[key]
        
        # Default to common vulnerabilities if no match
        logger.warning(f"No specific vulnerabilities found for project type: {project_type}. Using generic categories.")
        return cls.COMMON_VULNERABILITY_CATEGORIES
    
    @classmethod
    def get_vulnerability_description(cls, vulnerability_type: str) -> Dict[str, Any]:
        """Get detailed information about a specific vulnerability type
        
        Args:
            vulnerability_type: The type of vulnerability
            
        Returns:
            Dictionary with vulnerability details
        """
        # First try exact match
        if vulnerability_type in cls.VULNERABILITY_DESCRIPTIONS:
            return cls.VULNERABILITY_DESCRIPTIONS[vulnerability_type]
        
        # Try case-insensitive match
        for vuln_type, description in cls.VULNERABILITY_DESCRIPTIONS.items():
            if vuln_type.lower() == vulnerability_type.lower():
                return description
        
        # Try partial match
        for vuln_type, description in cls.VULNERABILITY_DESCRIPTIONS.items():
            if vuln_type.lower() in vulnerability_type.lower() or vulnerability_type.lower() in vuln_type.lower():
                return description
        
        logger.warning(f"Vulnerability description not found for: {vulnerability_type}")
        return {
            "description": f"Information about {vulnerability_type} is not available in the knowledge base.",
            "patterns": [],
            "severity": "Unknown",
            "recommendation": "Consult security documentation or experts for this specific vulnerability type."
        }
    
    @classmethod
    def get_security_patterns(cls, project_type: str) -> Dict[str, str]:
        """Get security patterns for a specific project type
        
        Args:
            project_type: The type of project
            
        Returns:
            Dictionary of security pattern names to descriptions
        """
        project_type = project_type.lower()
        
        # Check for direct matches
        if project_type in cls.SECURITY_PATTERNS:
            return cls.SECURITY_PATTERNS[project_type]
        
        # Check for partial matches
        for key in cls.SECURITY_PATTERNS:
            if key in project_type or project_type in key:
                return cls.SECURITY_PATTERNS[key]
        
        logger.warning(f"No specific security patterns found for project type: {project_type}")
        return {}
    
    @classmethod
    def load_custom_knowledge_base(cls, file_path: str) -> bool:
        """Load custom knowledge base from a JSON file
        
        Args:
            file_path: Path to the JSON file containing custom knowledge
            
        Returns:
            True if loading was successful, False otherwise
        """
        try:
            if not os.path.exists(file_path):
                logger.error(f"Knowledge base file not found: {file_path}")
                return False
                
            with open(file_path, 'r') as file:
                data = json.load(file)
                
            # Update vulnerability categories
            if 'vulnerability_categories' in data:
                for project_type, categories in data['vulnerability_categories'].items():
                    cls.PROJECT_VULNERABILITY_MAPPING[project_type] = categories
            
            # Update vulnerability descriptions
            if 'vulnerability_descriptions' in data:
                cls.VULNERABILITY_DESCRIPTIONS.update(data['vulnerability_descriptions'])
            
            # Update security patterns
            if 'security_patterns' in data:
                for project_type, patterns in data['security_patterns'].items():
                    cls.SECURITY_PATTERNS[project_type] = patterns
                    
            logger.info(f"Successfully loaded custom knowledge base from {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading custom knowledge base: {str(e)}")
            return False
    
    @classmethod
    def get_vulnerability_patterns(cls, project_type: str) -> Dict[str, List[str]]:
        """Get vulnerability patterns for a specific project type
        
        Args:
            project_type: The type of project
            
        Returns:
            Dictionary mapping vulnerability types to lists of patterns
        """
        categories = cls.get_vulnerability_categories(project_type)
        patterns = {}
        
        for category in categories:
            if category in cls.VULNERABILITY_DESCRIPTIONS:
                patterns[category] = cls.VULNERABILITY_DESCRIPTIONS[category].get("patterns", [])
        
        return patterns 