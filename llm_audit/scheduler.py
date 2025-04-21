"""
Scheduling Center for LLM Audit

Responsible for coordinating the multi-agent system, creating agent instances,
and facilitating inter-agent communication.
"""

import asyncio
import logging
from typing import Dict, List, Any, Optional

from .config import Config
from .tools.tool_center import ToolCenter
from .agents import (
    BaseAgent,
    SoftwareEngineerAgent,
    AuditEngineerAgent,
    PenetrationEngineerAgent,
    ReportEngineerAgent
)

logger = logging.getLogger(__name__)


class SchedulingCenter:
    """Coordinate the multi-agent system for LLM Audit"""
    
    def __init__(self, config: Config):
        """Initialize the scheduling center
        
        Args:
            config: Configuration object
        """
        self.config = config
        self.tool_center = ToolCenter(config)
        self.agents: Dict[str, BaseAgent] = {}
        self._initialize_agents()
        
        # Audit state
        self.findings: List[Dict[str, Any]] = []
        self.validated_findings: List[Dict[str, Any]] = []
        self.report_path: Optional[str] = None
    
    def _initialize_agents(self):
        """Initialize all agent instances"""
        logger.info("Initializing agents...")
        
        # Software Engineer agent
        self.agents["software_engineer"] = SoftwareEngineerAgent(
            config=self.config,
            tool_center=self.tool_center
        )
        
        # Audit Engineer agent
        self.agents["audit_engineer"] = AuditEngineerAgent(
            config=self.config,
            tool_center=self.tool_center
        )
        
        # Penetration Engineer agent
        self.agents["penetration_engineer"] = PenetrationEngineerAgent(
            config=self.config,
            tool_center=self.tool_center
        )
        
        # Report Engineer agent
        self.agents["report_engineer"] = ReportEngineerAgent(
            config=self.config,
            tool_center=self.tool_center
        )
        
        # Provide each agent with a reference to the scheduler for inter-agent communication
        for name, agent in self.agents.items():
            agent.scheduler = self
        
        logger.info(f"Initialized {len(self.agents)} agents")
    
    async def start_audit(self):
        """Start the audit process"""
        logger.info(f"Starting audit for codebase: {self.config.codebase_path}")
        
        try:
            # Step 1: Software Engineer analyzes the codebase
            logger.info("Step 1: Software Engineer analyzing codebase...")
            software_engineer = self.agents["software_engineer"]
            codebase_analysis = await software_engineer.run()
            logger.info("Codebase analysis completed")
            
            # Add codebase analysis to the report
            logger.info("Adding codebase analysis to report...")
            report_engineer = self.agents["report_engineer"]
            report_engineer.add_to_section("Smart Contract Analysis", codebase_analysis)
            
            # Step 2: Audit Engineer identifies vulnerabilities
            logger.info("Step 2: Audit Engineer identifying vulnerabilities...")
            audit_engineer = self.agents["audit_engineer"] 
            self.findings = await audit_engineer.run(software_engineer)
            logger.info(f"Identified {len(self.findings)} potential vulnerabilities")
            
            # Step 3: Penetration Engineer validates vulnerabilities
            logger.info("Step 3: Penetration Engineer validating vulnerabilities...")
            penetration_engineer = self.agents["penetration_engineer"]
            self.validated_findings = await penetration_engineer.run(self.findings, software_engineer)
            logger.info(f"Validated {len(self.validated_findings)} vulnerabilities")
            
            # Step 4: Report Engineer generates the final report
            logger.info("Step 4: Report Engineer generating report...")
            self.report_path = await report_engineer.run(self.validated_findings)
            logger.info(f"Report generated: {self.report_path}")
            
            return self.report_path
            
        except Exception as e:
            logger.error(f"Error during audit: {str(e)}")
            raise
    
    def get_agent(self, agent_name: str) -> Optional[BaseAgent]:
        """Get an agent by name
        
        Args:
            agent_name: Name of the agent
            
        Returns:
            Agent instance if found, None otherwise
        """
        # Normalize agent name: convert to lowercase and replace spaces/underscores
        normalized_name = agent_name.lower().replace(' ', '_').replace('-', '_')
        
        # Try direct lookup first
        if normalized_name in self.agents:
            return self.agents[normalized_name]
        
        # Try fuzzy matching if direct lookup fails
        for name, agent in self.agents.items():
            if name.lower().replace(' ', '_').replace('-', '_') == normalized_name:
                return agent
                
        # Try to match based on the agent's class name
        for name, agent in self.agents.items():
            if agent.name.lower().replace(' ', '_').replace('-', '_') == normalized_name:
                return agent
                
        return None
    
    async def send_message(self, from_agent: str, to_agent: str, message: str) -> str:
        """Send a message from one agent to another
        
        Args:
            from_agent: Name of the sending agent
            to_agent: Name of the receiving agent
            message: Message content
            
        Returns:
            Response from the receiving agent
        """
        sender = self.get_agent(from_agent)
        receiver = self.get_agent(to_agent)
        
        if not sender or not receiver:
            error = f"Invalid agent names: from={from_agent}, to={to_agent}"
            logger.error(error)
            return error
        
        logger.info(f"Message from {from_agent} to {to_agent}: {message[:50]}...")
        
        # Process the message with the receiving agent
        response = await receiver.process_message(message)
        
        logger.info(f"Response from {to_agent}: {response.content[:50]}...")
        return response.content
    
    def get_report_path(self) -> Optional[str]:
        """Get the path to the generated report
        
        Returns:
            Path to the report if generated, None otherwise
        """
        return self.report_path 