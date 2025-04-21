"""
Base Agent class that defines the common interface for all agents
"""

import logging
import os
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, BaseMessage

from ..config import Config
from ..tools.tool_center import ToolCenter

logger = logging.getLogger(__name__)


class BaseAgent(ABC):
    """Base class for all agents in the LLM Audit system"""
    
    def __init__(
        self,
        name: str,
        config: Config,
        tool_center: ToolCenter,
        model: Optional[BaseChatModel] = None,
        system_prompt: Optional[str] = None
    ):
        """Initialize the agent
        
        Args:
            name: Agent name
            config: Configuration object
            tool_center: Tool center for accessing tools
            model: LLM to use for the agent
            system_prompt: Optional system prompt override
        """
        self.name = name
        self.config = config
        self.tool_center = tool_center
        self.model = model
        self.system_prompt = system_prompt or self._get_default_system_prompt()
        self.message_history: List[BaseMessage] = [
            SystemMessage(content=self.system_prompt)
        ]
        
        # Scheduler reference (will be set by the scheduler when it initializes the agent)
        self.scheduler = None
        
        logger.info(f"Initialized agent: {self.name}")
    
    @abstractmethod
    def _get_default_system_prompt(self) -> str:
        """Get the default system prompt for this agent"""
        pass
    
    async def process_message(self, message: str) -> AIMessage:
        """Process a message and return the agent's response"""
        if not self.model:
            raise ValueError(f"No language model configured for agent: {self.name}")
        
        # Add the message to history
        self.message_history.append(HumanMessage(content=message))
        
        # Get response from the model
        response = await self.model.agenerate([self.message_history])
        ai_message = response.generations[0][0].message
        
        # Add the response to history
        self.message_history.append(ai_message)
        
        logger.debug(f"Agent {self.name} processed message: {message[:100]}...")
        return ai_message
    
    async def answer_question(self, question: str) -> str:
        """Answer a specific question
        
        Args:
            question: The question to answer
            
        Returns:
            The answer as a string
        """
        response = await self.process_message(question)
        return response.content
    
    async def communicate(self, target_agent_name: str, message: str) -> str:
        """Communicate with another agent to get information or assistance
        
        Args:
            target_agent_name: Name of the agent to communicate with (software_engineer, audit_engineer, etc)
            message: Message to send
            
        Returns:
            Response from the target agent
        """
        if self.scheduler is None:
            logger.warning(f"{self.name} attempted to communicate with {target_agent_name} but no scheduler was provided")
            return f"ERROR: Cannot communicate with {target_agent_name} because no scheduler reference was provided."
        
        try:
            # Normalize agent names to avoid format inconsistencies
            from_agent_name = self.name.lower().replace(' ', '_')
            to_agent_name = target_agent_name.lower().replace(' ', '_')
            
            logger.info(f"{self.name} communicating with {target_agent_name}: {message[:100]}...")
            response = await self.scheduler.send_message(
                from_agent=from_agent_name,
                to_agent=to_agent_name,
                message=message
            )
            logger.info(f"Received response from {target_agent_name}")
            return response
        except Exception as e:
            logger.error(f"Error communicating with {target_agent_name}: {str(e)}")
            return f"ERROR: Failed to communicate with {target_agent_name}: {str(e)}"
    
    def add_message_to_history(self, message: BaseMessage) -> None:
        """Add a message to the agent's history"""
        self.message_history.append(message)
    
    def clear_history(self) -> None:
        """Clear the message history except for the system prompt"""
        self.message_history = [SystemMessage(content=self.system_prompt)]
    
    @abstractmethod
    async def run(self, *args, **kwargs) -> Any:
        """Run the agent's main functionality"""
        pass 