"""
Base Agent class that defines the common interface for all agents
"""

import logging
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
        self.name = name
        self.config = config
        self.tool_center = tool_center
        self.model = model
        self.system_prompt = system_prompt or self._get_default_system_prompt()
        self.message_history: List[BaseMessage] = [
            SystemMessage(content=self.system_prompt)
        ]
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