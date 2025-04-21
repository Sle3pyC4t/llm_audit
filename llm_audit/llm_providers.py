"""
LLM Provider module for different language model integrations
"""

import os
import logging
import time
from typing import Dict, Any, Optional, List, Type

from langchain_core.language_models import BaseChatModel
from langchain_openai import ChatOpenAI
from langchain_anthropic import ChatAnthropic
from langchain.chat_models.base import BaseChatModel as LangchainBaseChatModel

logger = logging.getLogger(__name__)

# Try to import DeepSeek if available
DEEPSEEK_AVAILABLE = False
try:
    from langchain_community.chat_models import DeepSeekChat
    DEEPSEEK_AVAILABLE = True
except ImportError:
    try:
        # Try a direct implementation if langchain_community version doesn't have it
        from langchain_core.language_models.chat_models import BaseChatModel
        from langchain_core.messages import BaseMessage, AIMessage, HumanMessage, SystemMessage
        from langchain_core.callbacks.manager import CallbackManagerForLLMRun
        import requests
        import json
        
        class DeepSeekChat(BaseChatModel):
            """Custom implementation of DeepSeekChat"""
            
            model: str = "deepseek-chat"
            api_key: str
            temperature: float = 0.1
            max_tokens: Optional[int] = None
            top_p: Optional[float] = None
            request_timeout: Optional[float] = 300.0  # 5 minutes timeout
            
            @property
            def _llm_type(self) -> str:
                return "deepseek-chat"
                
            def _get_actual_model_name(self, model_name: str) -> str:
                """Get the actual model name for DeepSeek API"""
                # Map custom model names to actual API model names
                model_map = {
                    "deepseek-chat": "deepseek-chat",
                    "deepseek-reasoner": "deepseek-chat",
                    "deepseek-coder": "deepseek-coder"
                }
                
                # Default to deepseek-chat if not found
                return model_map.get(model_name, "deepseek-chat")
            
            def _call(
                self,
                messages: List[BaseMessage],
                stop: Optional[List[str]] = None,
                run_manager: Optional[CallbackManagerForLLMRun] = None,
                **kwargs: Any,
            ) -> str:
                """Call the DeepSeek API directly."""
                headers = {
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self.api_key}"
                }
                
                formatted_messages = []
                for message in messages:
                    if isinstance(message, HumanMessage):
                        role = "user"
                    elif isinstance(message, AIMessage):
                        role = "assistant"
                    elif isinstance(message, SystemMessage):
                        role = "system"
                    else:
                        role = "user"
                    
                    formatted_messages.append({
                        "role": role,
                        "content": message.content
                    })
                
                # Use the mapped model name
                actual_model = self._get_actual_model_name(self.model)
                
                payload = {
                    "model": actual_model,
                    "messages": formatted_messages,
                    "temperature": self.temperature,
                }
                
                if self.max_tokens is not None:
                    payload["max_tokens"] = self.max_tokens
                if self.top_p is not None:
                    payload["top_p"] = self.top_p
                if stop is not None:
                    payload["stop"] = stop
                
                logger.info(f"Sending request to DeepSeek API with model {actual_model} (original: {self.model})")
                logger.debug(f"Request payload: {json.dumps(payload, indent=2)}")
                
                start_time = time.time()
                try:
                    logger.info("Calling DeepSeek API...")
                    response = requests.post(
                        "https://api.deepseek.com/v1/chat/completions",
                        headers=headers,
                        json=payload,
                        timeout=self.request_timeout
                    )
                    elapsed_time = time.time() - start_time
                    logger.info(f"DeepSeek API response received in {elapsed_time:.2f} seconds")
                    
                    response.raise_for_status()
                    response_json = response.json()
                    logger.debug(f"Response status: {response.status_code}")
                    
                    message_content = response_json["choices"][0]["message"]["content"]
                    logger.info(f"Received response length: {len(message_content)} characters")
                    return message_content
                except requests.exceptions.Timeout:
                    error_msg = f"DeepSeek API request timed out after {self.request_timeout} seconds"
                    logger.error(error_msg)
                    return f"Error: {error_msg}"
                except requests.exceptions.HTTPError as e:
                    logger.error(f"HTTP error: {e} - Response: {response.text}")
                    return f"Error: HTTP error {response.status_code} - {response.text}"
                except requests.exceptions.RequestException as e:
                    logger.error(f"Request failed: {str(e)}")
                    return f"Error: Request failed - {str(e)}"
                except Exception as e:
                    logger.error(f"Error calling DeepSeek API: {str(e)}")
                    return f"Error: {str(e)}"
                finally:
                    total_time = time.time() - start_time
                    logger.info(f"Total API call time: {total_time:.2f} seconds")
                
            def _generate(
                self,
                messages: List[BaseMessage],
                stop: Optional[List[str]] = None,
                run_manager: Optional[CallbackManagerForLLMRun] = None,
                **kwargs: Any,
            ) -> dict:
                """Generate LLM response."""
                from langchain_core.outputs import ChatGeneration, ChatResult
                
                text = self._call(messages, stop, run_manager, **kwargs)
                generation = ChatGeneration(message=AIMessage(content=text))
                return ChatResult(generations=[generation])
        
        DEEPSEEK_AVAILABLE = True
        logger.info("Using custom DeepSeekChat implementation")
    except ImportError:
        logger.warning("DeepSeek integration not available. Install required packages.")


class LLMProviderFactory:
    """Factory for creating different LLM provider instances"""
    
    @staticmethod
    def create_llm(
        provider_name: str,
        model_name: str,
        api_key: Optional[str] = None,
        temperature: float = 0.1,
        **kwargs
    ) -> BaseChatModel:
        """Create an LLM provider instance
        
        Args:
            provider_name: Name of the provider (openai, anthropic, deepseek)
            model_name: Model name to use
            api_key: API key for the provider
            temperature: Temperature parameter for generation
            **kwargs: Additional parameters for the specific provider
            
        Returns:
            BaseChatModel instance
        """
        provider_name = provider_name.lower()
        
        if provider_name == "openai":
            return ChatOpenAI(
                model=model_name,
                api_key=api_key or os.getenv("OPENAI_API_KEY"),
                temperature=temperature,
                **kwargs
            )
        elif provider_name == "anthropic":
            return ChatAnthropic(
                model=model_name,
                api_key=api_key or os.getenv("ANTHROPIC_API_KEY"),
                temperature=temperature,
                **kwargs
            )
        elif provider_name == "deepseek":
            if not DEEPSEEK_AVAILABLE:
                raise ImportError("DeepSeek integration not available. Install required packages.")
            return DeepSeekChat(
                model=model_name,
                api_key=api_key or os.getenv("DEEPSEEK_API_KEY"),
                temperature=temperature,
                **kwargs
            )
        else:
            raise ValueError(f"Unsupported LLM provider: {provider_name}")
    
    @staticmethod
    def get_default_model_names() -> Dict[str, str]:
        """Get default model names for each provider
        
        Returns:
            Dictionary mapping provider names to default model names
        """
        return {
            "openai": "gpt-4-turbo",
            "anthropic": "claude-3-sonnet-20240229",
            "deepseek": "deepseek-chat"
        } 