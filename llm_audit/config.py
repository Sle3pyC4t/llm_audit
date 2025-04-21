"""
Configuration module for LLM Audit
"""

import os
from dataclasses import dataclass
from typing import Optional, Literal, Dict

from .llm_providers import LLMProviderFactory


@dataclass
class Config:
    """Configuration for the LLM Audit tool"""
    
    # Path to the codebase being audited
    codebase_path: str
    
    # Output directory for reports
    output_dir: str
    
    # Format of the generated report
    report_format: Literal["markdown", "html", "pdf"] = "markdown"
    
    # Path to the knowledge base
    knowledge_base_path: str = "./knowledge_base"
    
    # LLM provider settings (openai, anthropic, deepseek)
    llm_provider: str = os.getenv("LLM_PROVIDER", "openai")
    
    # LLM model settings
    software_engineer_model: str = os.getenv("SOFTWARE_ENGINEER_MODEL", "")
    audit_engineer_model: str = os.getenv("AUDIT_ENGINEER_MODEL", "")
    penetration_engineer_model: str = os.getenv("PENETRATION_ENGINEER_MODEL", "")
    report_engineer_model: str = os.getenv("REPORT_ENGINEER_MODEL", "")
    
    # API keys for different providers
    openai_api_key: Optional[str] = os.getenv("OPENAI_API_KEY")
    anthropic_api_key: Optional[str] = os.getenv("ANTHROPIC_API_KEY")
    deepseek_api_key: Optional[str] = os.getenv("DEEPSEEK_API_KEY")
    
    def __post_init__(self):
        """Validate configuration after initialization"""
        self._validate_api_keys()
        self._set_default_models()
        
        if not os.path.exists(self.codebase_path):
            raise ValueError(f"Codebase path does not exist: {self.codebase_path}")
            
        # Create knowledge base directory if it doesn't exist
        if not os.path.exists(self.knowledge_base_path):
            os.makedirs(self.knowledge_base_path)
            
        # Create output directory if it doesn't exist
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
    
    def _validate_api_keys(self):
        """Validate that the required API keys are available"""
        if self.llm_provider == "openai" and not self.openai_api_key:
            raise ValueError("OPENAI_API_KEY environment variable must be set when using OpenAI provider")
        
        if self.llm_provider == "anthropic" and not self.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY environment variable must be set when using Anthropic provider")
        
        if self.llm_provider == "deepseek" and not self.deepseek_api_key:
            raise ValueError("DEEPSEEK_API_KEY environment variable must be set when using DeepSeek provider")
    
    def _set_default_models(self):
        """Set default model names if not provided"""
        default_models = LLMProviderFactory.get_default_model_names()
        default_model = default_models.get(self.llm_provider, default_models["openai"])
        
        if not self.software_engineer_model:
            self.software_engineer_model = default_model
        
        if not self.audit_engineer_model:
            self.audit_engineer_model = default_model
        
        if not self.penetration_engineer_model:
            self.penetration_engineer_model = default_model
        
        if not self.report_engineer_model:
            self.report_engineer_model = default_model
    
    def get_api_key(self) -> Optional[str]:
        """Get the API key for the configured provider
        
        Returns:
            API key for the configured provider
        """
        if self.llm_provider == "openai":
            return self.openai_api_key
        elif self.llm_provider == "anthropic":
            return self.anthropic_api_key
        elif self.llm_provider == "deepseek":
            return self.deepseek_api_key
        else:
            return None 