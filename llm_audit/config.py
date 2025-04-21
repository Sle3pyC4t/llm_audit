"""
LLM Audit Configuration

Centralized configuration settings and constants for the LLM Audit system.
This module provides a consistent way to access configuration values across the codebase.
"""

import os
import logging
import yaml
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class Config:
    """
    Configuration manager for the LLM Audit system.
    
    This class provides access to configuration settings from environment variables,
    configuration files, and default values. It ensures consistent configuration
    across the application.
    """

    # Default configuration values
    DEFAULT_CONFIG = {
        # LLM Model Settings
        "model": {
            "name": "gpt-4",
            "temperature": 0.2,
            "max_tokens": 4000,
            "top_p": 1.0,
            "frequency_penalty": 0.0,
            "presence_penalty": 0.0
        },
        
        # Agent Settings
        "agents": {
            "software_engineer": {
                "name": "Software Engineer",
                "model": "gpt-4",
                "temperature": 0.2,
                "system_prompt": "You are an experienced software engineer specializing in smart contract development."
            },
            "audit_engineer": {
                "name": "Audit Engineer",
                "model": "gpt-4",
                "temperature": 0.1,
                "system_prompt": "You are an expert audit engineer specializing in smart contract security vulnerabilities."
            },
            "penetration_engineer": {
                "name": "Penetration Engineer",
                "model": "gpt-4",
                "temperature": 0.1,
                "system_prompt": "You are an expert penetration tester specializing in smart contract security exploits."
            },
            "report_engineer": {
                "name": "Report Engineer",
                "model": "gpt-4",
                "temperature": 0.3,
                "system_prompt": "You are an expert report writer specializing in security audit reports."
            }
        },
        
        # Audit Settings
        "audit": {
            "max_files_to_analyze": 20,
            "file_extensions": [".sol", ".js", ".ts", ".py", ".json"],
            "excluded_directories": ["node_modules", ".git", "build", "dist", "venv"],
            "max_vulnerabilities_per_file": 10,
            "timeout_seconds": 3600  # 1 hour timeout for the entire audit
        },
        
        # Logging Settings
        "logging": {
            "level": "INFO",
            "format": "%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            "file": "llm_audit.log"
        },
        
        # Reporting Settings
        "reporting": {
            "output_format": "markdown",
            "output_directory": "reports",
            "include_code_snippets": True,
            "include_recommendations": True,
            "severity_levels": ["Critical", "High", "Medium", "Low", "Informational"]
        },
        
        # API Keys (these should be overridden by environment variables)
        "api_keys": {
            "openai": ""
        },
        
        # Project-specific settings (will be set by main.py)
        "project": {
            "codebase_path": "",
            "report_format": "markdown",
            "output_dir": "reports",
            "knowledge_base_path": "knowledge_base",
            "llm_provider": "openai"
        }
    }

    _instance = None

    def __new__(cls):
        """Implement singleton pattern for configuration."""
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        """Initialize configuration from environment variables and config files."""
        if self._initialized:
            return
            
        self._config = self.DEFAULT_CONFIG.copy()
        self._load_from_file()
        self._load_from_environment()
        self._initialized = True
        
        # Set up logging based on configuration
        self._configure_logging()

    def _load_from_file(self):
        """Load configuration from a YAML file if available."""
        config_paths = [
            os.path.join(os.getcwd(), "llm_audit_config.yaml"),
            os.path.expanduser("~/.llm_audit_config.yaml"),
            os.environ.get("LLM_AUDIT_CONFIG", "")
        ]
        
        for path in config_paths:
            if path and os.path.exists(path):
                try:
                    with open(path, 'r') as config_file:
                        file_config = yaml.safe_load(config_file)
                        if file_config:
                            self._merge_config(self._config, file_config)
                    logger.info(f"Loaded configuration from {path}")
                    break
                except Exception as e:
                    logger.warning(f"Error loading configuration from {path}: {str(e)}")

    def _load_from_environment(self):
        """Load configuration from environment variables."""
        # API Keys have highest priority and should always be loaded from environment
        self._config["api_keys"]["openai"] = os.environ.get("OPENAI_API_KEY", self._config["api_keys"]["openai"])
        
        # Load model name if specified
        if os.environ.get("LLM_AUDIT_MODEL"):
            self._config["model"]["name"] = os.environ.get("LLM_AUDIT_MODEL")
            
        # Load logging level if specified
        if os.environ.get("LLM_AUDIT_LOG_LEVEL"):
            self._config["logging"]["level"] = os.environ.get("LLM_AUDIT_LOG_LEVEL")
            
        # Load other specific environment variables
        if os.environ.get("LLM_AUDIT_OUTPUT_DIR"):
            self._config["reporting"]["output_directory"] = os.environ.get("LLM_AUDIT_OUTPUT_DIR")
            
        # Load agent-specific model overrides
        for agent in self._config["agents"]:
            env_var = f"LLM_AUDIT_{agent.upper()}_MODEL"
            if os.environ.get(env_var):
                self._config["agents"][agent]["model"] = os.environ.get(env_var)

    def _merge_config(self, base: Dict[str, Any], override: Dict[str, Any]):
        """
        Recursively merge override dict into base dict.
        
        Args:
            base: Base configuration dictionary
            override: Override configuration dictionary
        """
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value

    def _configure_logging(self):
        """Configure logging based on settings."""
        log_level = getattr(logging, self._config["logging"]["level"].upper(), logging.INFO)
        log_format = self._config["logging"]["format"]
        log_file = self._config["logging"]["file"]
        
        # Create formatter
        formatter = logging.Formatter(log_format)
        
        # Configure root logger
        root_logger = logging.getLogger()
        root_logger.setLevel(log_level)
        
        # Clear existing handlers
        for handler in root_logger.handlers[:]:
            root_logger.removeHandler(handler)
        
        # Create console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        root_logger.addHandler(console_handler)
        
        # Create file handler if specified
        if log_file:
            try:
                file_handler = logging.FileHandler(log_file)
                file_handler.setFormatter(formatter)
                root_logger.addHandler(file_handler)
            except Exception as e:
                logger.warning(f"Could not create log file {log_file}: {str(e)}")

    def set(self, key_path: str, value: Any):
        """
        Set a configuration value using a dot-notation path.
        
        Args:
            key_path: Dot-notation path to the configuration value (e.g., "project.codebase_path")
            value: Value to set
        """
        keys = key_path.split('.')
        config_dict = self._config
        
        # Navigate to the right level in the config dictionary
        for key in keys[:-1]:
            if key not in config_dict:
                config_dict[key] = {}
            elif not isinstance(config_dict[key], dict):
                config_dict[key] = {}
            config_dict = config_dict[key]
            
        # Set the value at the final level
        config_dict[keys[-1]] = value
        logger.debug(f"Set config value for {key_path}: {value}")

    def get(self, key_path: str, default: Any = None) -> Any:
        """
        Get a configuration value using a dot-notation path.
        
        Args:
            key_path: Dot-notation path to the configuration value (e.g., "model.name")
            default: Default value to return if the key is not found
            
        Returns:
            The configuration value or the default value
        """
        keys = key_path.split('.')
        value = self._config
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
                
        return value
    
    def get_model_config(self, agent_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get model configuration for a specific agent or the default model.
        
        Args:
            agent_name: Optional name of the agent
            
        Returns:
            Dictionary with model configuration
        """
        if agent_name and agent_name in self._config["agents"]:
            # Create a model config based on the agent's settings
            agent_config = self._config["agents"][agent_name]
            model_config = self._config["model"].copy()
            
            # Override with agent-specific settings
            model_config["name"] = agent_config.get("model", model_config["name"])
            model_config["temperature"] = agent_config.get("temperature", model_config["temperature"])
            
            return model_config
        else:
            # Return the default model config
            return self._config["model"].copy()
    
    def get_all(self) -> Dict[str, Any]:
        """
        Get the entire configuration dictionary.
        
        Returns:
            Complete configuration dictionary
        """
        return self._config.copy()
        
    # Properties for commonly used config values
    @property
    def codebase_path(self) -> str:
        """Get the path to the codebase being audited"""
        return self.get("project.codebase_path", "")
        
    @codebase_path.setter
    def codebase_path(self, value: str):
        """Set the path to the codebase being audited"""
        self.set("project.codebase_path", value)
        
    @property
    def report_format(self) -> str:
        """Get the report format"""
        return self.get("project.report_format", "markdown")
        
    @report_format.setter
    def report_format(self, value: str):
        """Set the report format"""
        self.set("project.report_format", value)
        
    @property
    def output_dir(self) -> str:
        """Get the output directory for reports"""
        return self.get("project.output_dir", "reports")
        
    @output_dir.setter
    def output_dir(self, value: str):
        """Set the output directory for reports"""
        self.set("project.output_dir", value)
        
    @property
    def knowledge_base_path(self) -> str:
        """Get the path to the knowledge base"""
        return self.get("project.knowledge_base_path", "knowledge_base")
        
    @knowledge_base_path.setter
    def knowledge_base_path(self, value: str):
        """Set the path to the knowledge base"""
        self.set("project.knowledge_base_path", value)
        
    @property
    def llm_provider(self) -> str:
        """Get the LLM provider"""
        return self.get("project.llm_provider", "openai")
        
    @llm_provider.setter
    def llm_provider(self, value: str):
        """Set the LLM provider"""
        self.set("project.llm_provider", value)
        
    # Properties for agent-specific model names
    @property
    def software_engineer_model(self) -> str:
        """Get the model name for the Software Engineer agent"""
        return self.get("agents.software_engineer.model", self.get("model.name", "gpt-4"))
        
    @software_engineer_model.setter
    def software_engineer_model(self, value: str):
        """Set the model name for the Software Engineer agent"""
        self.set("agents.software_engineer.model", value)
        
    @property
    def audit_engineer_model(self) -> str:
        """Get the model name for the Audit Engineer agent"""
        return self.get("agents.audit_engineer.model", self.get("model.name", "gpt-4"))
        
    @audit_engineer_model.setter
    def audit_engineer_model(self, value: str):
        """Set the model name for the Audit Engineer agent"""
        self.set("agents.audit_engineer.model", value)
        
    @property
    def penetration_engineer_model(self) -> str:
        """Get the model name for the Penetration Engineer agent"""
        return self.get("agents.penetration_engineer.model", self.get("model.name", "gpt-4"))
        
    @penetration_engineer_model.setter
    def penetration_engineer_model(self, value: str):
        """Set the model name for the Penetration Engineer agent"""
        self.set("agents.penetration_engineer.model", value)
        
    @property
    def report_engineer_model(self) -> str:
        """Get the model name for the Report Engineer agent"""
        return self.get("agents.report_engineer.model", self.get("model.name", "gpt-4"))
        
    @report_engineer_model.setter
    def report_engineer_model(self, value: str):
        """Set the model name for the Report Engineer agent"""
        self.set("agents.report_engineer.model", value)
        
    def get_api_key(self) -> str:
        """Get the API key for the current LLM provider"""
        provider = self.llm_provider.lower()
        if provider == "openai":
            return self.get("api_keys.openai", "")
        elif provider == "anthropic":
            return self.get("api_keys.anthropic", "")
        elif provider == "deepseek":
            return self.get("api_keys.deepseek", "")
        return ""


# Create a singleton instance for global access
config = Config()


def get_config(key_path: str = None, default: Any = None) -> Any:
    """
    Global function to access configuration values.
    
    Args:
        key_path: Optional dot-notation path to the configuration value
        default: Default value to return if the key is not found
        
    Returns:
        The configuration value, the default value, or the entire config if no key_path is provided
    """
    if key_path:
        return config.get(key_path, default)
    return config.get_all() 