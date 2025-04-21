#!/usr/bin/env python3
"""
LLM Audit - Multi-Agent Solidity Smart Contract Auditing Tool
Main entry point for the application
"""

import os
import sys
import argparse
import logging
import asyncio
from dotenv import load_dotenv

from llm_audit.scheduler import SchedulingCenter
from llm_audit.config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("llm_audit.log")
    ]
)
logger = logging.getLogger(__name__)

async def run_audit(config: Config):
    """Run the audit process asynchronously
    
    Args:
        config: Configuration object
    
    Returns:
        Path to the generated report
    """
    # Initialize and run the scheduling center
    logger.info(f"Starting LLM Audit for Solidity contracts: {config.codebase_path}")
    scheduler = SchedulingCenter(config)
    
    try:
        report_path = await scheduler.start_audit()
        logger.info(f"Audit completed. Report saved to: {config.output_dir}")
        return report_path
    except Exception as e:
        logger.error(f"Audit failed: {str(e)}", exc_info=True)
        sys.exit(1)

def main():
    # Load environment variables
    load_dotenv()
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="LLM Audit - Multi-Agent Solidity Smart Contract Auditing Tool")
    parser.add_argument("codebase_path", help="Path to the smart contract codebase to audit")
    parser.add_argument("--report-format", choices=["markdown", "html", "pdf"], default="markdown",
                        help="Format of the generated report")
    parser.add_argument("--output-dir", help="Directory to store the audit report",
                        default=os.getenv("REPORT_OUTPUT_DIR", "./reports"))
    parser.add_argument("--knowledge-base", help="Path to knowledge base",
                        default=os.getenv("KNOWLEDGE_BASE_PATH", "./knowledge_base"))
    parser.add_argument("--llm-provider", choices=["openai", "anthropic", "deepseek"], 
                        default=os.getenv("LLM_PROVIDER", "openai"),
                        help="LLM provider to use (openai, anthropic, deepseek)")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Adjust logging level if verbose
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Check if the codebase path exists
    if not os.path.exists(args.codebase_path):
        logger.error(f"Codebase path does not exist: {args.codebase_path}")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
        
    # Create configuration - Using singleton pattern correctly
    config = Config()
    
    # Set properties on the config object
    config.codebase_path = os.path.abspath(args.codebase_path)
    config.report_format = args.report_format
    config.output_dir = os.path.abspath(args.output_dir)
    config.knowledge_base_path = os.path.abspath(args.knowledge_base)
    config.llm_provider = args.llm_provider
    
    # Run the audit asynchronously
    asyncio.run(run_audit(config))

if __name__ == "__main__":
    main() 