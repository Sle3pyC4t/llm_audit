# LLM Audit - Multi-Agent Code Auditing Tool

A multi-agent LLM-based code auditing tool that leverages large language models to identify vulnerabilities and security issues in codebases, with a special focus on Solidity smart contracts.

## Key Features

- Multi-agent architecture with specialized roles (Software Engineer, Audit Engineer, Penetration Engineer, Report Engineer)
- Centralized scheduling and dispatching of agent tasks
- Knowledge base integration for extended capabilities
- Comprehensive report generation

## Prerequisites

- Python 3.9 or higher
- pip (Python package installer)
- API keys for one or more of the following LLM providers:
  - OpenAI
  - Anthropic
  - DeepSeek

## Installation

1. Clone this repository
```bash
git clone https://github.com/yourusername/llm_audit.git
cd llm_audit
```

2. Create a virtual environment (recommended)
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Set up environment variables
```bash
cp .env.example .env
# Edit .env with your API keys and other configurations
```

## Configuration

Edit the `.env` file with your specific settings:

```
# Choose LLM provider (openai, anthropic, deepseek)
LLM_PROVIDER=deepseek

# API keys for different providers
OPENAI_API_KEY=your_openai_api_key_here
ANTHROPIC_API_KEY=your_anthropic_api_key_here
DEEPSEEK_API_KEY=your_deepseek_api_key_here

# Optional: Specific models for each agent
SOFTWARE_ENGINEER_MODEL=deepseek-chat
AUDIT_ENGINEER_MODEL=deepseek-reasoner
PENETRATION_ENGINEER_MODEL=deepseek-reasoner
REPORT_ENGINEER_MODEL=deepseek-chat
```

## Usage

Run the application with a path to the codebase you want to audit:

```bash
python main.py /path/to/solidity/codebase
```

### Additional Options

```
usage: main.py [-h] [--report-format {markdown,html,pdf}] [--output-dir OUTPUT_DIR]
               [--knowledge-base KNOWLEDGE_BASE] [--llm-provider {openai,anthropic,deepseek}]
               [--verbose]
               codebase_path

positional arguments:
  codebase_path         Path to the smart contract codebase to audit

options:
  -h, --help            show this help message and exit
  --report-format {markdown,html,pdf}
                        Format of the generated report (default: markdown)
  --output-dir OUTPUT_DIR
                        Directory to store the audit report (default: ./reports)
  --knowledge-base KNOWLEDGE_BASE
                        Path to knowledge base (default: ./knowledge_base)
  --llm-provider {openai,anthropic,deepseek}
                        LLM provider to use (default: from .env)
  --verbose, -v         Enable verbose output
```

## Example

```bash
# Basic usage
python main.py ./examples/simple_token

# Generate HTML report and store in custom directory
python main.py ./examples/defi_protocol --report-format html --output-dir ./my_reports

# Use a specific LLM provider with verbose logging
python main.py ./examples/nft_marketplace --llm-provider openai --verbose
```

## Design Principles

1. Use LLMs wherever possible instead of traditional static analysis for better adaptability
2. Implement a multi-agent system for more focused and efficient auditing
3. Extend capabilities through knowledge base integration

## Architecture

- **Scheduling Center**: Manages agent instances and coordinates communication
- **Tool Center**: Provides utilities for knowledge base access, report generation, and external system interaction
- **Agent Cluster**: Collection of specialized agents working together to analyze code

## Troubleshooting

- **API Key Issues**: Ensure your API keys are correctly set in the `.env` file
- **Model Availability**: Check if the selected models are available for your LLM provider
- **Log Files**: Check the `llm_audit.log` file for detailed error messages

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 