# AI Secure Code Analyzer & Deployment Agent

A Streamlit application that analyzes GitHub repositories for security vulnerabilities and provides automated deployment capabilities.

## Features

- **Local LLM Integration**: Uses Ollama to process code locally without relying on external APIs
- **GitHub Repository Scanning**: Securely authenticate with GitHub and scan your repositories
- **Automated Code Vulnerability Analysis**: Detects security vulnerabilities like SQL injection, hardcoded secrets, etc.
- **Code Context Understanding**: Analyzes repository structure and generates project summaries
- **Autonomous CI/CD Deployment**: Automatically deploys repositories that pass security checks
- **User-Friendly Interface**: Interactive visualizations and comprehensive reporting

## Prerequisites

- [Ollama](https://ollama.ai/) installed and running locally
- Python 3.8+
- Docker (optional, for deployment features)

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/yourusername/secure-code-analyzer.git
   cd secure-code-analyzer
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Ensure Ollama is installed and running:
   ```
   # Download a model like llama3 or codellama
   ollama pull llama3
   ```

## Usage

1. Start the application:
   ```
   streamlit run app.py
   ```

2. Navigate to the URL shown in the terminal (usually http://localhost:8501)

3. Follow these steps in the application:
   - Authenticate with GitHub using your Personal Access Token
   - Select a repository to analyze
   - Review the vulnerability report
   - Deploy your application if it passes security checks

## Security Considerations

- All code analysis is performed locally
- GitHub tokens are stored only in session state and not persisted
- The application follows security best practices for handling sensitive data

## Configuration

You can adjust the following settings in the sidebar:
- Ollama model selection
- Deployment settings
- Security scan thresholds

## License

MIT License
