# app.py
import streamlit as st
import os
import tempfile
import time
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from github import Github, GithubException
from git import Repo
import subprocess
import json
import hashlib
import re
import base64
from langchain_community.llms import Ollama
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate
import yaml
from io import BytesIO
import shutil
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import matplotlib
matplotlib.use('Agg')

# Set page configuration
st.set_page_config(
    page_title="AI Secure Code Analyzer & Deployment Agent",
    page_icon="🔒",
    layout="wide",
)

# Define CSS
st.markdown("""
<style>
    .main {
        background-color: black;
    }
    .stButton>button {
        background-color: #4CAF50;
        color: white;
        border: none;
        border-radius: 4px;
        padding: 10px 24px;
    }
    .vulnerability-critical {
        color: #721c24;
        background-color: #f8d7da;
        padding: 10px;
        border-radius: 5px;
        margin: 5px 0;
    }
    .vulnerability-high {
        color: #856404;
        background-color: #fff3cd;
        padding: 10px;
        border-radius: 5px;
        margin: 5px 0;
    }
    .vulnerability-medium {
        color: #0c5460;
        background-color: #d1ecf1;
        padding: 10px;
        border-radius: 5px;
        margin: 5px 0;
    }
    .vulnerability-low {
        color: #155724;
        background-color: #d4edda;
        padding: 10px;
        border-radius: 5px;
        margin: 5px 0;
    }
    .dashboard-card {
        background-color: white;
        border-radius: 10px;
        padding: 20px;
        box-shadow: 2px 2px 10px rgba(0,0,0,0.1);
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state variables
if 'github_token' not in st.session_state:
    st.session_state.github_token = None
if 'repos' not in st.session_state:
    st.session_state.repos = None
if 'selected_repo' not in st.session_state:
    st.session_state.selected_repo = None
if 'scan_results' not in st.session_state:
    st.session_state.scan_results = None
if 'project_summary' not in st.session_state:
    st.session_state.project_summary = None
if 'tech_stack' not in st.session_state:
    st.session_state.tech_stack = None
if 'deployment_status' not in st.session_state:
    st.session_state.deployment_status = None
if 'scan_progress' not in st.session_state:
    st.session_state.scan_progress = 0
if 'ollama_model' not in st.session_state:
    st.session_state.ollama_model = "deepseek-r1:latest"  # Default Ollama model
if 'deployment_config' not in st.session_state:
    st.session_state.deployment_config = {
        'platform': 'docker',
        'enabled': True
    }

# Function to check Ollama availability
def check_ollama():
    try:
        llm = Ollama(model=st.session_state.ollama_model)
        response = llm("Hello")
        return True
    except Exception as e:
        return False

# Function to authenticate with GitHub
def github_authenticate(token):
    try:
        g = Github(token)
        user = g.get_user()
        # Test API access
        user.login
        return g, user
    except GithubException as e:
        st.error(f"GitHub Authentication Error: {e}")
        return None, None

# Function to clone repository
def clone_repository(repo_full_name, token, temp_dir):
    clone_url = f"https://{token}@github.com/{repo_full_name}.git"
    try:
        repo = Repo.clone_from(clone_url, temp_dir)
        return True
    except Exception as e:
        st.error(f"Error cloning repository: {e}")
        return False

# Function to detect programming languages and frameworks in the repository
def detect_tech_stack(repo_path):
    tech_stack = {
        'languages': {},
        'frameworks': [],
        'dependencies': []
    }
    
    # Check for common project files
    file_indicators = {
        'Python': ['requirements.txt', 'setup.py', 'Pipfile', 'pyproject.toml'],
        'JavaScript': ['package.json', 'package-lock.json', 'yarn.lock'],
        'Java': ['pom.xml', 'build.gradle', '.java'],
        'C#': ['.csproj', '.sln'],
        'PHP': ['composer.json', 'composer.lock'],
        'Ruby': ['Gemfile', 'Gemfile.lock'],
        'Go': ['go.mod', 'go.sum'],
        'Rust': ['Cargo.toml', 'Cargo.lock'],
    }
    
    # Framework indicators
    framework_indicators = {
        'React': ['react', 'jsx'],
        'Vue': ['vue'],
        'Angular': ['angular'],
        'Django': ['django'],
        'Flask': ['flask'],
        'Spring': ['springframework'],
        'Laravel': ['laravel'],
        'Ruby on Rails': ['rails'],
        'ASP.NET': ['asp.net'],
        'Express': ['express'],
    }
    
    # Count files by extension
    for root, dirs, files in os.walk(repo_path):
        # Skip .git directory
        if '.git' in dirs:
            dirs.remove('.git')
        
        for file in files:
            # Get file extension
            _, ext = os.path.splitext(file)
            if ext:
                ext = ext[1:].lower()  # Remove the dot and convert to lowercase
                if ext in tech_stack['languages']:
                    tech_stack['languages'][ext] += 1
                else:
                    tech_stack['languages'][ext] = 1
            
            # Check for specific files indicating languages
            file_path = os.path.join(root, file)
            for lang, indicators in file_indicators.items():
                for indicator in indicators:
                    if file.endswith(indicator) or indicator in file.lower():
                        if lang not in tech_stack['frameworks']:
                            tech_stack['languages'][lang] = tech_stack['languages'].get(lang, 0) + 5  # Add more weight
            
            # Check for frameworks in dependency files
            if file in ['package.json', 'requirements.txt', 'pom.xml', 'composer.json', 'Gemfile']:
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        for framework, keywords in framework_indicators.items():
                            for keyword in keywords:
                                if keyword in content.lower() and framework not in tech_stack['frameworks']:
                                    tech_stack['frameworks'].append(framework)
                except Exception:
                    pass  # Skip files that can't be read
    
    # Sort languages by count
    sorted_languages = dict(sorted(tech_stack['languages'].items(), key=lambda item: item[1], reverse=True))
    tech_stack['languages'] = sorted_languages
    
    # Get the top 5 languages
    top_languages = list(sorted_languages.keys())[:5]
    
    # Determine primary language
    if top_languages:
        tech_stack['primary_language'] = top_languages[0]
    else:
        tech_stack['primary_language'] = "Unknown"
    
    return tech_stack

# LLM Functions
def init_ollama_llm():
    try:
        return Ollama(model=st.session_state.ollama_model)
    except Exception as e:
        st.error(f"Error initializing Ollama LLM: {e}")
        return None

def analyze_code_snippet(llm, code_snippet, language):
    prompt_template = PromptTemplate(
        input_variables=["code", "language"],
        template="""
        Analyze the following {language} code for security vulnerabilities:
        
        ```{language}
        {code}
        ```
        
        Focus on identifying:
        1. SQL injection vulnerabilities
        2. Hard-coded secrets (API keys, passwords)
        3. Code injection risks
        4. Authentication & authorization weaknesses
        5. XSS vulnerabilities
        6. Insecure data handling
        
        For each vulnerability found, provide:
        - Vulnerability type
        - Severity (Critical, High, Medium, Low)
        - Brief description
        - Remediation steps
        
        Format the output as JSON:
        {{
          "vulnerabilities": [
            {{
              "type": "vulnerability_type",
              "severity": "severity_level",
              "description": "brief_description",
              "remediation": "remediation_steps"
            }}
          ]
        }}
        
        If no vulnerabilities are found, return an empty array for "vulnerabilities".
        """
    )
    
    chain = LLMChain(llm=llm, prompt=prompt_template)
    
    try:
        response = chain.run(code=code_snippet, language=language)
        # Try to parse the JSON response
        try:
            json_response = json.loads(response)
            return json_response
        except json.JSONDecodeError:
            # If JSON parsing fails, extract JSON from the text
            match = re.search(r'({.*})', response, re.DOTALL)
            if match:
                try:
                    json_response = json.loads(match.group(1))
                    return json_response
                except json.JSONDecodeError:
                    pass
            return {"vulnerabilities": []}
    except Exception as e:
        st.error(f"Error analyzing code: {e}")
        return {"vulnerabilities": []}

def generate_project_summary(llm, repo_info, tech_stack):
    prompt_template = PromptTemplate(
        input_variables=["repo_name", "repo_description", "tech_stack"],
        template="""
        Generate a concise but comprehensive summary of the following GitHub repository:
        
        Repository Name: {repo_name}
        Repository Description: {repo_description}
        Technical Stack: {tech_stack}
        
        Please include:
        1. The main purpose of this project
        2. Key features or components
        3. Architecture overview based on the tech stack
        4. Potential use cases
        
        Format the response as a well-structured paragraph without using bullet points.
        """
    )
    
    chain = LLMChain(llm=llm, prompt=prompt_template)
    
    try:
        repo_description = repo_info.description if repo_info.description else "No description available"
        tech_stack_str = f"Primary language: {tech_stack['primary_language']}, Frameworks: {', '.join(tech_stack['frameworks'])}"
        
        response = chain.run(
            repo_name=repo_info.name,
            repo_description=repo_description,
            tech_stack=tech_stack_str
        )
        return response
    except Exception as e:
        st.error(f"Error generating project summary: {e}")
        return "Could not generate project summary due to an error."

# Functions for vulnerability scanning
def scan_repository_for_vulnerabilities(repo_path, llm):
    results = {
        'vulnerabilities': [],
        'statistics': {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'files_scanned': 0,
            'total_issues': 0
        }
    }
    
    # Patterns for detecting potential security issues
    patterns = {
        'hardcoded_secrets': [
            r'password\s*=\s*["\'](?!{{)(?!\$)(?!%)(?!\$\{)([^"\']+)["\']',
            r'api[_]?key\s*=\s*["\']([^"\']+)["\']',
            r'secret\s*=\s*["\']([^"\']+)["\']',
            r'token\s*=\s*["\']([^"\']+)["\']',
            r'BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY',
        ],
        'sql_injection': [
            r'execute\(\s*["\']SELECT.*\s*\+\s*.*["\']',
            r'executeQuery\(\s*["\']SELECT.*\s*\+\s*.*["\']',
            r'query\(\s*["\']SELECT.*\s*\+\s*.*["\']',
            r'(\$|@)sql\s*=.*\$_',
        ],
        'xss_vulnerabilities': [
            r'innerHTML\s*=',
            r'document\.write\(',
            r'eval\(',
        ],
        'insecure_file_operations': [
            r'os\.system\(',
            r'subprocess\.call\(',
            r'exec\(',
        ]
    }
    
    # File extensions to scan
    extensions_to_scan = [
        '.py', '.js', '.jsx', '.ts', '.tsx', '.php', '.java', '.cs', '.go', '.rb',
        '.html', '.htm', '.xml', '.json', '.yml', '.yaml', '.sh', '.bash', '.sql'
    ]
    
    total_files = sum(1 for root, _, files in os.walk(repo_path) 
                     for file in files 
                     if any(file.endswith(ext) for ext in extensions_to_scan))
    
    # Progress tracking
    progress_step = 100 / (total_files if total_files > 0 else 1)
    files_processed = 0
    
    # Scan files
    for root, dirs, files in os.walk(repo_path):
        # Skip .git directory
        if '.git' in dirs:
            dirs.remove('.git')
            
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, repo_path)
            
            # Only scan files with specific extensions
            if not any(file.endswith(ext) for ext in extensions_to_scan):
                continue
                
            try:
                # Get file extension to determine language
                _, ext = os.path.splitext(file)
                language = ext[1:] if ext else "text"
                
                # Read file content
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                # Skip empty files
                if not content.strip():
                    continue
                    
                results['statistics']['files_scanned'] += 1
                
                # Check for pattern-based vulnerabilities
                pattern_matches = []
                
                for vuln_type, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        matches = re.finditer(pattern, content, re.IGNORECASE)
                        for match in matches:
                            line_start = content[:match.start()].count('\n') + 1
                            line_content = content.split('\n')[line_start-1] if line_start <= len(content.split('\n')) else ""
                            
                            if vuln_type == 'hardcoded_secrets':
                                # Only consider as vulnerability if it's likely a real secret
                                potential_secret = match.group(1) if match.groups() else match.group(0)
                                # Skip if it looks like a placeholder or reference
                                if (len(potential_secret) < 8 or 
                                    re.search(r'^(\{|\$|\%|\<)', potential_secret) or
                                    "your_" in potential_secret.lower() or
                                    "placeholder" in potential_secret.lower()):
                                    continue
                            
                            severity = ""
                            if vuln_type == 'hardcoded_secrets':
                                severity = "Critical"
                                results['statistics']['critical'] += 1
                            elif vuln_type == 'sql_injection':
                                severity = "Critical"
                                results['statistics']['critical'] += 1
                            elif vuln_type == 'xss_vulnerabilities':
                                severity = "High"
                                results['statistics']['high'] += 1
                            else:
                                severity = "Medium"
                                results['statistics']['medium'] += 1
                                
                            pattern_matches.append({
                                "file": rel_path,
                                "line": line_start,
                                "code": line_content.strip(),
                                "type": vuln_type.replace('_', ' ').title(),
                                "severity": severity
                            })
                
                # If we found pattern-based vulnerabilities, add them to results
                if pattern_matches:
                    for match in pattern_matches:
                        results['vulnerabilities'].append(match)
                        results['statistics']['total_issues'] += 1
                
                # For more advanced analysis, use LLM for certain file types and limited size
                if len(content) < 5000 and content.strip() and any(ext == lang for lang in ['.py', '.js', '.php', '.java']):
                    # Sample a portion of the file for LLM analysis (to avoid token limits)
                    sample_size = min(len(content), 2000)
                    sample = content[:sample_size]
                    
                    llm_results = analyze_code_snippet(llm, sample, language)
                    
                    if 'vulnerabilities' in llm_results and llm_results['vulnerabilities']:
                        for vuln in llm_results['vulnerabilities']:
                            if 'severity' in vuln and 'type' in vuln:
                                if vuln['severity'] == 'Critical':
                                    results['statistics']['critical'] += 1
                                elif vuln['severity'] == 'High':
                                    results['statistics']['high'] += 1
                                elif vuln['severity'] == 'Medium':
                                    results['statistics']['medium'] += 1
                                elif vuln['severity'] == 'Low':
                                    results['statistics']['low'] += 1
                                
                                results['vulnerabilities'].append({
                                    "file": rel_path,
                                    "line": "LLM Analysis",
                                    "code": "AI-detected vulnerability",
                                    "type": vuln['type'],
                                    "severity": vuln['severity'],
                                    "description": vuln.get('description', 'No description provided'),
                                    "remediation": vuln.get('remediation', 'No remediation steps provided')
                                })
                                results['statistics']['total_issues'] += 1
                
            except Exception as e:
                # Skip files that can't be processed
                pass
            
            # Update progress
            files_processed += 1
            st.session_state.scan_progress = min(int(files_processed * progress_step), 100)
    
    # Sort vulnerabilities by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    results['vulnerabilities'] = sorted(
        results['vulnerabilities'], 
        key=lambda x: severity_order.get(x.get('severity', "Low"), 4)
    )
    
    return results

# Function to check for outdated dependencies
def check_outdated_dependencies(repo_path):
    results = []
    
    # Check package.json for Node.js projects
    package_json_path = os.path.join(repo_path, 'package.json')
    if os.path.exists(package_json_path):
        try:
            with open(package_json_path, 'r') as f:
                package_data = json.load(f)
                
            dependencies = {}
            if 'dependencies' in package_data:
                dependencies.update(package_data['dependencies'])
            if 'devDependencies' in package_data:
                dependencies.update(package_data['devDependencies'])
                
            for dep, version in dependencies.items():
                # Check if using a vulnerable version (simplified check)
                if version.startswith('^0.') or version.startswith('~0.'):
                    results.append({
                        "file": "package.json",
                        "line": "N/A",
                        "code": f"{dep}: {version}",
                        "type": "Outdated Dependency",
                        "severity": "Medium",
                        "description": f"Using potentially outdated version of {dep}",
                        "remediation": "Update to the latest stable version"
                    })
        except Exception:
            pass
    
    # Check requirements.txt for Python projects
    req_txt_path = os.path.join(repo_path, 'requirements.txt')
    if os.path.exists(req_txt_path):
        try:
            with open(req_txt_path, 'r') as f:
                requirements = f.readlines()
                
            for req in requirements:
                req = req.strip()
                if '==' in req:
                    package, version = req.split('==')
                    # Very simplified check for old versions
                    if version.startswith('0.') or version.startswith('1.0'):
                        results.append({
                            "file": "requirements.txt",
                            "line": "N/A",
                            "code": req,
                            "type": "Outdated Dependency",
                            "severity": "Medium",
                            "description": f"Using potentially outdated version of {package}",
                            "remediation": "Update to the latest stable version"
                        })
        except Exception:
            pass
    
    return results

# Deployment Functions
def check_deployment_readiness(repo_path, scan_results):
    # Determine if the repository is ready for deployment
    critical_issues = sum(1 for vuln in scan_results['vulnerabilities'] if vuln['severity'] == 'Critical')
    high_issues = sum(1 for vuln in scan_results['vulnerabilities'] if vuln['severity'] == 'High')
    
    # Check for essential deployment files
    has_docker = os.path.exists(os.path.join(repo_path, 'Dockerfile'))
    has_ci_config = (
        os.path.exists(os.path.join(repo_path, '.github', 'workflows')) or
        os.path.exists(os.path.join(repo_path, '.gitlab-ci.yml')) or
        os.path.exists(os.path.join(repo_path, 'azure-pipelines.yml'))
    )
    
    # Basic readiness check
    is_ready = critical_issues == 0 and high_issues < 3 and (has_docker or has_ci_config)
    
    return {
        'is_ready': is_ready,
        'critical_issues': critical_issues,
        'high_issues': high_issues,
        'has_docker': has_docker,
        'has_ci_config': has_ci_config,
        'deployment_platform': 'docker' if has_docker else ('ci' if has_ci_config else 'none')
    }

def deploy_application(repo_path, readiness_info, deployment_config):
    if not readiness_info['is_ready'] and not deployment_config.get('force', False):
        return {
            'success': False,
            'message': 'Repository has critical issues preventing deployment'
        }
    
    # Get deployment platform
    platform = deployment_config.get('platform', 'docker')
    
    if platform == 'docker':
        # Check if Docker is installed
        try:
            subprocess.run(['docker', '--version'], check=True, capture_output=True)
        except (subprocess.SubprocessError, FileNotFoundError):
            return {
                'success': False,
                'message': 'Docker is not installed or not in PATH'
            }
        
        # Build Docker image
        try:
            # Generate a unique tag based on repository name
            repo_name = os.path.basename(repo_path)
            safe_repo_name = re.sub(r'[^a-zA-Z0-9]', '', repo_name).lower()
            image_tag = f"{safe_repo_name}:latest"
            
            # Build Docker image
            build_process = subprocess.run(
                ['docker', 'build', '-t', image_tag, repo_path],
                check=True,
                capture_output=True,
                text=True
            )
            
            return {
                'success': True,
                'message': f'Successfully built Docker image: {image_tag}',
                'platform': 'docker',
                'image_tag': image_tag,
                'build_log': build_process.stdout
            }
        except subprocess.SubprocessError as e:
            return {
                'success': False,
                'message': f'Docker build failed: {e}',
                'error_log': e.stderr if hasattr(e, 'stderr') else str(e)
            }
    elif platform == 'ci':
        # Simulate CI/CD pipeline trigger
        return {
            'success': True,
            'message': 'CI/CD pipeline triggered successfully (simulated)',
            'platform': 'ci',
            'pipeline_url': 'https://example.com/pipeline/1234'
        }
    else:
        return {
            'success': False,
            'message': f'Unsupported deployment platform: {platform}'
        }

# Report generation functions
def generate_pdf_report(scan_results, project_summary, tech_stack, deployment_status):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    elements = []
    
    # Title
    title_style = styles['Heading1']
    elements.append(Paragraph("Security Analysis Report", title_style))
    elements.append(Spacer(1, 12))
    
    # Project Summary
    elements.append(Paragraph("Project Overview", styles['Heading2']))
    elements.append(Paragraph(project_summary, styles['Normal']))
    elements.append(Spacer(1, 12))
    
    # Tech Stack
    elements.append(Paragraph("Technical Stack", styles['Heading2']))
    elements.append(Paragraph(f"Primary Language: {tech_stack['primary_language']}", styles['Normal']))
    
    if tech_stack['frameworks']:
        elements.append(Paragraph(f"Frameworks: {', '.join(tech_stack['frameworks'])}", styles['Normal']))
    elements.append(Spacer(1, 12))
    
    # Vulnerability Summary
    elements.append(Paragraph("Vulnerability Summary", styles['Heading2']))
    
    data = [
        ["Severity", "Count"],
        ["Critical", scan_results['statistics']['critical']],
        ["High", scan_results['statistics']['high']],
        ["Medium", scan_results['statistics']['medium']],
        ["Low", scan_results['statistics']['low']],
    ]
    
    table = Table(data)
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (1, 0), colors.grey),
        ('TEXTCOLOR', (0, 0), (1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (0, 1), colors.red),
        ('BACKGROUND', (0, 2), (0, 2), colors.orange),
        ('BACKGROUND', (0, 3), (0, 3), colors.lightblue),
        ('BACKGROUND', (0, 4), (0, 4), colors.lightgreen),
        ('BOX', (0, 0), (-1, -1), 1, colors.black),
        ('GRID', (0, 0), (-1, -1), 1, colors.black),
    ]))
    elements.append(table)
    elements.append(Spacer(1, 12))
    
    # Detailed Vulnerabilities
    elements.append(Paragraph("Detailed Vulnerabilities", styles['Heading2']))
    
    if scan_results['vulnerabilities']:
        for i, vuln in enumerate(scan_results['vulnerabilities'][:20]):  # Limit to first 20 for PDF size
            elements.append(Paragraph(f"Issue {i+1}: {vuln['type']} ({vuln['severity']})", styles['Heading3']))
            elements.append(Paragraph(f"File: {vuln['file']}", styles['Normal']))
            elements.append(Paragraph(f"Line: {vuln['line']}", styles['Normal']))
            elements.append(Paragraph(f"Code: {vuln['code']}", styles['Code']))
            
            if 'description' in vuln:
                elements.append(Paragraph(f"Description: {vuln['description']}", styles['Normal']))
            if 'remediation' in vuln:
                elements.append(Paragraph(f"Remediation: {vuln['remediation']}", styles['Normal']))
                
            elements.append(Spacer(1, 6))
    else:
        elements.append(Paragraph("No vulnerabilities found", styles['Normal']))
    
    # Deployment Status
    elements.append(Paragraph("Deployment Status", styles['Heading2']))
    if deployment_status:
        if deployment_status['success']:
            elements.append(Paragraph("Status: Success", styles['Normal']))
            elements.append(Paragraph(f"Message: {deployment_status['message']}", styles['Normal']))
            elements.append(Paragraph(f"Platform: {deployment_status['platform']}", styles['Normal']))
        else:
            elements.append(Paragraph("Status: Failed", styles['Normal']))
            elements.append(Paragraph(f"Message: {deployment_status['message']}", styles['Normal']))
    else:
        elements.append(Paragraph("Status: Not attempted", styles['Normal']))
    
    # Build document
    doc.build(elements)
    buffer.seek(0)
    return buffer

def generate_markdown_report(scan_results, project_summary, tech_stack, deployment_status):
    md = []
    
    # Title
    md.append("# Security Analysis Report\n")
    
    # Project Summary
    md.append("## Project Overview\n")
    md.append(f"{project_summary}\n")
    
    # Tech Stack
    md.append("## Technical Stack\n")
    md.append(f"**Primary Language:** {tech_stack['primary_language']}\n")
    
    if tech_stack['frameworks']:
        md.append(f"**Frameworks:** {', '.join(tech_stack['frameworks'])}\n")
    
    # Vulnerability Summary
    md.append("## Vulnerability Summary\n")
    md.append("| Severity | Count |\n")
    md.append("| -------- | ----- |\n")
    md.append(f"| Critical | {scan_results['statistics']['critical']} |\n")
    md.append(f"| High     | {scan_results['statistics']['high']} |\n")
    md.append(f"| Medium   | {scan_results['statistics']['medium']} |\n")
    md.append(f"| Low      | {scan_results['statistics']['low']} |\n")
    md.append(f"\nTotal files scanned: {scan_results['statistics']['files_scanned']}\n")
    
    # Detailed Vulnerabilities
    md.append("## Detailed Vulnerabilities\n")
    
    if scan_results['vulnerabilities']:
        for i, vuln in enumerate(scan_results['vulnerabilities']):
            md.append(f"### Issue {i+1}: {vuln['type']} ({vuln['severity']})\n")
            md.append(f"**File:** {vuln['file']}\n")
            md.append(f"**Line:** {vuln['line']}\n")
            md.append(f"**Code:** `{vuln['code']}`\n")
            
            if 'description' in vuln:
                md.append(f"**Description:** {vuln['description']}\n")
            if 'remediation' in vuln:
                md.append(f"**Remediation:** {vuln['remediation']}\n")
                
            md.append("\n")
    else:
        md.append("No vulnerabilities found\n")
    
    # Deployment Status
    md.append("## Deployment Status\n")
    if deployment_status:
        if deployment_status['success']:
            md.append("**Status:** Success\n")
            md.append(f"**Message:** {deployment_status['message']}\n")
            md.append(f"**Platform:** {deployment_status['platform']}\n")
        else:
            md.append("**Status:** Failed\n")
            md.append(f"**Message:** {deployment_status['message']}\n")
    else:
        md.append("**Status:** Not attempted\n")
    
    return "\n".join(md)

# Main application layout and flow
def main():
    st.title("🔒 AI Secure Code Analyzer & Deployment Agent")
    
    # Sidebar for configuration and settings
    with st.sidebar:
        st.header("Settings")
        
        # Check Ollama availability
        if not check_ollama():
            st.error("⚠️ Ollama is not available. Please make sure it's running.")
            st.info("Install Ollama from https://ollama.ai/ and start it before using this app.")
            
            # Ollama model selection (even if not available, to allow configuration)
            ollama_models = ["llama3", "codellama", "llama2", "mistral", "deepseek-r1:latest"]
            selected_model = st.selectbox(
                "Select Ollama Model",
                options=ollama_models,
                index=0
            )
            st.session_state.ollama_model = selected_model
            
            # Stop further processing if Ollama is not available
            st.stop()
        else:
            st.success("✅ Ollama is running")
            
            # Ollama model selection
            ollama_models = ["llama3", "codellama", "llama2", "mistral", "deepseek-r1:latest"]
            selected_model = st.selectbox(
                "Select Ollama Model",
                options=ollama_models,
                index=ollama_models.index(st.session_state.ollama_model) if st.session_state.ollama_model in ollama_models else 0
            )
            st.session_state.ollama_model = selected_model
        
        # Deployment settings
        st.header("Deployment Settings")
        
        deployment_enabled = st.checkbox("Enable Automatic Deployment", value=st.session_state.deployment_config['enabled'])
        
        deployment_platform = st.selectbox(
            "Deployment Platform",
            options=["docker", "ci"],
            index=0 if st.session_state.deployment_config['platform'] == 'docker' else 1
        )
        
        force_deployment = st.checkbox("Force Deployment (Ignore Security Issues)", value=False)
        
        st.session_state.deployment_config = {
            'enabled': deployment_enabled,
            'platform': deployment_platform,
            'force': force_deployment
        }
    
    # Main content area
    tab1, tab2, tab3 = st.tabs(["GitHub Authentication", "Repository Analysis", "Deployment"])
    
    # GitHub Authentication Tab
    with tab1:
        st.header("GitHub Authentication")
        
        if st.session_state.github_token:
            st.success("✅ Successfully authenticated with GitHub")
            if st.button("Sign Out"):
                st.session_state.github_token = None
                st.session_state.repos = None
                st.session_state.selected_repo = None
                st.session_state.scan_results = None
                st.session_state.project_summary = None
                st.session_state.tech_stack = None
                st.session_state.deployment_status = None
                st.experimental_rerun()
        else:
            st.write("Please authenticate with GitHub to continue.")
            
            auth_method = st.radio("Authentication Method", ["Personal Access Token (PAT)"])
            
            if auth_method == "Personal Access Token (PAT)":
                pat = st.text_input("Enter your GitHub Personal Access Token", type="password", 
                                    help="Create a token with 'repo' scope at https://github.com/settings/tokens")
                
                if st.button("Authenticate") and pat:
                    g, user = github_authenticate(pat)
                    
                    if g and user:
                        st.session_state.github_token = pat
                        st.success(f"✅ Successfully authenticated as {user.login}")
                        st.rerun()
                    else:
                        st.error("❌ Authentication failed. Please check your token.")
    
    # Repository Analysis Tab
    with tab2:
        st.header("Repository Analysis")
        
        if not st.session_state.github_token:
            st.info("Please authenticate with GitHub in the first tab.")
        else:
            # Load repositories
            if not st.session_state.repos:
                g = Github(st.session_state.github_token)
                user = g.get_user()
                repos = list(user.get_repos())
                st.session_state.repos = [(repo.full_name, repo) for repo in repos]
            
            # Repository selection
            repo_names = [repo[0] for repo in st.session_state.repos]
            selected_repo_name = st.selectbox("Select Repository", repo_names)
            
            # Store selected repository object
            if selected_repo_name and selected_repo_name != st.session_state.selected_repo:
                st.session_state.selected_repo = selected_repo_name
                st.session_state.scan_results = None
                st.session_state.project_summary = None
                st.session_state.tech_stack = None
                st.session_state.deployment_status = None
            
            # Get repository object
            selected_repo_obj = next((repo[1] for repo in st.session_state.repos if repo[0] == st.session_state.selected_repo), None)
            
            if st.button("Scan Repository") and selected_repo_obj:
                # Reset progress and results
                st.session_state.scan_progress = 0
                st.session_state.scan_results = None
                st.session_state.project_summary = None
                st.session_state.tech_stack = None
                st.session_state.deployment_status = None
                
                # Create progress bar
                progress_bar = st.progress(0)
                status_text = st.empty()
                status_text.text("Initializing repository scan...")
                
                # Clone repository to temporary directory
                with tempfile.TemporaryDirectory() as temp_dir:
                    status_text.text("Cloning repository...")
                    clone_success = clone_repository(selected_repo_obj.full_name, st.session_state.github_token, temp_dir)
                    
                    if not clone_success:
                        st.error("Failed to clone repository")
                        return
                    
                    # Update progress
                    st.session_state.scan_progress = 10
                    progress_bar.progress(st.session_state.scan_progress)
                    status_text.text("Repository cloned successfully. Detecting tech stack...")
                    
                    # Detect technology stack
                    tech_stack = detect_tech_stack(temp_dir)
                    st.session_state.tech_stack = tech_stack
                    
                    # Update progress
                    st.session_state.scan_progress = 20
                    progress_bar.progress(st.session_state.scan_progress)
                    status_text.text("Tech stack detected. Generating project summary...")
                    
                    # Initialize LLM
                    llm = init_ollama_llm()
                    if not llm:
                        st.error("Failed to initialize Ollama LLM")
                        return
                    
                    # Generate project summary
                    project_summary = generate_project_summary(llm, selected_repo_obj, tech_stack)
                    st.session_state.project_summary = project_summary
                    
                    # Update progress
                    st.session_state.scan_progress = 30
                    progress_bar.progress(st.session_state.scan_progress)
                    status_text.text("Scanning for vulnerabilities...")
                    
                    # Scan for vulnerabilities
                    scan_results = scan_repository_for_vulnerabilities(temp_dir, llm)
                    
                    # Check for outdated dependencies
                    dependency_issues = check_outdated_dependencies(temp_dir)
                    scan_results['vulnerabilities'].extend(dependency_issues)
                    scan_results['statistics']['total_issues'] += len(dependency_issues)
                    scan_results['statistics']['medium'] += len(dependency_issues)
                    
                    # Sort vulnerabilities by severity
                    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
                    scan_results['vulnerabilities'] = sorted(
                        scan_results['vulnerabilities'], 
                        key=lambda x: severity_order.get(x.get('severity', "Low"), 4)
                    )
                    
                    st.session_state.scan_results = scan_results
                    
                    # Update progress
                    progress_bar.progress(100)
                    status_text.text("Scan completed!")
                    
                    # Trigger rerun to update the UI
                    st.rerun()
            
            # Display scan results if available
            if st.session_state.scan_results and st.session_state.project_summary:
                # Show a loading indicator while scan is in progress
                if st.session_state.scan_progress < 100:
                    st.progress(st.session_state.scan_progress)
                    st.write(f"Scan in progress: {st.session_state.scan_progress}% complete")
                else:
                    # Project Summary
                    st.subheader("Project Overview")
                    st.write(st.session_state.project_summary)
                    
                    # Tech Stack
                    st.subheader("Technical Stack")
                    cols = st.columns(2)
                    with cols[0]:
                        st.write(f"**Primary Language:** {st.session_state.tech_stack['primary_language']}")
                    with cols[1]:
                        if st.session_state.tech_stack['frameworks']:
                            st.write(f"**Frameworks:** {', '.join(st.session_state.tech_stack['frameworks'])}")
                    
                    # Vulnerability Summary
                    st.subheader("Vulnerability Summary")
                    cols = st.columns(4)
                    cols[0].metric("Critical", st.session_state.scan_results['statistics']['critical'], help="Critical severity issues")
                    cols[1].metric("High", st.session_state.scan_results['statistics']['high'], help="High severity issues")
                    cols[2].metric("Medium", st.session_state.scan_results['statistics']['medium'], help="Medium severity issues")
                    cols[3].metric("Low", st.session_state.scan_results['statistics']['low'], help="Low severity issues")
                    
                    st.write(f"Total files scanned: {st.session_state.scan_results['statistics']['files_scanned']}")
                    
                    # Visualize vulnerability distribution
                    if sum(st.session_state.scan_results['statistics'][sev] for sev in ['critical', 'high', 'medium', 'low']) > 0:
                        fig, ax = plt.subplots(figsize=(10, 6))
                        severity_data = {
                            'Severity': ['Critical', 'High', 'Medium', 'Low'],
                            'Count': [
                                st.session_state.scan_results['statistics']['critical'],
                                st.session_state.scan_results['statistics']['high'],
                                st.session_state.scan_results['statistics']['medium'],
                                st.session_state.scan_results['statistics']['low']
                            ]
                        }
                        df = pd.DataFrame(severity_data)
                        sns.barplot(x='Severity', y='Count', data=df, palette=['#d9534f', '#f0ad4e', '#5bc0de', '#5cb85c'], ax=ax)
                        ax.set_title('Vulnerability Distribution')
                        st.pyplot(fig)
                    
                    # Detailed Vulnerabilities
                    st.subheader("Detailed Vulnerabilities")
                    
                    if st.session_state.scan_results['vulnerabilities']:
                        # Filter options
                        severity_filter = st.multiselect(
                            "Filter by Severity",
                            options=["Critical", "High", "Medium", "Low"],
                            default=["Critical", "High"]
                        )
                        
                        # Apply filters
                        filtered_vulns = [
                            v for v in st.session_state.scan_results['vulnerabilities']
                            if v['severity'] in severity_filter
                        ]
                        
                        for vuln in filtered_vulns:
                            with st.container():
                                severity_class = f"vulnerability-{vuln['severity'].lower()}"
                                st.markdown(f"""
                                <div class="{severity_class}">
                                    <h4>{vuln['type']} ({vuln['severity']})</h4>
                                    <p><strong>File:</strong> {vuln['file']}</p>
                                    <p><strong>Line:</strong> {vuln['line']}</p>
                                    <p><strong>Code:</strong> <code>{vuln['code']}</code></p>
                                    {f"<p><strong>Description:</strong> {vuln.get('description', '')}</p>" if vuln.get('description') else ""}
                                    {f"<p><strong>Remediation:</strong> {vuln.get('remediation', '')}</p>" if vuln.get('remediation') else ""}
                                </div>
                                """, unsafe_allow_html=True)
                    else:
                        st.success("No vulnerabilities found in the repository!")
                    
                    # Export options
                    st.subheader("Export Report")
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if st.button("Export as PDF"):
                            pdf_buffer = generate_pdf_report(
                                st.session_state.scan_results,
                                st.session_state.project_summary,
                                st.session_state.tech_stack,
                                st.session_state.deployment_status
                            )
                            st.download_button(
                                label="Download PDF Report",
                                data=pdf_buffer,
                                file_name="security_report.pdf",
                                mime="application/pdf"
                            )
                    
                    with col2:
                        if st.button("Export as Markdown"):
                            md_content = generate_markdown_report(
                                st.session_state.scan_results,
                                st.session_state.project_summary,
                                st.session_state.tech_stack,
                                st.session_state.deployment_status
                            )
                            st.download_button(
                                label="Download Markdown Report",
                                data=md_content,
                                file_name="security_report.md",
                                mime="text/markdown"
                            )
    
    # Deployment Tab
    with tab3:
        st.header("Deployment Pipeline")
        
        if not st.session_state.github_token:
            st.info("Please authenticate with GitHub in the first tab.")
        elif not st.session_state.scan_results:
            st.info("Please scan a repository before attempting deployment.")
        else:
            # Create temp directory and clone again for deployment
            with tempfile.TemporaryDirectory() as temp_dir:
                # Get selected repository object
                selected_repo_obj = next((repo[1] for repo in st.session_state.repos if repo[0] == st.session_state.selected_repo), None)
                
                # Clone repository
                clone_success = clone_repository(selected_repo_obj.full_name, st.session_state.github_token, temp_dir)
                
                if not clone_success:
                    st.error("Failed to clone repository for deployment")
                else:
                    # Check deployment readiness
                    readiness_info = check_deployment_readiness(temp_dir, st.session_state.scan_results)
                    
                    # Display readiness information
                    st.subheader("Deployment Readiness")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        if readiness_info['is_ready']:
                            st.success("✅ This repository is ready for deployment")
                        else:
                            st.error("❌ This repository is not ready for deployment")
                    
                    with col2:
                        st.write(f"Critical issues: {readiness_info['critical_issues']}")
                        st.write(f"High issues: {readiness_info['high_issues']}")
                        st.write(f"Docker configuration: {'Available' if readiness_info['has_docker'] else 'Missing'}")
                        st.write(f"CI configuration: {'Available' if readiness_info['has_ci_config'] else 'Missing'}")
                    
                    # Deployment button
                    if st.button("Deploy Application"):
                        if not st.session_state.deployment_config['enabled']:
                            st.warning("Deployment is disabled in settings. Please enable it in the sidebar.")
                        else:
                            with st.spinner("Deploying application..."):
                                # Attempt deployment
                                deployment_result = deploy_application(
                                    temp_dir,
                                    readiness_info,
                                    st.session_state.deployment_config
                                )
                                
                                # Store deployment status
                                st.session_state.deployment_status = deployment_result
                                
                                # Display result
                                if deployment_result['success']:
                                    st.success(f"✅ {deployment_result['message']}")
                                    
                                    # Show additional deployment information
                                    if 'platform' in deployment_result:
                                        st.write(f"Platform: {deployment_result['platform']}")
                                    
                                    if 'image_tag' in deployment_result:
                                        st.write(f"Docker Image: {deployment_result['image_tag']}")
                                        st.code("docker run -p 8080:8080 " + deployment_result['image_tag'])
                                    
                                    if 'pipeline_url' in deployment_result:
                                        st.write(f"Pipeline URL: {deployment_result['pipeline_url']}")
                                else:
                                    st.error(f"❌ {deployment_result['message']}")
                                    
                                    if 'error_log' in deployment_result:
                                        with st.expander("View Error Log"):
                                            st.code(deployment_result['error_log'])
                    
                    # Display previous deployment status
                    if st.session_state.deployment_status:
                        st.subheader("Last Deployment Status")
                        
                        if st.session_state.deployment_status['success']:
                            st.success(f"✅ {st.session_state.deployment_status['message']}")
                        else:
                            st.error(f"❌ {st.session_state.deployment_status['message']}")

if __name__ == "__main__":
    main()