import asyncio
import os
import socket
import ssl
import json
import urllib.parse
import uuid
import time
import shutil
from datetime import datetime, UTC
from typing import Dict, List, Optional, Set
from concurrent.futures import ThreadPoolExecutor
import aiohttp
import nmap
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import requests
import whois
import dns.resolver
import logging
from OpenSSL import crypto
import dns.reversename
import tldextract
import httpx
import xml.etree.ElementTree as ET
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import subprocess
import yaml
from jinja2 import Template
import aiofiles
import certifi
import google.generativeai as genai
# Structured logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scan.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    'timeout': 10,
    'max_redirects': 5,
    'user_agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/91.0.4472.124 Safari/537.36",
    'max_depth': 3,
    'rate_limit_delay': 0.2,
    'scan_profile': 'deep',
    'output_formats': ['json', 'html', 'pdf'],
    'wordlist_path': 'wordlists/common.txt',
    'testssl_path': 'testssl.sh',
    'gemini_api_key': 'AIzaSyAaYY2J9Q0xGoPx1SHqWuhVL11udYS5WkQ',  # Replace with actual API key
    'payloads': {
        'xss': [
            "<script>alert('xss')</script>",
            '""><img src=x onerror=alert(1)>',
            'javascript:alert(1)'
        ],
        'sql_injection': [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "1' OR SLEEP(5)--"
        ],
        'traversal': [
            '../../etc/passwd',
            '../../windows/win.ini',
            '../config.yaml'
        ]
    },
    'risky_ports': {
        21: 'FTP - Consider disabling or securing with FTPS',
        22: 'SSH - Ensure strong authentication',
        23: 'Telnet - Insecure, disable',
        80: 'HTTP - Should redirect to HTTPS',
        445: 'SMB - Vulnerable if not secured'
    }
}


class AdvancedAgent:
    """Base class for specialized AI agents."""

    def __init__(self, name: str, model: genai.GenerativeModel, safety_settings: List[Dict]):
        self.name = name
        self.model = model
        self.safety_settings = safety_settings

    async def process(self, prompt: str, context: Dict, thinking_budget: int) -> Dict:
        """Generic processing method for agent tasks."""
        try:
            response = self.model.generate_content(
                prompt,
                generation_config={
                    'temperature': 0.7,
                    'max_output_tokens': thinking_budget
                },
                safety_settings=self.safety_settings
            )
            if response.text:
                try:
                    return json.loads(response.text)
                except json.JSONDecodeError:
                    logger.warning(f"{self.name} response not valid JSON.")
                    return {}
            else:
                logger.warning(f"{self.name} response blocked by safety filters.")
                return {}
        except Exception as e:
            logger.error(f"{self.name} processing failed: {str(e)}")
            return {}


class PrioritizationAgent(AdvancedAgent):
    """Agent specialized in vulnerability prioritization."""

    async def prioritize(self, vulnerabilities: List[Dict], context: Dict) -> List[Dict]:
        logger.info(f"{self.name} prioritizing vulnerabilities...")
        thinking_budget = self.assess_complexity(vulnerabilities)
        prompt = (
            f"Analyze the following vulnerabilities and prioritize them based on severity, CVSS score, exploitability, and potential business impact:\n"
            f"{json.dumps(vulnerabilities, indent=2)}\n"
            f"Consider contextual factors: {json.dumps(context, indent=2)}\n"
            f"Return a JSON list of vulnerabilities in prioritized order, each with a 'reasoning' field explaining the prioritization."
        )
        result = await self.process(prompt, context, thinking_budget)
        if result:
            return result

        # Fallback to rule-based prioritization
        priority_order = {'critical': 1, 'high': 2, 'medium': 3, 'low': 4, 'info': 5}
        return sorted(
            vulnerabilities,
            key=lambda v: (priority_order.get(v['severity'], 5), -v['cvss_score'])
        )

    def assess_complexity(self, vulnerabilities: List[Dict]) -> int:
        """Determine thinking budget based on vulnerability count and severity."""
        critical_count = sum(1 for v in vulnerabilities if v['severity'] in ['critical', 'high'])
        if critical_count > 5 or len(vulnerabilities) > 20:
            return 24576  # High complexity
        elif critical_count > 2 or len(vulnerabilities) > 10:
            return 12288  # Medium complexity
        return 4096  # Low complexity


class RemediationAgent(AdvancedAgent):
    """Agent specialized in remediation planning."""

    def __init__(self, name: str, model: genai.GenerativeModel, safety_settings: List[Dict], remediation_actions: Dict):
        super().__init__(name, model, safety_settings)
        self.remediation_actions = remediation_actions

    async def plan(self, prioritized_vulns: List[Dict], context: Dict) -> List[Dict]:
        logger.info(f"{self.name} generating remediation plan...")
        thinking_budget = self.assess_complexity(prioritized_vulns)
        prompt = (
            f"Generate a detailed remediation plan for the following prioritized vulnerabilities:\n"
            f"{json.dumps(prioritized_vulns, indent=2)}\n"
            f"Context: {json.dumps(context, indent=2)}\n"
            f"For each critical or high-severity vulnerability, provide a specific remediation action, estimated effort (low/medium/high), and dependencies. "
            f"Return a JSON list of remediation plans with fields: vulnerability_type, details, severity, cvss_score, remediation_action, effort, dependencies, status."
        )
        result = await self.process(prompt, context, thinking_budget)
        if result:
            plan_path = os.path.join(context['output_dir'], 'remediation_plan.txt')
            with open(plan_path, 'w', encoding='utf-8') as f:
                f.write("=== Advanced Remediation Plan ===\n")
                for plan in result:
                    f.write(
                        f"Type: {plan['vulnerability_type']}\n"
                        f"Details: {plan['details']}\n"
                        f"Severity: {plan['severity']}\n"
                        f"CVSS: {plan['cvss_score']}\n"
                        f"Action: {plan['remediation_action']}\n"
                        f"Effort: {plan['effort']}\n"
                        f"Dependencies: {plan['dependencies']}\n"
                        f"Status: {plan['status']}\n\n"
                    )
            logger.info(f"Remediation plan saved to {plan_path}")
            return result

        # Fallback to rule-based remediation
        remediation_plan = []
        for vuln in prioritized_vulns:
            if vuln['severity'] in ['critical', 'high']:
                action = self.remediation_actions.get(vuln['type'], 'Review and mitigate manually.')
                remediation_plan.append({
                    'vulnerability_type': vuln['type'],
                    'details': vuln['details'],
                    'severity': vuln['severity'],
                    'cvss_score': vuln['cvss_score'],
                    'remediation_action': action,
                    'effort': 'Medium',
                    'dependencies': 'None',
                    'status': 'Pending'
                })
        plan_path = os.path.join(context['output_dir'], 'remediation_plan.txt')
        with open(plan_path, 'w', encoding='utf-8') as f:
            f.write("=== Fallback Remediation Plan ===\n")
            for plan in remediation_plan:
                f.write(
                    f"Type: {plan['vulnerability_type']}\n"
                    f"Details: {plan['details']}\n"
                    f"Severity: {plan['severity']}\n"
                    f"CVSS: {plan['cvss_score']}\n"
                    f"Action: {plan['remediation_action']}\n"
                    f"Effort: {plan['effort']}\n"
                    f"Dependencies: {plan['dependencies']}\n"
                    f"Status: {plan['status']}\n\n"
                )
        logger.info(f"Fallback remediation plan saved to {plan_path}")
        return remediation_plan

    def assess_complexity(self, vulnerabilities: List[Dict]) -> int:
        """Determine thinking budget based on vulnerability count and severity."""
        critical_count = sum(1 for v in vulnerabilities if v['severity'] in ['critical', 'high'])
        if critical_count > 5 or len(vulnerabilities) > 20:
            return 24576
        elif critical_count > 2 or len(vulnerabilities) > 10:
            return 12288
        return 4096


class AdaptiveScanAgent(AdvancedAgent):
    """Agent specialized in adaptive scan suggestions."""

    async def suggest(self, vulnerabilities: List[Dict], context: Dict) -> Dict:
        logger.info(f"{self.name} suggesting adaptive scan strategies...")
        thinking_budget = self.assess_complexity(vulnerabilities)
        prompt = (
            f"Analyze the following vulnerabilities and suggest adaptive scan strategies:\n"
            f"{json.dumps(vulnerabilities, indent=2)}\n"
            f"Context: {json.dumps(context, indent=2)}\n"
            f"For critical or high-severity vulnerabilities, recommend specific follow-up scans with parameters (e.g., wordlist size, scan depth). "
            f"Return a JSON dictionary with scan types as keys and detailed suggestions as values, including 'parameters' and 'priority'."
        )
        result = await self.process(prompt, context, thinking_budget)
        if result:
            return result

        # Fallback to rule-based suggestions
        adaptive_actions = {}
        for vuln in vulnerabilities:
            if vuln['severity'] in ['critical', 'high']:
                if vuln['type'] == 'subdomains_found':
                    adaptive_actions['subdomains'] = {
                        'suggestion': 'Perform deeper subdomain enumeration with larger wordlist.',
                        'parameters': {'wordlist_size': 'large', 'depth': 2},
                        'priority': 'high'
                    }
                elif vuln['type'] == 'risky_open_port':
                    adaptive_actions['ports'] = {
                        'suggestion': 'Run detailed service version scan on risky ports.',
                        'parameters': {'ports': 'all', 'scan_type': 'version'},
                        'priority': 'high'
                    }
                elif vuln['type'] in ['sql_injection', 'xss']:
                    adaptive_actions['web'] = {
                        'suggestion': 'Increase payload variations for web vulnerability tests.',
                        'parameters': {'payload_count': 50, 'depth': 3},
                        'priority': 'medium'
                    }
        return adaptive_actions

    def assess_complexity(self, vulnerabilities: List[Dict]) -> int:
        """Determine thinking budget based on vulnerability count and severity."""
        critical_count = sum(1 for v in vulnerabilities if v['severity'] in ['critical', 'high'])
        if critical_count > 5 or len(vulnerabilities) > 20:
            return 24576
        elif critical_count > 2 or len(vulnerabilities) > 10:
            return 12288
        return 4096


class AgenticController:
    def __init__(self, output_dir: str, api_key: str):
        self.output_dir = output_dir
        self.api_key = api_key
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        self.safety_settings = [
            {
                'category': 'HARM_CATEGORY_DANGEROUS_CONTENT',
                'threshold': 'BLOCK_LOW_AND_ABOVE'
            },
            {
                'category': 'HARM_CATEGORY_HATE_SPEECH',
                'threshold': 'BLOCK_LOW_AND_ABOVE'
            },
            {
                'category': 'HARM_CATEGORY_SEXUALLY_EXPLICIT',
                'threshold': 'BLOCK_LOW_AND_ABOVE'
            }
        ]
        self.remediation_actions = {
            'self_signed_certificate': 'Replace with a trusted certificate from a CA (e.g., Let’s Encrypt).',
            'expired_certificate': 'Renew the SSL/TLS certificate immediately.',
            'weak_ssl_protocol': 'Disable deprecated protocols (e.g., SSLv2, SSLv3, TLSv1, TLSv1.1) and enable TLS 1.2 or higher.',
            'weak_ssl_cipher': 'Disable weak ciphers and use strong ciphers like AES-GCM.',
            'risky_open_port': 'Close or secure the risky port (e.g., firewall rule, disable service).',
            'sql_injection': 'Implement parameterized queries and input validation.',
            'xss': 'Sanitize inputs and implement Content Security Policy (CSP).',
            'directory_traversal': 'Validate and sanitize file path inputs.',
            'sensitive_file_exposed': 'Remove sensitive files from public access.',
            'vcs_exposed': 'Remove version control directories from production.'
        }
        self.context = {
            'output_dir': output_dir,
            'scan_profile': 'deep',
            'timestamp': datetime.now(UTC).isoformat()
        }
        self.agents = {
            'prioritization': PrioritizationAgent('PrioritizationAgent', self.model, self.safety_settings),
            'remediation': RemediationAgent('RemediationAgent', self.model, self.safety_settings,
                                            self.remediation_actions),
            'adaptive_scan': AdaptiveScanAgent('AdaptiveScanAgent', self.model, self.safety_settings)
        }
        self.feedback_log = os.path.join(output_dir, 'agent_feedback.json')
        self.initialize_feedback_log()

    def initialize_feedback_log(self):
        """Initialize feedback log for tracking agent performance."""
        if not os.path.exists(self.feedback_log):
            with open(self.feedback_log, 'w', encoding='utf-8') as f:
                json.dump([], f)

    async def log_feedback(self, agent_name: str, task: str, success: bool, details: str):
        """Log agent performance feedback for iterative improvement."""
        feedback = {
            'agent': agent_name,
            'task': task,
            'success': success,
            'details': details,
            'timestamp': datetime.now(UTC).isoformat()
        }
        async with aiofiles.open(self.feedback_log, 'r+', encoding='utf-8') as f:
            content = await f.read()
            feedback_list = json.loads(content) if content else []
            feedback_list.append(feedback)
            await f.seek(0)
            await f.write(json.dumps(feedback_list, indent=2))

    async def prioritize_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """Coordinate vulnerability prioritization with feedback loop."""
        result = await self.agents['prioritization'].prioritize(vulnerabilities, self.context)
        success = bool(result and len(result) == len(vulnerabilities))
        await self.log_feedback(
            'PrioritizationAgent',
            'prioritize_vulnerabilities',
            success,
            f"Processed {len(vulnerabilities)} vulnerabilities, returned {len(result)}"
        )
        return result

    async def plan_remediation(self, prioritized_vulns: List[Dict]) -> List[Dict]:
        """Coordinate remediation planning with feedback loop."""
        result = await self.agents['remediation'].plan(prioritized_vulns, self.context)
        success = bool(result and all('remediation_action' in plan for plan in result))
        await self.log_feedback(
            'RemediationAgent',
            'plan_remediation',
            success,
            f"Generated {len(result)} remediation plans"
        )
        return result

    async def suggest_adaptive_scan(self, vulnerabilities: List[Dict]) -> Dict:
        """Coordinate adaptive scan suggestions with feedback loop."""
        result = await self.agents['adaptive_scan'].suggest(vulnerabilities, self.context)
        success = bool(result)
        await self.log_feedback(
            'AdaptiveScanAgent',
            'suggest_adaptive_scan',
            success,
            f"Generated {len(result)} adaptive scan suggestions"
        )
        return result


class VulnerabilityScanner:
    """Main class for coordinating vulnerability scans."""

    def __init__(self, config: Dict = None):
        self.config = {**DEFAULT_CONFIG, **(config or {})}
        self.result = {}
        self.executor = ThreadPoolExecutor(max_workers=15)
        self.http_client = None
        self.dependencies_checked = False

    def check_dependencies(self):
        """Check for required external dependencies."""
        if self.dependencies_checked:
            return
        missing = []
        if not shutil.which('nmap'):
            missing.append('nmap')
            logger.warning(
                "nmap not found in PATH. Port scanning will be skipped. Install nmap: https://nmap.org/download.html")
        if not shutil.which(self.config['testssl_path']):
            missing.append('testssl.sh')
            logger.warning(
                f"testssl.sh not found at {self.config['testssl_path']}. SSL deep analysis will be limited. Install testssl.sh: https://testssl.sh/")
        if not shutil.which('latexmk'):
            missing.append('latexmk')
            logger.warning("latexmk not found in PATH. PDF report generation will fail. Install TeX Live or MiKTeX.")
        if missing:
            logger.info(f"Missing dependencies: {', '.join(missing)}. Install them to enable full functionality.")
        self.dependencies_checked = True

    async def initialize(self, target: str, scan_id: str, output_dir: str = "scan_results"):
        """Initialize scan parameters."""
        self.check_dependencies()
        self.result = {
            'target': target,
            'timestamp': datetime.now(UTC).isoformat(),
            'scan_id': scan_id,
            'target_ip': None,
            'dns_info': {},
            'whois_info': {},
            'http_headers': {},
            'ssl_info': {},
            'server_technologies': [],
            'open_ports': [],
            'cms_detection': None,
            'subdomains': [],
            'directory_listing': [],
            'email_exposure': [],
            'api_endpoints': [],
            'sensitive_files': [],
            'cors_misconfig': [],
            'security_txt': None,
            'robots_txt': None,
            'sitemap_xml': None,
            'dnssec_status': None,
            'vulnerabilities': [],
            'recommendations': [],
            'scan_metrics': {
                'start_time': datetime.now(UTC).isoformat(),
                'end_time': None,
                'duration': None
            },
            'missing_dependencies': [],
            'prioritized_vulnerabilities': [],
            'remediation_plan': [],
            'adaptive_scan_suggestions': {},
            'adaptive_scan_results': {}
        }
        os.makedirs(output_dir, exist_ok=True)
        self.output_dir = output_dir
        self.target = target.strip()
        if not self.target.startswith(('http://', 'https://')):
            self.target = f"https://{self.target}"
        self.parsed_url = urllib.parse.urlparse(self.target)
        self.domain = self.parsed_url.netloc
        self.base_url = f"{self.parsed_url.scheme}://{self.domain}"
        self.http_client = httpx.AsyncClient(
            timeout=self.config['timeout'],
            follow_redirects=True,
            max_redirects=self.config['max_redirects'],
            headers={'User-Agent': self.config['user_agent']},
            verify=certifi.where()
        )
        self.agentic_controller = AgenticController(self.output_dir, self.config['gemini_api_key'])

    def make_json_serializable(self, obj):
        """Convert objects to JSON-serializable format."""
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='ignore')
        elif isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, dns.resolver.Answer):
            return [str(r) for r in obj]
        elif isinstance(obj, (list, tuple)):
            return [self.make_json_serializable(item) for item in obj]
        elif isinstance(obj, dict):
            return {self.make_json_serializable(k): self.make_json_serializable(v) for k, v in obj.items()}
        elif isinstance(obj, (set, frozenset)):
            return list(self.make_json_serializable(item) for item in obj)
        elif hasattr(obj, '__dict__'):
            return self.make_json_serializable(obj.__dict__)
        return obj

    def validate_url(self, url: str) -> bool:
        """Validate a URL."""
        url_pattern = r'^(https?:\/\/)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:\/.*)?$'
        return bool(re.match(url_pattern, url))

    async def resolve_target(self):
        """Resolve target IP and perform reverse DNS lookup."""
        try:
            target_ip = await asyncio.get_event_loop().run_in_executor(
                self.executor, socket.gethostbyname, self.domain
            )
            self.result['target_ip'] = target_ip
            try:
                rev_name = dns.reversename.from_address(target_ip)
                reversed_dns = await asyncio.get_event_loop().run_in_executor(
                    self.executor, dns.resolver.resolve, rev_name, "PTR"
                )
                self.result['dns_info']['reverse_dns'] = [str(r) for r in reversed_dns]
            except Exception as e:
                logger.warning(f"Reverse DNS lookup failed: {str(e)}")
                self.result['dns_info']['reverse_dns'] = []
        except socket.gaierror:
            self.result['error'] = f'Could not resolve {self.domain} to an IP address'
            self.result['error_type'] = 'ResolutionError'
            return False
        return True

    async def scan_whois(self):
        """Perform WHOIS lookup and check domain expiration."""
        try:
            w = await asyncio.get_event_loop().run_in_executor(
                self.executor, whois.whois, self.domain
            )
            self.result['whois_info'] = self.make_json_serializable(w)
            if w.expiration_date:
                expiry_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
                if expiry_date < datetime.now(UTC):
                    self.result['vulnerabilities'].append({
                        'type': 'domain_expired',
                        'details': f"Domain expired on {expiry_date.isoformat()}",
                        'severity': 'high',
                        'cvss_score': 9.0,
                        'mitigation': "Renew the domain immediately."
                    })
        except Exception as e:
            logger.warning(f"WHOIS lookup failed: {str(e)}")

    async def scan_dns(self):
        """Perform DNS security checks including DNSSEC and email records."""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            # DNSSEC validation
            try:
                ds_answer = await asyncio.get_event_loop().run_in_executor(
                    self.executor, resolver.resolve, self.domain, 'DS'
                )
                self.result['dnssec_status'] = 'enabled' if ds_answer else 'disabled'
            except dns.resolver.NoAnswer:
                self.result['dnssec_status'] = 'disabled'

            # DNS records
            for record in ['MX', 'TXT', 'NS', 'CNAME']:
                try:
                    answer = await asyncio.get_event_loop().run_in_executor(
                        self.executor, resolver.resolve, self.domain, record
                    )
                    self.result['dns_info'][record.lower()] = [str(r) for r in answer]
                except Exception:
                    pass

            # Email exposure
            try:
                mx_records = await asyncio.get_event_loop().run_in_executor(
                    self.executor, resolver.resolve, self.domain, 'MX'
                )
                self.result['email_exposure'] = [str(r.exchange) for r in mx_records]
            except Exception:
                pass

            # SPF and DMARC
            try:
                txt_records = await asyncio.get_event_loop().run_in_executor(
                    self.executor, resolver.resolve, self.domain, 'TXT'
                )
                spf_records = [r for r in txt_records if 'v=spf1' in str(r)]
                self.result['dns_info']['spf'] = [str(r) for r in spf_records]
                if not spf_records:
                    self.result['vulnerabilities'].append({
                        'type': 'dns_misconfiguration',
                        'details': "No SPF record found",
                        'severity': 'medium',
                        'cvss_score': 5.5,
                        'mitigation': "Add an SPF record to prevent email spoofing."
                    })
            except Exception:
                pass

            try:
                dmarc_records = await asyncio.get_event_loop().run_in_executor(
                    self.executor, resolver.resolve, f"_dmarc.{self.domain}", 'TXT'
                )
                self.result['dns_info']['dmarc'] = [str(r) for r in dmarc_records]
                if not any('v=DMARC1' in str(r) for r in dmarc_records):
                    self.result['vulnerabilities'].append({
                        'type': 'dns_misconfiguration',
                        'details': "No DMARC record found",
                        'severity': 'medium',
                        'cvss_score': 5.5,
                        'mitigation': "Add a DMARC record to protect against email fraud."
                    })
            except Exception:
                pass

        except Exception as e:
            logger.warning(f"DNS checks failed: {str(e)}")

    async def scan_ports(self):
        """Perform port scanning with nmap."""
        if not shutil.which('nmap'):
            logger.warning("nmap not installed. Skipping port scan.")
            self.result['missing_dependencies'].append('nmap')
            self.result['open_ports'] = []
            self.result['vulnerabilities'].append({
                'type': 'missing_tool',
                'details': "nmap not found. Port scanning skipped.",
                'severity': 'info',
                'cvss_score': 0.0,
                'mitigation': "Install nmap from https://nmap.org/download.html"
            })
            return
        try:
            nm = nmap.PortScanner()
            ports = "80,443,8080,8443,8000,8008,8888,3000,8081,8090"
            scan_args = "-sS -T4 --max-retries 2 --host-timeout 5m"
            await asyncio.get_event_loop().run_in_executor(
                self.executor, nm.scan, self.result['target_ip'], ports, scan_args
            )
            open_ports = []
            for proto in nm[self.result['target_ip']].all_protocols():
                for port in nm[self.result['target_ip']][proto].keys():
                    if nm[self.result['target_ip']][proto][port]['state'] == 'open':
                        open_ports.append({
                            'port': port,
                            'protocol': proto,
                            'service': nm[self.result['target_ip']][proto][port]['name'],
                            'product': nm[self.result['target_ip']][proto][port].get('product', ''),
                            'version': nm[self.result['target_ip']][proto][port].get('version', '')
                        })
            self.result['open_ports'] = open_ports
            for port_info in open_ports:
                port_num = port_info['port']
                if port_num in self.config['risky_ports']:
                    self.result['vulnerabilities'].append({
                        'type': 'risky_open_port',
                        'details': f"Risky port open: {port_num} ({self.config['risky_ports'][port_num]})",
                        'severity': 'medium',
                        'cvss_score': 5.0,
                        'mitigation': self.config['risky_ports'][port_num]
                    })
        except Exception as e:
            logger.warning(f"Port scan failed: {str(e)}")
            self.result['open_ports'] = []

    async def scan_headers(self):
        """Analyze HTTP headers with advanced validation."""
        try:
            response = await self.http_client.get(self.base_url)
            headers = {k.lower(): v for k, v in response.headers.items()}
            self.result['http_headers'] = headers

            security_headers = {
                'content-security-policy': {
                    'description': 'Prevents XSS and data injection',
                    'severity': 'high',
                    'cvss_score': 7.5,
                    'alternate': ['content-security-policy-report-only'],
                    'validate': lambda v: "'unsafe-inline'" not in v
                },
                'strict-transport-security': {
                    'description': 'Enforces HTTPS',
                    'severity': 'high',
                    'cvss_score': 7.5,
                    'validate': lambda v: 'max-age=' in v and 'max-age=0' not in v
                },
                'x-frame-options': {
                    'description': 'Protects against clickjacking',
                    'severity': 'medium',
                    'cvss_score': 5.0,
                    'validate': lambda v: v.upper() in ['DENY', 'SAMEORIGIN']
                },
                'x-content-type-options': {
                    'description': 'Prevents MIME-type sniffing',
                    'severity': 'low',
                    'cvss_score': 3.0,
                    'validate': lambda v: v.lower() == 'nosniff'
                },
                'x-xss-protection': {
                    'description': 'Enables XSS protection in older browsers',
                    'severity': 'medium',
                    'cvss_score': 5.0,
                    'validate': lambda v: v == '1; mode=block'
                },
                'referrer-policy': {
                    'description': 'Controls referrer information',
                    'severity': 'low',
                    'cvss_score': 3.0,
                    'validate': lambda v: v in ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin']
                },
                'permissions-policy': {
                    'description': 'Controls browser features',
                    'severity': 'medium',
                    'cvss_score': 5.0,
                    'validate': lambda v: v != ''
                },
                'cross-origin-embedder-policy': {
                    'description': 'Prevents cross-origin attacks',
                    'severity': 'medium',
                    'cvss_score': 5.0,
                    'validate': lambda v: v == 'require-corp'
                },
                'cross-origin-opener-policy': {
                    'description': 'Prevents cross-origin attacks',
                    'severity': 'medium',
                    'cvss_score': 5.0,
                    'validate': lambda v: v == 'same-origin'
                },
                'cross-origin-resource-policy': {
                    'description': 'Prevents cross-origin attacks',
                    'severity': 'medium',
                    'cvss_score': 5.0,
                    'validate': lambda v: v in ['same-origin', 'same-site']
                }
            }

            for header, info in security_headers.items():
                header_lower = header.lower()
                alternate = info.get('alternate', [])
                found = any(h in headers for h in [header_lower] + alternate)
                if not found:
                    self.result['vulnerabilities'].append({
                        'type': 'missing_security_header',
                        'details': f"Missing security header: {header} - {info['description']}",
                        'severity': info['severity'],
                        'cvss_score': info['cvss_score'],
                        'mitigation': f"Implement {header} with appropriate values."
                    })
                elif headers.get(header_lower) and not info['validate'](headers[header_lower]):
                    self.result['vulnerabilities'].append({
                        'type': 'invalid_security_header',
                        'details': f"Invalid {header} value: {headers[header_lower]}",
                        'severity': info['severity'],
                        'cvss_score': info['cvss_score'],
                        'mitigation': f"Correct {header} configuration."
                    })

            if 'set-cookie' in headers:
                cookies = headers['set-cookie']
                if isinstance(cookies, str):
                    cookies = [cookies]
                for cookie in cookies:
                    issues = []
                    if 'Secure' not in cookie:
                        issues.append("Missing 'Secure' flag")
                    if 'HttpOnly' not in cookie:
                        issues.append("Missing 'HttpOnly' flag")
                    if 'SameSite' not in cookie:
                        issues.append("Missing 'SameSite' attribute")
                    if issues:
                        self.result['vulnerabilities'].append({
                            'type': 'insecure_cookie',
                            'details': f"Insecure cookie settings: {', '.join(issues)}",
                            'severity': 'medium',
                            'cvss_score': 5.5,
                            'mitigation': "Set Secure, HttpOnly, and SameSite attributes."
                        })

            if 'access-control-allow-origin' in headers:
                if headers['access-control-allow-origin'] == '*':
                    self.result['vulnerabilities'].append({
                        'type': 'insecure_cors',
                        'details': "Overly permissive CORS policy (Access-Control-Allow-Origin: *)",
                        'severity': 'medium',
                        'cvss_score': 5.5,
                        'mitigation': "Restrict CORS to specific trusted domains."
                    })

        except Exception as e:
            logger.warning(f"Header analysis failed: {str(e)}")

    async def scan_ssl(self):
        """Perform advanced SSL/TLS analysis with fallback for self-signed certificates."""
        try:
            # Try standard SSL connection with verification
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.config['timeout']) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                    self.result['ssl_info'] = {
                        'version': ssock.version(),
                        'cipher': ssock.cipher(),
                        'certificate': {
                            'subject': {attr.rfc4514_attribute_name: attr.value for attr in x509_cert.subject},
                            'issuer': {attr.rfc4514_attribute_name: attr.value for attr in x509_cert.issuer},
                            'serial_number': str(x509_cert.serial_number),
                            'not_valid_before': x509_cert.not_valid_before_utc.isoformat(),
                            'not_valid_after': x509_cert.not_valid_after_utc.isoformat(),
                            'signature_algorithm': x509_cert.signature_algorithm_oid._name,
                            'extensions': [ext.oid._name for ext in x509_cert.extensions]
                        }
                    }
        except ssl.SSLError as e:
            logger.warning(f"SSL verification failed: {str(e)}. Attempting with disabled verification.")
            self.result['vulnerabilities'].append({
                'type': 'self_signed_certificate',
                'details': "Self-signed or unverifiable SSL certificate detected.",
                'severity': 'medium',
                'cvss_score': 5.5,
                'mitigation': "Use a valid, trusted SSL certificate from a recognized CA."
            })
            try:
                # Fallback with disabled verification
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                with socket.create_connection((self.domain, 443), timeout=self.config['timeout']) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert = ssock.getpeercert(binary_form=True)
                        x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                        self.result['ssl_info'] = {
                            'version': ssock.version(),
                            'cipher': ssock.cipher(),
                            'certificate': {
                                'subject': {attr.rfc4514_attribute_name: attr.value for attr in x509_cert.subject},
                                'issuer': {attr.rfc4514_attribute_name: attr.value for attr in x509_cert.issuer},
                                'serial_number': str(x509_cert.serial_number),
                                'not_valid_before': x509_cert.not_valid_before_utc.isoformat(),
                                'not_valid_after': x509_cert.not_valid_after_utc.isoformat(),
                                'signature_algorithm': x509_cert.signature_algorithm_oid._name,
                                'extensions': [ext.oid._name for ext in x509_cert.extensions]
                            }
                        }
            except Exception as e:
                logger.warning(f"SSL analysis failed even with disabled verification: {str(e)}")
                self.result['ssl_info'] = {}
                return

        # Common SSL checks
        try:
            if x509_cert.not_valid_after_utc < datetime.now(UTC):
                self.result['vulnerabilities'].append({
                    'type': 'expired_certificate',
                    'details': f"Certificate expired on {x509_cert.not_valid_after_utc.isoformat()}",
                    'severity': 'high',
                    'cvss_score': 7.5,
                    'mitigation': "Renew the SSL/TLS certificate immediately."
                })

            weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']
            if ssock.version() in weak_protocols:
                self.result['vulnerabilities'].append({
                    'type': 'weak_ssl_protocol',
                    'details': f"Using deprecated protocol: {ssock.version()}",
                    'severity': 'high',
                    'cvss_score': 7.5,
                    'mitigation': f"Disable {ssock.version()} and use TLS 1.2 or higher."
                })

            has_ct = any(ext.oid._name == 'ctPrecertificateScts' for ext in x509_cert.extensions)
            if not has_ct:
                self.result['vulnerabilities'].append({
                    'type': 'missing_certificate_transparency',
                    'details': "Certificate Transparency (CT) not enabled",
                    'severity': 'medium',
                    'cvss_score': 5.0,
                    'mitigation': "Enable Certificate Transparency."
                })

            # Run testssl.sh for deeper analysis
            if shutil.which(self.config['testssl_path']):
                try:
                    ssl_temp_file = os.path.join(self.output_dir, f"ssl_{self.result['scan_id']}.json")
                    proc = await asyncio.create_subprocess_exec(
                        self.config['testssl_path'], '--jsonfile', ssl_temp_file, self.domain,
                        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                    stdout, stderr = await proc.communicate()
                    if proc.returncode != 0:
                        logger.warning(f"testssl.sh failed: {stderr.decode()}")
                    else:
                        async with aiofiles.open(ssl_temp_file, 'r') as f:
                            ssl_data = json.loads(await f.read())
                        self.result['ssl_info'].update({
                            'weak_ciphers': [c['id'] for c in ssl_data.get('ciphers', []) if
                                             c.get('severity') in ['MEDIUM', 'HIGH']],
                            'vulnerabilities': ssl_data.get('vulnerabilities', [])
                        })
                        weak_ciphers = [c['id'] for c in ssl_data.get('ciphers', []) if c.get('severity') != 'LOW']
                        if weak_ciphers:
                            self.result['vulnerabilities'].append({
                                'type': 'weak_ssl_cipher',
                                'details': f"Using weak ciphers: {', '.join(weak_ciphers)}",
                                'severity': 'high',
                                'cvss_score': 7.5,
                                'mitigation': "Disable weak ciphers and use strong ciphers like AES-GCM."
                            })
                except Exception as e:
                    logger.warning(f"testssl.sh analysis failed: {str(e)}")
            else:
                logger.warning(f"testssl.sh not found at {self.config['testssl_path']}. Skipping deep SSL analysis.")
                self.result['missing_dependencies'].append('testssl.sh')
        except Exception as e:
            logger.warning(f"SSL post-analysis failed: {str(e)}")

    async def scan_cms(self):
        """Detect CMS and admin panels."""
        try:
            cms_paths = {
                'WordPress': ['/wp-admin/', '/wp-content/', '/wp-includes/', '/readme.html'],
                'Joomla': ['/administrator/', '/joomla.inc.php', '/templates/system/'],
                'Drupal': ['/sites/all/', '/misc/drupal.js', '/core/COPYRIGHT.txt'],
                'Magento': ['/js/mage/', '/skin/frontend/', '/app/etc/local.xml']
            }
            detected_cms = None
            for cms, paths in cms_paths.items():
                for path in paths:
                    try:
                        response = await self.http_client.get(f"{self.base_url}{path}")
                        if response.status_code == 200:
                            detected_cms = cms
                            break
                    except Exception:
                        pass
                if detected_cms:
                    break
            if detected_cms:
                self.result['cms_detection'] = detected_cms
                self.result['vulnerabilities'].append({
                    'type': 'cms_detected',
                    'details': f"Detected CMS: {detected_cms}",
                    'severity': 'info',
                    'cvss_score': 0.0,
                    'mitigation': f"Ensure {detected_cms} is updated with security patches."
                })

            admin_paths = ['/admin/', '/administrator/', '/wp-admin/', '/manager/', '/backend/']
            for path in admin_paths:
                try:
                    response = await self.http_client.get(f"{self.base_url}{path}")
                    if response.status_code == 200:
                        self.result['vulnerabilities'].append({
                            'type': 'admin_panel_exposed',
                            'details': f"Admin panel accessible at: {path}",
                            'severity': 'medium',
                            'cvss_score': 5.5,
                            'mitigation': "Restrict access to admin panels."
                        })
                        break
                except Exception:
                    pass
        except Exception as e:
            logger.warning(f"CMS detection failed: {str(e)}")

    async def scan_subdomains(self, wordlist_path: str = None):
        """Enumerate subdomains using common list, crt.sh, or custom wordlist."""
        try:
            found_subdomains = []
            # Use provided wordlist or default
            if wordlist_path and os.path.exists(wordlist_path):
                with open(wordlist_path, 'r') as f:
                    subdomains = [line.strip() for line in f if line.strip()]
            else:
                subdomains = ['www', 'mail', 'ftp', 'blog', 'webmail', 'admin', 'dev', 'test', 'api']

            for sub in subdomains:
                try:
                    full_domain = f"{sub}.{self.domain}"
                    await asyncio.get_event_loop().run_in_executor(
                        self.executor, socket.gethostbyname, full_domain
                    )
                    found_subdomains.append(full_domain)
                except socket.gaierror:
                    pass

            # Query crt.sh for additional subdomains
            try:
                crt_url = f"https://crt.sh/?q=%.{self.domain}&output=json"
                response = await self.http_client.get(crt_url)
                if response.status_code == 200:
                    crt_data = response.json()
                    for entry in crt_data:
                        subdomain = entry.get('name_value', '').strip()
                        if subdomain.endswith(self.domain) and subdomain not in found_subdomains:
                            found_subdomains.append(subdomain)
            except Exception as e:
                logger.warning(f"crt.sh subdomain query failed: {str(e)}")

            if found_subdomains:
                self.result['subdomains'] = list(set(found_subdomains))
                self.result['vulnerabilities'].append({
                    'type': 'subdomains_found',
                    'details': f"Found {len(found_subdomains)} subdomains",
                    'severity': 'info',
                    'cvss_score': 0.0,
                    'mitigation': "Ensure all subdomains are secured."
                })
        except Exception as e:
            logger.warning(f"Subdomain enumeration failed: {str(e)}")

    async def scan_ports_deep(self, ports: str):
        """Perform detailed port scan with version detection."""
        if not shutil.which('nmap'):
            logger.warning("nmap not installed. Skipping deep port scan.")
            self.result['missing_dependencies'].append('nmap')
            return []
        try:
            nm = nmap.PortScanner()
            scan_args = "-sV -T4 --max-retries 2 --host-timeout 5m"
            await asyncio.get_event_loop().run_in_executor(
                self.executor, nm.scan, self.result['target_ip'], ports, scan_args
            )
            open_ports = []
            for proto in nm[self.result['target_ip']].all_protocols():
                for port in nm[self.result['target_ip']][proto].keys():
                    if nm[self.result['target_ip']][proto][port]['state'] == 'open':
                        open_ports.append({
                            'port': port,
                            'protocol': proto,
                            'service': nm[self.result['target_ip']][proto][port]['name'],
                            'product': nm[self.result['target_ip']][proto][port].get('product', ''),
                            'version': nm[self.result['target_ip']][proto][port].get('version', '')
                        })
            return open_ports
        except Exception as e:
            logger.warning(f"Deep port scan failed: {str(e)}")
            return []

    async def scan_web_vulnerabilities_extended(self, additional_payloads: Dict):
        """Perform extended web vulnerability scan with additional payloads."""
        try:
            urls: Set[str] = {self.base_url}
            visited: Set[str] = set()
            forms = []
            seen_forms: Set[str] = set()

            async def crawl(url: str, depth: int = 0):
                if depth > self.config['max_depth'] or url in visited:
                    return
                visited.add(url)
                try:
                    response = await self.http_client.get(url)
                    if response.status_code != 200:
                        return
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for form in soup.find_all('form'):
                        action = form.get('action', '')
                        form_url = urljoin(url, action)
                        form_key = f"{form_url}:{form.get('method', 'get').lower()}"
                        if form_key in seen_forms:
                            continue
                        seen_forms.add(form_key)
                        inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
                        if inputs:
                            forms.append({
                                'url': form_url,
                                'inputs': inputs,
                                'method': form.get('method', 'get').lower()
                            })
                    for a in soup.find_all('a', href=True):
                        next_url = urljoin(url, a['href'])
                        if urlparse(next_url).netloc == self.parsed_url.netloc:
                            urls.add(next_url)
                            await crawl(next_url, depth + 1)
                except Exception:
                    pass

            await crawl(self.base_url)

            for form in forms:
                for input_name in form['inputs']:
                    for vuln_type, payloads in additional_payloads.items():
                        for payload in payloads:
                            try:
                                if form['method'] == 'post':
                                    response = await self.http_client.post(
                                        form['url'], data={input_name: payload}
                                    )
                                else:
                                    response = await self.http_client.get(
                                        form['url'], params={input_name: payload}
                                    )
                                if vuln_type == 'xss' and payload in response.text:
                                    self.result['vulnerabilities'].append({
                                        'type': 'xss',
                                        'details': f"Reflected XSS at {form['url']} with input {input_name}",
                                        'severity': 'high',
                                        'cvss_score': 7.5,
                                        'mitigation': "Sanitize inputs and use CSP."
                                    })
                                elif vuln_type == 'sql_injection' and re.search(r"(sql|mysql|database|syntax|error)",
                                                                                response.text, re.IGNORECASE):
                                    self.result['vulnerabilities'].append({
                                        'type': 'sql_injection',
                                        'details': f"Potential SQLi at {form['url']} with input {input_name}",
                                        'severity': 'critical',
                                        'cvss_score': 9.8,
                                        'mitigation': "Use parameterized queries."
                                    })
                                await asyncio.sleep(self.config['rate_limit_delay'])
                            except Exception:
                                pass
        except Exception as e:
            logger.warning(f"Extended web vulnerability scan failed: {str(e)}")

    async def scan_directories(self):
        """Discover directories and sensitive files."""
        try:
            common_paths = [
                '/robots.txt', '/sitemap.xml', '/.git/', '/.svn/', '/.env',
                '/backup/', '/admin/', '/wp-config.php', '/config.php', '/phpinfo.php'
            ]
            benign_files = ['/robots.txt', '/sitemap.xml']
            found_paths = []
            for path in common_paths:
                try:
                    response = await self.http_client.get(f"{self.base_url}{path}")
                    if response.status_code == 200:
                        if path not in benign_files:
                            found_paths.append(path)
                        if path in ['/.env', '/wp-config.php', '/config.php']:
                            self.result['vulnerabilities'].append({
                                'type': 'sensitive_file_exposed',
                                'details': f"Sensitive file accessible: {path}",
                                'severity': 'high',
                                'cvss_score': 7.5,
                                'mitigation': f"Remove {path} from public access."
                            })
                        if path in ['/.git/', '/.svn/']:
                            self.result['vulnerabilities'].append({
                                'type': 'vcs_exposed',
                                'details': f"Version control system exposed: {path}",
                                'severity': 'high',
                                'cvss_score': 7.5,
                                'mitigation': f"Remove {path} from production."
                            })
                        if path == '/robots.txt':
                            self.result['robots_txt'] = response.text
                        if path == '/sitemap.xml':
                            self.result['sitemap_xml'] = response.text
                except Exception:
                    pass
            try:
                response = await self.http_client.get(f"{self.base_url}/.well-known/security.txt")
                if response.status_code == 200:
                    self.result['security_txt'] = response.text
            except Exception:
                pass
            self.result['sensitive_files'] = found_paths
        except Exception as e:
            logger.warning(f"Directory discovery failed: {str(e)}")

    async def scan_web_vulnerabilities(self):
        """Perform deep web vulnerability scanning."""
        try:
            urls: Set[str] = {self.base_url}
            visited: Set[str] = set()
            forms = []
            seen_forms: Set[str] = set()
            skip_endpoints = ['/search']

            if any(ep in self.base_url for ep in skip_endpoints):
                logger.info(f"Skipping vulnerability tests for {self.base_url}")
                return

            async def crawl(url: str, depth: int = 0):
                if depth > self.config['max_depth'] or url in visited:
                    return
                visited.add(url)
                try:
                    response = await self.http_client.get(url)
                    if response.status_code != 200:
                        return
                    soup = BeautifulSoup(response.text, 'html.parser')
                    for form in soup.find_all('form'):
                        action = form.get('action', '')
                        form_url = urljoin(url, action)
                        form_key = f"{form_url}:{form.get('method', 'get').lower()}"
                        if form_key in seen_forms:
                            continue
                        seen_forms.add(form_key)
                        inputs = [inp.get('name') for inp in form.find_all('input') if inp.get('name')]
                        if inputs:
                            forms.append({
                                'url': form_url,
                                'inputs': inputs,
                                'method': form.get('method', 'get').lower()
                            })
                    for a in soup.find_all('a', href=True):
                        next_url = urljoin(url, a['href'])
                        if urlparse(next_url).netloc == self.parsed_url.netloc:
                            urls.add(next_url)
                            await crawl(next_url, depth + 1)
                except Exception:
                    pass

            await crawl(self.base_url)

            for form in forms:
                for input_name in form['inputs']:
                    for payload in self.config['payloads']['xss']:
                        try:
                            if form['method'] == 'post':
                                response = await self.http_client.post(
                                    form['url'], data={input_name: payload}
                                )
                            else:
                                response = await self.http_client.get(
                                    form['url'], params={input_name: payload}
                                )
                            if payload in response.text:
                                self.result['vulnerabilities'].append({
                                    'type': 'xss',
                                    'details': f"Reflected XSS at {form['url']} with input {input_name}",
                                    'severity': 'high',
                                    'cvss_score': 7.5,
                                    'mitigation': "Sanitize inputs and use CSP."
                                })
                            await asyncio.sleep(self.config['rate_limit_delay'])
                        except Exception:
                            pass

                    for payload in self.config['payloads']['sql_injection']:
                        try:
                            if form['method'] == 'post':
                                response = await self.http_client.post(
                                    form['url'], data={input_name: payload}
                                )
                            else:
                                response = await self.http_client.get(
                                    form['url'], params={input_name: payload}
                                )
                            if re.search(r"(sql|mysql|database|syntax|error)", response.text, re.IGNORECASE):
                                self.result['vulnerabilities'].append({
                                    'type': 'sql_injection',
                                    'details': f"Potential SQLi at {form['url']} with input {input_name}",
                                    'severity': 'critical',
                                    'cvss_score': 9.8,
                                    'mitigation': "Use parameterized queries."
                                })
                            await asyncio.sleep(self.config['rate_limit_delay'])
                        except Exception:
                            pass

            for payload in self.config['payloads']['traversal']:
                test_url = f"{self.base_url}/{payload}"
                try:
                    response = await self.http_client.get(test_url)
                    content = response.text
                    if "root:" in content or "[extensions]" in content:
                        self.result['vulnerabilities'].append({
                            'type': 'directory_traversal',
                            'details': f"Directory traversal at {test_url}",
                            'severity': 'high',
                            'cvss_score': 7.5,
                            'mitigation': "Sanitize file path inputs."
                        })
                    await asyncio.sleep(self.config['rate_limit_delay'])
                except Exception:
                    pass

            for form in forms:
                try:
                    response = await self.http_client.get(form['url'])
                    if response.status_code != 200:
                        continue
                    soup = BeautifulSoup(response.text, 'html.parser')
                    form_elem = soup.find('form', action=form['url'].split('/')[-1])
                    if form_elem and not any(
                            form_elem.find('input', {'name': name, 'type': 'hidden'}) for name in
                            ['csrf', 'token', '_token']
                    ):
                        self.result['vulnerabilities'].append({
                            'type': 'csrf',
                            'details': f"Missing CSRF token in form at {form['url']}",
                            'severity': 'medium',
                            'cvss_score': 5.5,
                            'mitigation': "Implement CSRF tokens."
                        })
                except Exception:
                    pass
                await asyncio.sleep(self.config['rate_limit_delay'])

            ssrf_test_url = f"{self.base_url}/?url=http://169.254.169.254/latest/meta-data/"
            try:
                response = await self.http_client.get(ssrf_test_url)
                if "ami-id" in response.text or "instance-id" in response.text:
                    self.result['vulnerabilities'].append({
                        'type': 'ssrf',
                        'details': "Potential SSRF vulnerability (AWS metadata accessible)",
                        'severity': 'high',
                        'cvss_score': 7.5,
                        'mitigation': "Restrict URL inputs."
                    })
            except Exception:
                pass
            await asyncio.sleep(self.config['rate_limit_delay'])

            xxe_payload = """<?xml version="1.0"?>
            <!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
            <foo>&xxe;</foo>"""
            try:
                headers = {'Content-Type': 'application/xml'}
                response = await self.http_client.post(self.base_url, data=xxe_payload, headers=headers)
                if "root:" in response.text:
                    self.result['vulnerabilities'].append({
                        'type': 'xxe',
                        'details': "Potential XXE vulnerability",
                        'severity': 'high',
                        'cvss_score': 7.5,
                        'mitigation': "Disable XML external entity processing."
                    })
            except Exception:
                pass
            await asyncio.sleep(self.config['rate_limit_delay'])

        except Exception as e:
            logger.warning(f"Web vulnerability scan failed: {str(e)}")

    async def scan_api_endpoints(self):
        """Discover API endpoints."""
        try:
            common_api_paths = ['/api/', '/graphql', '/rest/', '/v1/', '/v2/', '/oauth/', '/auth/']
            found_endpoints = []
            for path in common_api_paths:
                try:
                    response = await self.http_client.get(f"{self.base_url}{path}")
                    if response.status_code in [200, 201, 401, 403]:
                        found_endpoints.append(path)
                except Exception:
                    pass
            if found_endpoints:
                self.result['api_endpoints'] = found_endpoints
                self.result['vulnerabilities'].append({
                    'type': 'api_endpoints_found',
                    'details': f"Found {len(found_endpoints)} API endpoints",
                    'severity': 'info',
                    'cvss_score': 0.0,
                    'mitigation': "Ensure API endpoints are authenticated and rate-limited."
                })
        except Exception as e:
            logger.warning(f"API endpoint discovery failed: {str(e)}")

    async def scan_technologies(self):
        """Detect server technologies and frameworks."""
        try:
            response = await self.http_client.get(self.base_url)
            headers = response.headers
            content = response.text.lower()
            technologies = []
            if 'x-powered-by' in headers:
                technologies.append(headers['x-powered-by'])
            if 'server' in headers:
                technologies.append(headers['server'])
            if 'wordpress' in content:
                technologies.append('WordPress')
            if 'jquery' in content:
                technologies.append('jQuery')
            self.result['server_technologies'] = technologies
            if technologies:
                self.result['vulnerabilities'].append({
                    'type': 'information_disclosure',
                    'details': f"Technologies exposed: {', '.join(technologies)}",
                    'severity': 'low',
                    'cvss_score': 3.0,
                    'mitigation': "Remove or obfuscate technology-specific headers and signatures."
                })
        except Exception as e:
            logger.warning(f"Technology scan failed: {str(e)}")

    def generate_recommendations(self):
        """Generate security recommendations based on findings."""
        recommendations = [
            "Keep all software and dependencies updated with security patches.",
            "Implement a Web Application Firewall (WAF).",
            "Regularly backup website and database.",
            "Monitor for suspicious activity."
        ]
        vuln_types = {v['type'] for v in self.result['vulnerabilities']}
        if 'missing_security_header' in vuln_types or 'invalid_security_header' in vuln_types:
            recommendations.append("Implement and validate security headers (CSP, HSTS, etc.).")
        if 'insecure_cookie' in vuln_types:
            recommendations.append("Set Secure, HttpOnly, and SameSite attributes on cookies.")
        if 'insecure_cors' in vuln_types:
            recommendations.append("Restrict CORS to trusted domains.")
        if 'expired_certificate' in vuln_types or 'weak_ssl_protocol' in vuln_types or 'weak_ssl_cipher' in vuln_types:
            recommendations.append("Use TLS 1.2/1.3 and strong ciphers.")
        if 'sql_injection' in vuln_types or 'xss' in vuln_types:
            recommendations.append("Implement input validation and output encoding.")
        if 'directory_traversal' in vuln_types:
            recommendations.append("Validate file path inputs.")
        if 'csrf' in vuln_types:
            recommendations.append("Implement CSRF tokens.")
        if 'ssrf' in vuln_types:
            recommendations.append("Restrict URL inputs to prevent SSRF.")
        if 'xxe' in vuln_types:
            recommendations.append("Disable XML external entity processing.")
        if 'sensitive_file_exposed' in vuln_types:
            recommendations.append("Remove sensitive files from public access.")
        if 'vcs_exposed' in vuln_types:
            recommendations.append("Remove version control directories from production.")
        if 'admin_panel_exposed' in vuln_types:
            recommendations.append("Restrict admin panel access.")
        if 'subdomains_found' in vuln_types:
            recommendations.append("Audit and secure all subdomains.")
        if 'api_endpoints_found' in vuln_types:
            recommendations.append("Authenticate and rate-limit API endpoints.")
        self.result['recommendations'] = recommendations

    async def execute_adaptive_scans(self):
        """Execute adaptive scans based on suggestions."""
        logger.info("Executing adaptive scans...")
        adaptive_results = {}
        for scan_type, suggestion in self.result['adaptive_scan_suggestions'].items():
            if scan_type == 'subdomains':
                wordlist_path = 'wordlists/large_subdomains.txt'  # Assume a larger wordlist exists
                logger.info("Running deeper subdomain enumeration...")
                await self.scan_subdomains(wordlist_path)
                adaptive_results['subdomains'] = {
                    'suggestion': suggestion['suggestion'],
                    'parameters': suggestion['parameters'],
                    'new_subdomains': self.result['subdomains']
                }
            elif scan_type == 'ports':
                ports = ','.join(str(p['port']) for p in self.result['open_ports'])
                logger.info(f"Running detailed port scan on ports: {ports}")
                deep_ports = await self.scan_ports_deep(ports)
                adaptive_results['ports'] = {
                    'suggestion': suggestion['suggestion'],
                    'parameters': suggestion['parameters'],
                    'detailed_ports': deep_ports
                }
            elif scan_type == 'web':
                additional_payloads = {
                    'xss': ['<img src="javascript:alert(1)">', '<svg onload=alert(1)>'],
                    'sql_injection': ["' OR SLEEP(10)--", "1' UNION ALL SELECT 1,2,3--"]
                }
                logger.info("Running extended web vulnerability scan...")
                await self.scan_web_vulnerabilities_extended(additional_payloads)
                adaptive_results['web'] = {
                    'suggestion': suggestion['suggestion'],
                    'parameters': suggestion['parameters'],
                    'new_vulnerabilities': [v for v in self.result['vulnerabilities'] if
                                            v['type'] in ['xss', 'sql_injection']]
                }
        self.result['adaptive_scan_results'] = adaptive_results

    async def generate_report(self):
        """Generate reports in multiple formats."""
        self.result = self.make_json_serializable(self.result)
        self.generate_recommendations()

        # Run agentic analysis
        self.result['prioritized_vulnerabilities'] = await self.agentic_controller.prioritize_vulnerabilities(
            self.result['vulnerabilities'])
        self.result['remediation_plan'] = await self.agentic_controller.plan_remediation(
            self.result['prioritized_vulnerabilities'])
        self.result['adaptive_scan_suggestions'] = await self.agentic_controller.suggest_adaptive_scan(
            self.result['vulnerabilities'])

        # Execute adaptive scans
        await self.execute_adaptive_scans()

        # JSON report
        json_path = os.path.join(self.output_dir, f"{self.result['scan_id']}.json")
        async with aiofiles.open(json_path, 'w', encoding='utf-8') as f:
            await f.write(json.dumps(self.result, indent=4))

        # HTML report
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Security Scan Report - {{ target }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
                .critical { color: red; }
                .high { color: orange; }
                .medium { color: blue; }
                .low { color: green; }
            </style>
        </head>
        <body>
            <h1>Security Scan Report for {{ target }}</h1>
            <p>Scan ID: {{ scan_id }}</p>
            <p>Timestamp: {{ timestamp }}</p>
            <h2>Prioritized Vulnerabilities</h2>
            <table>
                <tr><th>Type</th><th>Details</th><th>Severity</th><th>CVSS</th><th>Mitigation</th><th>Reasoning</th></tr>
                {% for vuln in prioritized_vulnerabilities %}
                <tr>
                    <td>{{ vuln.type }}</td>
                    <td>{{ vuln.details }}</td>
                    <td class="{{ vuln.severity }}">{{ vuln.severity }}</td>
                    <td>{{ vuln.cvss_score }}</td>
                    <td>{{ vuln.mitigation }}</td>
                    <td>{{ vuln.reasoning }}</td>
                </tr>
                {% endfor %}
            </table>
            <h2>Remediation Plan</h2>
            <table>
                <tr><th>Type</th><th>Details</th><th>Severity</th><th>Action</th><th>Effort</th><th>Dependencies</th><th>Status</th></tr>
                {% for plan in remediation_plan %}
                <tr>
                    <td>{{ plan.vulnerability_type }}</td>
                    <td>{{ plan.details }}</td>
                    <td>{{ plan.severity }}</td>
                    <td>{{ plan.remediation_action }}</td>
                    <td>{{ plan.effort }}</td>
                    <td>{{ plan.dependencies }}</td>
                    <td>{{ plan.status }}</td>
                </tr>
                {% endfor %}
            </table>
            <h2>Adaptive Scan Suggestions</h2>
            <ul>
                {% for key, suggestion in adaptive_scan_suggestions.items() %}
                <li>{{ key }}: {{ suggestion.suggestion }} (Parameters: {{ suggestion.parameters|tojson }})</li>
                {% endfor %}
            </ul>
            <h2>Adaptive Scan Results</h2>
            <ul>
                {% for key, result in adaptive_scan_results.items() %}
                <li>{{ key }}: {{ result.suggestion }} (Parameters: {{ result.parameters|tojson }})</li>
                {% endfor %}
            </ul>
            <h2>Recommendations</h2>
            <ul>
                {% for rec in recommendations %}
                <li>{{ rec }}</li>
                {% endfor %}
            </ul>
            <h2>Risk Matrix</h2>
            <table>
                <tr><th>Severity</th><th>Count</th></tr>
                {% for severity, count in risk_matrix.items() %}
                <tr><td class="{{ severity }}">{{ severity }}</td><td>{{ count }}</td></tr>
                {% endfor %}
            </table>
        </body>
        </html>
        """
        risk_matrix = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for vuln in self.result['vulnerabilities']:
            risk_matrix[vuln['severity']] += 1
        self.result['risk_matrix'] = risk_matrix
        template = Template(html_template)
        html_content = template.render(**self.result)
        html_path = os.path.join(self.output_dir, f"{self.result['scan_id']}.html")
        async with aiofiles.open(html_path, 'w', encoding='utf-8') as f:
            await f.write(html_content)

        # PDF report
        await self.generate_pdf_report()

    async def generate_pdf_report(self):
        """Generate PDF report using LaTeX."""
        latex_content = r"""
\documentclass{article}
\usepackage[utf8]{inputenc}
\usepackage{geometry}
\geometry{a4paper, margin=1in}
\usepackage{booktabs}
\usepackage{xcolor}
\usepackage{hyperref}
\usepackage{textcomp}
\definecolor{critical}{RGB}{255,0,0}
\definecolor{high}{RGB}{255,165,0}
\definecolor{medium}{RGB}{0,0,255}
\definecolor{low}{RGB}{0,128,0}
\definecolor{info}{RGB}{128,128,128}
\title{Security Scan Report for \texttt{{{target}}}}
\author{Automated Scanner}
\date{{{timestamp}}}
\begin{document}
\maketitle
\section{Overview}
Scan ID: \texttt{{{scan_id}}} \\
Target IP: \texttt{{{target_ip}}} \\
Duration: \texttt{{{scan_metrics.duration}}} \\
\section{Prioritized Vulnerabilities}
\begin{tabular}{p{2cm}p{4cm}p{2cm}p{1.5cm}p{4cm}p{4cm}}
\toprule
Type & Details & Severity & CVSS & Mitigation & Reasoning \\
\midrule
{% for vuln in prioritized_vulnerabilities %}
\texttt{{{vuln.type}}} & \texttt{{{vuln.details}}} & \textcolor{{{vuln.severity}}}{{{vuln.severity}}} & \texttt{{{vuln.cvss_score}}} & \texttt{{{vuln.mitigation}}} & \texttt{{{vuln.reasoning}}} \\
{% endfor %}
\bottomrule
\end{tabular}
\section{Remediation Plan}
\begin{tabular}{p{2cm}p{4cm}p{2cm}p{4cm}p{2cm}p{2cm}p{2cm}}
\toprule
Type & Details & Severity & Action & Effort & Dependencies & Status \\
\midrule
{% for plan in remediation_plan %}
\texttt{{{plan.vulnerability_type}}} & \texttt{{{plan.details}}} & \texttt{{{plan.severity}}} & \texttt{{{plan.remediation_action}}} & \texttt{{{plan.effort}}} & \texttt{{{plan.dependencies}}} & \texttt{{{plan.status}}} \\
{% endfor %}
\bottomrule
\end{tabular}
\section{Adaptive Scan Suggestions}
\begin{itemize}
{% for key, suggestion in adaptive_scan_suggestions.items() %}
\item \texttt{{{key}}}: \texttt{{{suggestion.suggestion}}} (Parameters: \texttt{{{suggestion.parameters|tojson}}})
{% endfor %}
\end{itemize}
\section{Adaptive Scan Results}
\begin{itemize}
{% for key, result in adaptive_scan_results.items() %}
\item \texttt{{{key}}}: \texttt{{{result.suggestion}}} (Parameters: \texttt{{{result.parameters|tojson}}})
{% endfor %}
\end{itemize}
\section{Recommendations}
\begin{itemize}
{% for rec in recommendations %}
\item \texttt{{{rec}}}
{% endfor %}
\end{itemize}
\section{Risk Matrix}
\begin{tabular}{ll}
\toprule
Severity & Count \\
\midrule
{% for severity, count in risk_matrix.items() %}
\texttt{{{severity}}} & \texttt{{{count}}} \\
{% endfor %}
\bottomrule
\end{tabular}
\end{document}
"""
        try:
            template = Template(latex_content)
            latex_rendered = template.render(
                target=self.result.get('target', 'Unknown'),
                timestamp=self.result.get('timestamp', ''),
                scan_id=self.result.get('scan_id', ''),
                target_ip=self.result.get('target_ip', 'Unknown'),
                scan_metrics=self.result.get('scan_metrics', {}),
                prioritized_vulnerabilities=self.result.get('prioritized_vulnerabilities', []),
                remediation_plan=self.result.get('remediation_plan', []),
                adaptive_scan_suggestions=self.result.get('adaptive_scan_suggestions', {}),
                adaptive_scan_results=self.result.get('adaptive_scan_results', {}),
                recommendations=self.result.get('recommendations', []),
                risk_matrix=self.result.get('risk_matrix', {})
            )
            latex_path = os.path.join(self.output_dir, f"{self.result['scan_id']}.tex")
            async with aiofiles.open(latex_path, 'w', encoding='utf-8') as f:
                await f.write(latex_rendered)
            if shutil.which('latexmk'):
                proc = await asyncio.create_subprocess_exec(
                    'latexmk', '-pdf', latex_path,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                if proc.returncode != 0:
                    logger.error(f"LaTeX compilation failed: {stderr.decode()}")
                else:
                    logger.info(f"PDF report generated at {latex_path.replace('.tex', '.pdf')}")
            else:
                logger.warning("latexmk not found. Skipping PDF report generation.")
                self.result['missing_dependencies'].append('latexmk')
        except Exception as e:
            logger.error(f"PDF generation failed: {str(e)}")

    async def run(self):
        """Execute all scans."""
        if not self.validate_url(self.target):
            self.result['error'] = 'Invalid URL'
            return self.result
        if not await self.resolve_target():
            return self.result
        tasks = [
            self.scan_whois(),
            self.scan_dns(),
            self.scan_ports(),
            self.scan_headers(),
            self.scan_ssl(),
            self.scan_cms(),
            self.scan_subdomains(),
            self.scan_directories(),
            self.scan_web_vulnerabilities(),
            self.scan_api_endpoints(),
            self.scan_technologies()
        ]
        await asyncio.gather(*tasks)
        self.result['scan_metrics']['end_time'] = datetime.now(UTC).isoformat()
        self.result['scan_metrics']['duration'] = str(
            datetime.fromisoformat(self.result['scan_metrics']['end_time']) -
            datetime.fromisoformat(self.result['scan_metrics']['start_time'])
        )
        await self.generate_report()
        await self.http_client.aclose()
        return self.result


async def main():
    config_path = 'config.yaml'
    config = DEFAULT_CONFIG
    if os.path.exists(config_path):
        with open(config_path, 'r') as f:
            config = {**config, **yaml.safe_load(f)}

    scan_id = str(uuid.uuid4())
    url = input("Enter URL to scan (e.g., https://example.com): ").strip()

    print(f"\nStarting security scan for {url} (Scan ID: {scan_id})")
    start_time = time.time()

    scanner = VulnerabilityScanner(config)
    await scanner.initialize(url, scan_id)
    result = await scanner.run()

    end_time = time.time()
    duration = end_time - start_time

    print(f"\nScan completed in {result['scan_metrics']['duration']}")
    print(f"Duration: {duration:.2f} seconds")
    print(f"Results saved to: {scanner.output_dir}/{scan_id}.*")
    print(f"Remediation plan saved to: {scanner.output_dir}/remediation_plan.txt")
    print(f"\n=== Scan Summary ===")
    print(f"Target: {url}")
    print(f"IP Address: {result.get('target_ip', 'Unknown')}")
    print(f"Vulnerabilities Found: {len(result.get('vulnerabilities', []))}")
    critical_vulns = [v for v in result.get('prioritized_vulnerabilities', []) if
                      v.get('severity') in ['high', 'critical']]
    if critical_vulns:
        print("\nCritical/High Severity Vulnerabilities:")
        for vuln in critical_vulns:
            print(f"- {vuln['type']}: {vuln['details']} (Severity: {vuln['severity']}, CVSS: {vuln['cvss_score']})")
    else:
        print("No critical or high severity vulnerabilities found.")
    print(f"Total Subdomains Found: {len(result.get('subdomains', []))}")
    print(f"Open Ports Detected: {len(result.get('open_ports', []))}")
    print(f"Recommendations: {len(result.get('recommendations', []))}")
    print(f"\nFull report saved in: {scanner.output_dir}/{scan_id}.json")
    print(f"HTML report: {scanner.output_dir}/{scan_id}.html")
    if os.path.exists(os.path.join(scanner.output_dir, f"{scan_id}.pdf")):
        print(f"PDF report: {scanner.output_dir}/{scan_id}.pdf")
    else:
        print("PDF report generation failed (check for latexmk dependency).")
    print(f"Remediation plan: {scanner.output_dir}/remediation_plan.txt")
    print("Review the remediation plan and adaptive scan suggestions for next steps.")


if __name__ == "__main__":
    asyncio.run(main())