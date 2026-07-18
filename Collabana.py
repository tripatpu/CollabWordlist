#!/usr/bin/env python3
"""
ffuf-analyzer.py — Intelligent ffuf Output Parser & Validator
=============================================================
Parses ffuf JSON output, deep-validates each hit, eliminates false positives,
classifies severity, and outputs confirmed findings in JSON/CSV/TXT.

Usage:
    python3 ffuf-analyzer.py -i ffuf_output.json
    python3 ffuf-analyzer.py -i ffuf_output.json -t 50 --timeout 10
    python3 ffuf-analyzer.py -i scan1.json scan2.json --merge
    python3 ffuf-analyzer.py -i ffuf_output.json --no-revalidate
    python3 ffuf-analyzer.py -i ffuf_output.json -o results --severity critical,high

Author: Bug Bounty Research Tool
Version: 2.0.0
"""

import argparse
import csv
import hashlib
import io
import json
import mmap
import os
import re
import signal
import sys
import time
import traceback
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Optional imports — degrade gracefully
# ---------------------------------------------------------------------------
try:
    import urllib.request
    import urllib.error
    import ssl
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

try:
    import xml.etree.ElementTree as ET
    HAS_XML = True
except ImportError:
    HAS_XML = False

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ---------------------------------------------------------------------------
# ANSI colors (disabled if not a TTY)
# ---------------------------------------------------------------------------
class C:
    if sys.stdout.isatty():
        R = '\033[91m'; G = '\033[92m'; Y = '\033[93m'; B = '\033[94m'
        M = '\033[95m'; CY = '\033[96m'; W = '\033[97m'; BOLD = '\033[1m'
        DIM = '\033[2m'; RST = '\033[0m'
        BG_R = '\033[41m'; BG_G = '\033[42m'; BG_Y = '\033[43m'; BG_B = '\033[44m'
    else:
        R = G = Y = B = M = CY = W = BOLD = DIM = RST = ''
        BG_R = BG_G = BG_Y = BG_B = ''

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
VERSION = "2.0.0"
CHUNK_SIZE = 64 * 1024  # 64KB read chunks for memory efficiency

# Severity levels
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
SEVERITY_COLOR = {
    CRITICAL: C.BG_R + C.W,
    HIGH: C.R,
    MEDIUM: C.Y,
    LOW: C.B,
    INFO: C.DIM,
}

# ---------------------------------------------------------------------------
# Secret / credential detection patterns (compiled once)
# ---------------------------------------------------------------------------
SECRET_PATTERNS = {
    "AWS Access Key":          re.compile(r'AKIA[0-9A-Z]{16}'),
    "AWS Secret Key":          re.compile(r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*[A-Za-z0-9/+=]{40}'),
    "AWS Session Token":       re.compile(r'(?i)aws[_\-]?session[_\-]?token\s*[=:]'),
    "Generic API Key":         re.compile(r'(?i)(api[_\-]?key|apikey|api[_\-]?secret)\s*[=:]\s*["\']?[A-Za-z0-9\-_]{16,}'),
    "Generic Secret":          re.compile(r'(?i)(secret|password|passwd|pwd|token|auth[_\-]?token|access[_\-]?token|refresh[_\-]?token|private[_\-]?key|encryption[_\-]?key|signing[_\-]?key)\s*[=:]\s*["\']?[^\s"\']{8,}'),
    "Bearer Token":            re.compile(r'(?i)bearer\s+[A-Za-z0-9\-_\.]{20,}'),
    "JWT Token":               re.compile(r'eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+'),
    "Private Key Block":       re.compile(r'-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
    "GitHub Token":            re.compile(r'gh[ps]_[A-Za-z0-9_]{36,}'),
    "GitHub Fine-grained":     re.compile(r'github_pat_[A-Za-z0-9_]{22,}'),
    "GitLab Token":            re.compile(r'glpat-[A-Za-z0-9\-_]{20,}'),
    "Slack Token":             re.compile(r'xox[baprs]-[0-9]{10,}-[A-Za-z0-9\-]+'),
    "Slack Webhook":           re.compile(r'hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+'),
    "Google API Key":          re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
    "Google OAuth":            re.compile(r'[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com'),
    "Firebase Key":            re.compile(r'(?i)firebase[_\-]?api[_\-]?key\s*[=:]\s*["\']?AIza[0-9A-Za-z\-_]{35}'),
    "Stripe Secret Key":       re.compile(r'sk_live_[0-9a-zA-Z]{24,}'),
    "Stripe Publishable":      re.compile(r'pk_live_[0-9a-zA-Z]{24,}'),
    "Twilio Account SID":      re.compile(r'AC[a-f0-9]{32}'),
    "Twilio Auth Token":       re.compile(r'(?i)twilio[_\-]?auth[_\-]?token\s*[=:]\s*[0-9a-f]{32}'),
    "SendGrid Key":            re.compile(r'SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}'),
    "Mailgun Key":             re.compile(r'key-[0-9a-zA-Z]{32}'),
    "Square OAuth":            re.compile(r'sq0csp-[0-9A-Za-z\-_]{43}'),
    "Square Access Token":     re.compile(r'sqOatp-[0-9A-Za-z\-_]{22}'),
    "PayPal/Braintree":        re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'),
    "Heroku API Key":          re.compile(r'(?i)heroku[_\-]?api[_\-]?key\s*[=:]\s*[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'),
    "DigitalOcean Token":      re.compile(r'dop_v1_[a-f0-9]{64}'),
    "NPM Token":               re.compile(r'npm_[A-Za-z0-9]{36}'),
    "PyPI Token":              re.compile(r'pypi-[A-Za-z0-9\-_]{16,}'),
    "Telegram Bot Token":      re.compile(r'[0-9]{9,10}:[A-Za-z0-9_\-]{35}'),
    "Discord Bot Token":       re.compile(r'[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}'),
    "Azure Client Secret":     re.compile(r'(?i)azure[_\-]?client[_\-]?secret\s*[=:]\s*[A-Za-z0-9\-_.~]{34,}'),
    "Database URL":            re.compile(r'(?i)(postgres|mysql|mongodb|redis|amqp|sqlite)://[^\s"\'<>]{10,}'),
    "Connection String":       re.compile(r'(?i)(server|host)=[^;]+;.*(password|pwd)=[^;]+', re.DOTALL),
    "IP Address (Private)":    re.compile(r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b'),
    "Email in Config":         re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'),
    "Hardcoded Password":      re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']?[^\s"\']{4,}'),
    "S3 Bucket URL":           re.compile(r'[a-z0-9\-]+\.s3[\.\-][a-z0-9\-]+\.amazonaws\.com'),
    "GCS Bucket URL":          re.compile(r'storage\.googleapis\.com/[a-z0-9\-_.]+'),
}

# Known false-positive body patterns (generic error pages, default pages, etc.)
FALSE_POSITIVE_PATTERNS = [
    re.compile(r'(?i)<title>\s*(404|not\s*found|page\s*not\s*found|error|forbidden|access\s*denied|unauthorized)\s*</title>'),
    re.compile(r'(?i)(the\s+page\s+you\s+(are\s+looking\s+for|requested)\s+(was\s+not\s+found|does\s+not\s+exist|could\s+not\s+be\s+found))'),
    re.compile(r'(?i)(this\s+page\s+(doesn.t|does\s+not)\s+exist)'),
    re.compile(r'(?i)(<h1>\s*403\s*</h1>|<h1>\s*forbidden\s*</h1>)'),
    re.compile(r'(?i)(nginx|apache|iis)\s+(default|welcome)\s+page'),
    re.compile(r'(?i)directory\s+listing\s+(for|of)\s+/\s*$'),
    re.compile(r'^\s*$'),  # empty body
]

# Content-type based classification
INTERESTING_CONTENT_TYPES = {
    'application/json':       ('JSON', HIGH),
    'application/xml':        ('XML', MEDIUM),
    'text/xml':               ('XML', MEDIUM),
    'application/yaml':       ('YAML', HIGH),
    'text/yaml':              ('YAML', HIGH),
    'application/x-yaml':     ('YAML', HIGH),
    'text/plain':             ('Text', MEDIUM),
    'application/javascript': ('JavaScript', MEDIUM),
    'text/javascript':        ('JavaScript', MEDIUM),
    'application/octet-stream': ('Binary', HIGH),
    'application/sql':        ('SQL', CRITICAL),
    'application/zip':        ('Archive', HIGH),
    'application/gzip':       ('Archive', HIGH),
    'application/x-tar':      ('Archive', HIGH),
    'application/x-7z-compressed': ('Archive', HIGH),
    'application/pdf':        ('PDF', LOW),
    'text/csv':               ('CSV', HIGH),
    'text/html':              ('HTML', LOW),
    'application/x-pem-file': ('Certificate', CRITICAL),
    'application/x-x509-ca-cert': ('Certificate', CRITICAL),
    'application/toml':       ('TOML', HIGH),
    'application/x-sqlite3':  ('SQLite', CRITICAL),
}

# Path-based severity overrides (regex -> severity)
PATH_SEVERITY_RULES = [
    (re.compile(r'(?i)\.(env|env\..*)$'),                    CRITICAL, "Environment file"),
    (re.compile(r'(?i)\.git/(config|HEAD|index|packed-refs)'), CRITICAL, "Git repository exposed"),
    (re.compile(r'(?i)\.aws/credentials'),                    CRITICAL, "AWS credentials file"),
    (re.compile(r'(?i)\.ssh/(id_rsa|id_ed25519|authorized_keys)'), CRITICAL, "SSH key exposed"),
    (re.compile(r'(?i)(terraform\.tfstate|terraform\.tfvars)'), CRITICAL, "Terraform state/vars"),
    (re.compile(r'(?i)\.kube/config|kubeconfig'),             CRITICAL, "Kubernetes config"),
    (re.compile(r'(?i)(wp-config\.php|configuration\.php|settings\.php|LocalSettings\.php)'), CRITICAL, "CMS config exposed"),
    (re.compile(r'(?i)actuator/(env|heapdump|configprops)'),  CRITICAL, "Spring Actuator sensitive"),
    (re.compile(r'(?i)(private\.key|server\.key|privkey\.pem|\.p12|\.pfx|keystore\.jks)'), CRITICAL, "Private key/certificate"),
    (re.compile(r'(?i)(dump|backup|database|db|export|mysql|postgres|snapshot|full-backup|daily-backup|weekly-backup|monthly-backup|auto|migration)[\-_.].*\.(sql|sql\.gz|sql\.bz2|sql\.zip|zip|tar\.gz|tar\.bz2|7z|rar|gz|tgz|bz2)'), CRITICAL, "Database dump/backup archive"),
    (re.compile(r'(?i)(dump|backup|database|db|export|mysql|postgres)\.(sql|sql\.gz|sql\.bz2|zip|tar\.gz)'), CRITICAL, "Database dump"),
    (re.compile(r'(?i)\.sqlite3?$|\.db$|\.mdb$'),            CRITICAL, "Database file"),
    (re.compile(r'(?i)(credentials|secrets|tokens|api[_-]?keys?)\.(json|yaml|yml|xml)'), CRITICAL, "Credentials file"),
    (re.compile(r'(?i)master\.key$|encryption\.key$'),        CRITICAL, "Encryption key"),
    (re.compile(r'(?i)(swagger|openapi)\.(json|yaml|yml)'),   HIGH, "API documentation"),
    (re.compile(r'(?i)graphi?ql|altair|voyager'),             HIGH, "GraphQL endpoint"),
    (re.compile(r'(?i)(phpinfo|info|pi|i)\.php'),             HIGH, "PHP info disclosure"),
    (re.compile(r'(?i)actuator/(health|info|mappings|beans|metrics)'), HIGH, "Spring Actuator info"),
    (re.compile(r'(?i)\.htpasswd|\.htdigest'),                HIGH, "HTTP auth file"),
    (re.compile(r'(?i)docker-compose\.(yml|yaml)'),           HIGH, "Docker compose exposed"),
    (re.compile(r'(?i)(package|composer|Gemfile|requirements|Pipfile|go\.mod|Cargo\.toml)'), MEDIUM, "Dependency file"),
    (re.compile(r'(?i)\.git(ignore|attributes|modules)'),     MEDIUM, "Git metadata"),
    (re.compile(r'(?i)wp-json/wp/v2/users'),                  MEDIUM, "WordPress user enumeration"),
    (re.compile(r'(?i)(readme|changelog|version|license)\.(txt|md|html)'), LOW, "Information disclosure"),
    (re.compile(r'(?i)robots\.txt|sitemap\.xml|humans\.txt'), INFO, "Standard file"),
]


# ---------------------------------------------------------------------------
# Memory-efficient ffuf JSON parser (streaming for large files)
# ---------------------------------------------------------------------------
def parse_ffuf_json_streaming(filepath: str) -> tuple[dict, list[dict]]:
    """Parse ffuf JSON output. Uses mmap for large files, standard json for small ones."""
    fsize = os.path.getsize(filepath)

    if fsize == 0:
        raise ValueError(f"Empty file: {filepath}")

    # For files < 50MB, just load normally
    if fsize < 50 * 1024 * 1024:
        with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
            data = json.load(f)
    else:
        # Memory-map large files
        with open(filepath, 'rb') as f:
            with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                data = json.loads(mm[:])

    # Handle both ffuf output formats
    config = data.get('config', data.get('commandline', {}))
    results = data.get('results', [])

    if not results:
        raise ValueError(f"No results found in {filepath}")

    return config, results


def parse_ffuf_csv(filepath: str) -> list[dict]:
    """Parse ffuf CSV output format."""
    results = []
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append({
                'input': {'FUZZ': row.get('input', row.get('FUZZ', ''))},
                'status': int(row.get('status', 0)),
                'length': int(row.get('length', row.get('content-length', 0))),
                'words': int(row.get('words', 0)),
                'lines': int(row.get('lines', 0)),
                'content-type': row.get('content-type', row.get('resultfile', '')),
                'url': row.get('url', ''),
                'redirectlocation': row.get('redirectlocation', ''),
                'duration': int(row.get('duration', 0)),
            })
    return results


# ---------------------------------------------------------------------------
# Content validation engine
# ---------------------------------------------------------------------------
class ContentValidator:
    """Deep content validation — parses body, detects secrets, classifies severity."""

    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        if not verify_ssl:
            self.ssl_ctx = ssl.create_default_context()
            self.ssl_ctx.check_hostname = False
            self.ssl_ctx.verify_mode = ssl.CERT_NONE
        else:
            self.ssl_ctx = None

    def fetch_url(self, url: str, headers: Optional[dict] = None) -> Optional[dict]:
        """Re-fetch a URL for deep validation. Returns dict with status, headers, body."""
        if not HAS_URLLIB:
            return None
        try:
            req_headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': '*/*',
                'Accept-Encoding': 'identity',
                'Connection': 'close',
            }
            if headers:
                req_headers.update(headers)

            req = urllib.request.Request(url, headers=req_headers)
            ctx = self.ssl_ctx if not self.verify_ssl else None
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                # Read max 2MB to avoid memory issues
                body = resp.read(2 * 1024 * 1024)
                return {
                    'status': resp.status,
                    'headers': dict(resp.headers),
                    'body': body,
                    'content_type': resp.headers.get('Content-Type', ''),
                    'content_length': len(body),
                    'url': resp.url,  # final URL after redirects
                }
        except urllib.error.HTTPError as e:
            return {
                'status': e.code,
                'headers': dict(e.headers) if e.headers else {},
                'body': e.read(2 * 1024 * 1024) if hasattr(e, 'read') else b'',
                'content_type': e.headers.get('Content-Type', '') if e.headers else '',
                'content_length': 0,
                'url': url,
                'error': str(e),
            }
        except Exception as e:
            return {
                'status': 0,
                'headers': {},
                'body': b'',
                'content_type': '',
                'content_length': 0,
                'url': url,
                'error': str(e),
            }

    @staticmethod
    def detect_content_format(body: bytes, content_type: str) -> tuple[str, Any]:
        """Detect and parse content format. Returns (format_name, parsed_data_or_None)."""
        ct_lower = content_type.lower() if content_type else ''
        text = None

        try:
            text = body.decode('utf-8', errors='replace').strip()
        except Exception:
            return ('binary', None)

        if not text:
            return ('empty', None)

        # JSON detection
        if 'json' in ct_lower or (text and text[0] in '{['):
            try:
                parsed = json.loads(text)
                return ('json', parsed)
            except (json.JSONDecodeError, ValueError):
                pass

        # XML detection
        if 'xml' in ct_lower or (text and text.startswith('<?xml')) or (text and text.startswith('<')):
            if HAS_XML:
                try:
                    parsed = ET.fromstring(text)
                    return ('xml', parsed)
                except ET.ParseError:
                    pass

        # YAML detection
        if 'yaml' in ct_lower or 'yml' in ct_lower:
            if HAS_YAML:
                try:
                    parsed = yaml.safe_load(text)
                    if isinstance(parsed, (dict, list)):
                        return ('yaml', parsed)
                except Exception:
                    pass
            else:
                # Basic YAML detection without parser
                if re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\s*:', text):
                    return ('yaml', None)

        # ENV file detection
        env_lines = [l for l in text.split('\n') if re.match(r'^[A-Z_][A-Z0-9_]*\s*=', l)]
        if len(env_lines) >= 2:
            env_data = {}
            for line in env_lines:
                k, _, v = line.partition('=')
                env_data[k.strip()] = v.strip().strip('"\'')
            return ('env', env_data)

        # INI/Config detection
        if re.match(r'^\[[\w\-\.]+\]', text):
            return ('ini', None)

        # SQL detection
        if re.match(r'(?i)^(--|CREATE\s|INSERT\s|DROP\s|ALTER\s|SELECT\s|/\*)', text):
            return ('sql', None)

        # CSV detection
        lines = text.split('\n')[:5]
        if len(lines) >= 2:
            first_commas = lines[0].count(',')
            if first_commas >= 2 and all(abs(l.count(',') - first_commas) <= 1 for l in lines[1:] if l.strip()):
                return ('csv', None)

        # HTML detection
        if '<html' in text.lower() or '<body' in text.lower() or '<!doctype' in text.lower():
            return ('html', None)

        # JavaScript detection
        if 'javascript' in ct_lower or re.match(r'^(var |let |const |function |import |export |module\.)', text):
            return ('javascript', None)

        # Source map detection
        if '"mappings"' in text and '"sources"' in text:
            return ('sourcemap', None)

        # Plain text with content
        if len(text) > 10:
            return ('text', None)

        return ('unknown', None)

    @staticmethod
    def scan_for_secrets(text: str) -> list[dict]:
        """Scan text for secret/credential patterns. Returns list of findings."""
        findings = []
        seen = set()

        for name, pattern in SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                matched = match.group()
                # Deduplicate
                key = (name, matched[:50])
                if key in seen:
                    continue
                seen.add(key)

                # Mask the actual secret value for safety
                if len(matched) > 20:
                    masked = matched[:8] + '****' + matched[-4:]
                else:
                    masked = matched[:4] + '****'

                findings.append({
                    'type': name,
                    'value_masked': masked,
                    'position': match.start(),
                    'line': text[:match.start()].count('\n') + 1,
                })
        return findings

    @staticmethod
    def is_false_positive(body_text: str, status: int, url: str) -> tuple[bool, str]:
        """Check if a response is a false positive. Returns (is_fp, reason)."""
        if not body_text or not body_text.strip():
            return True, "Empty response body"

        # Soft 404 detection
        for pattern in FALSE_POSITIVE_PATTERNS:
            if pattern.search(body_text):
                return True, f"Matches false positive pattern"

        # Default/placeholder page detection
        stripped = body_text.strip()
        if len(stripped) < 50 and not any(c in stripped for c in ['{', '[', '=', ':']):
            return True, "Response too short and no structured data"

        # Check if it's just a generic JSON error
        try:
            data = json.loads(stripped)
            if isinstance(data, dict):
                error_keys = {'error', 'message', 'status', 'statusCode', 'code'}
                if set(data.keys()).issubset(error_keys | {'timestamp', 'path', 'detail'}):
                    msg = str(data.get('message', data.get('error', ''))).lower()
                    if any(w in msg for w in ['not found', 'forbidden', 'unauthorized', 'denied', 'invalid']):
                        return True, f"JSON error response: {msg[:100]}"
        except (json.JSONDecodeError, ValueError):
            pass

        return False, ""

    @staticmethod
    def classify_severity(url: str, content_format: str, secrets: list, parsed_data: Any) -> tuple[str, str]:
        """Classify the severity of a finding. Returns (severity, reason)."""
        path = urlparse(url).path if url else ''

        # Check path-based rules first
        for pattern, severity, desc in PATH_SEVERITY_RULES:
            if pattern.search(path):
                # Upgrade if secrets found
                if secrets and severity != CRITICAL:
                    return CRITICAL, f"{desc} + contains secrets"
                return severity, desc

        # Secret-based classification
        if secrets:
            critical_secrets = [s for s in secrets if s['type'] in {
                'AWS Access Key', 'AWS Secret Key', 'Private Key Block',
                'Database URL', 'Connection String', 'Stripe Secret Key',
                'GitHub Token', 'GitLab Token',
            }]
            if critical_secrets:
                return CRITICAL, f"Contains {critical_secrets[0]['type']}"
            return HIGH, f"Contains {secrets[0]['type']}"

        # Content-type based
        if content_format == 'sql':
            return CRITICAL, "SQL dump detected"
        if content_format == 'env':
            return CRITICAL, "Environment variables exposed"
        if content_format == 'sourcemap':
            return HIGH, "Source map exposed (source code reconstruction)"
        if content_format == 'json' and parsed_data:
            if isinstance(parsed_data, dict):
                suspicious_keys = {'password', 'secret', 'token', 'key', 'credential',
                                   'api_key', 'apiKey', 'private', 'auth'}
                found = suspicious_keys & set(str(k).lower() for k in parsed_data.keys())
                if found:
                    return HIGH, f"JSON contains sensitive keys: {found}"
                # Check if it's configuration/settings
                if len(parsed_data) > 3:
                    return MEDIUM, "JSON configuration/data exposed"
            if isinstance(parsed_data, list) and len(parsed_data) > 0:
                if isinstance(parsed_data[0], dict):
                    return MEDIUM, "JSON data array exposed"
        if content_format == 'xml':
            return MEDIUM, "XML data exposed"
        if content_format == 'yaml':
            return MEDIUM, "YAML configuration exposed"
        if content_format == 'csv':
            return MEDIUM, "CSV data exposed"
        if content_format == 'ini':
            return MEDIUM, "Configuration file exposed"
        if content_format == 'archive':
            return HIGH, "Archive/compressed file accessible"
        if content_format == 'javascript':
            return LOW, "JavaScript file accessible"
        if content_format == 'html':
            return LOW, "HTML page accessible"

        return INFO, "Resource accessible"


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------
class FfufAnalyzer:
    """Main analysis engine — threaded, memory-optimized."""

    def __init__(self, args):
        self.args = args
        self.validator = ContentValidator(
            timeout=args.timeout,
            verify_ssl=args.verify_ssl,
        )
        self.findings = []
        self.false_positives = []
        self.errors = []
        self.stats = defaultdict(int)
        self._lock = __import__('threading').Lock()
        self._progress_count = 0
        self._total_count = 0

    def analyze_single(self, result: dict) -> Optional[dict]:
        """Analyze a single ffuf result entry. Returns finding dict or None."""
        try:
            url = result.get('url', '')
            status = result.get('status', 0)
            length = result.get('length', result.get('content-length', 0))
            words = result.get('words', 0)
            lines = result.get('lines', 0)
            content_type = result.get('content-type', '')
            fuzz_input = ''
            if isinstance(result.get('input'), dict):
                fuzz_input = result['input'].get('FUZZ', '')
            elif isinstance(result.get('input'), str):
                fuzz_input = result['input']
            redirect = result.get('redirectlocation', '')
            duration = result.get('duration', 0)

            # Build URL if not present
            if not url and fuzz_input:
                url = fuzz_input  # fallback

            # --- PHASE 1: Quick filters (no network) ---

            # Skip non-200 unless specifically interesting
            if status not in (200, 204):
                with self._lock:
                    self.stats['filtered_status'] += 1
                return None

            # Skip zero-length responses
            if length == 0 and status == 200:
                with self._lock:
                    self.stats['filtered_empty'] += 1
                return None

            # --- PHASE 2: Path-based pre-classification ---
            path = urlparse(url).path if url else fuzz_input
            path_severity = INFO
            path_reason = "Unknown"
            for pattern, sev, desc in PATH_SEVERITY_RULES:
                if pattern.search(path):
                    path_severity = sev
                    path_reason = desc
                    break

            # --- PHASE 3: Deep validation (re-fetch if enabled) ---
            body_text = ''
            content_format = 'unknown'
            parsed_data = None
            secrets = []
            revalidated = False

            if self.args.no_revalidate:
                # Use ffuf data only
                content_format = self._guess_format_from_path(path, content_type)
                severity = path_severity
                reason = path_reason
            else:
                # Re-fetch for deep analysis
                resp = self.validator.fetch_url(url)
                if resp and resp['status'] == 200 and resp['body']:
                    revalidated = True
                    body = resp['body']
                    actual_ct = resp.get('content_type', content_type)

                    # Detect format
                    content_format, parsed_data = self.validator.detect_content_format(body, actual_ct)

                    # Get text for analysis
                    try:
                        body_text = body.decode('utf-8', errors='replace')
                    except Exception:
                        body_text = ''

                    # False positive check
                    is_fp, fp_reason = self.validator.is_false_positive(body_text, status, url)
                    if is_fp:
                        with self._lock:
                            self.false_positives.append({
                                'url': url,
                                'reason': fp_reason,
                                'status': status,
                            })
                            self.stats['false_positives'] += 1
                        return None

                    # Secret scanning
                    if body_text:
                        secrets = self.validator.scan_for_secrets(body_text[:500000])  # scan first 500KB

                    # Classify severity
                    severity, reason = self.validator.classify_severity(url, content_format, secrets, parsed_data)
                elif resp and resp['status'] != 200:
                    # Re-fetch returned different status — false positive
                    with self._lock:
                        self.false_positives.append({
                            'url': url,
                            'reason': f"Re-validation returned status {resp['status']}",
                            'status': resp['status'],
                        })
                        self.stats['false_positives'] += 1
                    return None
                elif resp and resp.get('error'):
                    # Network error during re-validation — keep as unverified
                    severity = path_severity
                    reason = f"{path_reason} (unverified: {resp['error'][:80]})"
                    revalidated = False
                else:
                    severity = path_severity
                    reason = path_reason

            # --- PHASE 4: Severity filter ---
            if self.args.severity:
                allowed = [s.upper() for s in self.args.severity.split(',')]
                if severity not in allowed:
                    with self._lock:
                        self.stats['filtered_severity'] += 1
                    return None

            # --- PHASE 5: Build finding ---
            finding = {
                'url': url,
                'path': path,
                'fuzz_input': fuzz_input,
                'status': status,
                'length': length,
                'words': words,
                'lines': lines,
                'content_type': content_type,
                'content_format': content_format,
                'redirect': redirect,
                'duration_ms': duration,
                'severity': severity,
                'reason': reason,
                'secrets_found': len(secrets),
                'secrets': secrets[:10],  # cap at 10
                'revalidated': revalidated,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }

            # Add parsed data summary (not full body — memory optimization)
            if parsed_data and isinstance(parsed_data, dict):
                finding['data_keys'] = list(parsed_data.keys())[:50]
                finding['data_preview'] = str(parsed_data)[:500]
            elif parsed_data and isinstance(parsed_data, list):
                finding['data_count'] = len(parsed_data)
                finding['data_preview'] = str(parsed_data[:3])[:500]

            with self._lock:
                self.stats[f'severity_{severity}'] += 1
                self.stats[f'format_{content_format}'] += 1
                self.stats['true_positives'] += 1

            return finding

        except Exception as e:
            with self._lock:
                self.errors.append({'url': result.get('url', '?'), 'error': str(e)})
                self.stats['errors'] += 1
            return None
        finally:
            with self._lock:
                self._progress_count += 1
                if self._progress_count % 50 == 0 or self._progress_count == self._total_count:
                    pct = (self._progress_count / self._total_count * 100) if self._total_count else 0
                    print(f"\r  {C.CY}[{self._progress_count}/{self._total_count}]{C.RST} "
                          f"Analyzed {pct:.0f}% | "
                          f"{C.G}TP:{self.stats['true_positives']}{C.RST} "
                          f"{C.R}FP:{self.stats['false_positives']}{C.RST} "
                          f"{C.Y}Err:{self.stats['errors']}{C.RST}",
                          end='', flush=True)

    @staticmethod
    def _guess_format_from_path(path: str, content_type: str) -> str:
        """Guess content format from path extension when not re-validating."""
        ext = Path(path).suffix.lower() if path else ''
        ct = content_type.lower() if content_type else ''

        ext_map = {
            '.json': 'json', '.xml': 'xml', '.yaml': 'yaml', '.yml': 'yaml',
            '.toml': 'toml', '.ini': 'ini', '.cfg': 'ini', '.conf': 'ini',
            '.properties': 'ini', '.env': 'env', '.sql': 'sql',
            '.csv': 'csv', '.tsv': 'csv', '.html': 'html', '.htm': 'html',
            '.js': 'javascript', '.map': 'sourcemap', '.php': 'php',
            '.py': 'python', '.rb': 'ruby', '.txt': 'text', '.log': 'text',
            '.zip': 'archive', '.gz': 'archive', '.tar': 'archive',
            '.7z': 'archive', '.rar': 'archive',
            '.sqlite': 'sqlite', '.sqlite3': 'sqlite', '.db': 'sqlite',
            '.pem': 'certificate', '.crt': 'certificate', '.key': 'key',
            '.pdf': 'pdf', '.wasm': 'wasm',
        }
        if ext in ext_map:
            return ext_map[ext]

        for ct_pattern, (fmt, _) in INTERESTING_CONTENT_TYPES.items():
            if ct_pattern in ct:
                return fmt.lower()

        return 'unknown'

    def run(self, input_files: list[str]):
        """Main entry point — parse, analyze, output."""
        start_time = time.time()

        # Banner
        print(f"\n{C.BOLD}{C.CY}╔══════════════════════════════════════════════╗{C.RST}")
        print(f"{C.BOLD}{C.CY}║  ffuf-analyzer v{VERSION}                       ║{C.RST}")
        print(f"{C.BOLD}{C.CY}║  Intelligent False Positive Elimination      ║{C.RST}")
        print(f"{C.BOLD}{C.CY}╚══════════════════════════════════════════════╝{C.RST}\n")

        # --- Parse input files ---
        all_results = []
        configs = []

        for fpath in input_files:
            print(f"  {C.B}[*]{C.RST} Parsing: {fpath}")
            try:
                if fpath.endswith('.csv'):
                    results = parse_ffuf_csv(fpath)
                    configs.append({})
                else:
                    config, results = parse_ffuf_json_streaming(fpath)
                    configs.append(config)
                print(f"      {C.G}✓{C.RST} {len(results)} results loaded")
                all_results.extend(results)
                self.stats['total_input'] += len(results)
            except Exception as e:
                print(f"      {C.R}✗{C.RST} Error: {e}")
                self.errors.append({'file': fpath, 'error': str(e)})

        if not all_results:
            print(f"\n  {C.R}[!] No results to analyze. Exiting.{C.RST}\n")
            return

        # Deduplicate by URL
        seen_urls = set()
        unique_results = []
        for r in all_results:
            url = r.get('url', '')
            if url not in seen_urls:
                seen_urls.add(url)
                unique_results.append(r)
            else:
                self.stats['duplicates'] += 1

        print(f"\n  {C.B}[*]{C.RST} Total: {len(all_results)} | Unique: {len(unique_results)} | Dupes removed: {self.stats['duplicates']}")

        # --- Pre-filter: only 200/204 status ---
        status_200 = [r for r in unique_results if r.get('status', 0) in (200, 204)]
        other_status = len(unique_results) - len(status_200)
        print(f"  {C.B}[*]{C.RST} Status 200/204: {len(status_200)} | Other (filtered): {other_status}")

        if not status_200:
            print(f"\n  {C.Y}[!] No 200/204 responses found. Nothing to validate.{C.RST}\n")
            return

        # --- Threaded analysis ---
        self._total_count = len(status_200)
        self._progress_count = 0
        threads = min(self.args.threads, len(status_200))

        mode = "NO-REVALIDATE (ffuf data only)" if self.args.no_revalidate else f"DEEP VALIDATION ({threads} threads)"
        print(f"  {C.B}[*]{C.RST} Mode: {C.BOLD}{mode}{C.RST}")
        print(f"  {C.B}[*]{C.RST} Analyzing...\n")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.analyze_single, r): r for r in status_200}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    self.findings.append(result)

        print()  # newline after progress

        # Sort findings by severity
        self.findings.sort(key=lambda f: SEVERITY_ORDER.get(f['severity'], 99))

        # --- Output ---
        elapsed = time.time() - start_time
        self._print_summary(elapsed)
        self._write_outputs()

    def _print_summary(self, elapsed: float):
        """Print colored terminal summary."""
        print(f"\n{C.BOLD}{'='*60}{C.RST}")
        print(f"{C.BOLD}  ANALYSIS COMPLETE — {elapsed:.1f}s{C.RST}")
        print(f"{'='*60}\n")

        print(f"  {C.BOLD}Input Stats:{C.RST}")
        print(f"    Total results parsed:    {self.stats['total_input']}")
        print(f"    Duplicates removed:      {self.stats['duplicates']}")
        print(f"    Filtered (non-200):      {self.stats.get('filtered_status', 0)}")
        print(f"    Filtered (empty):        {self.stats.get('filtered_empty', 0)}")
        print(f"    Filtered (severity):     {self.stats.get('filtered_severity', 0)}")
        print()

        print(f"  {C.BOLD}Validation Results:{C.RST}")
        print(f"    {C.G}True Positives:      {self.stats['true_positives']}{C.RST}")
        print(f"    {C.R}False Positives:     {self.stats['false_positives']}{C.RST}")
        print(f"    {C.Y}Errors:              {self.stats['errors']}{C.RST}")
        print()

        if self.findings:
            print(f"  {C.BOLD}Severity Breakdown:{C.RST}")
            for sev in [CRITICAL, HIGH, MEDIUM, LOW, INFO]:
                count = self.stats.get(f'severity_{sev}', 0)
                if count > 0:
                    color = SEVERITY_COLOR.get(sev, '')
                    bar = '█' * min(count, 40)
                    print(f"    {color}{sev:10s}{C.RST} {count:5d}  {color}{bar}{C.RST}")
            print()

            print(f"  {C.BOLD}Content Format Breakdown:{C.RST}")
            formats = [(k.replace('format_', ''), v) for k, v in self.stats.items() if k.startswith('format_')]
            formats.sort(key=lambda x: -x[1])
            for fmt, count in formats[:15]:
                print(f"    {fmt:20s} {count:5d}")
            print()

            # Top findings preview
            print(f"  {C.BOLD}Top Findings:{C.RST}\n")
            for f in self.findings[:20]:
                sev_color = SEVERITY_COLOR.get(f['severity'], '')
                secret_tag = f" {C.R}🔑 {f['secrets_found']} secrets{C.RST}" if f['secrets_found'] > 0 else ""
                verified = f" {C.G}✓{C.RST}" if f['revalidated'] else f" {C.Y}?{C.RST}"
                print(f"    {sev_color}[{f['severity']:8s}]{C.RST}{verified} "
                      f"{C.W}{f['url']}{C.RST}")
                print(f"             {C.DIM}{f['reason']} | {f['content_format']} | {f['length']}B{C.RST}{secret_tag}")
            if len(self.findings) > 20:
                print(f"\n    {C.DIM}... and {len(self.findings) - 20} more (see output files){C.RST}")
        else:
            print(f"  {C.Y}No true positive findings.{C.RST}")

        print(f"\n{'='*60}\n")

    def _write_outputs(self):
        """Write JSON, CSV, and TXT output files."""
        if not self.findings:
            return

        base = self.args.output
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')

        # --- JSON Report ---
        json_path = f"{base}_findings_{ts}.json"
        report = {
            'metadata': {
                'tool': f'ffuf-analyzer v{VERSION}',
                'timestamp': datetime.now(timezone.utc).isoformat(),
                'input_files': self.args.input,
                'total_input': self.stats['total_input'],
                'true_positives': self.stats['true_positives'],
                'false_positives': self.stats['false_positives'],
                'errors': self.stats['errors'],
                'revalidation': not self.args.no_revalidate,
                'threads': self.args.threads,
            },
            'severity_summary': {
                sev: self.stats.get(f'severity_{sev}', 0)
                for sev in [CRITICAL, HIGH, MEDIUM, LOW, INFO]
            },
            'findings': self.findings,
            'false_positives_sample': self.false_positives[:100],
            'errors_sample': self.errors[:50],
        }
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, default=str)
        print(f"  {C.G}[+]{C.RST} JSON report:  {C.BOLD}{json_path}{C.RST}")

        # --- CSV ---
        csv_path = f"{base}_findings_{ts}.csv"
        csv_fields = ['severity', 'url', 'path', 'status', 'content_format',
                      'length', 'secrets_found', 'reason', 'revalidated']
        with open(csv_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=csv_fields, extrasaction='ignore')
            writer.writeheader()
            for finding in self.findings:
                writer.writerow(finding)
        print(f"  {C.G}[+]{C.RST} CSV report:   {C.BOLD}{csv_path}{C.RST}")

        # --- Plain text URLs (by severity) ---
        txt_path = f"{base}_urls_{ts}.txt"
        with open(txt_path, 'w', encoding='utf-8') as f:
            current_sev = None
            for finding in self.findings:
                if finding['severity'] != current_sev:
                    current_sev = finding['severity']
                    f.write(f"\n# === {current_sev} ===\n")
                secret_note = f"  # {finding['secrets_found']} secrets detected" if finding['secrets_found'] > 0 else ""
                f.write(f"{finding['url']}{secret_note}\n")
        print(f"  {C.G}[+]{C.RST} URL list:     {C.BOLD}{txt_path}{C.RST}")

        # --- Critical/High only (for quick action) ---
        crit_path = f"{base}_critical_{ts}.txt"
        crit_findings = [f for f in self.findings if f['severity'] in (CRITICAL, HIGH)]
        if crit_findings:
            with open(crit_path, 'w', encoding='utf-8') as f:
                for finding in crit_findings:
                    f.write(f"[{finding['severity']}] {finding['url']} | {finding['reason']}\n")
            print(f"  {C.G}[+]{C.RST} Critical/High: {C.BOLD}{crit_path}{C.RST}")

        print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description='ffuf-analyzer: Intelligent ffuf output parser with deep validation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i ffuf_output.json
  %(prog)s -i ffuf_output.json -t 50 --timeout 15
  %(prog)s -i scan1.json scan2.json --merge
  %(prog)s -i ffuf_output.json --no-revalidate
  %(prog)s -i ffuf_output.json -o results --severity critical,high
  %(prog)s -i ffuf_output.csv
        """
    )
    parser.add_argument('-i', '--input', nargs='+', required=True,
                        help='ffuf JSON/CSV output file(s)')
    parser.add_argument('-o', '--output', default='ffuf_analyzed',
                        help='Output file prefix (default: ffuf_analyzed)')
    parser.add_argument('-t', '--threads', type=int, default=30,
                        help='Number of threads for re-validation (default: 30)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='HTTP timeout for re-validation in seconds (default: 10)')
    parser.add_argument('--no-revalidate', action='store_true',
                        help='Skip re-fetching URLs (analyze ffuf data only)')
    parser.add_argument('--verify-ssl', action='store_true',
                        help='Verify SSL certificates during re-validation')
    parser.add_argument('--severity', type=str, default=None,
                        help='Filter by severity: critical,high,medium,low,info')
    parser.add_argument('--merge', action='store_true',
                        help='Merge multiple input files into one analysis')
    parser.add_argument('--version', action='version', version=f'ffuf-analyzer v{VERSION}')

    args = parser.parse_args()

    # Validate inputs
    for f in args.input:
        if not os.path.exists(f):
            print(f"{C.R}[!] File not found: {f}{C.RST}")
            sys.exit(1)

    # Handle SIGINT gracefully
    def signal_handler(sig, frame):
        print(f"\n\n{C.Y}[!] Interrupted. Saving partial results...{C.RST}")
        analyzer._write_outputs()
        sys.exit(0)
    signal.signal(signal.SIGINT, signal_handler)

    # Run
    analyzer = FfufAnalyzer(args)
    analyzer.run(args.input)


if __name__ == '__main__':
    main()
