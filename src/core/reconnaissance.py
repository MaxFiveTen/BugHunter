"""
Reconnaissance module for BugHunt.
Implements passive and active reconnaissance techniques.
"""

import asyncio
import aiohttp
import socket
import subprocess
import re
import json
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin
import logging
from datetime import datetime
try:
    import dns.resolver
except ImportError:
    dns = None
try:
    import whois
except ImportError:
    whois = None
import requests
from bs4 import BeautifulSoup
import random
import string


class ReconnaissanceModule:
    """Advanced reconnaissance and information gathering module."""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.session = None
        self.logger = logging.getLogger(__name__)
        self.recon_results = {}
        
        # Parse target information
        parsed_url = urlparse(target_url)
        self.domain = parsed_url.hostname
        self.scheme = parsed_url.scheme
        self.port = parsed_url.port or (443 if self.scheme == 'https' else 80)
        
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
            
    async def run_reconnaissance(self) -> Dict:
        """Run comprehensive reconnaissance."""
        print("🔍 Starting reconnaissance...")
        
        try:
            # Basic target information
            self.recon_results['target_info'] = await self._gather_target_info()
            
            # DNS reconnaissance
            self.recon_results['dns_info'] = await self._dns_reconnaissance()
            
            # Subdomain enumeration
            self.recon_results['subdomains'] = await self._subdomain_enumeration()
            
            # Technology stack detection
            self.recon_results['technology_stack'] = await self._detect_technology_stack()
            
            # Directory and file discovery
            self.recon_results['directories'] = await self._directory_discovery()
            
            # Port scanning
            self.recon_results['ports'] = await self._port_scanning()
            
            # WHOIS information
            self.recon_results['whois_info'] = await self._whois_lookup()
            
            # Certificate information
            self.recon_results['certificate_info'] = await self._certificate_analysis()
            
            # Social media and external reconnaissance
            self.recon_results['external_info'] = await self._external_reconnaissance()
            
        except Exception as e:
            self.logger.error(f"Reconnaissance error: {str(e)}")
            
        return self.recon_results
        
    async def _gather_target_info(self) -> Dict:
        """Gather basic target information."""
        print("📋 Gathering target information...")
        
        target_info = {
            'domain': self.domain,
            'scheme': self.scheme,
            'port': self.port,
            'ip_address': None,
            'server_info': None,
            'response_headers': None,
            'robots_txt': None,
            'sitemap': None
        }
        
        try:
            # Get IP address
            target_info['ip_address'] = socket.gethostbyname(self.domain)
            
            # Get server information
            response = await self._make_request(self.target_url)
            if response:
                target_info['server_info'] = response.headers.get('Server', 'Unknown')
                target_info['response_headers'] = dict(response.headers)
                
                # Check for robots.txt
                robots_url = urljoin(self.target_url, '/robots.txt')
                robots_response = await self._make_request(robots_url)
                if robots_response and robots_response.status == 200:
                    target_info['robots_txt'] = await robots_response.text()
                    
                # Check for sitemap
                sitemap_url = urljoin(self.target_url, '/sitemap.xml')
                sitemap_response = await self._make_request(sitemap_url)
                if sitemap_response and sitemap_response.status == 200:
                    target_info['sitemap'] = await sitemap_response.text()
                    
        except Exception as e:
            self.logger.error(f"Target info gathering error: {str(e)}")
            
        return target_info
        
    async def _dns_reconnaissance(self) -> Dict:
        """Perform DNS reconnaissance."""
        print("🌐 Performing DNS reconnaissance...")
        
        dns_info = {
            'a_records': [],
            'aaaa_records': [],
            'mx_records': [],
            'txt_records': [],
            'ns_records': [],
            'cname_records': [],
            'soa_record': None,
            'dnssec': False
        }
        
        try:
            # A records
            if dns:
                try:
                    a_records = dns.resolver.resolve(self.domain, 'A')
                    dns_info['a_records'] = [str(record) for record in a_records]
                except:
                    pass
                
            # AAAA records
            if dns:
                try:
                    aaaa_records = dns.resolver.resolve(self.domain, 'AAAA')
                    dns_info['aaaa_records'] = [str(record) for record in aaaa_records]
                except:
                    pass
                    
                # MX records
                try:
                    mx_records = dns.resolver.resolve(self.domain, 'MX')
                    dns_info['mx_records'] = [str(record) for record in mx_records]
                except:
                    pass
                    
                # TXT records
                try:
                    txt_records = dns.resolver.resolve(self.domain, 'TXT')
                    dns_info['txt_records'] = [str(record) for record in txt_records]
                except:
                    pass
                    
                # NS records
                try:
                    ns_records = dns.resolver.resolve(self.domain, 'NS')
                    dns_info['ns_records'] = [str(record) for record in ns_records]
                except:
                    pass
                    
                # SOA record
                try:
                    soa_record = dns.resolver.resolve(self.domain, 'SOA')
                    dns_info['soa_record'] = str(soa_record[0])
                except:
                    pass
                
        except Exception as e:
            self.logger.error(f"DNS reconnaissance error: {str(e)}")
            
        return dns_info
        
    async def _subdomain_enumeration(self) -> Dict:
        """Enumerate subdomains."""
        print("🔍 Enumerating subdomains...")
        
        subdomain_results = {
            'discovered_subdomains': set(),
            'wildcard_dns': False,
            'total_found': 0
        }
        
        # Common subdomain wordlist
        subdomain_wordlist = [
            'www', 'mail', 'ftp', 'admin', 'test', 'dev', 'staging', 'prod',
            'api', 'app', 'blog', 'shop', 'store', 'support', 'help', 'docs',
            'secure', 'ssl', 'vpn', 'remote', 'backup', 'old', 'new', 'temp',
            'beta', 'alpha', 'demo', 'stage', 'preview', 'cdn', 'static',
            'assets', 'media', 'files', 'download', 'upload', 'images', 'img',
            'css', 'js', 'scripts', 'lib', 'libs', 'js', 'css', 'fonts',
            'mobile', 'm', 'wap', 'i', 'touch', 'web', 'site', 'sites',
            'portal', 'gateway', 'proxy', 'cache', 'mirror', 'cdn', 'edge',
            'origin', 'api-v1', 'api-v2', 'v1', 'v2', 'v3', 'api1', 'api2',
            'internal', 'intranet', 'extranet', 'partner', 'client', 'customers',
            'members', 'users', 'accounts', 'billing', 'payment', 'pay',
            'shop', 'store', 'cart', 'checkout', 'order', 'orders',
            'news', 'press', 'media', 'events', 'calendar', 'schedule'
        ]
        
        try:
            # Test for wildcard DNS
            random_subdomain = f"{''.join(random.choices(string.ascii_lowercase, k=10))}.{self.domain}"
            try:
                socket.gethostbyname(random_subdomain)
                subdomain_results['wildcard_dns'] = True
            except:
                subdomain_results['wildcard_dns'] = False
                
            # Enumerate subdomains
            for subdomain in subdomain_wordlist:
                full_domain = f"{subdomain}.{self.domain}"
                
                try:
                    ip = socket.gethostbyname(full_domain)
                    subdomain_results['discovered_subdomains'].add(full_domain)
                    
                    # Test if subdomain is accessible via HTTP/HTTPS
                    for scheme in ['http', 'https']:
                        subdomain_url = f"{scheme}://{full_domain}"
                        response = await self._make_request(subdomain_url)
                        if response and response.status in [200, 301, 302, 403]:
                            subdomain_results['discovered_subdomains'].add(subdomain_url)
                            
                except:
                    pass
                    
            subdomain_results['total_found'] = len(subdomain_results['discovered_subdomains'])
            subdomain_results['discovered_subdomains'] = list(subdomain_results['discovered_subdomains'])
            
        except Exception as e:
            self.logger.error(f"Subdomain enumeration error: {str(e)}")
            
        return subdomain_results
        
    async def _detect_technology_stack(self) -> Dict:
        """Detect technology stack."""
        print("🔧 Detecting technology stack...")
        
        tech_stack = {
            'web_server': 'Unknown',
            'programming_language': 'Unknown',
            'framework': 'Unknown',
            'cms': 'Unknown',
            'javascript_libraries': [],
            'analytics': [],
            'cdn': 'Unknown',
            'security_headers': {},
            'cookies': []
        }
        
        try:
            response = await self._make_request(self.target_url)
            if response:
                headers = response.headers
                content = await response.text()
                
                # Detect web server
                server_header = headers.get('Server', '').lower()
                if 'apache' in server_header:
                    tech_stack['web_server'] = 'Apache'
                elif 'nginx' in server_header:
                    tech_stack['web_server'] = 'Nginx'
                elif 'iis' in server_header:
                    tech_stack['web_server'] = 'IIS'
                elif 'cloudflare' in server_header:
                    tech_stack['web_server'] = 'Cloudflare'
                    
                # Detect programming language and framework
                if 'x-powered-by' in headers:
                    powered_by = headers['x-powered-by'].lower()
                    if 'php' in powered_by:
                        tech_stack['programming_language'] = 'PHP'
                    elif 'asp.net' in powered_by:
                        tech_stack['programming_language'] = 'ASP.NET'
                    elif 'python' in powered_by:
                        tech_stack['programming_language'] = 'Python'
                        
                # Detect CMS
                if 'wp-content' in content or 'wp-includes' in content:
                    tech_stack['cms'] = 'WordPress'
                elif 'drupal' in content.lower():
                    tech_stack['cms'] = 'Drupal'
                elif 'joomla' in content.lower():
                    tech_stack['cms'] = 'Joomla'
                    
                # Detect JavaScript libraries
                js_libraries = re.findall(r'src="[^"]*/([^/]+\.js)"', content)
                tech_stack['javascript_libraries'] = list(set(js_libraries))
                
                # Detect analytics
                if 'google-analytics' in content or 'gtag' in content:
                    tech_stack['analytics'].append('Google Analytics')
                if 'facebook' in content and 'pixel' in content:
                    tech_stack['analytics'].append('Facebook Pixel')
                    
                # Check security headers
                security_headers = [
                    'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
                    'Strict-Transport-Security', 'Content-Security-Policy',
                    'Referrer-Policy', 'Permissions-Policy'
                ]
                
                for header in security_headers:
                    if header in headers:
                        tech_stack['security_headers'][header] = headers[header]
                        
                # Check cookies
                set_cookie = headers.get('Set-Cookie', '')
                if set_cookie:
                    tech_stack['cookies'] = set_cookie.split(',')
                    
        except Exception as e:
            self.logger.error(f"Technology stack detection error: {str(e)}")
            
        return tech_stack
        
    async def _directory_discovery(self) -> Dict:
        """Discover directories and files."""
        print("📁 Discovering directories and files...")
        
        directory_results = {
            'directories': [],
            'files': [],
            'admin_panels': [],
            'backup_files': [],
            'config_files': [],
            'total_found': 0
        }
        
        # Common directories and files
        common_paths = [
            '/admin', '/administrator', '/wp-admin', '/login', '/panel',
            '/dashboard', '/control', '/manage', '/config', '/settings',
            '/api', '/rest', '/graphql', '/soap', '/rpc',
            '/upload', '/uploads', '/files', '/images', '/media', '/assets',
            '/backup', '/backups', '/old', '/test', '/dev', '/staging',
            '/phpinfo.php', '/info.php', '/test.php', '/debug.php', '/status.php',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/.git', '/.svn', '/.env', '/config.php', '/database.php', '/db.php',
            '/cgi-bin', '/bin', '/sbin', '/usr', '/var', '/tmp', '/temp',
            '/wp-content', '/wp-includes', '/administrator',
            '/.htaccess', '/web.config', '/.htpasswd', '/.htgroup',
            '/readme.txt', '/changelog.txt', '/license.txt', '/install.txt',
            '/error_log', '/access.log', '/error.log', '/access_log'
        ]
        
        try:
            for path in common_paths:
                test_url = urljoin(self.target_url, path)
                
                response = await self._make_request(test_url)
                if response:
                    status = response.status
                    
                    if status == 200:
                        if path.endswith('/'):
                            directory_results['directories'].append(test_url)
                        else:
                            directory_results['files'].append(test_url)
                            
                        # Categorize findings
                        if 'admin' in path.lower():
                            directory_results['admin_panels'].append(test_url)
                        elif 'backup' in path.lower():
                            directory_results['backup_files'].append(test_url)
                        elif any(ext in path for ext in ['.php', '.config', '.env']):
                            directory_results['config_files'].append(test_url)
                            
                    elif status in [301, 302, 403, 401]:
                        directory_results['directories'].append(f"{test_url} (Status: {status})")
                        
            directory_results['total_found'] = (
                len(directory_results['directories']) +
                len(directory_results['files']) +
                len(directory_results['admin_panels']) +
                len(directory_results['backup_files']) +
                len(directory_results['config_files'])
            )
            
        except Exception as e:
            self.logger.error(f"Directory discovery error: {str(e)}")
            
        return directory_results
        
    async def _port_scanning(self) -> Dict:
        """Perform port scanning."""
        print("🔌 Performing port scanning...")
        
        port_results = {
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'total_scanned': 0
        }
        
        # Common ports to scan
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 1433, 3306,
            3389, 5432, 5900, 8080, 8443, 8888, 9090, 9200, 9300
        ]
        
        try:
            for port in common_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(1)
                    result = sock.connect_ex((self.domain, port))
                    sock.close()
                    
                    if result == 0:
                        port_results['open_ports'].append(port)
                    else:
                        port_results['closed_ports'].append(port)
                        
                except:
                    port_results['filtered_ports'].append(port)
                    
                port_results['total_scanned'] += 1
                
        except Exception as e:
            self.logger.error(f"Port scanning error: {str(e)}")
            
        return port_results
        
    async def _whois_lookup(self) -> Dict:
        """Perform WHOIS lookup."""
        print("📋 Performing WHOIS lookup...")
        
        whois_info = {}
        
        try:
            if whois:
                domain_info = whois.whois(self.domain)
            else:
                raise ImportError("whois module not available")
            
            whois_info = {
                'registrar': domain_info.registrar,
                'creation_date': str(domain_info.creation_date) if domain_info.creation_date else None,
                'expiration_date': str(domain_info.expiration_date) if domain_info.expiration_date else None,
                'name_servers': domain_info.name_servers if domain_info.name_servers else [],
                'status': domain_info.status if domain_info.status else [],
                'emails': domain_info.emails if domain_info.emails else [],
                'dnssec': domain_info.dnssec if domain_info.dnssec else False
            }
            
        except Exception as e:
            self.logger.error(f"WHOIS lookup error: {str(e)}")
            whois_info = {'error': str(e)}
            
        return whois_info
        
    async def _certificate_analysis(self) -> Dict:
        """Analyze SSL certificate."""
        print("🔐 Analyzing SSL certificate...")
        
        cert_info = {}
        
        try:
            if self.scheme == 'https':
                import ssl
                import socket
                from datetime import datetime
                
                context = ssl.create_default_context()
                with socket.create_connection((self.domain, 443), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        cert = ssock.getpeercert()
                        
                        cert_info = {
                            'subject': dict(x[0] for x in cert['subject']),
                            'issuer': dict(x[0] for x in cert['issuer']),
                            'version': cert['version'],
                            'serial_number': cert['serialNumber'],
                            'not_before': cert['notBefore'],
                            'not_after': cert['notAfter'],
                            'signature_algorithm': cert['signatureAlgorithm'],
                            'tls_version': ssock.version()
                        }
                        
                        # Check certificate expiration
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        days_until_expiry = (not_after - datetime.now()).days
                        cert_info['days_until_expiry'] = days_until_expiry
                        cert_info['is_expired'] = days_until_expiry < 0
                        
        except Exception as e:
            self.logger.error(f"Certificate analysis error: {str(e)}")
            cert_info = {'error': str(e)}
            
        return cert_info
        
    async def _external_reconnaissance(self) -> Dict:
        """Perform external reconnaissance."""
        print("🌍 Performing external reconnaissance...")
        
        external_info = {
            'shodan_results': {},
            'virustotal_results': {},
            'social_media': {},
            'github_repos': [],
            'pastebin_results': []
        }
        
        try:
            # Search for mentions on social media and other platforms
            search_terms = [self.domain, self.domain.replace('.', ' ')]
            
            for term in search_terms:
                # This would typically use APIs for external services
                # For now, we'll just structure the data
                external_info['social_media'][term] = 'External API integration needed'
                
        except Exception as e:
            self.logger.error(f"External reconnaissance error: {str(e)}")
            
        return external_info
        
    async def _make_request(self, url: str, **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make HTTP request with error handling."""
        try:
            async with self.session.request('GET', url, **kwargs) as response:
                return response
        except Exception as e:
            self.logger.debug(f"Request failed for {url}: {str(e)}")
            return None
