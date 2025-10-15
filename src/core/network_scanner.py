"""
Network scanning module for BugHunt.
Implements comprehensive network scanning capabilities.
"""

import asyncio
import socket
import subprocess
import threading
import time
from typing import Dict, List, Optional, Tuple, Set
import logging
from datetime import datetime
import ipaddress
import struct
import os


class NetworkScanner:
    """Advanced network scanning class."""
    
    def __init__(self, target: str):
        self.target = target
        self.logger = logging.getLogger(__name__)
        self.scan_results = {}
        
        # Common ports for different services
        self.common_ports = {
            'web': [80, 443, 8080, 8443, 8000, 8888, 9090, 3000, 5000],
            'database': [3306, 5432, 1433, 1521, 27017, 6379, 11211],
            'mail': [25, 110, 143, 993, 995, 587, 465],
            'ftp': [21, 22, 990, 989],
            'ssh': [22, 2222, 22222],
            'dns': [53],
            'dhcp': [67, 68],
            'ldap': [389, 636],
            'smb': [135, 139, 445],
            'rdp': [3389],
            'vnc': [5900, 5901, 5902, 5903],
            'telnet': [23],
            'snmp': [161, 162],
            'nfs': [2049],
            'kerberos': [88],
            'pop3': [110, 995],
            'imap': [143, 993],
            'smtp': [25, 587, 465],
            'http_alt': [8080, 8443, 8000, 8888, 9000],
            'admin': [8080, 8443, 9090, 10000],
            'proxy': [3128, 8080, 8118, 8888],
            'tor': [9050, 9051],
            'elasticsearch': [9200, 9300],
            'mongodb': [27017, 27018],
            'redis': [6379],
            'memcached': [11211],
            'rabbitmq': [5672, 15672],
            'kafka': [9092, 9093],
            'zookeeper': [2181, 2888, 3888],
            'consul': [8300, 8301, 8302, 8500],
            'etcd': [2379, 2380],
            'kubernetes': [6443, 8080, 10250, 10255],
            'docker': [2376, 2377],
            'jenkins': [8080, 8443],
            'gitlab': [80, 443, 8080, 8443],
            'jira': [8080, 8443],
            'confluence': [8080, 8443],
            'sonarqube': [9000],
            'grafana': [3000],
            'prometheus': [9090],
            'influxdb': [8086, 8088],
            'cassandra': [7000, 7001, 9042],
            'couchdb': [5984, 6984],
            'neo4j': [7474, 7687],
            'splunk': [8000, 8089, 9997],
            'graylog': [9000, 12201, 12202],
            'kibana': [5601],
            'logstash': [5044, 9600],
            'elastic': [9200, 9300],
            'nagios': [80, 443, 8080],
            'zabbix': [80, 443, 10051, 10052],
            'prtg': [80, 443, 8080],
            'cacti': [80, 443],
            'observium': [80, 443],
            'librenms': [80, 443],
            'openvas': [9392],
            'nessus': [8834],
            'burp': [8080],
            'owasp': [8080],
            'nexus': [8081, 8443],
            'artifactory': [8081, 8443],
            'harbor': [80, 443],
            'registry': [5000],
            'minio': [9000, 9001],
            'owncloud': [80, 443],
            'nextcloud': [80, 443],
            'seafile': [80, 443, 8082],
            'rocket_chat': [3000, 8080],
            'mattermost': [80, 443, 8065],
            'slack': [443],
            'discord': [443],
            'teams': [443],
            'zoom': [443],
            'webex': [443],
            'gotomeeting': [443],
            'bluejeans': [443],
            'jitsi': [80, 443, 4443, 10000],
            'bigbluebutton': [80, 443, 7443],
            'openmeetings': [80, 443, 8080],
            'matrix': [443, 8448],
            'signal': [443],
            'telegram': [443],
            'whatsapp': [443],
            'facebook': [443],
            'twitter': [443],
            'instagram': [443],
            'linkedin': [443],
            'youtube': [443],
            'twitch': [443],
            'reddit': [443],
            'github': [443],
            'gitlab': [80, 443, 8080, 8443],
            'bitbucket': [443],
            'sourceforge': [443],
            'codeplex': [443],
            'stackoverflow': [443],
            'stackexchange': [443],
            'medium': [443],
            'dev_to': [443],
            'hashnode': [443],
            'hackernews': [443],
            'producthunt': [443],
            'behance': [443],
            'dribbble': [443],
            'figma': [443],
            'sketch': [443],
            'adobe': [443],
            'canva': [443],
            'unsplash': [443],
            'pexels': [443],
            'shutterstock': [443],
            'getty': [443],
            'istock': [443],
            '123rf': [443],
            'depositphotos': [443],
            'freepik': [443],
            'vecteezy': [443],
            'flaticon': [443],
            'iconfinder': [443],
            'icons8': [443],
            'material_icons': [443],
            'feather_icons': [443],
            'heroicons': [443],
            'phosphor_icons': [443],
            'tabler_icons': [443],
            'lucide_icons': [443],
            'bootstrap_icons': [443],
            'font_awesome': [443],
            'fonticons': [443],
            'icomoon': [443],
            'iconify': [443],
            'unpkg': [443],
            'jsdelivr': [443],
            'cdnjs': [443],
            'google_apis': [443],
            'cloudflare': [443],
            'amazon_aws': [443],
            'microsoft_azure': [443],
            'google_cloud': [443],
            'ibm_cloud': [443],
            'oracle_cloud': [443],
            'digital_ocean': [443],
            'linode': [443],
            'vultr': [443],
            'hetzner': [443],
            'ovh': [443],
            'scaleway': [443],
            'contabo': [443],
            'ionos': [443],
            'godaddy': [443],
            'namecheap': [443],
            'cloudflare': [443],
            'incapsula': [443],
            'sucuri': [443],
            'stackpath': [443],
            'keycdn': [443],
            'bunnycdn': [443],
            'fastly': [443],
            'maxcdn': [443],
            'jsdelivr': [443],
            'unpkg': [443],
            'cdnjs': [443],
            'bootstrap': [443],
            'jquery': [443],
            'angular': [443],
            'react': [443],
            'vue': [443],
            'svelte': [443],
            'ember': [443],
            'backbone': [443],
            'knockout': [443],
            'mootools': [443],
            'prototype': [443],
            'scriptaculous': [443],
            'dojo': [443],
            'extjs': [443],
            'yui': [443],
            'mootools': [443],
            'prototype': [443],
            'scriptaculous': [443],
            'dojo': [443],
            'extjs': [443],
            'yui': [443]
        }
        
    async def run_network_scan(self) -> Dict:
        """Run comprehensive network scan."""
        print("🌐 Starting network scan...")
        
        try:
            # Determine scan type based on target
            if self._is_ip_address(self.target):
                # Single IP scan
                self.scan_results = await self._scan_single_ip(self.target)
            elif '/' in self.target:
                # CIDR range scan
                self.scan_results = await self._scan_ip_range(self.target)
            else:
                # Hostname scan
                self.scan_results = await self._scan_hostname(self.target)
                
        except Exception as e:
            self.logger.error(f"Network scan error: {str(e)}")
            self.scan_results = {'error': str(e)}
            
        return self.scan_results
        
    async def _scan_single_ip(self, ip: str) -> Dict:
        """Scan a single IP address."""
        print(f"🎯 Scanning single IP: {ip}")
        
        results = {
            'target': ip,
            'scan_type': 'single_ip',
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'services': {},
            'os_fingerprint': {},
            'banner_grab': {},
            'vulnerabilities': [],
            'scan_time': datetime.now().isoformat()
        }
        
        # Get all unique ports from common_ports
        all_ports = set()
        for port_list in self.common_ports.values():
            all_ports.update(port_list)
            
        # Scan ports
        open_ports = await self._scan_ports(ip, list(all_ports))
        results['open_ports'] = open_ports
        
        # Service detection
        for port in open_ports:
            service_info = await self._detect_service(ip, port)
            results['services'][port] = service_info
            
            # Banner grabbing
            banner = await self._grab_banner(ip, port)
            if banner:
                results['banner_grab'][port] = banner
                
        # OS fingerprinting
        results['os_fingerprint'] = await self._os_fingerprint(ip)
        
        # Vulnerability scanning
        results['vulnerabilities'] = await self._scan_vulnerabilities(ip, open_ports)
        
        return results
        
    async def _scan_ip_range(self, cidr: str) -> Dict:
        """Scan an IP range (CIDR notation)."""
        print(f"🌐 Scanning IP range: {cidr}")
        
        results = {
            'target': cidr,
            'scan_type': 'ip_range',
            'hosts': {},
            'total_hosts': 0,
            'alive_hosts': 0,
            'scan_time': datetime.now().isoformat()
        }
        
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            results['total_hosts'] = network.num_addresses
            
            # Limit to reasonable number of hosts
            if results['total_hosts'] > 1000:
                print(f"⚠️ Large network detected ({results['total_hosts']} hosts). Limiting scan to first 1000 hosts.")
                hosts_to_scan = list(network.hosts())[:1000]
            else:
                hosts_to_scan = list(network.hosts())
                
            # Scan each host
            for ip in hosts_to_scan:
                ip_str = str(ip)
                
                # Quick ping to check if host is alive
                if await self._is_host_alive(ip_str):
                    results['alive_hosts'] += 1
                    host_results = await self._scan_single_ip(ip_str)
                    results['hosts'][ip_str] = host_results
                    
        except Exception as e:
            self.logger.error(f"IP range scan error: {str(e)}")
            results['error'] = str(e)
            
        return results
        
    async def _scan_hostname(self, hostname: str) -> Dict:
        """Scan a hostname."""
        print(f"🏠 Scanning hostname: {hostname}")
        
        results = {
            'target': hostname,
            'scan_type': 'hostname',
            'ip_addresses': [],
            'scan_results': {},
            'scan_time': datetime.now().isoformat()
        }
        
        try:
            # Resolve hostname to IP addresses
            ip_addresses = await self._resolve_hostname(hostname)
            results['ip_addresses'] = ip_addresses
            
            # Scan each IP address
            for ip in ip_addresses:
                ip_results = await self._scan_single_ip(ip)
                results['scan_results'][ip] = ip_results
                
        except Exception as e:
            self.logger.error(f"Hostname scan error: {str(e)}")
            results['error'] = str(e)
            
        return results
        
    async def _scan_ports(self, ip: str, ports: List[int]) -> List[int]:
        """Scan ports on a host."""
        open_ports = []
        
        # Use asyncio to scan ports concurrently
        tasks = []
        for port in ports:
            task = asyncio.create_task(self._scan_port(ip, port))
            tasks.append(task)
            
        # Wait for all tasks to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self.logger.debug(f"Port scan error for {ip}:{ports[i]}: {result}")
            elif result:
                open_ports.append(ports[i])
                
        return open_ports
        
    async def _scan_port(self, ip: str, port: int) -> bool:
        """Scan a single port."""
        try:
            # Create socket with timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            
            # Try to connect
            result = sock.connect_ex((ip, port))
            sock.close()
            
            return result == 0
            
        except Exception as e:
            self.logger.debug(f"Port scan error for {ip}:{port}: {e}")
            return False
            
    async def _is_host_alive(self, ip: str) -> bool:
        """Check if host is alive using ping."""
        try:
            # Use ping command
            if os.name == 'nt':  # Windows
                cmd = ['ping', '-n', '1', '-w', '1000', ip]
            else:  # Unix/Linux
                cmd = ['ping', '-c', '1', '-W', '1', ip]
                
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            return process.returncode == 0
            
        except Exception as e:
            self.logger.debug(f"Ping error for {ip}: {e}")
            return False
            
    async def _detect_service(self, ip: str, port: int) -> Dict:
        """Detect service running on port."""
        service_info = {
            'port': port,
            'service': 'unknown',
            'version': 'unknown',
            'protocol': 'tcp',
            'state': 'open'
        }
        
        try:
            # Common port to service mapping
            port_services = {
                21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
                80: 'http', 110: 'pop3', 143: 'imap', 443: 'https',
                993: 'imaps', 995: 'pop3s', 1433: 'mssql', 3306: 'mysql',
                3389: 'rdp', 5432: 'postgresql', 5900: 'vnc', 6379: 'redis',
                8080: 'http-alt', 8443: 'https-alt', 9200: 'elasticsearch',
                27017: 'mongodb', 11211: 'memcached'
            }
            
            if port in port_services:
                service_info['service'] = port_services[port]
                
            # Try to get more detailed service information
            banner = await self._grab_banner(ip, port)
            if banner:
                service_info['banner'] = banner
                # Try to extract version from banner
                version = self._extract_version_from_banner(banner)
                if version:
                    service_info['version'] = version
                    
        except Exception as e:
            self.logger.debug(f"Service detection error for {ip}:{port}: {e}")
            
        return service_info
        
    async def _grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Grab banner from service."""
        try:
            # Connect to service and grab banner
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=5
            )
            
            # Send common probe
            if port in [21, 22, 25, 80, 110, 143, 443, 993, 995]:
                # Send appropriate probe for service
                if port == 80:
                    writer.write(b'GET / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                elif port == 443:
                    # For HTTPS, we'd need SSL context
                    pass
                else:
                    writer.write(b'\r\n')
                    
                await writer.drain()
                
                # Read response
                banner = await asyncio.wait_for(reader.read(1024), timeout=3)
                writer.close()
                await writer.wait_closed()
                
                return banner.decode('utf-8', errors='ignore').strip()
                
        except Exception as e:
            self.logger.debug(f"Banner grab error for {ip}:{port}: {e}")
            
        return None
        
    async def _os_fingerprint(self, ip: str) -> Dict:
        """Perform OS fingerprinting."""
        os_info = {
            'os': 'unknown',
            'version': 'unknown',
            'architecture': 'unknown',
            'confidence': 0
        }
        
        try:
            # TTL-based OS detection
            ttl = await self._get_ttl(ip)
            if ttl:
                if 64 <= ttl <= 128:
                    os_info['os'] = 'linux'
                    os_info['confidence'] = 60
                elif 128 <= ttl <= 255:
                    os_info['os'] = 'windows'
                    os_info['confidence'] = 60
                elif ttl == 255:
                    os_info['os'] = 'cisco'
                    os_info['confidence'] = 80
                    
            # Port-based OS detection
            open_ports = await self._scan_ports(ip, [135, 139, 445, 3389])
            if any(port in open_ports for port in [135, 139, 445]):
                os_info['os'] = 'windows'
                os_info['confidence'] = max(os_info['confidence'], 80)
                
        except Exception as e:
            self.logger.debug(f"OS fingerprinting error for {ip}: {e}")
            
        return os_info
        
    async def _scan_vulnerabilities(self, ip: str, open_ports: List[int]) -> List[Dict]:
        """Scan for common vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check for common vulnerable services
            for port in open_ports:
                if port == 21:  # FTP
                    vuln = await self._check_ftp_vulnerabilities(ip, port)
                    if vuln:
                        vulnerabilities.extend(vuln)
                        
                elif port == 22:  # SSH
                    vuln = await self._check_ssh_vulnerabilities(ip, port)
                    if vuln:
                        vulnerabilities.extend(vuln)
                        
                elif port == 23:  # Telnet
                    vulnerabilities.append({
                        'type': 'Insecure Protocol',
                        'severity': 'High',
                        'port': port,
                        'description': 'Telnet service detected - credentials transmitted in plain text'
                    })
                    
                elif port == 80 or port == 8080:  # HTTP
                    vuln = await self._check_http_vulnerabilities(ip, port)
                    if vuln:
                        vulnerabilities.extend(vuln)
                        
                elif port == 443 or port == 8443:  # HTTPS
                    vuln = await self._check_https_vulnerabilities(ip, port)
                    if vuln:
                        vulnerabilities.extend(vuln)
                        
        except Exception as e:
            self.logger.error(f"Vulnerability scanning error for {ip}: {e}")
            
        return vulnerabilities
        
    async def _check_ftp_vulnerabilities(self, ip: str, port: int) -> List[Dict]:
        """Check FTP vulnerabilities."""
        vulnerabilities = []
        
        try:
            banner = await self._grab_banner(ip, port)
            if banner:
                # Check for anonymous FTP
                if 'anonymous' in banner.lower():
                    vulnerabilities.append({
                        'type': 'Anonymous FTP',
                        'severity': 'Medium',
                        'port': port,
                        'description': 'Anonymous FTP access enabled'
                    })
                    
                # Check for old FTP versions
                if any(version in banner.lower() for version in ['2.0', '1.0']):
                    vulnerabilities.append({
                        'type': 'Outdated FTP',
                        'severity': 'Medium',
                        'port': port,
                        'description': 'Potentially outdated FTP server version'
                    })
                    
        except Exception as e:
            self.logger.debug(f"FTP vulnerability check error: {e}")
            
        return vulnerabilities
        
    async def _check_ssh_vulnerabilities(self, ip: str, port: int) -> List[Dict]:
        """Check SSH vulnerabilities."""
        vulnerabilities = []
        
        try:
            banner = await self._grab_banner(ip, port)
            if banner:
                # Check for weak SSH versions
                if 'ssh-1' in banner.lower():
                    vulnerabilities.append({
                        'type': 'Weak SSH Version',
                        'severity': 'High',
                        'port': port,
                        'description': 'SSH version 1 detected - vulnerable to man-in-the-middle attacks'
                    })
                    
        except Exception as e:
            self.logger.debug(f"SSH vulnerability check error: {e}")
            
        return vulnerabilities
        
    async def _check_http_vulnerabilities(self, ip: str, port: int) -> List[Dict]:
        """Check HTTP vulnerabilities."""
        vulnerabilities = []
        
        try:
            import aiohttp
            url = f"http://{ip}:{port}"
            
            # Check for common vulnerabilities
            async with aiohttp.ClientSession() as session:
                # Check for directory listing
                async with session.get(url + '/') as response:
                    if response.status == 200:
                        content = await response.text()
                        if 'Index of' in content or 'Directory listing' in content:
                            vulnerabilities.append({
                                'type': 'Directory Listing',
                                'severity': 'Medium',
                                'port': port,
                                'description': 'Directory listing enabled'
                            })
                            
                # Check for common files
                common_files = ['/robots.txt', '/sitemap.xml', '/.env', '/config.php']
                for file_path in common_files:
                    async with session.get(url + file_path) as response:
                        if response.status == 200:
                            vulnerabilities.append({
                                'type': 'Information Disclosure',
                                'severity': 'Low',
                                'port': port,
                                'file': file_path,
                                'description': f'Sensitive file accessible: {file_path}'
                            })
                            
        except Exception as e:
            self.logger.debug(f"HTTP vulnerability check error: {e}")
            
        return vulnerabilities
        
    async def _check_https_vulnerabilities(self, ip: str, port: int) -> List[Dict]:
        """Check HTTPS vulnerabilities."""
        vulnerabilities = []
        
        try:
            # Check SSL/TLS configuration
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    version = ssock.version()
                    
                    # Check for weak TLS versions
                    if version in ['TLSv1', 'TLSv1.1']:
                        vulnerabilities.append({
                            'type': 'Weak TLS Version',
                            'severity': 'Medium',
                            'port': port,
                            'description': f'Weak TLS version detected: {version}'
                        })
                        
        except Exception as e:
            self.logger.debug(f"HTTPS vulnerability check error: {e}")
            
        return vulnerabilities
        
    async def _resolve_hostname(self, hostname: str) -> List[str]:
        """Resolve hostname to IP addresses."""
        try:
            import socket
            ip_addresses = []
            
            # Get all IP addresses for hostname
            addr_info = socket.getaddrinfo(hostname, None)
            
            for addr in addr_info:
                ip = addr[4][0]
                if ip not in ip_addresses:
                    ip_addresses.append(ip)
                    
            return ip_addresses
            
        except Exception as e:
            self.logger.error(f"Hostname resolution error for {hostname}: {e}")
            return []
            
    async def _get_ttl(self, ip: str) -> Optional[int]:
        """Get TTL for IP address."""
        try:
            import subprocess
            
            if os.name == 'nt':  # Windows
                cmd = ['ping', '-n', '1', ip]
            else:  # Unix/Linux
                cmd = ['ping', '-c', '1', ip]
                
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode('utf-8')
                # Extract TTL from ping output
                import re
                ttl_match = re.search(r'ttl=(\d+)', output.lower())
                if ttl_match:
                    return int(ttl_match.group(1))
                    
        except Exception as e:
            self.logger.debug(f"TTL detection error for {ip}: {e}")
            
        return None
        
    def _extract_version_from_banner(self, banner: str) -> Optional[str]:
        """Extract version information from banner."""
        try:
            import re
            
            # Common version patterns
            version_patterns = [
                r'version\s+([\d\.]+)',
                r'v([\d\.]+)',
                r'([\d\.]+\.[\d\.]+)',
                r'([\d]+\.[\d]+\.[\d]+)'
            ]
            
            for pattern in version_patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    return match.group(1)
                    
        except Exception as e:
            self.logger.debug(f"Version extraction error: {e}")
            
        return None
        
    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address."""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
