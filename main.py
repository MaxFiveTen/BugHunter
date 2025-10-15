#!/usr/bin/env python3
"""
BugHunter - Advanced Web Vulnerability Scanner and Penetration Testing Tool
A comprehensive tool for automated web security testing and bug hunting.
Author: Infosec_Viking
Repository: https://github.com/MaxFiveTen/BugHunter
"""

import sys
import argparse
import asyncio
from typing import Dict, List, Optional
from datetime import datetime
import logging
from pathlib import Path

from src.core.scanner import VulnerabilityScanner
from src.core.reconnaissance import ReconnaissanceModule
from src.core.fuzzer import WebFuzzer
from src.core.injection_tester import InjectionTester
from src.core.network_scanner import NetworkScanner
from src.utils.reporting import ReportGenerator
from src.utils.config import Config
from src.utils.logger import setup_logging


class BugHunter:
    """Main BugHunter application class."""
    
    def __init__(self):
        self.config = Config()
        self.logger = logging.getLogger(__name__)
        self.scanner = None
        self.target_url = None
        self.results = {}
        
    def display_banner(self):
        """Display the BugHunter banner."""
        banner = """
╔══════════════════════════════════════════════════════════════╗
║                   🕵️ BugHunter v1.0.0                       ║
║              Advanced Web Vulnerability Scanner              ║
║              & Penetration Testing Framework                 ║
║              Author: Infosec_Viking                          ║
║              Repository: github.com/MaxFiveTen/BugHunter     ║
╚══════════════════════════════════════════════════════════════╝
        """
        print(banner)
        
    def get_target_from_user(self) -> str:
        """Get target website from user input."""
        print("\n🎯 Target Selection")
        print("=" * 50)
        
        while True:
            target = input("Enter target website (e.g., contoso.com): ").strip()
            
            if not target:
                print("❌ Please enter a valid target!")
                continue
                
            # Basic validation
            if not (target.startswith('http://') or target.startswith('https://')):
                target = f"https://{target}"
                
            # Confirm target
            confirm = input(f"Target: {target} - Confirm? (y/n): ").strip().lower()
            if confirm in ['y', 'yes']:
                return target
            elif confirm in ['n', 'no']:
                continue
            else:
                print("Please enter 'y' or 'n'")
                
    def display_vulnerability_menu(self) -> List[str]:
        """Display available vulnerability scans."""
        vulnerabilities = {
            '1': 'SQL Injection',
            '2': 'Cross-Site Scripting (XSS)',
            '3': 'Cross-Site Request Forgery (CSRF)',
            '4': 'Directory Traversal',
            '5': 'File Upload Vulnerabilities',
            '6': 'Authentication Bypass',
            '7': 'Session Management Issues',
            '8': 'HTTP Security Headers',
            '9': 'SSL/TLS Configuration',
            '10': 'Information Disclosure',
            '11': 'Command Injection',
            '12': 'LDAP Injection',
            '13': 'XML External Entity (XXE)',
            '14': 'Server-Side Request Forgery (SSRF)',
            '15': 'All Common Vulnerabilities'
        }
        
        print("\n🔍 Available Vulnerability Scans")
        print("=" * 50)
        for key, value in vulnerabilities.items():
            print(f"{key:2}. {value}")
            
        print("\nAdvanced Testing Modules:")
        print("16. Network Reconnaissance")
        print("17. Web Application Fuzzing")
        print("18. Advanced Injection Testing")
        print("19. Complete Penetration Test")
        print("20. Custom Scan Configuration")
        
        while True:
            choice = input("\nSelect scans (comma-separated, e.g., 1,3,5 or 'all'): ").strip()
            
            if choice.lower() == 'all':
                return list(vulnerabilities.values()) + ['Network Reconnaissance', 'Web Application Fuzzing']
            
            try:
                selected = []
                for num in choice.split(','):
                    num = num.strip()
                    if num in vulnerabilities:
                        selected.append(vulnerabilities[num])
                    elif num == '16':
                        selected.append('Network Reconnaissance')
                    elif num == '17':
                        selected.append('Web Application Fuzzing')
                    elif num == '18':
                        selected.append('Advanced Injection Testing')
                    elif num == '19':
                        selected.append('Complete Penetration Test')
                    elif num == '20':
                        selected.append('Custom Scan Configuration')
                        
                if selected:
                    return selected
                else:
                    print("❌ Invalid selection. Please try again.")
            except:
                print("❌ Invalid format. Please use comma-separated numbers.")
                
    async def run_scans(self, target: str, selected_scans: List[str]):
        """Run selected vulnerability scans."""
        self.target_url = target
        
        print(f"\n🚀 Starting scans for: {target}")
        print("=" * 60)
        
        start_time = datetime.now()
        
        # Initialize results
        self.results = {
            'target': target,
            'scan_time': start_time,
            'vulnerabilities': [],
            'reconnaissance': {},
            'network_info': {},
            'summary': {}
        }
        
        # Initialize scanner with async context manager
        async with VulnerabilityScanner(target, self.config) as scanner:
            self.scanner = scanner
            
            # Run vulnerability scans
            for scan_type in selected_scans:
                print(f"\n🔍 Running: {scan_type}")
                print("-" * 40)
                
                try:
                    if scan_type == 'SQL Injection':
                        results = await self.scanner.test_sql_injection()
                    elif scan_type == 'Cross-Site Scripting (XSS)':
                        results = await self.scanner.test_xss()
                    elif scan_type == 'Cross-Site Request Forgery (CSRF)':
                        results = await self.scanner.test_csrf()
                    elif scan_type == 'Directory Traversal':
                        results = await self.scanner.test_directory_traversal()
                    elif scan_type == 'File Upload Vulnerabilities':
                        results = await self.scanner.test_file_upload()
                    elif scan_type == 'Authentication Bypass':
                        results = await self.scanner.test_auth_bypass()
                    elif scan_type == 'Session Management Issues':
                        results = await self.scanner.test_session_management()
                    elif scan_type == 'HTTP Security Headers':
                        results = await self.scanner.test_security_headers()
                    elif scan_type == 'SSL/TLS Configuration':
                        results = await self.scanner.test_ssl_config()
                    elif scan_type == 'Information Disclosure':
                        results = await self.scanner.test_info_disclosure()
                    elif scan_type == 'Command Injection':
                        results = await self.scanner.test_command_injection()
                    elif scan_type == 'LDAP Injection':
                        results = await self.scanner.test_ldap_injection()
                    elif scan_type == 'XML External Entity (XXE)':
                        results = await self.scanner.test_xxe()
                    elif scan_type == 'Server-Side Request Forgery (SSRF)':
                        results = await self.scanner.test_ssrf()
                    elif scan_type == 'Network Reconnaissance':
                        recon = ReconnaissanceModule(target)
                        results = await recon.run_reconnaissance()
                        self.results['reconnaissance'] = results
                    elif scan_type == 'Web Application Fuzzing':
                        fuzzer = WebFuzzer(target)
                        results = await fuzzer.run_fuzzing()
                    elif scan_type == 'Advanced Injection Testing':
                        injection_tester = InjectionTester(target)
                        results = await injection_tester.run_comprehensive_tests()
                    elif scan_type == 'Complete Penetration Test':
                        # Run all tests
                        results = await self.run_comprehensive_scan()
                    else:
                        print(f"⚠️ Unknown scan type: {scan_type}")
                        continue
                        
                    if results:
                        self.results['vulnerabilities'].extend(results if isinstance(results, list) else [results])
                        print(f"✅ {scan_type} completed - Found {len(results) if isinstance(results, list) else 1} issues")
                    else:
                        print(f"✅ {scan_type} completed - No issues found")
                        
                except Exception as e:
                    self.logger.error(f"Error running {scan_type}: {str(e)}")
                    print(f"❌ Error running {scan_type}: {str(e)}")
            
            end_time = datetime.now()
            duration = end_time - start_time
            
            self.results['scan_duration'] = duration
            self.results['end_time'] = end_time
            
            print(f"\n🎉 Scan completed in {duration}")
        print(f"👋 BugHunter scan completed!")
        
    async def run_comprehensive_scan(self):
        """Run a comprehensive penetration test with 100+ vulnerability types."""
        print("🔍 Running comprehensive penetration test...")
        
        # Use the enhanced scanner's comprehensive scan method
        comprehensive_results = await self.scanner.run_comprehensive_scan()
        return comprehensive_results
        
    def generate_report(self):
        """Generate and display scan report."""
        if not self.results:
            print("❌ No scan results to report!")
            return
            
        report_gen = ReportGenerator()
        report_path = report_gen.generate_report(self.results)
        
        print(f"\n📊 Scan Report Generated: {report_path}")
        
        # Display summary
        vuln_count = len(self.results.get('vulnerabilities', []))
        print(f"\n📈 Scan Summary:")
        print(f"   Target: {self.results['target']}")
        print(f"   Duration: {self.results.get('scan_duration', 'Unknown')}")
        print(f"   Vulnerabilities Found: {vuln_count}")
        
        if vuln_count > 0:
            print(f"\n🚨 Critical Issues:")
            critical_vulns = [v for v in self.results['vulnerabilities'] if v.get('severity') == 'Critical']
            for vuln in critical_vulns[:5]:  # Show top 5
                print(f"   • {vuln.get('type', 'Unknown')}: {vuln.get('description', 'No description')}")
                
    async def main(self):
        """Main application entry point."""
        try:
            self.display_banner()
            
            # Get target from user
            target = self.get_target_from_user()
            
            # Display vulnerability menu and get selections
            selected_scans = self.display_vulnerability_menu()
            
            # Run scans
            await self.run_scans(target, selected_scans)
            
            # Generate report
            self.generate_report()
            
        except KeyboardInterrupt:
            print("\n\n⚠️ Scan interrupted by user")
        except Exception as e:
            self.logger.error(f"Unexpected error: {str(e)}")
            print(f"❌ Unexpected error: {str(e)}")
        finally:
            print("\n👋 BugHunt scan completed!")


def main():
    """Entry point for the application."""
    parser = argparse.ArgumentParser(description='BugHunt - Advanced Web Vulnerability Scanner')
    parser.add_argument('--target', '-t', help='Target URL to scan')
    parser.add_argument('--config', '-c', help='Configuration file path')
    parser.add_argument('--output', '-o', help='Output directory for reports')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--quiet', '-q', action='store_true', help='Suppress output')
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(verbose=args.verbose, quiet=args.quiet)
    
    # Create and run BugHunter
    bug_hunter = BugHunter()
    
    # Override target if provided via command line
    if args.target:
        bug_hunter.target_url = args.target
        
    try:
        asyncio.run(bug_hunter.main())
    except KeyboardInterrupt:
        print("\n🛑 Scan interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        logging.error(f"Unexpected error: {e}", exc_info=True)


if __name__ == "__main__":
    main()
