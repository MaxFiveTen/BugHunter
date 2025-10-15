"""
Reporting module for BugHunter.
Generates comprehensive reports in multiple formats.
Author: Infosec_Viking
Repository: https://github.com/MaxFiveTen/BugHunter
"""

import json
import csv
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional
import logging
from datetime import datetime
from pathlib import Path
import os

# Import DOCX report generator
try:
    from .docx_report_generator import ProfessionalDocxReportGenerator
    DOCX_AVAILABLE = True
except ImportError:
    DOCX_AVAILABLE = False


class ReportGenerator:
    """Generate comprehensive security assessment reports."""
    
    def __init__(self, output_dir: str = "reports"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.logger = logging.getLogger(__name__)
        
        # Initialize DOCX report generator if available
        if DOCX_AVAILABLE:
            self.docx_generator = ProfessionalDocxReportGenerator(str(self.output_dir))
        else:
            self.docx_generator = None
        
    def generate_report(self, scan_results: Dict) -> str:
        """Generate comprehensive report in multiple formats."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base_filename = f"bughunter_report_{timestamp}"
        
        # Generate different report formats
        json_report = self._generate_json_report(scan_results, base_filename)
        html_report = self._generate_html_report(scan_results, base_filename)
        csv_report = self._generate_csv_report(scan_results, base_filename)
        xml_report = self._generate_xml_report(scan_results, base_filename)
        
        # Generate executive summary
        summary_report = self._generate_summary_report(scan_results, base_filename)
        
        # Generate professional DOCX report if available
        docx_report = None
        if self.docx_generator:
            try:
                target = scan_results.get('target', 'Unknown Target')
                docx_report = self.docx_generator.generate_report(scan_results, target)
                self.logger.info(f"Professional DOCX report saved: {docx_report}")
            except Exception as e:
                self.logger.error(f"Error generating DOCX report: {e}")
        
        self.logger.info(f"Reports generated in {self.output_dir}")
        
        return json_report  # Return main report path
        
    def _generate_json_report(self, scan_results: Dict, base_filename: str) -> str:
        """Generate JSON report."""
        report_path = self.output_dir / f"{base_filename}.json"
        
        try:
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(scan_results, f, indent=2, default=str)
                
            self.logger.info(f"JSON report saved: {report_path}")
            
        except Exception as e:
            self.logger.error(f"Error generating JSON report: {e}")
            
        return str(report_path)
        
    def _generate_html_report(self, scan_results: Dict, base_filename: str) -> str:
        """Generate HTML report."""
        report_path = self.output_dir / f"{base_filename}.html"
        
        try:
            html_content = self._create_html_content(scan_results)
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            self.logger.info(f"HTML report saved: {report_path}")
            
        except Exception as e:
            self.logger.error(f"Error generating HTML report: {e}")
            
        return str(report_path)
        
    def _generate_csv_report(self, scan_results: Dict, base_filename: str) -> str:
        """Generate CSV report."""
        report_path = self.output_dir / f"{base_filename}.csv"
        
        try:
            with open(report_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                
                # Write header
                writer.writerow([
                    'Type', 'Severity', 'Parameter', 'Payload', 'URL', 'Method',
                    'Description', 'Confidence', 'Timestamp'
                ])
                
                # Write vulnerability data
                vulnerabilities = scan_results.get('vulnerabilities', [])
                for vuln in vulnerabilities:
                    writer.writerow([
                        vuln.get('type', ''),
                        vuln.get('severity', ''),
                        vuln.get('parameter', ''),
                        vuln.get('payload', ''),
                        vuln.get('url', ''),
                        vuln.get('method', ''),
                        vuln.get('description', ''),
                        vuln.get('confidence', ''),
                        vuln.get('timestamp', '')
                    ])
                    
            self.logger.info(f"CSV report saved: {report_path}")
            
        except Exception as e:
            self.logger.error(f"Error generating CSV report: {e}")
            
        return str(report_path)
        
    def _generate_xml_report(self, scan_results: Dict, base_filename: str) -> str:
        """Generate XML report."""
        report_path = self.output_dir / f"{base_filename}.xml"
        
        try:
            root = ET.Element("bughunter_report")
            
            # Add metadata
            metadata = ET.SubElement(root, "metadata")
            ET.SubElement(metadata, "target").text = scan_results.get('target', '')
            ET.SubElement(metadata, "scan_time").text = str(scan_results.get('scan_time', ''))
            ET.SubElement(metadata, "scan_duration").text = str(scan_results.get('scan_duration', ''))
            
            # Add summary
            summary = ET.SubElement(root, "summary")
            vuln_count = len(scan_results.get('vulnerabilities', []))
            ET.SubElement(summary, "total_vulnerabilities").text = str(vuln_count)
            
            # Add vulnerabilities
            vulnerabilities_elem = ET.SubElement(root, "vulnerabilities")
            for vuln in scan_results.get('vulnerabilities', []):
                vuln_elem = ET.SubElement(vulnerabilities_elem, "vulnerability")
                ET.SubElement(vuln_elem, "type").text = vuln.get('type', '')
                ET.SubElement(vuln_elem, "severity").text = vuln.get('severity', '')
                ET.SubElement(vuln_elem, "description").text = vuln.get('description', '')
                ET.SubElement(vuln_elem, "confidence").text = vuln.get('confidence', '')
                
            # Write XML
            tree = ET.ElementTree(root)
            tree.write(report_path, encoding='utf-8', xml_declaration=True)
            
            self.logger.info(f"XML report saved: {report_path}")
            
        except Exception as e:
            self.logger.error(f"Error generating XML report: {e}")
            
        return str(report_path)
        
    def _generate_summary_report(self, scan_results: Dict, base_filename: str) -> str:
        """Generate executive summary report."""
        report_path = self.output_dir / f"{base_filename}_summary.txt"
        
        try:
            summary_content = self._create_summary_content(scan_results)
            
            with open(report_path, 'w', encoding='utf-8') as f:
                f.write(summary_content)
                
            self.logger.info(f"Summary report saved: {report_path}")
            
        except Exception as e:
            self.logger.error(f"Error generating summary report: {e}")
            
        return str(report_path)
        
    def _create_html_content(self, scan_results: Dict) -> str:
        """Create HTML report content."""
        target = scan_results.get('target', 'Unknown')
        scan_time = scan_results.get('scan_time', 'Unknown')
        scan_duration = scan_results.get('scan_duration', 'Unknown')
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Count vulnerabilities by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>BugHunt Security Assessment Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #007acc;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #007acc;
            margin: 0;
            font-size: 2.5em;
        }}
        .header p {{
            color: #666;
            margin: 10px 0 0 0;
            font-size: 1.1em;
        }}
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .info-card {{
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #007acc;
        }}
        .info-card h3 {{
            margin: 0 0 10px 0;
            color: #007acc;
        }}
        .info-card p {{
            margin: 0;
            color: #666;
        }}
        .severity-stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .severity-card {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            color: white;
            font-weight: bold;
        }}
        .critical {{ background: #dc3545; }}
        .high {{ background: #fd7e14; }}
        .medium {{ background: #ffc107; color: #333; }}
        .low {{ background: #28a745; }}
        .vulnerabilities {{
            margin-top: 30px;
        }}
        .vuln-item {{
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}
        .vuln-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .vuln-type {{
            font-size: 1.2em;
            font-weight: bold;
            color: #333;
        }}
        .severity-badge {{
            padding: 5px 10px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-critical {{ background: #dc3545; color: white; }}
        .severity-high {{ background: #fd7e14; color: white; }}
        .severity-medium {{ background: #ffc107; color: #333; }}
        .severity-low {{ background: #28a745; color: white; }}
        .vuln-details {{
            color: #666;
            line-height: 1.6;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕵️ BugHunt Security Assessment Report</h1>
            <p>Advanced Web Vulnerability Scanner & Penetration Testing Framework</p>
        </div>
        
        <div class="info-grid">
            <div class="info-card">
                <h3>Target</h3>
                <p>{target}</p>
            </div>
            <div class="info-card">
                <h3>Scan Time</h3>
                <p>{scan_time}</p>
            </div>
            <div class="info-card">
                <h3>Duration</h3>
                <p>{scan_duration}</p>
            </div>
            <div class="info-card">
                <h3>Total Vulnerabilities</h3>
                <p>{len(vulnerabilities)}</p>
            </div>
        </div>
        
        <div class="severity-stats">
            <div class="severity-card critical">
                <h3>{severity_counts.get('Critical', 0)}</h3>
                <p>Critical</p>
            </div>
            <div class="severity-card high">
                <h3>{severity_counts.get('High', 0)}</h3>
                <p>High</p>
            </div>
            <div class="severity-card medium">
                <h3>{severity_counts.get('Medium', 0)}</h3>
                <p>Medium</p>
            </div>
            <div class="severity-card low">
                <h3>{severity_counts.get('Low', 0)}</h3>
                <p>Low</p>
            </div>
        </div>
        
        <div class="vulnerabilities">
            <h2>Vulnerability Details</h2>
        """
        
        # Add vulnerability details
        for vuln in vulnerabilities:
            vuln_type = vuln.get('type', 'Unknown')
            severity = vuln.get('severity', 'Unknown')
            description = vuln.get('description', 'No description available')
            confidence = vuln.get('confidence', 'Unknown')
            url = vuln.get('url', '')
            parameter = vuln.get('parameter', '')
            payload = vuln.get('payload', '')
            method = vuln.get('method', '')
            
            html += f"""
            <div class="vuln-item">
                <div class="vuln-header">
                    <div class="vuln-type">{vuln_type}</div>
                    <div class="severity-badge severity-{severity.lower()}">{severity}</div>
                </div>
                <div class="vuln-details">
                    <p><strong>Description:</strong> {description}</p>
                    <p><strong>Confidence:</strong> {confidence}</p>
            """
            
            if url:
                html += f'<p><strong>URL:</strong> {url}</p>'
            if parameter:
                html += f'<p><strong>Parameter:</strong> {parameter}</p>'
            if payload:
                html += f'<p><strong>Payload:</strong> <code>{payload}</code></p>'
            if method:
                html += f'<p><strong>Method:</strong> {method}</p>'
                
            html += """
                </div>
            </div>
            """
            
        html += f"""
        </div>
        
        <div class="footer">
            <p>Report generated by BugHunt on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>For more information, visit: https://github.com/bughunt</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html
        
    def _create_summary_content(self, scan_results: Dict) -> str:
        """Create executive summary content."""
        target = scan_results.get('target', 'Unknown')
        scan_time = scan_results.get('scan_time', 'Unknown')
        scan_duration = scan_results.get('scan_duration', 'Unknown')
        vulnerabilities = scan_results.get('vulnerabilities', [])
        
        # Count vulnerabilities by severity
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
        summary = f"""
╔══════════════════════════════════════════════════════════════╗
║                    BugHunt Security Assessment Report        ║
╚══════════════════════════════════════════════════════════════╝

EXECUTIVE SUMMARY
================

Target: {target}
Scan Time: {scan_time}
Duration: {scan_duration}
Total Vulnerabilities Found: {len(vulnerabilities)}

VULNERABILITY BREAKDOWN
=======================

Critical: {severity_counts.get('Critical', 0)}
High: {severity_counts.get('High', 0)}
Medium: {severity_counts.get('Medium', 0)}
Low: {severity_counts.get('Low', 0)}

TOP VULNERABILITIES
===================

"""
        
        # Add top 10 vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'Critical'][:5]
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'High'][:5]
        
        if critical_vulns:
            summary += "CRITICAL ISSUES:\n"
            summary += "-" * 50 + "\n"
            for i, vuln in enumerate(critical_vulns, 1):
                summary += f"{i}. {vuln.get('type', 'Unknown')}\n"
                summary += f"   {vuln.get('description', 'No description')}\n\n"
                
        if high_vulns:
            summary += "HIGH PRIORITY ISSUES:\n"
            summary += "-" * 50 + "\n"
            for i, vuln in enumerate(high_vulns, 1):
                summary += f"{i}. {vuln.get('type', 'Unknown')}\n"
                summary += f"   {vuln.get('description', 'No description')}\n\n"
                
        summary += f"""
RECOMMENDATIONS
===============

1. Address all Critical and High severity vulnerabilities immediately
2. Implement proper input validation and sanitization
3. Use parameterized queries to prevent SQL injection
4. Implement proper authentication and session management
5. Configure security headers (HSTS, CSP, X-Frame-Options, etc.)
6. Keep all software and dependencies updated
7. Implement proper error handling to avoid information disclosure
8. Use HTTPS everywhere and configure proper SSL/TLS settings
9. Implement rate limiting and DDoS protection
10. Regular security assessments and penetration testing

DETAILED FINDINGS
================

For detailed information about each vulnerability, refer to the complete
HTML, JSON, or XML reports generated alongside this summary.

Report generated by BugHunt on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        """
        
        return summary
