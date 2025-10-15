#!/usr/bin/env python3
"""
Setup script for BugHunt - Advanced Web Vulnerability Scanner
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read requirements
requirements = []
requirements_path = this_directory / "requirements.txt"
if requirements_path.exists():
    with open(requirements_path, 'r', encoding='utf-8') as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="bughunt",
    version="1.0.0",
    author="BugHunt Team",
    author_email="bughunt@example.com",
    description="Advanced Web Vulnerability Scanner & Penetration Testing Framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/bughunt",
    project_urls={
        "Bug Tracker": "https://github.com/yourusername/bughunt/issues",
        "Documentation": "https://github.com/yourusername/bughunt/wiki",
        "Source Code": "https://github.com/yourusername/bughunt",
    },
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: Indexing/Search",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
        "Natural Language :: English",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.19.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=0.950",
        ],
        "advanced": [
            "selenium>=4.0.0",
            "playwright>=1.25.0",
            "shodan>=1.25.0",
            "censys>=2.0.0",
            "python-nmap>=0.7.0",
            "scapy>=2.4.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "bughunt=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "bughunt": [
            "config/*.json",
            "payloads/*.txt",
            "wordlists/*.txt",
        ],
    },
    keywords=[
        "security",
        "vulnerability",
        "scanner",
        "penetration-testing",
        "web-security",
        "bug-bounty",
        "owasp",
        "security-testing",
        "network-security",
        "application-security",
    ],
    zip_safe=False,
)
