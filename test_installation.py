#!/usr/bin/env python3
"""
Test script to verify BugHunt installation and basic functionality.
"""

import sys
import importlib
import traceback
from pathlib import Path


def test_imports():
    """Test if all required modules can be imported."""
    print("🔍 Testing module imports...")
    
    required_modules = [
        'aiohttp',
        'requests',
        'beautifulsoup4',
        'click',
        'colorama',
        'tqdm',
        'cryptography',
        'pyyaml',
        'structlog',
        'jinja2',
        'matplotlib',
        'pandas',
        'numpy',
        'psutil',
        'python-dotenv'
    ]
    
    optional_modules = [
        'dns.resolver',
        'whois',
        'scapy',
        'python-nmap',
        'selenium',
        'playwright',
        'shodan',
        'censys'
    ]
    
    missing_required = []
    missing_optional = []
    
    # Test required modules
    for module in required_modules:
        try:
            if '.' in module:
                # Handle modules with dots
                parts = module.split('.')
                base_module = importlib.import_module(parts[0])
                for part in parts[1:]:
                    base_module = getattr(base_module, part)
            else:
                importlib.import_module(module)
            print(f"✅ {module}")
        except ImportError as e:
            print(f"❌ {module} - {e}")
            missing_required.append(module)
            
    # Test optional modules
    for module in optional_modules:
        try:
            if '.' in module:
                parts = module.split('.')
                base_module = importlib.import_module(parts[0])
                for part in parts[1:]:
                    base_module = getattr(base_module, part)
            else:
                importlib.import_module(module)
            print(f"✅ {module} (optional)")
        except ImportError:
            print(f"⚠️ {module} (optional - not installed)")
            missing_optional.append(module)
            
    return missing_required, missing_optional


def test_bughunt_modules():
    """Test if BugHunt modules can be imported."""
    print("\n🔍 Testing BugHunt modules...")
    
    bughunt_modules = [
        'src.core.scanner',
        'src.core.fuzzer',
        'src.core.injection_tester',
        'src.core.reconnaissance',
        'src.core.network_scanner',
        'src.utils.reporting',
        'src.utils.config',
        'src.utils.logger'
    ]
    
    missing_modules = []
    
    for module in bughunt_modules:
        try:
            importlib.import_module(module)
            print(f"✅ {module}")
        except ImportError as e:
            print(f"❌ {module} - {e}")
            missing_modules.append(module)
        except Exception as e:
            print(f"❌ {module} - {e}")
            missing_modules.append(module)
            
    return missing_modules


def test_basic_functionality():
    """Test basic BugHunt functionality."""
    print("\n🔍 Testing basic functionality...")
    
    try:
        # Test configuration
        from src.utils.config import Config
        config = Config()
        print("✅ Configuration system")
        
        # Test logging
        from src.utils.logger import setup_logging
        setup_logging(quiet=True)
        print("✅ Logging system")
        
        # Test reporting
        from src.utils.reporting import ReportGenerator
        report_gen = ReportGenerator()
        print("✅ Reporting system")
        
        return True
        
    except Exception as e:
        print(f"❌ Basic functionality test failed - {e}")
        traceback.print_exc()
        return False


def main():
    """Main test function."""
    print("🕵️ BugHunt Installation Test")
    print("=" * 50)
    
    # Test Python version
    print(f"Python version: {sys.version}")
    if sys.version_info < (3, 8):
        print("❌ Python 3.8 or higher is required!")
        return False
    else:
        print("✅ Python version compatible")
        
    # Test imports
    missing_required, missing_optional = test_imports()
    
    if missing_required:
        print(f"\n❌ Missing required modules: {', '.join(missing_required)}")
        print("Please install missing modules with: pip install -r requirements.txt")
        return False
    else:
        print("\n✅ All required modules available")
        
    if missing_optional:
        print(f"\n⚠️ Missing optional modules: {', '.join(missing_optional)}")
        print("Some advanced features may not be available")
        
    # Test BugHunt modules
    missing_bughunt = test_bughunt_modules()
    
    if missing_bughunt:
        print(f"\n❌ Missing BugHunt modules: {', '.join(missing_bughunt)}")
        return False
    else:
        print("\n✅ All BugHunt modules available")
        
    # Test basic functionality
    if test_basic_functionality():
        print("\n✅ Basic functionality test passed")
    else:
        print("\n❌ Basic functionality test failed")
        return False
        
    # Final result
    print("\n" + "=" * 50)
    print("🎉 BugHunt installation test completed successfully!")
    print("You can now run BugHunt with: python main.py")
    print("=" * 50)
    
    return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
