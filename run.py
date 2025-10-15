#!/usr/bin/env python3
"""
Quick run script for BugHunt.
This script provides an easy way to run BugHunt with common options.
"""

import sys
import os
import subprocess
from pathlib import Path


def check_installation():
    """Check if BugHunt is properly installed."""
    try:
        import src.core.scanner
        import src.utils.config
        return True
    except ImportError as e:
        print(f"❌ BugHunt not properly installed: {e}")
        print("Please run: pip install -r requirements.txt")
        return False


def install_dependencies():
    """Install required dependencies."""
    print("📦 Installing dependencies...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "-r", "requirements.txt"])
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False


def run_bughunt(target=None):
    """Run BugHunt with the given target."""
    cmd = [sys.executable, "main.py"]
    
    if target:
        cmd.extend(["--target", target])
        
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n⚠️ Scan interrupted by user")
    except Exception as e:
        print(f"❌ Error running BugHunt: {e}")


def main():
    """Main function."""
    print("🕵️ BugHunt Quick Runner")
    print("=" * 30)
    
    # Check if target is provided as argument
    target = None
    if len(sys.argv) > 1:
        target = sys.argv[1]
        
    # Check installation
    if not check_installation():
        print("\n🔧 Attempting to install dependencies...")
        if install_dependencies():
            print("✅ Installation complete, trying again...")
            if not check_installation():
                print("❌ Installation failed. Please check the error messages above.")
                return
        else:
            return
            
    # Run BugHunt
    print(f"\n🚀 Starting BugHunt...")
    if target:
        print(f"Target: {target}")
    else:
        print("Interactive mode")
        
    run_bughunt(target)


if __name__ == "__main__":
    main()
