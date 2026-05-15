#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Security Network - WiFi & Network Security Scanner
🔒 i7tarafiya mn jami3 nawa7i 🛡️

Usage:
    python main.py         # CLI mode (default)
    python main.py --gui   # GUI mode
    python main.py --cli   # CLI mode
"""

import sys
import argparse


def main():
    parser = argparse.ArgumentParser(
        description="Security Network - WiFi & Network Security Scanner",
        epilog="i7tarafiya mn jami3 nawa7i"
    )
    parser.add_argument("--gui", action="store_true", help="Launch GUI version")
    parser.add_argument("--cli", action="store_true", help="Launch CLI version (default)")
    args = parser.parse_args()

    if args.gui:
        from src.security_scanner.gui import main as gui_main
        gui_main()
    else:
        from src.security_scanner.cli import main as cli_main
        cli_main()


if __name__ == "__main__":
    main()
