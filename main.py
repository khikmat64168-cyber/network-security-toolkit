#!/usr/bin/env python3
"""
Entry point for the Network Security Toolkit.

Run directly:
    sudo python main.py --help
    sudo python main.py sniff -i eth0

Or after `pip install -e .`:
    sudo nst --help
"""
import sys
from pathlib import Path

# Allow `python main.py` to work without `pip install -e .`
sys.path.insert(0, str(Path(__file__).parent))

from src.cli.main import cli

if __name__ == "__main__":
    cli()
