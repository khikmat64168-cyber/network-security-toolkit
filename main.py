#!/usr/bin/env python3
"""
Entry point for the Network Security Toolkit.

Run directly from a source checkout:
    sudo python main.py --help
    sudo python main.py sniff -i eth0

Or after `pip install .` (or `pip install -e .`):
    sudo nst --help
"""
import sys
from pathlib import Path

# Allow `python main.py` to work without installing the package.
sys.path.insert(0, str(Path(__file__).parent / "src"))

from nst.cli.main import main

if __name__ == "__main__":
    main()
