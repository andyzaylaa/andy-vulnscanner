#!/usr/bin/env python3
"""Andy VulnScanner - Entry point."""

import sys


def main():
    """Launch the Andy VulnScanner GUI application."""
    try:
        from vulnscanner.gui.app import AndyVulnScanner
    except ImportError as e:
        print(f"Error importing modules: {e}")
        print("Make sure you have installed the required dependencies.")
        sys.exit(1)

    print("Starting Andy VulnScanner v1.0...")
    print("Use responsibly and only on systems you have permission to test.")
    print()

    app = AndyVulnScanner()
    app.mainloop()


if __name__ == "__main__":
    main()
