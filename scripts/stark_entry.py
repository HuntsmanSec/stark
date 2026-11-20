"""Entry point used by PyInstaller to build standalone binaries."""
import sys

from stark.cli import main

if __name__ == "__main__":
    sys.exit(main())
