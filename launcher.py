"""PyInstaller entry point (build on the target operating system)."""
from cyberintel.app import main
import sys

if __name__ == "__main__":
    sys.exit(main())
