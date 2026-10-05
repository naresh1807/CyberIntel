#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != "Linux" ]]; then
  printf '%s\n' 'Linux bundles must be built on Linux.' >&2
  exit 1
fi
.venv/bin/python -m PyInstaller --noconfirm --clean --windowed --onedir --name CyberIntelSuite --collect-all pyqtgraph --collect-all folium --collect-all plotly --collect-all phonenumbers launcher.py
printf '%s\n' 'Bundle: dist/CyberIntelSuite/CyberIntelSuite. TShark and Nmap remain external system dependencies.'
