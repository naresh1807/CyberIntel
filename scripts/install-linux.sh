#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip libegl1 libopengl0 libxcb-cursor0 libxkbcommon-x11-0 libxcb-icccm4 libxcb-keysyms1 libxcb-shape0 libxcb-xinerama0 tshark nmap
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
printf '%s\n' 'Installed. Run .venv/bin/python -m cyberintel as your regular user.'
