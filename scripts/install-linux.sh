#!/usr/bin/env bash
set -Eeuo pipefail
stage='checking prerequisites'
trap 'code=$?; printf "\nInstallation failed during: %s (line %s, exit %s).\nSend the preceding error and python3 --version output.\n" "$stage" "$LINENO" "$code" >&2; exit "$code"' ERR
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ "$(uname -s)" != Linux ]] || ! command -v apt-get >/dev/null; then
  printf '%s\n' 'This installer requires Kali or another apt-based Linux system.' >&2
  exit 1
fi
elevate=()
if (( EUID != 0 )); then
  if ! command -v sudo >/dev/null; then
    printf '%s\n' 'sudo is required to install system packages. Ask your system administrator to install it.' >&2
    exit 1
  fi
  elevate=(sudo)
fi
stage='updating apt repositories'
printf '%s\n' 'Updating system package lists...'
"${elevate[@]}" apt-get update
stage='installing system packages'
"${elevate[@]}" apt-get install -y python3 python3-venv python3-pip libgl1 libfontconfig1 libegl1 libopengl0 libxcb-cursor0 libxkbcommon-x11-0 libxcb-icccm4 libxcb-keysyms1 libxcb-shape0 libxcb-xinerama0 tshark nmap
stage='checking Python compatibility'
python3 -c 'import sys; print("Python:", sys.version.split()[0]); sys.exit("Python 3.12 or newer is required; update Python before installing.") if sys.version_info < (3, 12) else None'
if [[ -d .venv && ! -x .venv/bin/python ]]; then
  printf '%s\n' 'The existing .venv is incompatible with Linux. Rename it before retrying; the installer will not delete it.' >&2
  exit 1
fi
stage='creating the Python virtual environment'
python3 -m venv .venv
stage='updating virtual-environment packaging tools'
.venv/bin/python -m pip install --upgrade pip setuptools wheel
stage='installing CyberIntel dependencies'
.venv/bin/python -m pip install -e .
stage='checking installed dependencies'
.venv/bin/python -m pip check
printf '%s\n' 'Installed. Run .venv/bin/python -m cyberintel as your regular user.'
