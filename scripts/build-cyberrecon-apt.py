#!/usr/bin/env python3
"""Create a signed local APT repository; does not publish it."""
import argparse
import gzip
import os
import shutil
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path


def build(packages, output, signing_key=None, development_key=False, passphrase_file=None):
    if bool(signing_key) == bool(development_key):
        raise ValueError("Select exactly one operator key or development key.")
    if signing_key and (len(signing_key) not in (40, 64) or any(c not in '0123456789abcdefABCDEF' for c in signing_key)):
        raise ValueError("Use a complete signing key fingerprint.")
    root = Path(output).resolve()
    if root.exists() and any(root.iterdir()):
        raise ValueError("Choose a new or empty repository directory.")
    root.mkdir(parents=True, exist_ok=True)
    pool = root / "pool/main/c/cyberrecon"
    pool.mkdir(parents=True)
    architectures = set()
    for package in packages:
        path = Path(package).resolve()
        if path.suffix != ".deb":
            raise ValueError("Only .deb packages are accepted.")
        architecture = subprocess.check_output(["dpkg-deb", "-f", str(path), "Architecture"], text=True, timeout=10).strip()
        if architecture not in {"all", "amd64"}:
            raise ValueError("Unsupported package architecture: " + architecture)
        architectures.add(architecture)
        name = subprocess.check_output(["dpkg-deb", "-f", str(path), "Package"], text=True, timeout=10).strip()
        if name != 'cyberrecon':
            raise ValueError("Only CyberRecon release packages are accepted.")
        destination = pool / path.name
        if destination.exists():
            raise ValueError("Duplicate package filename.")
        shutil.copy2(path, destination)
    if not architectures:
        raise ValueError("At least one package is required.")
    if "all" in architectures:
        architectures.add("amd64")
        architectures.remove("all")
    packages_data = subprocess.check_output(["apt-ftparchive", "packages", "pool"], cwd=root, timeout=60)
    # Generate per-architecture indices, including Architecture: all entries.
    for architecture in sorted(architectures):
        index = root / "dists/stable/main" / ("binary-" + architecture)
        index.mkdir(parents=True)
        entries = [block for block in packages_data.decode().split("\n\n") if
                   f"Architecture: {architecture}\n" in block + "\n" or "Architecture: all\n" in block + "\n"]
        data = ("\n\n".join(entries) + "\n\n").encode()
        (index / "Packages").write_bytes(data)
        (index / "Packages.gz").write_bytes(gzip.compress(data, mtime=0))
    release = root / "dists/stable/Release"
    options = ["apt-ftparchive", "-o", "APT::FTPArchive::Release::Origin=CyberRecon",
               "-o", "APT::FTPArchive::Release::Label=" + ("CyberRecon development" if development_key else "CyberRecon"),
               "-o", "APT::FTPArchive::Release::Suite=stable", "-o", "APT::FTPArchive::Release::Codename=stable",
               "-o", "APT::FTPArchive::Release::Components=main",
               "-o", "APT::FTPArchive::Release::Architectures=" + " ".join(sorted(architectures)), "release", "dists/stable"]
    validity = (datetime.now(timezone.utc) + timedelta(days=7)).strftime("%a, %d %b %Y %H:%M:%S +0000")
    release.write_bytes(subprocess.check_output(options, cwd=root, timeout=60) + ("Valid-Until: " + validity + "\n").encode())
    with tempfile.TemporaryDirectory(prefix="cyberrecon-signing-") as temporary:
        environment = os.environ.copy()
        try:
            if development_key:
                environment["GNUPGHOME"] = temporary
                subprocess.run(["gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key",
                    "CyberRecon development test key", "ed25519", "sign", "1d"], env=environment, check=True, stdout=subprocess.DEVNULL, timeout=60)
                keys = subprocess.check_output(["gpg", "--batch", "--with-colons", "--list-secret-keys"], env=environment, text=True, timeout=60)
                signing_key = next(line.split(":")[9] for line in keys.splitlines() if line.startswith("fpr:"))
            if not signing_key:
                raise ValueError("Provide --sign-key or explicitly select --development-key.")
            base = ["gpg", "--batch", "--yes", "--local-user", signing_key]
            if passphrase_file:
                base += ['--pinentry-mode', 'loopback', '--passphrase-file', str(passphrase_file)]
            subprocess.run([*base, "--output", str(release.with_name("InRelease")), "--clearsign", str(release)], env=environment, check=True, timeout=60)
            subprocess.run([*base, "--output", str(release.with_name("Release.gpg")), "--detach-sign", str(release)], env=environment, check=True, timeout=60)
            keyring = root / "cyberrecon-archive-keyring.gpg"
            keyring.write_bytes(subprocess.check_output(["gpg", "--batch", "--export", signing_key], env=environment, timeout=60))
            subprocess.run(["gpgv", "--keyring", str(keyring), str(release.with_name("InRelease"))], check=True, timeout=30)
            subprocess.run(["gpgv", "--keyring", str(keyring), str(release.with_name("Release.gpg")), str(release)], check=True, timeout=30)
            (root / "SIGNING.txt").write_text("Signing key: " + signing_key + "\n" +
                ("DEVELOPMENT ONLY. Private key discarded; use an operator-managed key for releases and upgrades.\n" if development_key else
                 "Operator-managed signing key. Validate fingerprint through a trusted channel before configuring APT.\n"))
        finally:
            if development_key:
                subprocess.run(["gpgconf", "--kill", "gpg-agent"], env=environment, check=False, timeout=60)
    return root


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("packages", nargs="+")
    parser.add_argument("--output", required=True)
    keys = parser.add_mutually_exclusive_group(required=True)
    keys.add_argument("--sign-key")
    keys.add_argument("--development-key", action="store_true")
    args = parser.parse_args()
    print(build(args.packages, args.output, args.sign_key, args.development_key))
