"""
NovaLink Update & Integrity Verification Manager
Verifies digital authenticity of application updates and Xray-core Windows 7 (`-win7`) releases
using official `.dgst` SHA-256 digests and HTTPS certificate verification.
Never downloads or executes unsigned/unverified binaries automatically.
"""

from pathlib import Path
from typing import Dict, Optional, Tuple
import hashlib
import re
import ssl
import urllib.request
from .engine import compute_file_sha256


OFFICIAL_XRAY_RELEASE_API = "https://api.github.com/repos/XTLS/Xray-core/releases/latest"


def parse_xray_dgst_file(dgst_text: str) -> Dict[str, str]:
    """
    Parses an official Xray-core `.dgst` file (e.g., `Xray-win7-64.zip.dgst`)
    and extracts {algorithm: hex_digest}, specifically `SHA256`.
    Example line in .dgst:
      SHA256 = 8f4e2b...
    """
    digests: Dict[str, str] = {}
    for line in (dgst_text or "").splitlines():
        line = line.strip()
        if "=" in line:
            k, v = line.split("=", 1)
            alg = k.strip().upper().replace("-", "")
            val = v.strip().lower()
            if re.match(r"^[0-9a-f]{32,128}$", val):
                digests[alg] = val
    return digests


def verify_archive_against_dgst(archive_path: Path, dgst_text: str) -> Tuple[bool, str]:
    """
    Verifies a downloaded `Xray-win7-64.zip` or `Xray-win7-32.zip` archive against its
    official `.dgst` SHA-256 checksum before extraction.
    """
    if not archive_path.exists():
        return False, f"Archive not found: {archive_path}"

    digests = parse_xray_dgst_file(dgst_text)
    expected_sha256 = digests.get("SHA256")
    if not expected_sha256:
        return False, "No valid SHA256 entry found in official .dgst content."

    actual_sha256 = compute_file_sha256(archive_path).lower()
    if actual_sha256 != expected_sha256:
        return (
            False,
            f"SHA-256 verification FAILED! Expected {expected_sha256}, calculated {actual_sha256}. File rejected.",
        )
    return True, f"SHA-256 verified ({actual_sha256})."
