#!/usr/bin/env python3
"""Quick validation of Sanitize-DeviceState fixtures (no PowerShell required)."""

import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"

REDACT = {
    "phash", "password", "private-key", "public-key", "preshared-key",
    "bind-password", "secret", "api-key", "auth-password", "priv-password",
    "community", "shared-secret", "client-key", "master-key",
    "snmp-community-string", "authpwd", "privpwd",
}

SAFETY = [
    re.compile(r"\$[156]\$[^\s<]{1,120}"),
    re.compile(r"-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----"),
]


def classify_root(text: str) -> str:
    if "<template" in text[:500] or "<template>" in text:
        return "pushed-template"
    if "device-group" in text and "deviceconfig/system" not in text:
        if "pre-rulebase" in text or "post-rulebase" in text or "device-group" in text:
            return "pushed-device-group"
    if "<config" in text and ("deviceconfig/system" in text or "mgt-config" in text):
        return "local-config"
    return "other"


def tier1_hits(text: str) -> int:
    count = 0
    for name in REDACT:
        for m in re.finditer(
            rf"<{name}(?:\s[^>]*)?>([^<]*)</{name}>", text, re.IGNORECASE
        ):
            if m.group(1).strip():
                count += 1
    return count


def safety_hits(text: str) -> int:
    hits = 0
    for pat in SAFETY:
        for m in pat.finditer(text):
            if m.group(0) != "REDACTED":
                hits += 1
    return hits


def extract_tar(path: Path, dest: Path) -> None:
    with tarfile.open(path) as tf:
        tf.extractall(dest)


def main() -> int:
    errors = []

    # device_state_cfg expectations
    src = FIXTURES / "device_state_cfg"
    running = (src / "running-config.xml").read_text()
    if tier1_hits(running) != 3:
        errors.append("device_state_cfg running-config should have 3 tier1 targets")
    if "PA-VM" not in running:
        errors.append("device_state_cfg should contain PA-VM hostname")

    knob = (src / "knob-setting.xml").read_bytes()
    if tier1_hits(knob.decode()) != 0:
        errors.append("knob-setting should have no tier1 targets")

    # canary expectations
    canary = FIXTURES / "canary_device_state"
    run_c = (canary / "running-config.xml").read_text()
    if "CANARY-" in run_c.replace("CANARYHASH", ""):
        pass  # CANARYHASH is ok in source
    for needle in ("CANARY-COMMUNITY", "CANARY-BIND", "CANARY-PSK", "CANARY-LDAP", "CANARY-SNMP"):
        if needle not in (canary / "running-config.xml").read_text() and needle not in (
            canary / "template" / "pretrans-template-config.xml"
        ).read_text():
            if needle in ("CANARY-LDAP", "CANARY-SNMP"):
                continue
            errors.append(f"canary source missing {needle}")

    if safety_hits(run_c) < 1:
        errors.append("canary running-config should have safety-net target ($6$ hash)")

    roles = {
        classify_root((canary / "running-config.xml").read_text()),
        classify_root((canary / "template" / "pretrans-template-config.xml").read_text()),
        classify_root((canary / "sp" / "vsys1" / "pretrans-sp-config.xml").read_text()),
    }
    if roles != {"local-config", "pushed-template", "pushed-device-group"}:
        errors.append(f"canary roles mismatch: {roles}")

    # Try PowerShell if available
    ps = None
    for cmd in ("pwsh", "powershell"):
        try:
            subprocess.run([cmd, "-NoProfile", "-Command", "exit 0"], check=True, capture_output=True)
            ps = cmd
            break
        except (FileNotFoundError, subprocess.CalledProcessError):
            continue

    if ps:
        print(f"Running full suite via {ps}...")
        r = subprocess.run([ps, "-NoProfile", "-File", str(REPO / "tests" / "Run-Tests.ps1")])
        return r.returncode

    if errors:
        for e in errors:
            print(f"FAIL: {e}")
        return 1

    print("Fixture static checks passed (PowerShell not installed — full suite skipped).")
    print("Install PowerShell 7+ to run tests/Run-Tests.ps1 end-to-end.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
