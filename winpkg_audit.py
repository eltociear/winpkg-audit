#!/usr/bin/env python3
"""winpkg-audit - security-scan Scoop, winget & Chocolatey packages before you install them.

`scoop checkup`, `winget validate` and Chocolatey's moderation validator check structure and
conventions. None of them ask whether an install script does something dangerous on *your*
machine. This scanner does: `iex (iwr ...)` download-and-run, base64-decoded-then-executed
payloads, Defender tampering, UAC/firewall disabling, LOLBin downloads (certutil, bitsadmin,
mshta, regsvr32), Mark-of-the-Web stripping (Unblock-File / Zone.Identifier), persistent
execution-policy changes, Run-key / scheduled-task persistence, credential & browser-profile
access and exfiltration, TLS bypass, hosts-file edits, and downloads with no checksum.

It is context-aware: every PowerShell line is classified by where it runs - an install hook
(Scoop `pre_install`/`post_install`/`installer.script`, Chocolatey `chocolateyInstall.ps1`/
`chocolateyBeforeModify.ps1`), an uninstall hook (cleanup: removing a Run key there is not
persistence), or a message shown to the user (`Write-Host` advice is capped at MEDIUM).
Capability mentions (plain downloads through the package manager's own checksummed helpers,
vendor installers, PATH edits, firewall *rules*) are reported as INFO and never scored.
Deterministic, no LLM, zero dependencies (standard library only, Python 3.8+).

Usage:
  python3 winpkg_audit.py <file|dir> [...]           # Scoop .json / winget .yaml / .ps1 / .nupkg / dirs
  python3 winpkg_audit.py --scoop-bucket owner/repo  # fetch + scan a whole Scoop bucket (one tarball)
  python3 winpkg_audit.py --scoop app                # an app from ScoopInstaller/Main|Extras (or bucket/app)
  python3 winpkg_audit.py --winget Publisher.App     # latest manifest from microsoft/winget-pkgs
  python3 winpkg_audit.py --choco id[@version]       # a package from community.chocolatey.org
  python3 winpkg_audit.py --text "<powershell>"      # scan a snippet as an install hook
  add --json (family schema) or --sarif (SARIF 2.1.0) for machine-readable output,
  --all to also list SAFE targets, --verbose for INFO, --fail-on {critical,high,medium,low,never}
  exit code 2 if any target reaches --fail-on (default HIGH; CI-friendly), 1 on usage errors

MIT licensed. https://github.com/eltociear/winpkg-audit
"""
import hashlib
import io
import json
import os
import re
import stat
import sys
import tarfile
import time
import urllib.parse
import urllib.request
import zipfile

__version__ = "1.1.0"
MAX_READ = 4000000   # bytes read per manifest / script
UA = {"User-Agent": "winpkg-audit/%s (github.com/eltociear/winpkg-audit)" % __version__}

# Contexts:
#   hook    : code that runs at install/upgrade time
#   remove  : uninstall / pre_uninstall / post_uninstall / chocolateyUninstall.ps1 (cleanup)
#   message : Write-Host / Write-Output / Write-Warning text (advice, capped at MEDIUM)
#   meta    : manifest metadata (winget YAML, Scoop url/hash fields)
HOOK = {"hook"}
SCORED = {"hook", "meta"}
EVERYWHERE = {"hook", "remove", "message", "meta"}

PATTERNS = {
    "critical": [
        {
            "id": "download_exec",
            "name": "Download & Execute (iex / pipe-to-shell)",
            "desc": "Fetches remote code and executes it without verification",
            "ctx": EVERYWHERE,
            "regexes": [
                # iex (iwr ...) / Invoke-Expression ((New-Object Net.WebClient).DownloadString(...))
                r"\b(?:iex|Invoke-Expression)\b\s*[\(\$]?\s*[\(\[]*\s*(?:\(?\s*New-Object\s+(?:System\.)?Net\.WebClient\s*\)?\s*\.\s*DownloadString|iwr|irm|Invoke-WebRequest|Invoke-RestMethod|curl|wget|\[?(?:System\.)?Net\.WebClient)",
                # ... DownloadString(...) | iex   /  irm url | iex
                r"(?:DownloadString\s*\([^)]*\)|\b(?:iwr|irm|Invoke-WebRequest|Invoke-RestMethod)\b[^|\n]*)\|\s*(?:iex|Invoke-Expression)\b",
                r"\.Content\s*\|\s*(?:iex|Invoke-Expression)\b",
                r"\[ScriptBlock\]::Create\s*\(\s*\(?\s*(?:\(?\s*New-Object\s+(?:System\.)?Net\.WebClient|iwr|irm|Invoke-WebRequest|Invoke-RestMethod)",
                r"(?:curl|wget)(?:\.exe)?\b[^|\n]*\|\s*(?:sh|bash|cmd|powershell|pwsh)\b",
                r"\bmshta(?:\.exe)?\s+[\"']?(?:https?|vbscript|javascript):",
                r"\bregsvr32(?:\.exe)?\b[^\n]*/i:\s*[\"']?https?://",
                r"\brundll32(?:\.exe)?\b[^\n]*javascript:",
            ],
        },
        {
            "id": "encoded_exec",
            "name": "Encoded-then-Executed Payload",
            "desc": "Runs a base64 / -EncodedCommand blob, or loads a decoded assembly into memory",
            "ctx": EVERYWHERE,
            "regexes": [
                r"(?:powershell|pwsh)(?:\.exe)?\b[^\n]*\s-(?:e|en|enc|enco|encod|encode|encoded|encodedc|encodedcommand)\s+[\"']?[A-Za-z0-9+/]{24,}={0,2}",
                r"\b(?:iex|Invoke-Expression)\b[^\n]{0,80}FromBase64String",
                r"FromBase64String[^\n]{0,160}\|\s*(?:iex|Invoke-Expression)\b",
                r"\[ScriptBlock\]::Create\s*\([^\n]{0,120}FromBase64String",
                r"\[(?:System\.)?Reflection\.Assembly\]::Load\s*\([^\n]{0,80}(?:FromBase64String|DownloadData)",
            ],
        },
        {
            "id": "defender_tamper",
            "name": "Defender / AV Tampering",
            "desc": "Disables Microsoft Defender protections or excludes paths from scanning",
            "ctx": {"hook", "meta", "message"},
            "regexes": [
                r"\bSet-MpPreference\b[^\n]*-Disable(?:RealtimeMonitoring|BehaviorMonitoring|IOAVProtection|ScriptScanning|BlockAtFirstSeen|IntrusionPreventionSystem|ArchiveScanning)\b(?!\s*(?::\s*)?(?:\$false|0)\b)",
                r"\b(?:Add|Set)-MpPreference\b[^\n]*-Exclusion(?:Path|Process|Extension|IpAddress)\b",
                r"\bDisableAntiSpyware\b|\bDisableRealtimeMonitoring\b[^\n]*(?:-Value|/d)\s*1\b",
                r"\b(?:sc(?:\.exe)?|Stop-Service|Set-Service)\b[^\n]*\bWinDefend\b",
                r"\bMpCmdRun(?:\.exe)?\b[^\n]*-RemoveDefinitions\b",
            ],
        },
        {
            "id": "security_disable",
            "name": "System Security Disabled",
            "desc": "Turns off the firewall, UAC, or SmartScreen machine-wide",
            "ctx": {"hook", "meta", "message"},
            "regexes": [
                r"\bnetsh(?:\.exe)?\s+(?:advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+(?:mode=)?disable)",
                r"\bSet-NetFirewallProfile\b[^\n]*-Enabled\s+(?:False|\$false|0)\b",
                r"\bEnableLUA\b[^\n]*(?:-Value\s*|/d\s*|=\s*)0\b",
                r"\bConsentPromptBehaviorAdmin\b[^\n]*(?:-Value\s*|/d\s*|=\s*)0\b",
                r"\b(?:SmartScreenEnabled|EnableSmartScreen)\b[^\n]*(?:-Value\s*|/d\s*|=\s*)[\"']?(?:Off|0)\b",
            ],
        },
        {
            "id": "uac_bypass",
            "name": "UAC Bypass Technique",
            "desc": "Hijacks an auto-elevating binary's registry handler",
            "ctx": EVERYWHERE,
            "regexes": [
                r"ms-settings\\+shell\\+open\\+command",
                r"mscfile\\+shell\\+open\\+command",
                r"Folder\\+shell\\+open\\+command[^\n]*DelegateExecute",
                r"\b(?:fodhelper|computerdefaults|sdclt|eventvwr)(?:\.exe)?\b[^\n]*(?:ms-settings|DelegateExecute)",
            ],
        },
        {
            "id": "credential_exfil",
            "name": "Credential Exfiltration",
            "desc": "Reads credentials / browser or wallet data and sends it to an external host",
            "ctx": EVERYWHERE,
            "regexes": [],  # combination rule, see scan()
        },
        {
            "id": "reverse_shell",
            "name": "Reverse Shell",
            "desc": "Opens a raw TCP stream and executes what arrives",
            "ctx": EVERYWHERE,
            "regexes": [
                r"Net\.Sockets\.TCPClient\s*\([^)]*\)[^\n]{0,200}GetStream\(\)",
                r"GetStream\(\)[^\n]{0,200}(?:iex|Invoke-Expression)\b",
            ],
        },
    ],
    "high": [
        {
            "id": "motw_strip",
            "name": "Mark-of-the-Web Stripped",
            "desc": "Removes Zone.Identifier so SmartScreen / Office protected view never inspect the file",
            "ctx": {"hook", "message"},
            "regexes": [
                r"\bUnblock-File\b",
                r"\bRemove-Item\b[^\n]*-Stream\s+[\"']?Zone\.Identifier",
                r"\bClear-Content\b[^\n]*-Stream\s+[\"']?Zone\.Identifier",
                r"[\w\"'$)]:Zone\.Identifier\b",
                r"\bstreams(?:64)?(?:\.exe)?\s+(?:-accepteula\s+)?-[sd]\b",
            ],
        },
        {
            "id": "credential_access",
            "name": "Credential / Browser-Profile Access",
            "desc": "Reads saved passwords, browser cookies/logins, wallets, SSH or cloud keys",
            "ctx": {"hook", "meta"},
            "regexes": [
                r"\\(?:Google\\Chrome|Microsoft\\Edge|BraveSoftware\\Brave-Browser)\\User Data\\[^\n]*(?:Login Data|Cookies|Local State|Web Data)",
                r"\\Mozilla\\Firefox\\Profiles\\[^\n]*(?:logins\.json|key[34]\.db|cookies\.sqlite)",
                r"\b(?:logins\.json|key4\.db)\b",
                r"\\(?:Exodus|Electrum\\wallets|Ethereum\\keystore|atomic\\Local Storage|Armory)\b",
                r"\bnkbihfbeogaeaoehlefnkodbefgpgknn\b",  # MetaMask extension id
                r"\b(?:cmdkey(?:\.exe)?\s+/list|vaultcmd(?:\.exe)?\s+/list|Get-StoredCredential)\b",
                r"\[Windows\.Security\.Credentials\.PasswordVault\]",
                # key/credential files only count when they are actually READ (an ssh config line
                # `IdentityFile ~/.ssh/id_rsa` merely names the user's key)
                r"\b(?:Get-Content|gc|cat|type|Copy-Item|cp|Compress-Archive|Import-Clixml|ReadAll(?:Text|Bytes|Lines))\b[^\n]{0,80}(?:\.ssh[\\/]+id_(?:rsa|ed25519|ecdsa)(?!\.pub)|\.aws[\\/]+credentials|\.azure[\\/]+accessTokens|\.docker[\\/]+config\.json)\b",
                r"\bProtectedData\]::Unprotect\b",
            ],
        },
        {
            "id": "lolbin_download",
            "name": "LOLBin Download / Decode",
            "desc": "Uses certutil / bitsadmin (living-off-the-land binaries) to fetch or decode payloads",
            "ctx": {"hook", "meta", "message"},
            "regexes": [
                r"\bcertutil(?:\.exe)?\b[^\n]*-(?:urlcache|verifyctl)\b[^\n]*https?://",
                r"\bcertutil(?:\.exe)?\b[^\n]*-decode(?:hex)?\b",
                r"\bbitsadmin(?:\.exe)?\b[^\n]*/(?:transfer|addfile)\b",
                r"\besentutl(?:\.exe)?\b[^\n]*/y\s+\\\\",
            ],
        },
        {
            "id": "execpolicy_persist",
            "name": "Persistent Execution-Policy Change",
            "desc": "Weakens PowerShell's execution policy machine-/user-wide (not just for this process)",
            "ctx": {"hook", "meta"},
            "regexes": [
                r"\bSet-ExecutionPolicy\b(?![^\n]*-Scope\s*[\"']?Process\b)[^\n]*\b(?:Bypass|Unrestricted)\b",
                r"\\PowerShell\\1\\ShellIds\\Microsoft\.PowerShell[^\n]*ExecutionPolicy[^\n]*(?:Bypass|Unrestricted)",
            ],
        },
        {
            "id": "tls_bypass",
            "name": "TLS Verification Disabled",
            "desc": "Accepts any certificate, so downloads can be swapped in transit",
            "ctx": {"hook", "meta"},
            "regexes": [
                r"ServerCertificateValidationCallback\s*=\s*\{\s*\$true\s*\}",
                r"ServerCertificateValidationCallback\s*=\s*\{[^}]*return\s+\$true",
                r"\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^\n]*-SkipCertificateCheck\b",
                r"\bTrustAllCertsPolicy\b",
                r"(?:curl|wget)(?:\.exe)?\b[^\n]*\s(?:-k|--insecure|--no-check-certificate)\b",
            ],
        },
        {
            "id": "suspicious_host",
            "name": "Payload / Collector Host",
            "desc": "Talks to a paste site, chat webhook, tunnel, anonymous file drop or OAST host",
            "ctx": EVERYWHERE,
            "regexes": [
                r"https?://(?:www\.)?(?:pastebin\.com/raw|paste\.ee/r|hastebin\.com/raw|rentry\.co/[^/\s]+/raw|ghostbin\.\w+)",
                r"https?://(?:\w+\.)?discord(?:app)?\.com/api/webhooks/",
                r"https?://(?:cdn|media)\.discordapp\.(?:com|net)/attachments/",
                r"https?://api\.telegram\.org/bot",
                r"https?://(?:[\w-]+\.)*(?:ngrok\.io|ngrok-free\.app|ngrok\.app|trycloudflare\.com|serveo\.net|loca\.lt)\b",
                r"https?://(?:www\.)?(?:transfer\.sh|file\.io|temp\.sh|0x0\.st|bashupload\.com|anonfiles\.com|gofile\.io/d)",
                r"https?://(?:[\w-]+\.)*(?:webhook\.site|requestbin\.(?:com|net|io)|requestb\.in|pipedream\.net|oast\.(?:fun|me|pro|site|live|online)|interact\.sh|burpcollaborator\.net)\b",
                r"https?://[a-z2-7]{16,56}\.onion\b",
            ],
        },
        {
            "id": "unverified_plaintext",
            "name": "Unverified Plaintext Download",
            "desc": "Downloads over http:// with no checksum, so the bytes can be swapped in transit",
            "ctx": EVERYWHERE,
            "regexes": [],  # structural, see scan()
        },
        {
            "id": "fetch_exec",
            "name": "Unverified Fetch-then-Run",
            "desc": "Downloads a file outside the package manager's checksummed path and executes it",
            "ctx": HOOK,
            "regexes": [],  # window rule, see scan()
        },
        {
            "id": "hosts_tamper",
            "name": "Hosts File Tampering",
            "desc": "Writes to the system hosts file (classic licence-check / update blocking or redirect)",
            "ctx": HOOK,
            "regexes": [
                r"(?:Add-Content|Set-Content|Out-File|>>?)\s*[^\n]*drivers\\+etc\\+hosts\b",
                r"drivers\\+etc\\+hosts\b[^\n]*\|\s*(?:Add-Content|Set-Content|Out-File)",
                r"\[(?:System\.)?IO\.File\]::(?:Append|Write)All\w*\([^\n]*drivers\\+etc\\+hosts",
            ],
        },
        {
            "id": "destructive",
            "name": "Destructive Command",
            "desc": "Recursively deletes user or system directories, or wipes shadow copies",
            "ctx": {"hook", "remove", "meta"},
            "regexes": [
                r"\bRemove-Item\b[^\n]*(?:\$env:(?:USERPROFILE|SystemRoot|windir|HOMEDRIVE)\s*[\"']?\s*(?:-|$)|\$HOME\s*[\"']?\s*-|[\"']?C:\\\\?(?:Windows|Users)?\\?[\"']?\s+-)[^\n]*-Recurse",
                r"\bvssadmin(?:\.exe)?\s+delete\s+shadows\b",
                r"\bwmic(?:\.exe)?\s+shadowcopy\s+delete\b",
                r"\b(?:bcdedit|wbadmin)(?:\.exe)?\b[^\n]*(?:recoveryenabled\s+no|delete\s+catalog)",
                r"\bcipher(?:\.exe)?\s+/w:",
                r"\bFormat-Volume\b|\bClear-Disk\b",
            ],
        },
    ],
    "medium": [
        {
            "id": "persistence",
            "name": "Autostart Persistence",
            "desc": "Adds a Run key, scheduled task, startup-folder entry or WMI subscription at install time",
            "ctx": HOOK,
            "regexes": [
                r"\\(?:Microsoft\\Windows\\CurrentVersion\\Run(?:Once)?|Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run)\b(?![^\n]*Remove-ItemProperty)",
                r"\bschtasks(?:\.exe)?\s+/create\b",
                r"\bRegister-ScheduledTask\b",
                r"\\Start Menu\\Programs\\Startup\\|\[Environment\]::GetFolderPath\(\s*[\"']Startup[\"']\s*\)|shell:startup",
                r"\b(?:__EventFilter|CommandLineEventConsumer|__FilterToConsumerBinding)\b",
                r"\\Winlogon\b[^\n]*\b(?:Userinit|Shell)\b",
                r"\\Image File Execution Options\\[^\n]*\bDebugger\b",
            ],
        },
        {
            "id": "install_fetch",
            "name": "Install-time Fetch (no checksum)",
            "desc": "Downloads extra content from inside an install script, bypassing manifest hashes",
            "ctx": HOOK,
            "regexes": [
                r"\b(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^\n]*-(?:OutFile|o)\b",
                r"\.DownloadFile(?:Async|TaskAsync)?\s*\(",
                r"\bStart-BitsTransfer\b",
                r"\bcurl(?:\.exe)?\b[^\n]*\s(?:-o|--output|-O)\s",
            ],
        },
        {
            "id": "missing_checksum",
            "name": "Missing Checksum",
            "desc": "Downloads over HTTPS with no hash pinned in the manifest",
            "ctx": EVERYWHERE,
            "regexes": [],  # structural, see scan()
        },
        {
            "id": "obfuscation",
            "name": "Obfuscated PowerShell",
            "desc": "Character-code joins, format-string splitting or tick-escaped cmdlet names",
            "ctx": EVERYWHERE,
            "regexes": [
                r"(?:\[char\]\s*0?x?[0-9a-fA-F]{2,3}\s*\+\s*){6,}",
                r"\(\s*(?:\d{2,3}\s*,\s*){10,}\d{2,3}\s*\)\s*\|\s*%\s*\{\s*\[char\]",
                r"-join\s*\(\s*(?:\d{2,3}\s*,\s*){10,}",
                r"[\"']\s*(?:\{\d+\}){4,}\s*[\"']\s*-f\s*[\"'][^\"']{1,10}[\"']\s*,\s*[\"'][^\"']{1,10}[\"']",  # literal fragments only
                r"\b[iI]`[eE]`?[xX]\b|\b[Ii]nv`o`?ke-|\bN`e`?w-O`?bject\b|\bD`o`?wnloadS`?tring\b",
                r"\(\s*[\"']\s*\w\s*[\"']\s*\+\s*[\"']\s*\w\s*[\"']\s*\+\s*[\"']\s*\w\s*[\"']\s*\)\s*(?:\||$)",
                r"\$(?:env:comspec|pshome)\[\d+\][^\n]*\+\s*\$\w+\[\d+\]",
            ],
        },
        {
            "id": "raw_ip_host",
            "name": "Raw-IP Download Host",
            "desc": "Fetches from a bare IP address instead of a named, certificate-bearing host",
            "ctx": EVERYWHERE,
            "regexes": [
                r"https?://(?!(?:127\.|10\.|192\.168\.|0\.0\.0\.0|localhost))(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?/",
            ],
        },
    ],
    "low": [
        {
            "id": "insecure_url",
            "name": "Plaintext URL (checksummed)",
            "desc": "Downloads over http://, but the manifest pins a hash",
            "ctx": EVERYWHERE,
            "regexes": [],  # structural, see scan()
        },
    ],
    "info": [
        {"id": "execpolicy_process", "name": "Process-scoped ExecutionPolicy Bypass",
         "desc": "One-off `-ExecutionPolicy Bypass` for a child process / -Scope Process", "ctx": EVERYWHERE,
         "regexes": [r"-ExecutionPolicy\s+(?:Bypass|Unrestricted)\b", r"Set-ExecutionPolicy\b[^\n]*-Scope\s*[\"']?Process\b"]},
        {"id": "base64_decode", "name": "Base64 decode", "desc": "Decodes base64 (not executed)", "ctx": EVERYWHERE,
         "regexes": [r"FromBase64String"]},
        {"id": "firewall_rule", "name": "Firewall rule", "desc": "Adds/removes a specific firewall rule", "ctx": EVERYWHERE,
         "regexes": [r"\bnetsh(?:\.exe)?\s+advfirewall\s+firewall\b", r"\b(?:New|Remove)-NetFirewallRule\b"]},
        {"id": "service_install", "name": "Service install", "desc": "Registers a Windows service", "ctx": EVERYWHERE,
         "regexes": [r"\bNew-Service\b", r"\bsc(?:\.exe)?\s+create\b", r"\bInstall-ChocolateyService\b"]},
        {"id": "vendor_installer", "name": "Vendor installer", "desc": "Runs the publisher's own installer", "ctx": EVERYWHERE,
         "regexes": [r"\bInstall-Chocolatey(?:Install)?Package\b", r"\bStart-Process\b[^\n]*\.(?:exe|msi)\b", r"\bmsiexec\b",
                     r"^\s*InstallerType:\s*(?:exe|inno|nullsoft|burn|wix|msi)\b"]},
        {"id": "env_path", "name": "PATH / environment edit", "desc": "Modifies environment variables", "ctx": EVERYWHERE,
         "regexes": [r"\[Environment\]::SetEnvironmentVariable", r"\bInstall-ChocolateyPath\b", r"\bsetx\b"]},
        {"id": "elevation", "name": "Elevation", "desc": "Requires or requests administrator rights", "ctx": EVERYWHERE,
         "regexes": [r"-Verb\s+RunAs\b", r"ElevationRequirement:\s*\w+", r"\bTest-IsAdmin\b|\bis_admin\b"]},
        {"id": "registry_write", "name": "Registry write", "desc": "Writes registry values (settings / file associations)",
         "ctx": EVERYWHERE, "regexes": [r"\b(?:New|Set)-ItemProperty\b", r"\breg(?:\.exe)?\s+(?:add|import)\b"]},
        {"id": "vendor_fetch", "name": "Package-manager download helper",
         "desc": "Download through Chocolatey's checksummed helpers", "ctx": EVERYWHERE,
         "regexes": [r"\bGet-ChocolateyWebFile\b", r"\bInstall-ChocolateyZipPackage\b", r"\bInstall-ChocolateyVsixPackage\b"]},
        {"id": "install_hook", "name": "Install hook", "desc": "Has install-time script code", "ctx": {"hook"},
         "regexes": []},
    ],
}

SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3}
SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "SAFE": 0, "INFO": 0}

CRED_TERM = re.compile(
    r"Login Data|Local State|logins\.json|key4\.db|cookies\.sqlite|\\Cookies\b|"
    r"\.ssh[\\/]+id_|\.aws[\\/]+credentials|\bcmdkey\b|\bvaultcmd\b|PasswordVault|ProtectedData\]::Unprotect|"
    r"nkbihfbeogaeaoehlefnkodbefgpgknn|\\Exodus\b|Electrum\\wallets|"
    r"\$env:(?:GITHUB_TOKEN|NPM_TOKEN|AWS_SECRET_ACCESS_KEY|AZURE_\w+SECRET\w*|CHOCOLATEY_API_KEY)|"
    r"Get-ChildItem\s+env:|\bgci\s+env:|\[Environment\]::GetEnvironmentVariables\(\)", re.I)
SEND = re.compile(
    r"-Method\s+(?:Post|Put)\b|\.Upload(?:String|File|Data|Values)\s*\(|\bSend-MailMessage\b|"
    r"\bInvoke-RestMethod\b[^\n]*-Body\b|\bInvoke-WebRequest\b[^\n]*-Body\b|Net\.Sockets\.(?:TCP|Udp)Client|"
    r"\bcurl(?:\.exe)?\b[^\n]*\s(?:-d|--data|-F|--form|-T|--upload-file)\s|Resolve-DnsName\s+[^\n]*\+", re.I)
HOST = re.compile(r"https?://([A-Za-z0-9.-]+)")
TRUSTED_HOST = re.compile(
    r"(?:^|\.)(?:github\.com|githubusercontent\.com|chocolatey\.org|microsoft\.com|windows\.net|"
    r"visualstudio\.com|nuget\.org|scoop\.sh|localhost)$", re.I)

# Anchored on the download keyword: the old leading `(?:$var=)?[^\n]*?` made every unanchored
# search O(n^2) per line (a 40 kB one-line script took ~40 s, 5 MB never finished).
_DL_CMD = re.compile(
    r"(?:Invoke-WebRequest|iwr|Invoke-RestMethod|irm)\b[^\n]*-(?:OutFile|o)\s+(?P<out>\S+)"
    r"|\.DownloadFile\s*\(\s*[^,)\n]{1,2000},\s*(?P<out2>[^)\n]{1,2000})\)"
    r"|\bStart-BitsTransfer\b[^\n]*-Destination\s+(?P<out3>\S+)", re.I)
_DL_VAR = re.compile(r"\$(\w+)\s*=\s*")


class _DlMatch:
    def __init__(self, m, var):
        self.m, self.var = m, var

    def group(self, name):
        return self.var if name == "var" else self.m.group(name)


class _DlAssign:
    """Same groups as the old single regex: var is only captured from a `$x =` at the line start."""

    def search(self, line):
        m = _DL_CMD.search(line)
        if not m:
            return None
        v = _DL_VAR.match(line)
        return _DlMatch(m, v.group(1) if v and v.end() <= m.start() else None)


DL_ASSIGN = _DlAssign()
# prefix that makes the following token the *command* (not an argument such as `7z x <file>`)
RUN_AS_CMD = (r"(?:\bStart-Process\s+(?:-FilePath\s+)?|(?:^|[;{(|]|&&)\s*&\s*|\bInvoke-Item\s+|"
              r"\bmsiexec(?:\.exe)?\b[^\n]*?/[ia]\s*|\bcmd(?:\.exe)?\s+/[ck]\s+(?:call\s+)?|-File(?:Path)?\s+|"
              r"(?:^|[;{(])\s*\.\s+|\bInstall-ChocolateyInstallPackage\b[^\n]*?-File(?:64)?\s+|^\s*)[\"']?")

MSG_LINE = re.compile(r"^\s*(?:Write-(?:Host|Output|Warning|Information|Verbose|Debug)|echo|Write-Log)\b", re.I)

_COMPILED = [(sev, pg, [re.compile(r, re.I) for r in pg["regexes"]])
             for sev, groups in PATTERNS.items() for pg in groups]


def _by_id(pid):
    for sev, groups in PATTERNS.items():
        for pg in groups:
            if pg["id"] == pid:
                return sev, pg
    raise KeyError(pid)


# ---------------------------------------------------------------------------
# Parsing: every target becomes a list of (context, locator, text) "units"
# ---------------------------------------------------------------------------
def _strip_ps_comments(text):
    """Blank out <# ... #> block comments and whole-line # comments, keep line numbers."""
    out, in_block = [], False
    for line in text.split("\n"):
        s = line
        if in_block:
            if "#>" in s:
                s = s.split("#>", 1)[1]
                in_block = False
            else:
                out.append("")
                continue
        while "<#" in s:
            pre, post = s.split("<#", 1)
            if "#>" in post:
                s = pre + post.split("#>", 1)[1]
            else:
                s = pre
                in_block = True
                break
        if s.lstrip().startswith("#"):
            s = ""
        out.append(s)
    return out


LONG_LINE = 4000   # longer (minified / padded) lines are scanned in overlapping windows
SEG, SEG_OVERLAP = 4000, 600


def _windows(line):
    if len(line) <= LONG_LINE:
        return [line]
    return [line[i:i + SEG] for i in range(0, len(line), SEG - SEG_OVERLAP)]


def ps_units(text, ctx, prefix=""):
    units = []
    for i, line in enumerate(_strip_ps_comments(text)):
        if not line.strip():
            continue
        c = ctx
        if ctx == "hook" and MSG_LINE.match(line):
            c = "message"
        for seg in _windows(line):
            units.append((c, "%sL%d" % (prefix, i + 1), seg))
    return units


SCOOP_HOOKS = {"pre_install": "hook", "post_install": "hook", "pre_uninstall": "remove",
               "post_uninstall": "remove"}


def _as_lines(v):
    if isinstance(v, list):
        return "\n".join(str(x) for x in v)
    return str(v) if v is not None else ""


def scoop_units(doc):
    """Return (units, downloads) for a Scoop manifest dict. downloads: [(locator, url, hash)]"""
    units, downloads = [], []

    def walk(node, path):
        if not isinstance(node, dict):
            return
        for k, ctx in SCOOP_HOOKS.items():
            if k in node:
                units.extend(ps_units(_as_lines(node[k]), ctx, "%s%s:" % (path, k)))
        for k, ctx in (("installer", "hook"), ("uninstaller", "remove")):
            if isinstance(node.get(k), dict):
                inst = node[k]
                if "script" in inst:
                    units.extend(ps_units(_as_lines(inst["script"]), ctx, "%s%s.script:" % (path, k)))
                if "args" in inst:
                    units.append(("meta", "%s%s.args" % (path, k), _as_lines(inst["args"])))
        if "url" in node:
            urls = node["url"] if isinstance(node["url"], list) else [node["url"]]
            hashes = node.get("hash")
            hashes = hashes if isinstance(hashes, list) else ([hashes] if hashes else [])
            for j, u in enumerate(urls):
                h = hashes[j] if j < len(hashes) else (hashes[0] if len(hashes) == 1 and len(urls) == 1 else None)
                downloads.append(("%surl[%d]" % (path, j), str(u), h))
        for k in ("bin", "shortcuts", "env_set", "env_add_path", "persist", "pre_install", "notes"):
            pass

    walk(doc, "")
    arch = doc.get("architecture")
    if isinstance(arch, dict):
        for name, sub in arch.items():
            walk(sub, "architecture.%s." % name)
    if doc.get("notes"):
        units.extend(("message", "notes:L%d" % (i + 1), l) for i, l in enumerate(_as_lines(doc["notes"]).split("\n")) if l.strip())
    # top-level url inherited by architectures without their own: already handled (both walked)
    return units, downloads


YAML_KV = re.compile(r"^\s*-?\s*(?P<k>[A-Za-z0-9]+):\s*(?P<v>.*?)\s*$")


def winget_units(text):
    """Line-level parse of a winget installer manifest (no YAML dependency)."""
    units, downloads = [], []
    cur_url, cur_hash, cur_loc = None, None, None
    blocks, dep_ind = [], None
    for i, line in enumerate(text.split("\n")):
        if line.lstrip().startswith("#") or not line.strip():
            continue
        ind = len(line) - len(line.lstrip(" -"))
        if dep_ind is not None and ind <= dep_ind:
            dep_ind = None
        if re.match(r"^\s*-?\s*Dependencies:", line):
            dep_ind = ind
            continue
        if dep_ind is not None:
            continue
        m = YAML_KV.match(line)
        loc = "L%d" % (i + 1)
        if m:
            k, v = m.group("k"), m.group("v").strip("'\"")
            if k == "InstallerUrl":
                if cur_url is not None:
                    blocks.append((cur_loc, cur_url, cur_hash))
                cur_url, cur_hash, cur_loc = v, None, loc
            elif k == "InstallerSha256":
                if cur_url is None:
                    cur_hash = v
                else:
                    cur_hash = v
            if k in ("Silent", "SilentWithProgress", "Interactive", "Custom", "Log", "InstallLocation",
                     "Upgrade", "Repair", "InstallerUrl", "ElevationRequirement", "InstallerType", "Commands",
                     "RelativeFilePath", "PortableCommandAlias"):
                units.append(("meta", loc, line))
        elif line.strip().startswith("- ") or line.startswith("  "):
            units.append(("meta", loc, line))
    if cur_url is not None:
        blocks.append((cur_loc, cur_url, cur_hash))
    # InstallerSha256 may precede InstallerUrl inside an entry; re-pair by proximity
    if blocks and any(h is None for _, _, h in blocks):
        hashes = re.findall(r"^\s*-?\s*InstallerSha256:\s*['\"]?([0-9A-Fa-f]{64})", text, re.M)
        if len(hashes) >= len(blocks):
            blocks = [(l, u, h or "paired") for l, u, h in blocks]
    downloads.extend(blocks)
    return units, downloads


CHOCO_CTX = [
    (re.compile(r"chocolatey(?:Before)?Modify\.ps1$|chocolateyInstall\.ps1$", re.I), "hook"),
    (re.compile(r"chocolateyUninstall\.ps1$", re.I), "remove"),
]
CHOCO_DL_CALL = re.compile(r"\b(?:Install-ChocolateyPackage|Install-ChocolateyZipPackage|Get-ChocolateyWebFile|"
                           r"Install-ChocolateyVsixPackage|Install-ChocolateyPowershellCommand)\b", re.I)
CHECKSUM_TOKEN = re.compile(r"\bchecksum(?:64)?\s*=|-Checksum(?:64)?\b|\$checksum\w*\s*=|\bchecksum(?:64)?\s*:", re.I)
URL_LITERAL = re.compile(r"[\"'](?P<u>(?:https?|ftp)://[^\"'\s]+)[\"']")
URL_ASSIGN = re.compile(r"^\s*(?:\$?url(?:64(?:bit)?)?|-Url(?:64(?:bit)?)?)\s*[=\s]\s*[\"'](?P<u>(?:https?|ftp)://[^\"'\s]+)", re.I)


def choco_ctx(name):
    base = name.replace("\\", "/").split("/")[-1]
    for rx, c in CHOCO_CTX:
        if rx.search(base):
            return c
    if base.lower().endswith((".ps1", ".psm1")):
        return "hook"  # helper scripts dot-sourced by the install script
    return None


def choco_units(files):
    """files: [(name, text)] of a package. Returns (units, downloads)."""
    units, downloads = [], []
    for name, text in files:
        c = choco_ctx(name)
        if c is None:
            continue
        short = name.replace("\\", "/").split("/")[-1]
        units.extend(ps_units(text, c, short + ":"))
        if c != "hook" or not CHOCO_DL_CALL.search(text):
            continue
        has_sum = bool(CHECKSUM_TOKEN.search(text))
        lines = _strip_ps_comments(text)
        for i, line in enumerate(lines):
            m = URL_ASSIGN.search(line)
            if not m:
                continue
            downloads.append(("%s:L%d" % (short, i + 1), m.group("u"), "present" if has_sum else None))
    return units, downloads


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------
def _item(sev, pg, loc, matched, line, ctx):
    it = {"severity": sev.upper(), "id": pg["id"], "name": pg["name"], "description": pg["desc"],
          "line": loc, "context_block": ctx, "matched": matched[:120], "context": line.strip()[:200]}
    m = re.match(r"(.+\.psm?1):L\d+$", str(loc), re.I)   # Chocolatey package script ("tools/x.ps1:L3")
    if m:
        it["file"] = m.group(1)
    return it


def scan_units(units, downloads, kind):
    findings, info, seen = [], [], set()

    def add(sev, pg, loc, matched, line, ctx):
        key = (pg["id"], loc)
        if key in seen:
            return
        seen.add(key)
        it = _item(sev, pg, loc, matched, line, ctx)
        if sev == "info" or ctx not in pg["ctx"]:
            it["severity"] = "INFO"
            info.append(it)
            return
        if ctx == "message" and SEVERITY_RANK[it["severity"]] > SEVERITY_RANK["MEDIUM"]:
            it["severity"] = "MEDIUM"
            it["name"] += " (advised to the user in a message)"
        findings.append(it)

    if any(c == "hook" for c, _, _ in units):
        sev, pg = _by_id("install_hook")
        first = next(u for u in units if u[0] == "hook")
        add(sev, pg, first[1], "", first[2], "hook")

    for ctx, loc, line in units:
        for sev, pg, regs in _COMPILED:
            for rx in regs:
                m = rx.search(line)
                if m:
                    add(sev, pg, loc, m.group(0), line, ctx)
                    break

    # credential_exfil: credential term + send primitive + non-trusted host within +-6 units
    sev, pg = _by_id("credential_exfil")
    for i, (ctx, loc, line) in enumerate(units):
        cm = CRED_TERM.search(line)
        if not cm:
            continue
        window = [u[2] for u in units[max(0, i - 6):i + 7]]
        if not any(SEND.search(l) for l in window):
            continue
        hosts = [h for l in window for h in HOST.findall(l)]
        foreign = [h for h in hosts if not TRUSTED_HOST.search(h)]
        if foreign or (not hosts and any(re.search(r"Net\.Sockets|Resolve-DnsName", l, re.I) for l in window)):
            add(sev, pg, loc, cm.group(0), line, ctx)

    # fetch_exec: a hook downloads to a path and then runs it within the next 8 units
    sev, pg = _by_id("fetch_exec")
    for i, (ctx, loc, line) in enumerate(units):
        if ctx != "hook":
            continue
        m = DL_ASSIGN.search(line)
        if not m:
            continue
        target = (m.group("out") or m.group("out2") or m.group("out3") or "").strip().strip("\"'),;")
        var = m.group("var")
        tail = [u for u in units[i + 1:i + 9] if u[0] == "hook"]
        needles = [t for t in (target, ("$" + var) if var else None) if t and len(t) > 2]
        runs = [re.compile(RUN_AS_CMD + re.escape(n) + r"[\"']?(?!\w)(?!\s*[+\-]?=)", re.I) for n in needles]
        for _, l2, t2 in tail:
            if any(rx.search(t2) for rx in runs):
                # A pinned release asset over HTTPS from a trusted forge is weaker evidence
                # than a mutable branch, plaintext, or an unknown host -> MEDIUM, not HIGH.
                um = re.search(r"https?://[^\s\"')]+", line)
                u = um.group(0) if um else ""
                pinned = (u.startswith("https://") and TRUSTED_HOST.search(HOST.findall(u)[0] if HOST.findall(u) else "")
                          and "/releases/download/" in u)
                add("medium" if pinned else sev, pg, loc, line.strip(), line, ctx)
                break

    # checksum posture
    for loc, url, h in downloads:
        u = (url or "").strip()
        if not re.match(r"(?:https?|ftp)://", u, re.I):
            continue
        hv = (str(h).strip().lower() if h else "")
        unpinned = (not hv) or hv in ("skip", "none", "null")
        plain = u.lower().startswith(("http://", "ftp://"))
        line = "url: %s  hash: %s" % (u, h or "<none>")
        if plain and unpinned:
            add(*_by_id("unverified_plaintext"), loc, u, line, "meta")
        elif plain:
            add(*_by_id("insecure_url"), loc, u, line, "meta")
        elif unpinned:
            add(*_by_id("missing_checksum"), loc, u, line, "meta")
        for sev2, pg2, regs in _COMPILED:
            if pg2["id"] in ("suspicious_host", "raw_ip_host"):
                for rx in regs:
                    mm = rx.search(u)
                    if mm:
                        add(sev2, pg2, loc, mm.group(0), line, "meta")
                        break

    total, counts = 0, {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        total += SEVERITY_SCORE[f["severity"].lower()]
        counts[f["severity"]] += 1
    level = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]), "SAFE")
    findings.sort(key=lambda f: (-SEVERITY_RANK[f["severity"]], str(f["line"])))
    parts = ["%d %s" % (counts[s], s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]]
    return {"risk_score": min(total, 100), "risk_level": level, "kind": kind,
            "findings": findings, "info": info,
            "summary": ", ".join(parts) if parts else "No issues found",
            "total_findings": len(findings), "info_count": len(info)}


def detect_kind(name, text):
    low = name.lower()
    if low.endswith(".json"):
        return "scoop"
    if low.endswith((".yaml", ".yml")):
        return "winget"
    if low.endswith((".ps1", ".psm1")):
        return "choco" if "chocolatey" in low else "ps1"
    s = text.lstrip()
    if s.startswith("{"):
        return "scoop"
    if re.search(r"^\s*(?:PackageIdentifier|ManifestType):", text, re.M):
        return "winget"
    return "ps1"


def scan(text, name="<text>", kind=None):
    """Scan one manifest or script. Returns the audit result dict."""
    kind = kind or detect_kind(name, text)
    if kind == "scoop":
        try:
            doc = json.loads(text.lstrip("\ufeff"), strict=False)  # tolerate raw tabs, as Scoop does
        except ValueError:
            doc = None
        if isinstance(doc, dict):
            units, dls = scoop_units(doc)
            return scan_units(units, dls, "scoop")
        return scan_units(ps_units(text, "hook"), [], "scoop")
    if kind == "winget":
        units, dls = winget_units(text)
        return scan_units(units, dls, "winget")
    if kind == "choco":
        units, dls = choco_units([(name, text)])
        return scan_units(units, dls, "choco")
    return scan_units(ps_units(text, "hook"), [], "ps1")


def scan_choco_package(files):
    """files: [(name, text)] from one .nupkg or package directory."""
    units, dls = choco_units(files)
    return scan_units(units, dls, "choco")


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------
def _fetch(url, binary=False, tries=3):
    headers = dict(UA)
    tok = os.environ.get("GITHUB_TOKEN")
    if tok and "api.github.com" in url:
        headers["Authorization"] = "Bearer " + tok
    for i in range(tries):
        try:
            data = urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=90).read()
            return data if binary else data.decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code in (404, 410):
                break
        except Exception:
            pass
        time.sleep(2 * (i + 1))
    return b"" if binary else ""


def _nupkg_files(blob):
    out, budget = [], ArchiveBudget()
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as z:
            for zi in z.infolist():
                n = safe_member(zi.filename)
                if (n and not zi.is_dir() and n.lower().endswith((".ps1", ".psm1")) and zi.file_size < 4_000_000
                        and budget.take(zi.file_size)):
                    out.append((n, z.read(zi).decode("utf-8-sig", "replace")))
    except (zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError, EOFError, ValueError, OSError):
        pass
    return out


def from_choco(spec):
    pid, _, ver = spec.partition("@")
    # /package/<id> without a version redirects to the latest published .nupkg
    url = "https://community.chocolatey.org/api/v2/package/%s%s" % (urllib.parse.quote(pid), "/" + ver if ver else "")
    blob = _fetch(url, binary=True, tries=4)
    if not blob:
        print("winpkg-audit: could not download Chocolatey package %r (not found, or rate-limited: HTTP 429)" % spec,
              file=sys.stderr)
        return []
    if not ver:
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as z:
                nus = [n for n in z.namelist() if n.lower().endswith(".nuspec")]
                m = re.search(r"<version>([^<]+)</version>", z.read(nus[0]).decode("utf-8", "replace")) if nus else None
                ver = m.group(1) if m else "latest"
        except zipfile.BadZipFile:
            ver = "latest"
    return [("choco:%s@%s" % (pid, ver), ("choco-pkg", _nupkg_files(blob)))]


def from_scoop_bucket(repo):
    blob = _fetch("https://codeload.github.com/%s/tar.gz/HEAD" % repo, binary=True)
    out = []
    if not blob:
        return out
    budget = ArchiveBudget()
    with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as tf:
        for m in tf:
            name = safe_member(m.name)
            if not m.isreg() or not name or not name.endswith(".json") or not budget.take(min(m.size, MAX_READ)):
                continue
            rel = name.split("/", 1)[1] if "/" in name else name
            parts = rel.split("/")
            if not ((len(parts) == 2 and parts[0].lower() == "bucket") or len(parts) == 1):
                continue
            if parts[-1].startswith(".") or parts[-1] in ("package.json", "renovate.json", "tsconfig.json"):
                continue
            f = tf.extractfile(m)
            if f:
                out.append(("%s/%s" % (repo, rel), f.read(MAX_READ).decode("utf-8-sig", "replace")))
    return out


def from_scoop_app(spec):
    if "/" in spec:
        bucket, app = spec.rsplit("/", 1)
        repos = [bucket] if "/" in bucket else ["ScoopInstaller/" + bucket.capitalize()]
    else:
        app, repos = spec, ["ScoopInstaller/Main", "ScoopInstaller/Extras"]
    for repo in repos:
        t = _fetch("https://raw.githubusercontent.com/%s/HEAD/bucket/%s.json" % (repo, app))
        if t.strip().startswith("{"):
            return [("%s/bucket/%s.json" % (repo, app), t)]
    return []


def from_winget(pid):
    parts = pid.split(".")
    path = "manifests/%s/%s" % (pid[0].lower(), "/".join(parts))
    listing = _fetch("https://api.github.com/repos/microsoft/winget-pkgs/contents/" + urllib.parse.quote(path))
    try:
        entries = json.loads(listing)
    except ValueError:
        return []
    vers = [e["name"] for e in entries if isinstance(e, dict) and e.get("type") == "dir"]
    if not vers:
        return []

    def vkey(v):
        return [int(x) if x.isdigit() else x for x in re.split(r"[.\-+]", v)]
    try:
        latest = sorted(vers, key=vkey)[-1]
    except TypeError:
        latest = sorted(vers)[-1]
    name = "%s/%s/%s.installer.yaml" % (path, latest, pid)
    t = _fetch("https://raw.githubusercontent.com/microsoft/winget-pkgs/HEAD/" + urllib.parse.quote(name))
    if not t.strip():
        t = _fetch("https://raw.githubusercontent.com/microsoft/winget-pkgs/HEAD/%s/%s/%s.yaml" % (path, latest, pid))
    return [("winget:%s@%s" % (pid, latest), t)] if t.strip() else []


def _read(p):
    with open(p, "rb") as fh:
        return fh.read(MAX_READ).decode("utf-8-sig", "replace")


def _read_blob(p, cap=200000000):
    with open(p, "rb") as fh:
        return fh.read(cap)


def from_path(p):
    if p == "-":
        return [("<stdin>", sys.stdin.read(MAX_READ))]
    if not os.path.isdir(p) and not os.path.isfile(p):
        raise ValueError("not a regular file: %s" % p)
    if p.lower().endswith(".nupkg"):
        return [(p, ("choco-pkg", _nupkg_files(_read_blob(p))))]
    if not os.path.isdir(p):
        return [(p, _read(p))]
    out = []
    for root, dirs, files in os.walk(p):
        dirs[:] = sorted(d for d in dirs if not d.startswith("."))
        files = [f for f in files if regular_file(os.path.join(root, f))]
        ps = [f for f in files if f.lower().endswith((".ps1", ".psm1"))]
        if any(re.match(r"chocolatey(?:install|uninstall|beforemodify)\.ps1$", f, re.I) for f in ps):
            out.append((root, ("choco-pkg", [(os.path.join(root, f), _read(os.path.join(root, f))) for f in sorted(ps)])))
            ps = []
        for f in sorted(files):
            full = os.path.join(root, f)
            low = f.lower()
            if low.endswith(".nupkg"):
                out.append((full, ("choco-pkg", _nupkg_files(_read_blob(full)))))
            elif low.endswith(".json") and low not in ("package.json", "renovate.json", "tsconfig.json") and not low.startswith("."):
                out.append((full, _read(full)))
            elif low.endswith((".yaml", ".yml")) and (".installer." in low or not (".locale." in low)):
                t = _read(full)
                if re.search(r"^\s*-?\s*InstallerUrl:", t, re.M):
                    out.append((full, t))
            elif f in ps:
                out.append((full, _read(full)))
    return out


def scan_target(label, payload):
    if isinstance(payload, tuple) and payload[0] == "choco-pkg":
        return scan_choco_package(payload[1])
    return scan(payload, label)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


# ---------------------------------------------------------------------------
# Pipeline output shared by the eltociear/*-audit family: --json / --sarif / --fail-on
# (this block is kept identical across the family; see "Output formats" in the README)
# ---------------------------------------------------------------------------
FAMILY_SCHEMA = "eltociear-audit/1"
TOOL_NAME = "winpkg-audit"
TOOL_URI = "https://github.com/eltociear/winpkg-audit"
FAIL_ON_CHOICES = ("critical", "high", "medium", "low", "never")
_FAM_RANK = {"SAFE": 0, "INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
_FAM_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
_FAM_SEC_SEV = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "0.0"}


def family_args(args):
    """Strip the shared output flags from argv. Returns (remaining_args, opts)."""
    opts = {"json": False, "sarif": False, "fail_on": "high"}
    rest, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "--json":
            opts["json"] = True
        elif a == "--sarif":
            opts["sarif"] = True
        elif a == "--fail-on" or a.startswith("--fail-on="):
            if "=" in a:
                v = a.split("=", 1)[1]
            else:
                v = args[i + 1] if i + 1 < len(args) else ""
                i += 1
            if v.lower() not in FAIL_ON_CHOICES:
                sys.stderr.write("%s: --fail-on must be one of %s\n" % (TOOL_NAME, ", ".join(FAIL_ON_CHOICES)))
                raise SystemExit(1)
            opts["fail_on"] = v.lower()
        else:
            rest.append(a)
        i += 1
    return rest, opts


def _fam_sev(s):
    s = str(s or "").upper()
    return s if s in _FAM_RANK else "INFO"


def _fam_line(v):
    try:
        n = int(v)
    except (TypeError, ValueError):
        m = re.search(r"(\d+)\s*$", str(v or ""))
        n = int(m.group(1)) if m else 0
    return n if n > 0 else 0


def family_finding(f, target):
    out = dict(f) if isinstance(f, dict) else {"name": str(f)}
    rid = str(out.get("id") or out.get("rule_id") or out.get("pattern") or "finding")
    out.update({"rule_id": rid, "severity": _fam_sev(out.get("severity")),
                "name": str(out.get("name") or rid), "description": str(out.get("description") or ""),
                "file": str(out.get("file") or out.get("path") or ""), "line": _fam_line(out.get("line")),
                "matched": str(out.get("matched") or ""), "context": str(out.get("context") or "")})
    return out


def family_result(r):
    out = dict(r)
    target = str(out.get("target") or "")
    findings = [family_finding(f, target) for f in (out.get("findings") or [])]
    info = [family_finding(f, target) for f in (out.get("info") or [])]
    worst = max([_FAM_RANK[f["severity"]] for f in findings] + [_FAM_RANK.get(str(out.get("risk_level") or "").upper(), 0)])
    level = next(k for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE") if _FAM_RANK[k] == worst)
    counts = {k: sum(1 for f in findings if f["severity"] == k) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    out.update({"target": target, "risk_level": level, "risk_score": int(out.get("risk_score") or 0),
                "error": out.get("error") or None, "counts": counts, "findings": findings, "info": info})
    return out


def family_exit(results, fail_on="high"):
    """0 = below the threshold, 2 = a target reached it. Default threshold HIGH (the historic behaviour)."""
    if fail_on == "never":
        return 0
    worst = max([_FAM_RANK[family_result(r)["risk_level"]] for r in results] or [0])
    return 2 if worst >= _FAM_RANK[fail_on.upper()] else 0


def family_json(results, fail_on="high"):
    res = [family_result(r) for r in results]
    worst = max([_FAM_RANK[r["risk_level"]] for r in res] or [0])
    return {"schema": FAMILY_SCHEMA, "tool": {"name": TOOL_NAME, "version": __version__},
            "fail_on": fail_on, "exit_code": family_exit(results, fail_on),
            "max_severity": next(k for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE") if _FAM_RANK[k] == worst),
            "errors": sum(1 for r in res if r["error"]), "results": res}


def _fam_uri(target, file):
    """Repo-relative URI when the target is a local path, else the in-package path."""
    file = (file or "").replace("\\", "/")
    t = target or ""
    if t and os.path.isdir(t):
        p = os.path.normpath(os.path.join(t, file)) if file else os.path.normpath(t)
        parts = file.split("/")
        for k in range(1, len(parts)):   # scanner-side prefixes (e.g. custom_components/<d>/) not on disk
            if not os.path.exists(p) and os.path.exists(os.path.join(t, *parts[k:])):
                p = os.path.normpath(os.path.join(t, *parts[k:]))
    elif t and os.path.isfile(t) and (not file or file == t or file == os.path.basename(t)):
        p = os.path.normpath(t)
    elif t and os.path.isfile(t):
        p = os.path.normpath(t).replace("\\", "/") + "/" + file  # member of a local archive
    else:
        p = file or t or "unknown"
    p = p.replace("\\", "/")
    if os.path.isabs(p):
        try:
            rel = os.path.relpath(p)
        except ValueError:
            rel = None
        if rel is not None and not rel.startswith(".."):
            p = rel.replace("\\", "/")
        else:
            return "file://" + urllib.parse.quote(p, safe="/:")
    parts = [s for s in p.split("/") if s not in ("", ".", "..")]
    return urllib.parse.quote("/".join(parts) or "unknown", safe="/@+,;=-._~")


def family_sarif(results):
    rules, index, out, notes = [], {}, [], []
    for r in (family_result(x) for x in results):
        if r["error"]:
            notes.append({"level": "error", "message": {"text": "%s: %s" % (r["target"], r["error"])}})
        for f in r["findings"]:
            sev, rid = f["severity"], f["rule_id"]
            if rid not in index:
                index[rid] = len(rules)
                rules.append({"id": rid, "name": "".join(w.capitalize() for w in re.split(r"[^A-Za-z0-9]+", rid) if w) or "Finding",
                              "shortDescription": {"text": f["name"]},
                              "fullDescription": {"text": f["description"] or f["name"]},
                              "helpUri": TOOL_URI + "#readme",
                              "defaultConfiguration": {"level": _FAM_SARIF_LEVEL[sev]},
                              "properties": {"tags": ["security", TOOL_NAME], "security-severity": _FAM_SEC_SEV[sev]}})
            else:
                rule = rules[index[rid]]
                if float(_FAM_SEC_SEV[sev]) > float(rule["properties"]["security-severity"]):
                    rule["properties"]["security-severity"] = _FAM_SEC_SEV[sev]
                    rule["defaultConfiguration"]["level"] = _FAM_SARIF_LEVEL[sev]
            phys = {"artifactLocation": {"uri": _fam_uri(r["target"], f["file"])}}
            if f["line"]:
                phys["region"] = {"startLine": f["line"]}
                if f["context"]:
                    phys["region"]["snippet"] = {"text": f["context"]}
            msg = "%s: %s%s" % (sev, f["description"] or f["name"], (" [%s]" % f["matched"]) if f["matched"] else "")
            fp = "%s|%s|%s|%s" % (r["target"], rid, f["file"], f["matched"] or f["line"])
            out.append({"ruleId": rid, "ruleIndex": index[rid], "level": _FAM_SARIF_LEVEL[sev],
                        "message": {"text": msg}, "locations": [{"physicalLocation": phys}],
                        "partialFingerprints": {"auditFinding/v1": hashlib.sha256(fp.encode("utf-8", "replace")).hexdigest()[:32]},
                        "properties": {"severity": sev, "target": r["target"]}})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": TOOL_NAME, "version": __version__, "semanticVersion": __version__,
                                          "informationUri": TOOL_URI, "rules": rules}},
                      "invocations": [{"executionSuccessful": not notes, "toolExecutionNotifications": notes}],
                      "results": out}]}


def family_emit(results, opts):
    """Print --json / --sarif output (if requested) and return the process exit code."""
    if opts.get("sarif"):
        print(json.dumps(family_sarif(results), indent=1, ensure_ascii=False))
    elif opts.get("json"):
        print(json.dumps(family_json(results, opts["fail_on"]), indent=1, ensure_ascii=False))
    return family_exit(results, opts["fail_on"])


# ---------------------------------------------------------------------------
# Untrusted-input hygiene shared by the family (nothing is ever extracted to disk)
# ---------------------------------------------------------------------------
MAX_MEMBERS = 50000             # archive entries considered per target
MAX_ARCHIVE_TOTAL = 300000000   # decompressed bytes read per archive (zip/tar bomb budget)


def safe_member(name):
    """Normalise an archive member name; None for traversal (../), absolute, drive or NUL paths."""
    n = (name or "").replace("\\", "/")
    if "\x00" in n or n.startswith("/") or re.match(r"^[A-Za-z]:", n):
        return None
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def regular_file(path):
    """True only for a real regular file (no symlinks, FIFOs, devices or sockets)."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


class ArchiveBudget:
    """Caps entries and total decompressed bytes read from one archive."""

    def __init__(self, total=None, members=None):
        self.left = MAX_ARCHIVE_TOTAL if total is None else total
        self.members = MAX_MEMBERS if members is None else members
        self.truncated = False

    def take(self, size):
        self.members -= 1
        if self.members < 0 or size > self.left:
            self.truncated = True
            return False
        self.left -= size
        return True


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if args[0] == "--version":
        print(TOOL_NAME, __version__)
        return 0
    args, fam = family_args(args)
    quiet = fam["json"] or fam["sarif"]
    flags = {a for a in args if a in ("--all", "--verbose")}
    args = [a for a in args if a not in flags]
    targets, i, local = [], 0, False
    while i < len(args):
        a, nxt = args[i], (args[i + 1] if i + 1 < len(args) else "")
        if a == "--scoop-bucket":
            targets += from_scoop_bucket(nxt); i += 2
        elif a == "--scoop":
            targets += from_scoop_app(nxt); i += 2
        elif a == "--winget":
            targets += from_winget(nxt); i += 2
        elif a == "--choco":
            targets += from_choco(nxt); i += 2
        elif a == "--text":
            targets.append(("<text>", nxt)); i += 2
        elif os.path.exists(a) or a == "-":
            local = True
            try:
                targets += from_path(a)
            except (OSError, ValueError) as e:
                print("winpkg-audit: %s" % e, file=sys.stderr)
            i += 1
        else:
            print("winpkg-audit: %r is not a file/dir; use --scoop, --scoop-bucket, --winget or --choco" % a,
                  file=sys.stderr)
            i += 1
    if not targets:
        print("winpkg-audit: nothing to scan", file=sys.stderr)
        if not local:
            return 1

    results, worst = [], "SAFE"
    tally = dict.fromkeys(("CRITICAL", "HIGH", "MEDIUM", "LOW", "SAFE"), 0)
    for label, payload in targets:
        r = scan_target(label, payload if not isinstance(payload, str) else payload[:800000])
        tally[r["risk_level"]] += 1
        if SEVERITY_RANK[r["risk_level"]] > SEVERITY_RANK[worst]:
            worst = r["risk_level"]
        results.append(dict(target=label, **r))
        if quiet:
            continue
        if r["risk_level"] == "SAFE" and "--all" not in flags and len(targets) > 1:
            continue
        print("%s %s  [%s]  score=%d  (%d findings, %d info)" % (
            _ICON[r["risk_level"]], label, r["risk_level"], r["risk_score"], r["total_findings"], r["info_count"]))
        for f in r["findings"]:
            print("    %-8s %s (%s, %s)" % (f["severity"], f["name"], f["line"], f["context_block"]))
            print("             %s" % f["context"])
        if "--verbose" in flags:
            for f in r["info"]:
                print("    INFO     %s (%s, %s)" % (f["name"], f["line"], f["context_block"]))
    if not quiet:
        print("\nscanned %d: %s" % (len(targets), ", ".join("%d %s" % (v, k) for k, v in tally.items() if v)))
    return family_emit(results, fam)


if __name__ == "__main__":
    sys.exit(main())
