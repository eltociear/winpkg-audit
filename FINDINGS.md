# What we found scanning 117,000 Windows package manifests

This is the research behind `winpkg-audit`: a real scan of the three Windows package ecosystems -
Scoop, winget and Chocolatey - with this exact engine, calibrated so that "clean" means clean
before any number is reported. Sister reports: [homebrew-audit](https://github.com/eltociear/homebrew-audit/blob/main/FINDINGS.md),
[npm-audit](https://github.com/eltociear/npm-audit/blob/main/FINDINGS.md), [mcp-audit](https://github.com/eltociear/mcp-audit/blob/main/FINDINGS.md).

## Corpus (scanned 2026-11-25, repository HEADs of that day)

| Source | Targets | What a target is |
| --- | --- | --- |
| Scoop - 9 official `ScoopInstaller/*` buckets | 6,508 | one app manifest (`bucket/*.json`) |
| Scoop - 49 community buckets (top by stars, `scoop-bucket` topic) | 93,087 | one app manifest |
| winget - `microsoft/winget-pkgs` | 16,502 | latest version of every package (from 400k manifest files) |
| Chocolatey - community repository, top by downloads | 50 | one published `.nupkg` (scripts only) |
| Chocolatey - 8 maintainer source repos on GitHub (incl. `chocolatey-community/chocolatey-packages`) | 1,227 | one package's `tools/*.ps1` |
| **Total** | **117,374** | |

43,988 Scoop manifests (44%) carry install-time PowerShell (`pre_install`, `post_install`,
`installer.script`). Community buckets overlap heavily - several are mirrors or aggregators of
others - so per-pattern counts below also give the number of *distinct apps*.

Chocolatey's package endpoint rate-limited the scan (HTTP 429 on every retry after the first ~50
packages), so the published-package sample is small. The 1,227 GitHub sources cover the
maintainers behind most of the popular community packages, and the scripts there are what gets
packed into the `.nupkg`.

## Method

1. **Tuning half.** Scoop manifests were split by a stable hash. One half (49,318 at the time) plus
   half of winget (8,236) was used to find misfires: every HIGH/CRITICAL hit was read by hand.
2. **Held-out half.** The other 49,891 Scoop manifests and 8,266 winget packages
   (the last 386 Scoop manifests, from buckets that downloaded late, were only in the final full run) were scanned
   once with the tuned engine and reviewed the same way.
3. **Second-source check.** The Chocolatey sets were scanned last.

Misfires found and fixed during tuning (each one is a regression in the code now):

| Misfire | Fix |
| --- | --- |
| `Set-MpPreference -DisableRealtimeMonitoring $false` (re-*enabling* Defender) read as tampering | value `$false`/`0` excluded |
| Downloading a zip and running `7z x <file>` read as fetch-then-run | the file must be the *command*, not an argument |
| `$file = "$dir\dl.7z"` (an assignment) read as running `$file` | assignments excluded |
| `Set-ExecutionPolicy … -Scope 'Process'` (quoted) read as a persistent change | quoted scope accepted |
| `'{0}{1}{2}{3}' -f $a, $b, …` (normal formatting) read as obfuscation | only literal fragments count |
| winget `Dependencies` → `InstallerUrl` read as an unhashed installer | dependency blocks skipped |

The held-out half surfaced **one** more misfire class - an app whose `notes`/config text names
`~/.ssh/id_rsa` in an ssh `IdentityFile` line - fixed by requiring a read primitive
(`Get-Content`, `Copy-Item`, `ReadAllBytes`, …). That manifest also had raw tabs in its JSON, which
Scoop tolerates; the parser now does too.

## Headline

| Source | HIGH / CRITICAL | Rate | Misfires among them |
| --- | --- | --- | --- |
| Scoop official buckets | 6 / 6,508 | 0.09% | 0 |
| winget-pkgs | 0 / 16,502 | 0.00% | 0 |
| Chocolatey top packages | 0 / 50 | 0.00% | 0 |
| `chocolatey-community` sources | 2 / 299 | 0.67% | 0 |
| Other Chocolatey maintainer sources | 10 / 928 | 1.08% | 0 |
| Scoop community buckets | 366 / 93,087 | 0.39% | 0 |

After calibration **every remaining HIGH/CRITICAL is a true pattern match** - the code really does
what the finding says. That does not make every one malicious (see below), but it means a red
result is worth reading. The six official Scoop hits are four `http://` downloads with no hash,
one install script that fetches a `.bat` from a mutable `master` branch and runs it, and one
`Unblock-File` on a module's own files. The two `chocolatey-community` hits are legacy packages
downloading over `http://` with no checksum (Chocolatey refuses those by default unless the user
allows empty checksums, which is a real mitigation).

## The noise: what looks dangerous on Windows but isn't

| Signal | How common | Why it's context |
| --- | --- | --- |
| Install-time scripts at all | 44% of Scoop manifests, ~97% of Chocolatey packages | Shims, context-menu `.reg` files, persist dirs - the normal way these managers work |
| Registry writes | 4,849 Scoop manifests | File associations and app settings |
| Running a vendor installer (`.exe`/`.msi`, Chocolatey helpers) | 71% of winget packages; most Chocolatey packages | This *is* the package |
| `-ExecutionPolicy Bypass` for one child process | 28 Scoop, 4 Chocolatey | Scoped to that process; changes nothing persistent |
| Specific firewall rules (`netsh advfirewall firewall add rule`) | 20 Scoop, 1 Chocolatey | A rule for the app, not the firewall turned off |
| `FromBase64String` alone | 29 Scoop | Decoding config/icons, nothing executed |
| Uninstall scripts deleting Run keys / scheduled tasks | common | Cleanup, not persistence |

A context-blind pass (no comment stripping, every script treated as an install hook, these
capabilities scored) flags 0.42% of Scoop, 1.22% of Chocolatey sources and 4% of the top
Chocolatey packages HIGH or worse; the calibrated engine flags 0.37%, 0.98% and 0%. The gap is
small on purpose: the scored signals were narrow from the start. Most of the work is in keeping
them narrow without missing the real thing.

## What the scan found

Described as patterns, not as accusations. No source is named except the official ones.

**Download-and-run from install hooks (CRITICAL).** 6 distinct Scoop apps (15 manifest copies
across 5 community buckets) run `iex (irm …)` / `Invoke-Expression ((New-Object
Net.WebClient).DownloadString(…))` from `post_install` or `pre_install`. The fetched scripts live on
mutable branches, two of them behind a third-party GitHub proxy and one on a short-link host. The
manifest's hash covers none of it: whoever controls that URL controls what runs on install, with
the installing user's rights. Not seen in any official bucket, winget, or Chocolatey sample.

**Defender exclusions at install (CRITICAL).** 5 distinct Scoop apps (15 copies, 6 community
buckets) add `Add-MpPreference -ExclusionPath/-ExclusionProcess` entries, and one also sets
`-DisableRealtimeMonitoring $true` while it installs. They are licence-activation tools, an RDP
patcher and a utility whose purpose is switching Defender off - software antivirus flags by
design. The exclusions stay behind after the app is gone. Whatever the intent, a package manager
quietly widening AV exclusions is the exact behaviour a dropper would want.

**Mark-of-the-Web stripping (HIGH).** 5 distinct Scoop apps and 9 Chocolatey packages from one
maintainer run `Unblock-File` on what they install. That is the Windows twin of macOS quarantine
stripping (651 casks do it in the homebrew-audit corpus): SmartScreen and Office protected view
never see the files. In every case seen it targets the package's own PowerShell modules, which
otherwise refuse to load - a convenience with a security cost, not an attack.

**Fetch-then-run outside the hash (HIGH).** 4 distinct Scoop apps (18 copies, including one in
an official bucket) download an installer helper from a `master`/`main` branch and execute it.
A further 97 distinct apps fetch extra content at install time with no hash (MEDIUM) - language
packs, `get-pip.py`, a bootstrap `7zr.exe`, HTML-scraped download links.

**Chat-CDN download hosts (HIGH).** 2 distinct Scoop apps download their binary from Discord
attachment URLs - anonymous, unaccountable, and long since expired as links. Both are hash-pinned,
which is the only thing standing between users and whoever re-uploads at that path.

**Plaintext with no hash (HIGH).** 155 distinct Scoop apps (311 manifests, 10 buckets; 4 in
official buckets) and 3 Chocolatey packages download over `http://` with no checksum. Another
1,838 distinct Scoop apps use `http://` but pin a hash (LOW). winget has **zero** unhashed
installers - its schema makes `InstallerSha256` mandatory - and 95 hashed `http://` URLs.

**HTTPS with no hash (MEDIUM).** 1,622 distinct Scoop apps (3,279 manifests, 3.3%; 29 in official
buckets, mostly nightly builds whose bytes change daily) pin nothing. Scoop installs them with a
warning.

**Autostart at install (MEDIUM).** 26 distinct Scoop apps and 9 Chocolatey packages add a Run
key, Startup-folder shortcut or scheduled task while installing. All were apps whose job is to
run in the background (launchers, tray tools, updaters).

**Not found anywhere in 117,374 targets:** credential or browser-profile theft, exfiltration to
webhooks, encoded (`-EncodedCommand` / base64→`iex`) payloads, reverse shells, UAC-bypass registry
hijacks, firewall/UAC/SmartScreen disabled machine-wide, LOLBin downloads (`certutil`,
`bitsadmin`), TLS-validation bypass, hosts-file tampering, shadow-copy deletion, or a persistent
execution-policy downgrade. Each has an inert canary in `tests/canaries/` that fires.

## Takeaways

1. **The official channels are in good shape.** winget's mandatory hashes and Chocolatey's
   moderation show: 0 HIGH+ in 16,502 winget packages, 0 in the top Chocolatey packages, 6 in 6,508
   official Scoop manifests.
2. **Third-party Scoop buckets are where the risk concentrates** - every CRITICAL in the corpus is
   there. Adding a bucket means trusting every future commit to it; scan it first
   (`winpkg_audit.py --scoop-bucket owner/repo`) and again when it updates.
3. **A manifest hash protects the download, not the script.** `iex (irm …)` in `post_install`
   bypasses every checksum the manifest has.
4. **winget's risk is the installer itself.** Its manifests are clean metadata, so the remaining
   trust question is the publisher's binary, which no manifest scanner can answer.

---

Reproduce: `python winpkg_audit.py --scoop-bucket ScoopInstaller/Main`, `--winget <id>`, `--choco <id>`,
or point it at a checkout of any bucket or package repository.

*Findings are pattern matches warranting human review, not verdicts. No bucket, package or
maintainer outside the official repositories is named, and none is accused of anything. Report
suspected malicious manifests to the bucket maintainer, winget-pkgs, or Chocolatey's moderators.*
