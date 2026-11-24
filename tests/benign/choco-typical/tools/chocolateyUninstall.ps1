Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'App' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'App Updater' -Confirm:$false -ErrorAction SilentlyContinue
