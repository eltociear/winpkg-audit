$ErrorActionPreference = 'Stop'
$toolsDir = "$(Split-Path -parent $MyInvocation.MyCommand.Definition)"
$packageArgs = @{
  packageName    = $env:ChocolateyPackageName
  fileType       = 'exe'
  url64bit       = 'https://example.org/app-setup-x64.exe'
  checksum64     = '4444444444444444444444444444444444444444444444444444444444444444'
  checksumType64 = 'sha256'
  silentArgs     = '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-'
  validExitCodes = @(0)
}
Install-ChocolateyPackage @packageArgs
Install-ChocolateyPath "$env:ProgramFiles\App\bin" 'Machine'
# Unblock-File is mentioned only in this comment
<# netsh advfirewall set allprofiles state off  (documentation, not executed) #>
New-NetFirewallRule -DisplayName 'App' -Direction Inbound -Program "$env:ProgramFiles\App\app.exe" -Action Allow | Out-Null
Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -File "$toolsDir\helper.ps1"' -Wait
