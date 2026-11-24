[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
Get-ChocolateyWebFile -PackageName 'x' -FileFullPath "$env:TEMP\x.zip" -Url 'https://example.com/x.zip' -Checksum 'abc'
