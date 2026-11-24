$out = "$env:TEMP\helper.exe"
Invoke-WebRequest -Uri 'https://example.invalid/helper.exe' -OutFile $out
Start-Process -FilePath $out -ArgumentList '/quiet' -Wait
