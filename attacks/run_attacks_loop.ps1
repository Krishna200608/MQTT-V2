# CONTINUOUS ATTACK LOOP

$ConfigPath = Join-Path $PSScriptRoot "network_config.json"
$NetConfig = Get-Content $ConfigPath | ConvertFrom-Json

while ($true) {
    Write-Host "`n--- Running Attack Cycle ---" -ForegroundColor Cyan

    & "$PSScriptRoot\scan_A.bat"
    Start-Sleep -Seconds 3

    & "$PSScriptRoot\scan_sU.bat"
    Start-Sleep -Seconds 3

    & "$PSScriptRoot\ssh_bruteforce_nmap.bat"
    Start-Sleep -Seconds 3

    & python "$PSScriptRoot\mqtt_bruteforce.py"
    Start-Sleep -Seconds 5
}
