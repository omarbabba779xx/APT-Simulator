param(
    [string]$ServiceName = "AptSimulatorAgent",
    [string]$DisplayName = "APT Simulator Agent",
    [string]$BinaryPath = "$PSScriptRoot\..\..\dist\apt-agent.exe",
    [string]$ConfigPath = "$PSScriptRoot\..\..\config\default.yaml"
)

$resolvedBinary = Resolve-Path -LiteralPath $BinaryPath -ErrorAction Stop
$resolvedConfig = Resolve-Path -LiteralPath $ConfigPath -ErrorAction Stop
$binPath = "`"$resolvedBinary`" beacon --config `"$resolvedConfig`""

if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -ErrorAction SilentlyContinue
    sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

New-Service `
    -Name $ServiceName `
    -DisplayName $DisplayName `
    -BinaryPathName $binPath `
    -StartupType Manual `
    -Description "Lab-scoped APT Simulator beacon agent"

Write-Host "Installed $ServiceName with manual startup."
