# Build the APT Simulator agent into a single Windows executable.
# Usage:
#   .\packaging\build_agent.ps1
#
# Output: dist\apt-agent.exe
# Notes:
#   - Run from the project root.
#   - The venv must already have dev dependencies installed: pip install -e ".[dev]"
#   - Dev builds are NOT code-signed. Sign separately for production distribution.

$ErrorActionPreference = "Stop"

if (-not (Test-Path ".venv\Scripts\pyinstaller.exe")) {
    Write-Error "PyInstaller not found in .venv. Run: pip install -e \".[dev]\""
}

Write-Host "Building agent binary..."
& .venv\Scripts\pyinstaller.exe packaging\agent.spec --clean --noconfirm
if ($LASTEXITCODE -ne 0) { Write-Error "pyinstaller failed" }

if (Test-Path "dist\apt-agent.exe") {
    $size = (Get-Item "dist\apt-agent.exe").Length / 1MB
    Write-Host ("Build succeeded: dist\apt-agent.exe ({0:N1} MB)" -f $size)
} else {
    Write-Error "Expected output dist\apt-agent.exe not found"
}
