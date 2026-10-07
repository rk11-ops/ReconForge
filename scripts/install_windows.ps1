$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root
python -m venv .venv
& "$Root\.venv\Scripts\python.exe" -m pip install --upgrade pip
& "$Root\.venv\Scripts\python.exe" -m pip install -r "$Root\requirements.txt"
& "$Root\.venv\Scripts\python.exe" -m pip install -e "$Root"
$Bin = Join-Path $env:USERPROFILE "bin"
New-Item -ItemType Directory -Force -Path $Bin | Out-Null
Copy-Item -Force (Join-Path $Root "reconforge.cmd") (Join-Path $Bin "reconforge.cmd")
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$Bin*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$Bin", "User")
}
Write-Host "Installed. Open a new terminal and run: reconforge"
