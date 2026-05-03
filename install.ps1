# Overtrust Windows Installer
# Downloads latest release from GitHub
# Usage: powershell -c "irm https://raw.githubusercontent.com/cheese-cakee/overtrust/master/install.ps1 | iex"

param(
    [string]$Version = "latest",
    [string]$InstallDir = "$env:LOCALAPPDATA\overtrust"
)

$repo = "cheese-cakee/overtrust"

if ($Version -eq "latest") {
    $url = "https://github.com/$repo/releases/latest/download/overtrust.exe"
} else {
    $url = "https://github.com/$repo/releases/download/$Version/overtrust.exe"
}

Write-Host ":: Installing overtrust..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$dest = "$InstallDir\overtrust.exe"

Write-Host "   Downloading $url" -ForegroundColor Gray
Invoke-WebRequest -Uri $url -OutFile $dest

# Add to user PATH if not already there
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$InstallDir", "User")
    $env:Path += ";$InstallDir"
    Write-Host "   Added to PATH" -ForegroundColor Green
}

Write-Host ":: Done! Run 'overtrust' from any terminal." -ForegroundColor Green
Write-Host "   (Restart your terminal if the command isn't found)" -ForegroundColor Gray
