#Requires -Version 5.1
<#
.SYNOPSIS
    Bootstrap script for LocalSec AI-skills on Windows PowerShell.
    Run from <Project-Root> as:
        .\AI-skills\setup.ps1
    Or to uninstall cleanly:
        .\AI-skills\setup.ps1 --uninstall
#>
$ErrorActionPreference = "Stop"

$SkillDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectRoot = (Get-Location).Path
$SkillFolderName = Split-Path -Leaf $SkillDir
$Mode = if ($args.Count -gt 0) { $args[0] } else { "install" }

if ($SkillDir -eq $ProjectRoot) {
    Write-Host "[!] Bạn đang đứng bên trong thư mục $SkillFolderName." -ForegroundColor Yellow
    Write-Host "    Hãy cd ra thư mục gốc của Project cần áp dụng (<Project-Root>) rồi chạy:"
    Write-Host "    .\$SkillFolderName\setup.ps1"
    exit 1
}

if (Get-Command python -ErrorAction SilentlyContinue) {
    & python "$SkillDir\setup_bootstrap.py" "$SkillDir" "$ProjectRoot" "$SkillFolderName" "$Mode"
    exit $LASTEXITCODE
} elseif (Get-Command py -ErrorAction SilentlyContinue) {
    & py -3 "$SkillDir\setup_bootstrap.py" "$SkillDir" "$ProjectRoot" "$SkillFolderName" "$Mode"
    exit $LASTEXITCODE
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    & python3 "$SkillDir\setup_bootstrap.py" "$SkillDir" "$ProjectRoot" "$SkillFolderName" "$Mode"
    exit $LASTEXITCODE
} else {
    Write-Error "[!] Không tìm thấy Python (`python` hoặc `py -3`). Vui lòng cài đặt Python 3.10+ trên Windows và thêm vào PATH."
    exit 1
}
