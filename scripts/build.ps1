<#
.SYNOPSIS
    构建 SidAclReplacer 二进制 PowerShell 模块。

.DESCRIPTION
    使用 dotnet 编译 C# 项目，并将输出 DLL 复制到 module 目录。

.PARAMETER Configuration
    构建配置：Debug 或 Release。默认 Release。

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Configuration Debug
#>
[CmdletBinding()]
param(
    [ValidateSet('Debug', 'Release')]
    [string]$Configuration = 'Release'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path $PSScriptRoot -Parent
$projectPath = Join-Path $repoRoot 'src\SidAclReplacer\SidAclReplacer.csproj'
$moduleDir = Join-Path $repoRoot 'module'

Write-Host "=== SidAclReplacer 构建 ===" -ForegroundColor Cyan
Write-Host "项目路径: $projectPath"
Write-Host "构建配置: $Configuration"
Write-Host "输出目录: $moduleDir"
Write-Host ""

# 检查 dotnet
$dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
if (-not $dotnet) {
    throw "未找到 dotnet SDK。请安装 .NET SDK 8.0 或更高版本：https://dotnet.microsoft.com/download"
}

Write-Host "[1/3] 还原依赖..." -ForegroundColor Yellow
& dotnet restore $projectPath
if ($LASTEXITCODE -ne 0) { throw "依赖还原失败。" }

Write-Host "[2/3] 编译项目..." -ForegroundColor Yellow
& dotnet build $projectPath -c $Configuration --no-restore
if ($LASTEXITCODE -ne 0) { throw "编译失败。" }

Write-Host "[3/3] 复制输出到 module 目录..." -ForegroundColor Yellow
$binDir = Join-Path $repoRoot "src\SidAclReplacer\bin\$Configuration\netstandard2.0"
if (-not (Test-Path $binDir)) {
    throw "构建输出目录不存在: $binDir"
}

# 复制 DLL
$dllSource = Join-Path $binDir 'SidAclReplacer.dll'
if (Test-Path $dllSource) {
    Copy-Item $dllSource $moduleDir -Force
    Write-Host "  已复制: SidAclReplacer.dll" -ForegroundColor Green
}

# 复制依赖 DLL（如果有）
Get-ChildItem $binDir -Filter '*.dll' | Where-Object { $_.Name -ne 'SidAclReplacer.dll' } | ForEach-Object {
    # 跳过 PowerShell 标准库（由宿主提供）
    if ($_.Name -match '^System\.Management\.Automation' -or $_.Name -match '^PowerShellStandard') {
        return
    }
    Copy-Item $_.FullName $moduleDir -Force
    Write-Host "  已复制: $($_.Name)" -ForegroundColor Gray
}

# 复制脚本实现
$scriptSource = Join-Path $repoRoot 'scripts\Update-AclSid.ps1'
if (Test-Path $scriptSource) {
    Copy-Item $scriptSource $moduleDir -Force
    Write-Host "  已复制: Update-AclSid.ps1" -ForegroundColor Green
}

Write-Host ""
Write-Host "=== 构建完成 ===" -ForegroundColor Green
Write-Host "模块目录: $moduleDir"
Write-Host ""
Write-Host "使用方法:"
Write-Host "  Import-Module '$moduleDir\SidAclReplacer.psd1'"
Write-Host "  Update-AclSid -Path C:\Data -SourceSid S-1-5-... -TargetSid S-1-5-... -Recurse -WhatIf"
Write-Host "  Remove-AclSid -Path C:\Data -TargetSid S-1-5-... -Recurse"
Write-Host "  Remove-AclSid -Path C:\Data -AllUnknownSid -Recurse -WhatIf"
Write-Host ""
Write-Host "发布到 PowerShell Gallery:"
Write-Host "  Publish-Module -Path '$moduleDir' -NuGetApiKey '<YourApiKey>'"
