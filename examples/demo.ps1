<#
.SYNOPSIS
    SidAclReplacer 使用示例与自测脚本。

.DESCRIPTION
    本脚本演示 Update-AclSid 的典型用法，并包含一个本地自测流程：
    1. 创建临时测试目录和文件
    2. 使用 RawSecurityDescriptor 为源 SID 设置 ACL
    3. 执行 SID 替换
    4. 验证替换结果
    5. 清理测试数据

    注意：此脚本必须在 Windows 上以管理员权限运行。
#>

[CmdletBinding()]
param(
    [string]$TestRoot = (Join-Path $env:TEMP 'SidAclReplacer_Test')
)

$ErrorActionPreference = 'Stop'

# 加载模块
$moduleDir = Split-Path $PSScriptRoot -Parent
$manifest = Join-Path $moduleDir 'module\SidAclReplacer.psd1'
if (-not (Test-Path $manifest)) {
    . (Join-Path $moduleDir 'scripts\Update-AclSid.ps1')
}
else {
    Import-Module $manifest -Force
}

Write-Host "=== SidAclReplacer 自测 ===" -ForegroundColor Cyan

# ---------- 准备测试 SID ----------
# 使用 Everyone 和 Authenticated Users 作为测试 SID（系统已知 SID，可安全操作）
$sourceSid = 'S-1-1-0'      # Everyone
$targetSid = 'S-1-5-11'     # Authenticated Users

Write-Host "源 SID (Everyone): $sourceSid"
Write-Host "目标 SID (Authenticated Users): $targetSid"
Write-Host ""

# ---------- 创建测试目录结构 ----------
Write-Host "[1/5] 创建测试目录结构..." -ForegroundColor Yellow

if (Test-Path $TestRoot) {
    Remove-Item $TestRoot -Recurse -Force
}
New-Item -Path $TestRoot -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $TestRoot 'SubDir1') -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $TestRoot 'SubDir2') -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $TestRoot 'SubDir1\file1.txt') -ItemType File -Force | Out-Null
New-Item -Path (Join-Path $TestRoot 'SubDir2\file2.txt') -ItemType File -Force | Out-Null
New-Item -Path (Join-Path $TestRoot 'root.txt') -ItemType File -Force | Out-Null

Write-Host "  测试目录: $TestRoot"

# ---------- 为源 SID 设置 ACL ----------
Write-Host "[2/5] 为源 SID 设置 ACL..." -ForegroundColor Yellow

$srcId = [System.Security.Principal.SecurityIdentifier]::new($sourceSid)

foreach ($p in @(
        $TestRoot,
        (Join-Path $TestRoot 'SubDir1'),
        (Join-Path $TestRoot 'SubDir2'),
        (Join-Path $TestRoot 'SubDir1\file1.txt'),
        (Join-Path $TestRoot 'SubDir2\file2.txt'),
        (Join-Path $TestRoot 'root.txt')
    )) {
    $isDir = [System.IO.Directory]::Exists($p)
    $acl = Get-Acl $p

    if ($isDir) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $srcId,
            [System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::Write,
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
    }
    else {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $srcId,
            [System.Security.AccessControl.FileSystemRights]::Read -bor [System.Security.AccessControl.FileSystemRights]::Write,
            [System.Security.AccessControl.InheritanceFlags]::None,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
    }
    $acl.AddAccessRule($rule)
    Set-Acl -Path $p -AclObject $acl
}

Write-Host "  已为 6 个条目设置源 SID 的 ACL（Everyone -> Read+Write）"

# ---------- 验证替换前 ----------
Write-Host "[3/5] 验证替换前的 ACL..." -ForegroundColor Yellow

$aclBefore = Get-Acl $TestRoot
$aceBefore = $aclBefore.Access | Where-Object {
    try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $sourceSid } catch { $false }
}
Write-Host "  根目录中 Everyone (S-1-1-0) 的 ACE 数量: $($aceBefore.Count)"

# ---------- 执行替换 ----------
Write-Host "[4/5] 执行 SID 替换（WhatIf 模式）..." -ForegroundColor Yellow

$results = Update-AclSid -Path $TestRoot -SourceSid $sourceSid -TargetSid $targetSid -Recurse -PassThru -WhatIf
Write-Host "  WhatIf 模式结果:"
$results | ForEach-Object {
    Write-Host "    $($_.EntryType): $($_.Path) — DACL ACE 替换: $($_.DaclAceReplaced), 写入: $($_.Written)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "[4.5/5] 执行实际替换..." -ForegroundColor Yellow

$results = Update-AclSid -Path $TestRoot -SourceSid $sourceSid -TargetSid $targetSid -Recurse -PassThru -Verbose
$totalReplaced = ($results | Measure-Object -Property DaclAceReplaced -Sum).Sum
Write-Host "  实际替换完成，共替换 $totalReplaced 个 ACE"

# ---------- 验证替换后 ----------
Write-Host "[5/5] 验证替换后的 ACL..." -ForegroundColor Yellow

$aclAfter = Get-Acl $TestRoot
$aceAfter = $aclAfter.Access | Where-Object {
    try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $targetSid } catch { $false }
}
$aceOld = $aclAfter.Access | Where-Object {
    try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $sourceSid } catch { $false }
}

Write-Host "  根目录中 Authenticated Users (S-1-5-11) 的 ACE 数量: $($aceAfter.Count)"
Write-Host "  根目录中 Everyone (S-1-1-0) 的 ACE 数量: $($aceOld.Count)"

# 验证权限保留
if ($aceAfter.Count -gt 0) {
    $firstAce = $aceAfter[0]
    Write-Host "  替换后 ACE 的权限: $($firstAce.FileSystemRights)"
    Write-Host "  替换后 ACE 的类型: $($firstAce.AccessControlType)"
    Write-Host "  替换后 ACE 的继承: $($firstAce.InheritanceFlags)"
}

# ---------- 测试结果判断 ----------
Write-Host ""
if ($totalReplaced -eq 6 -and $aceAfter.Count -gt 0 -and $aceOld.Count -eq 0) {
    Write-Host "=== 所有测试通过! ===" -ForegroundColor Green
}
else {
    Write-Host "=== 测试结果: 总替换=$totalReplaced (预期6), 目标ACE=$($aceAfter.Count) (>0), 源ACE=$($aceOld.Count) (0) ===" -ForegroundColor Yellow
    if ($totalReplaced -ne 6) { Write-Warning "替换数量不符合预期" }
    if ($aceOld.Count -ne 0) { Write-Warning "源 SID 的 ACE 仍然存在" }
}

# ---------- 清理 ----------
Write-Host ""
Write-Host "清理测试数据..." -ForegroundColor Yellow
Remove-Item $TestRoot -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== 自测完成 ===" -ForegroundColor Green