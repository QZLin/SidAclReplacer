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
    Write-Host "=== Update-AclSid 测试通过! ===" -ForegroundColor Green
}
else {
    Write-Host "=== Update-AclSid 测试结果: 总替换=$totalReplaced (预期6), 目标ACE=$($aceAfter.Count) (>0), 源ACE=$($aceOld.Count) (0) ===" -ForegroundColor Yellow
    if ($totalReplaced -ne 6) { Write-Warning "替换数量不符合预期" }
    if ($aceOld.Count -ne 0) { Write-Warning "源 SID 的 ACE 仍然存在" }
}

# ---------- Remove-AclSid 测试 ----------
Write-Host ""
Write-Host "=== Remove-AclSid 测试 ===" -ForegroundColor Cyan

# 重新创建测试目录，为 Everyone 和 Authenticated Users 设置 ACL
if (Test-Path $TestRoot) { Remove-Item $TestRoot -Recurse -Force }
New-Item -Path $TestRoot -ItemType Directory -Force | Out-Null
New-Item -Path (Join-Path $TestRoot 'test.txt') -ItemType File -Force | Out-Null

$everyoneId = [System.Security.Principal.SecurityIdentifier]::new($sourceSid)
$authUsersId = [System.Security.Principal.SecurityIdentifier]::new($targetSid)

$acl = Get-Acl $TestRoot
$rule = [System.Security.AccessControl.FileSystemAccessRule]::new($everyoneId, 'Read', 'None', 'None', 'Allow')
$acl.AddAccessRule($rule)
Set-Acl -Path $TestRoot -AclObject $acl

$acl2 = Get-Acl $TestRoot
$rule2 = [System.Security.AccessControl.FileSystemAccessRule]::new($authUsersId, 'Read', 'None', 'None', 'Allow')
$acl2.AddAccessRule($rule2)
Set-Acl -Path $TestRoot -AclObject $acl2

Write-Host "[R1/5] Remove-AclSid -TargetSid -WhatIf" -ForegroundColor Yellow
$r = Remove-AclSid -Path $TestRoot -TargetSid $sourceSid -WhatIf -PassThru
Write-Host "  WhatIf: 移除 $($r.DaclAceReplaced) 个 ACE, 写入: $($r.Written)" -ForegroundColor Gray

Write-Host "[R2/5] Remove-AclSid -TargetSid (实际移除 Everyone)" -ForegroundColor Yellow
$r = Remove-AclSid -Path $TestRoot -TargetSid $sourceSid -PassThru
Write-Host "  结果: 移除 $($r.DaclAceReplaced) 个 ACE, 成功: $($r.Success)"
$rCount = $r.DaclAceReplaced

Write-Host "[R3/5] 验证移除结果" -ForegroundColor Yellow
$aclR = Get-Acl $TestRoot
$everyoneRem = $aclR.Access | Where-Object { try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $sourceSid } catch { $false } }
$authUsersRem = $aclR.Access | Where-Object { try { $_.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value -eq $targetSid } catch { $false } }
Write-Host "  Everyone 残留: $($everyoneRem.Count) (预期 0)"
Write-Host "  Authenticated Users 残留: $($authUsersRem.Count) (预期 1)"

Write-Host "[R4/5] Remove-AclSid -AccessControlType Deny" -ForegroundColor Yellow
$acl3 = Get-Acl $TestRoot
$rule3 = [System.Security.AccessControl.FileSystemAccessRule]::new($everyoneId, 'Write', 'None', 'None', 'Deny')
$acl3.AddAccessRule($rule3)
Set-Acl -Path $TestRoot -AclObject $acl3
$r2 = Remove-AclSid -Path $TestRoot -TargetSid $sourceSid -AccessControlType Deny -PassThru
Write-Host "  移除 Deny 类型: $($r2.DaclAceReplaced) 个 ACE"

Write-Host "[R5/5] Remove-AclSid -AllUnknownSid (WhatIf)" -ForegroundColor Yellow
$r3 = Remove-AclSid -Path $TestRoot -AllUnknownSid -WhatIf -PassThru
Write-Host "  AllUnknownSid WhatIf: 移除 $($r3.DaclAceReplaced) 个 ACE"

# Remove-AclSid 测试结果
$removePass = $rCount -eq 1 -and $everyoneRem.Count -eq 0 -and $authUsersRem.Count -eq 1
if ($removePass) {
    Write-Host "=== Remove-AclSid 测试通过! ===" -ForegroundColor Green
} else {
    Write-Host "=== Remove-AclSid 测试结果: 移除=$rCount (预期1), Everyone残留=$($everyoneRem.Count) (0), AuthUsers残留=$($authUsersRem.Count) (1) ===" -ForegroundColor Yellow
}

# ---------- 清理 ----------
Write-Host ""
Write-Host "清理测试数据..." -ForegroundColor Yellow
Remove-Item $TestRoot -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== 自测完成 ===" -ForegroundColor Green