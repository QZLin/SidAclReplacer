<#
.SYNOPSIS
    SidAclReplacer 模块入口。

.DESCRIPTION
    此模块文件优先加载编译好的二进制 DLL（SidAclReplacer.dll），
    如果 DLL 不存在则回退到纯 PowerShell 脚本实现。
    两种实现提供相同的 Update-AclSid 命令。
#>

# 检测 PowerShell 版本
$ps_ver = $PSVersionTable.PS_ver
if (-not $ps_ver) { $ps_ver = 'Desktop' }

# 尝试加载二进制 DLL
$dllName = 'SidAclReplacer.dll'
$moduleDir = $PSScriptRoot
$dllPath = Join-Path $moduleDir $dllName

if (Test-Path $dllPath) {
    try {
        # 加载依赖程序集（netstandard2.0 回退）
        if ($ps_ver -eq 'Core') {
            # PowerShell 7+ 通常已包含 System.IO.FileSystem.AccessControl
            $null = [System.Security.AccessControl.DirectorySecurity]
        }
        else {
            # Windows PowerShell 5.1 需要确保 ACL 程序集已加载
            Add-Type -AssemblyName 'System.IO.FileSystem.AccessControl' -ErrorAction SilentlyContinue
        }

        Import-Module $dllPath -ErrorAction Stop
        return
    }
    catch {
        Write-Warning "加载二进制 DLL 失败，回退到 PowerShell 脚本实现: $($_.Exception.Message)"
    }
}

# 回退：加载纯 PowerShell 脚本
$scriptPath = Join-Path $moduleDir 'Update-AclSid.ps1'
if (-not (Test-Path $scriptPath)) {
    # 尝试从 scripts 目录加载
    $scriptPath = Join-Path (Split-Path $moduleDir -Parent) 'scripts\Update-AclSid.ps1'
}

if (Test-Path $scriptPath) {
    . $scriptPath
}
else {
    throw "无法找到 Update-AclSid 的实现。请确保 SidAclReplacer.dll 或 Update-AclSid.ps1 存在。"
}
