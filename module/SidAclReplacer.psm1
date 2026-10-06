<#
.SYNOPSIS
    SidAclReplacer 模块入口。

.DESCRIPTION
    此模块文件优先加载编译好的二进制 DLL（SidAclReplacer.dll），
    如果 DLL 不存在或加载失败则回退到纯 PowerShell 脚本实现。
    两种实现均提供 Update-AclSid 和 Remove-AclSid 两个命令。
#>

# 检测 PowerShell 版本
$psEdition = if ($PSVersionTable.PSEdition) { $PSVersionTable.PSEdition } else { 'Desktop' }

# 尝试加载二进制 DLL
$moduleDir = $PSScriptRoot
$dllPath = Join-Path $moduleDir 'SidAclReplacer.dll'

if (Test-Path $dllPath) {
    try {
        # 预加载依赖程序集
        if ($psEdition -eq 'Core') {
            # PowerShell 7+：System.IO.FileSystem.AccessControl 已内置
            $null = [System.Security.AccessControl.DirectorySecurity] -as [type]
        } else {
            # Windows PowerShell 5.1：加载依赖 DLL
            $dependencyDlls = @(
                'System.IO.FileSystem.AccessControl.dll',
                'System.Security.AccessControl.dll',
                'System.Security.Principal.Windows.dll'
            )
            foreach ($depDll in $dependencyDlls) {
                $depPath = Join-Path $moduleDir $depDll
                if (Test-Path $depPath) {
                    [System.Reflection.Assembly]::LoadFrom($depPath) | Out-Null
                }
            }
        }

        Import-Module $dllPath -ErrorAction Stop
        return
    }
    catch {
        Write-Warning "加载二进制 DLL 失败，回退到 PowerShell 脚本实现：$($_.Exception.Message)"
    }
}

# 回退：加载纯 PowerShell 脚本
$scriptPath = Join-Path $moduleDir 'Update-AclSid.ps1'
if (Test-Path $scriptPath) {
    . $scriptPath
}
else {
    throw "无法找到模块实现。请确保 SidAclReplacer.dll 或 Update-AclSid.ps1 存在于模块目录中。"
}