@{
    # 模块清单
    RootModule             = 'SidAclReplacer.psm1'
    ModuleVersion          = '1.0.0'
    GUID                   = 'b3c4d5e6-f7a8-9012-bcde-f12345678901'
    Author                 = 'SidAclReplacer'
    CompanyName            = ''
    Copyright              = '(c) 2026 SidAclReplacer. All rights reserved.'
    Description            = 'NTFS ACL SID 管理工具 — 在文件/目录的 DACL 中替换或移除 SID，完整保留 ACE 类型、权限掩码、继承标志和规范顺序。提供 Update-AclSid（替换）和 Remove-AclSid（移除）两个命令。'

    PowerShellVersion      = '5.1'
    CLRVersion             = '4.0'
    DotNetFrameworkVersion = '4.6.1'

    # 兼容的 PowerShell 版本
    CompatiblePSEditions   = @('Desktop', 'Core')

    # 导出的函数 / cmdlet
    FunctionsToExport      = @('Update-AclSid', 'Remove-AclSid')
    CmdletsToExport        = @('Update-AclSid', 'Remove-AclSid')
    AliasesToExport        = @()
    VariablesToExport      = @()

    # 模块依赖
    RequiredModules        = @()
    RequiredAssemblies     = @()

    # 文件列表（构建后生成）
    FileList = @(
        'SidAclReplacer.dll'
        'SidAclReplacer.psd1'
        'SidAclReplacer.psm1'
        'Update-AclSid.ps1'
        'System.IO.FileSystem.AccessControl.dll'
        'System.Security.AccessControl.dll'
        'System.Security.Principal.Windows.dll'
        'System.Buffers.dll'
        'System.Memory.dll'
        'System.Numerics.Vectors.dll'
        'System.Runtime.CompilerServices.Unsafe.dll'
    )

    # 私有数据
    PrivateData            = @{
        PSData = @{
            Tags         = @('NTFS', 'ACL', 'SID', 'Security', 'Permissions', 'Migration', 'AccessControl', 'Windows', 'FileSystem')
            LicenseUri   = 'https://github.com/USER/SidAclReplacer/blob/main/LICENSE'
            ProjectUri   = 'https://github.com/USER/SidAclReplacer'
            IconUri      = ''
            ReleaseNotes = @'
v1.0.0

SidAclReplacer — NTFS ACL SID 管理工具

功能：
  - Update-AclSid: 将 ACL 中匹配的 SID 替换为新 SID，保留 ACE 完整结构
  - Remove-AclSid: 移除 ACL 中指定 SID 的所有权限记录，支持孤立 SID 清理

Update-AclSid 特性：
  - 支持 DACL / SACL / Owner / Group 替换
  - 使用 RawSecurityDescriptor 低层 API 原地替换，不破坏 ACE 规范顺序
  - 递归处理目录树，流式输出结果
  - WhatIf / Confirm 安全模式

Remove-AclSid 特性：
  - 按 -TargetSid 移除特定 SID 的权限记录
  - 按 -AllUnknownSid 清理所有无法解析的孤立 SID
  - 按 -AccessControlType 过滤 Allow / Deny 类型
  - 不处理 Owner/Group，专注 DACL 清理

技术栈：
  - C# 二进制 PowerShell 模块（netstandard2.0，兼容 PS 5.1 和 PS 7+）
  - 纯 PowerShell 脚本回退实现（零依赖）
  - 双实现自动切换，DLL 加载失败时无缝回退
'@
        }
    }

    # 帮助信息 URI
    HelpInfoURI            = ''
}