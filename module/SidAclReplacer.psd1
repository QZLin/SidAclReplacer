@{
    # 模块清单
    RootModule             = 'SidAclReplacer.psm1'
    ModuleVersion          = '1.0.0'
    GUID                   = 'b3c4d5e6-f7a8-9012-bcde-f12345678901'
    Author                 = 'SidAclReplacer'
    CompanyName            = 'SidAclReplacer'
    Description            = 'NTFS ACL SID replacement tool — replaces a SID in file/directory ACLs without breaking the original ACE structure (preserves AceType, AccessMask, inheritance flags, and canonical ordering).'
    PowerShellVersion      = '5.1'
    CLRVersion             = '4.0'
    DotNetFrameworkVersion = '4.6.1'

    # 兼容的 PowerShell 版本
    CompatiblePSEditions   = @('Desktop', 'Core')

    # 导出的函数
    FunctionsToExport      = @('Update-AclSid', 'Remove-AclSid')

    # 导出的 cmdlet（二进制模块时使用）
    CmdletsToExport        = @('Update-AclSid', 'Remove-AclSid')

    # 导出的别名
    AliasesToExport        = @()

    # 导出的变量
    VariablesToExport      = @()

    # 模块依赖
    RequiredModules        = @()

    # 所需程序集
    RequiredAssemblies     = @()

    # 私有数据
    PrivateData            = @{
        PSData = @{
            Tags         = @('NTFS', 'ACL', 'SID', 'Security', 'Permissions', 'Migration')
            LicenseUri   = ''
            ProjectUri   = ''
            ReleaseNotes = @'
v1.0.0
  - 初始版本
  - 支持单路径和递归 SID 替换
  - 使用 RawSecurityDescriptor 原地替换 ACE，保留完整结构
  - 支持 DACL / SACL / Owner / Group
  - 支持 WhatIf / Confirm
  - 提供 C# 二进制模块和纯 PowerShell 脚本双实现
'@
        }
    }

    # 帮助信息 URI
    HelpInfoURI            = ''
}
