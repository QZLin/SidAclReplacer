# SidAclReplacer

NTFS ACL SID 替换工具 — 在文件/目录的 ACL 中原地替换安全标识符 (SID)，完整保留 ACE 的所有属性（类型、权限掩码、继承标志、规范顺序）。

## 功能特性

- **SID 替换** — 将 ACL 中所有匹配 `-SourceSid` 的 ACE 替换为 `-TargetSid`
- **DACL / SACL 替换** — 支持替换自由访问控制列表和系统审计列表（SACL 需 `SeSecurityPrivilege`）
- **Owner / Group 替换** — 可选替换对象所有者和主组
- **递归处理** — 深度优先遍历目录树，流式输出结果
- **ACE 结构保留** — 使用 `RawSecurityDescriptor` 在二进制层面原地替换，完整保留：
  - AceType（Allow / Deny / Callback / ...）
  - AccessMask（精确的权限位掩码）
  - AceFlags（继承、传播、审计标志）
  - 规范顺序（Explicit-Deny → Explicit-Allow → Inherited-Deny → Inherited-Allow）
- **多格式 SID 输入** — 支持 S-1-5-... 格式、DOMAIN\user 格式、内置账户名（Everyone、Administrators 等）
- **WhatIf / Confirm** — 支持 PowerShell 的 ShouldProcess，安全预览变更
- **管道输入** — 支持 `Get-ChildItem` 等管道传参
- **双实现** — 提供 C# 编译二进制模块（高性能）和纯 PowerShell 脚本（零依赖）双实现，自动回退

## 系统要求

- Windows 操作系统
- PowerShell 5.1 或 PowerShell 7+
- 修改 ACL 需要 **管理员权限**
- 读取 SACL 需要 `SeSecurityPrivilege` 特权

## 安装

### 方法一：直接加载模块

```powershell
# 克隆或下载项目后，直接导入模块
Import-Module .\module\SidAclReplacer.psd1
```

### 方法二：从源码构建

```powershell
# 需要 .NET SDK（已安装 dotnet 即可）
.\scripts\build.ps1

# 导入构建后的模块
Import-Module .\module\SidAclReplacer.psd1
```

## 快速开始

```powershell
# 以管理员身份运行 PowerShell

# 加载模块
Import-Module .\module\SidAclReplacer.psd1

# 查看命令帮助
Get-Help Update-AclSid

# WhatIf 模式预览（不实际写入）
Update-AclSid -Path C:\Data -SourceSid S-1-5-21-xxx-xxx-xxx-1001 -TargetSid S-1-5-21-xxx-xxx-xxx-2002 -Recurse -WhatIf

# 实际执行替换
Update-AclSid -Path C:\Data -SourceSid S-1-5-21-xxx-xxx-xxx-1001 -TargetSid S-1-5-21-xxx-xxx-xxx-2002 -Recurse

# 使用账户名（通过域解析）
Update-AclSid -Path C:\Data -SourceSid 'OLDDOMAIN\user1' -TargetSid 'NEWDOMAIN\user1' -Recurse

# 管道输入 + 流式输出结果
Get-ChildItem C:\Data -Recurse -File | Update-AclSid -SourceSid 'Everyone' -TargetSid 'S-1-5-11' -PassThru
```

## 参数说明

| 参数 | 类型 | 必需 | 说明 |
| ------ | ------ | ------ | ------ |
| `-Path` | `string[]` | 是 | 目标路径，支持通配符和管道输入 |
| `-SourceSid` | `string` | 是 | 源 SID（要被替换的 SID），支持 S-1-5-... 或 DOMAIN\user |
| `-TargetSid` | `string` | 是 | 目标 SID（替换为的 SID），格式同上 |
| `-Recurse` | `switch` | 否 | 递归处理子目录和文件 |
| `-IncludeInherited` | `switch` | 否 | 也替换继承的 ACE（默认仅替换显式 ACE） |
| `-IncludeAudit` | `switch` | 否 | 也替换 SACL 中的 SID（需 SeSecurityPrivilege） |
| `-ReplaceOwner` | `switch` | 否 | 当 Owner 匹配源 SID 时替换 Owner |
| `-ReplaceGroup` | `switch` | 否 | 当 Group 匹配源 SID 时替换 Group |
| `-FollowReparsePoints` | `switch` | 否 | 递归时跟随重解析点（默认跳过） |
| `-StopOnError` | `switch` | 否 | 遇到第一个错误时停止（默认继续处理） |
| `-PassThru` | `switch` | 否 | 输出每个条目的处理结果对象 |

## 使用示例

### 基本替换

```powershell
# 替换单个文件或目录的 SID
Update-AclSid -Path C:\Target\file.txt -SourceSid S-1-5-21-xxx-xxx-xxx-1001 -TargetSid S-1-5-21-xxx-xxx-xxx-2002
```

### 递归替换

```powershell
# 替换整个目录树中所有 ACL 的 SID
Update-AclSid -Path C:\SharedFolder -SourceSid S-1-5-21-xxx-xxx-xxx-1001 -TargetSid S-1-5-21-xxx-xxx-xxx-2002 -Recurse
```

### 完整替换（Owner + Group + SACL）

```powershell
# 替换 Owner、Group 和审计规则中的 SID
Update-AclSid -Path C:\SharedFolder -SourceSid 'OLDDOMAIN\user1' -TargetSid 'NEWDOMAIN\user1' -Recurse -ReplaceOwner -ReplaceGroup -IncludeAudit
```

### 使用内置账户名

```powershell
# Everyone → Authenticated Users
Update-AclSid -Path C:\Data -SourceSid Everyone -TargetSid 'Authenticated Users' -Recurse
```

### 安全预览

```powershell
# 使用 -WhatIf 预览变更
Update-AclSid -Path C:\Data -SourceSid Everyone -TargetSid 'Authenticated Users' -Recurse -WhatIf -PassThru

# 使用 -Confirm 逐条确认
Update-AclSid -Path C:\Data -SourceSid Everyone -TargetSid 'Authenticated Users' -Recurse -Confirm
```

### 与 Get-ChildItem 配合

```powershell
# 只替换文件（不替换目录）
Get-ChildItem C:\Data -Recurse -File | Update-AclSid -SourceSid Everyone -TargetSid 'Authenticated Users' -PassThru
```

## Remove-AclSid — 移除 SID 权限

```powershell
# 移除特定 SID 的所有 ACE
Remove-AclSid -Path C:\Data -TargetSid S-1-5-21-xxx-xxx-xxx-1001 -Recurse

# 仅移除 Deny 类型的 ACE
Remove-AclSid -Path C:\Data -TargetSid S-1-5-21-xxx-xxx-xxx-1001 -AccessControlType Deny -Recurse

# 移除所有无法解析的 SID（孤立 SID 清理）
Remove-AclSid -Path C:\Data -AllUnknownSid -Recurse

# WhatIf 预览
Remove-AclSid -Path C:\Data -AllUnknownSid -Recurse -WhatIf -PassThru
```

### Remove-AclSid 参数

| 参数 | 类型 | 必需 | 说明 |
|------|------|------|------|
| `-Path` | `string[]` | 是 | 目标路径，支持通配符和管道输入 |
| `-TargetSid` | `string` | 是* | 要移除的 SID（与 `-AllUnknownSid` 二选一） |
| `-AllUnknownSid` | `switch` | 是* | 移除所有无法解析为账户名的 SID（孤立 SID） |
| `-AccessControlType` | `string[]` | 否 | 过滤类型：`Allow` / `Deny`，默认两者 |
| `-Recurse` | `switch` | 否 | 递归处理子目录和文件 |
| `-IncludeInherited` | `switch` | 否 | 也移除继承的 ACE（默认仅移除显式 ACE） |
| `-FollowReparsePoints` | `switch` | 否 | 递归时跟随重解析点（默认跳过） |
| `-StopOnError` | `switch` | 否 | 遇到第一个错误时停止（默认继续处理） |
| `-PassThru` | `switch` | 否 | 输出每个条目的处理结果对象 |

> `*` `-TargetSid` 和 `-AllUnknownSid` 属于不同参数集，必须且只能使用其中一个。

## 输出对象（ReplaceResult）

当使用 `-PassThru` 参数时，每个处理的条目会输出一个 `ReplaceResult` 对象：

| 属性 | 类型 | 说明 |
| ------ | ------ | ------ |
| `Path` | `string` | 处理的路径 |
| `EntryType` | `string` | 路径类型（File / Directory） |
| `Success` | `bool` | 是否成功 |
| `Error` | `string` | 错误信息（失败时） |
| `DaclAceReplaced` | `int` | DACL 中被替换的 ACE 数量 |
| `SaclAceReplaced` | `int` | SACL 中被替换的 ACE 数量 |
| `OwnerReplaced` | `bool` | Owner 是否被替换 |
| `GroupReplaced` | `bool` | Group 是否被替换 |
| `Written` | `bool` | 是否实际写入了磁盘（WhatIf 时为 false） |
| `ElapsedMilliseconds` | `long` | 处理耗时（毫秒） |

## 支持的 SID 输入格式

1. **SDDL SID 字符串**: `S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx`
2. **NT 账户名**: `DOMAIN\user` 或 `user@domain`（UPN 格式）
3. **内置账户名**（大小写不敏感）:
   - `Everyone` / `World`
   - `Authenticated Users` / `AuthenticatedUsers`
   - `System` / `LocalSystem`
   - `Administrators`
   - `Users`
   - `Guests`
   - `NETWORK SERVICE` / `NetworkService`
   - `LOCAL SERVICE` / `LocalService`
   - `CREATOR OWNER` / `CreatorOwner`

## 项目结构

```
SidAclReplacer/
├── src/
│   └── SidAclReplacer/          # C# 源码（二进制模块）
│       ├── AclReplacerService.cs # 核心替换逻辑
│       ├── ReplaceOptions.cs     # 选项配置
│       ├── ReplaceResult.cs      # 结果对象
│       ├── ReplaceSidCommand.cs  # PowerShell cmdlet 实现
│       ├── SidResolver.cs        # SID 解析器
│       └── SidAclReplacer.csproj # 项目文件 (netstandard2.0)
├── module/
│   ├── SidAclReplacer.psd1      # 模块清单
│   ├── SidAclReplacer.psm1      # 模块入口（优先加载 DLL，回退到 PS 脚本）
│   └── SidAclReplacer.dll       # 编译后的二进制模块（由 build.ps1 生成）
├── scripts/
│   ├── Update-AclSid.ps1       # 纯 PowerShell 脚本实现（回退方案）
│   └── build.ps1                # 构建脚本
├── examples/
│   └── demo.ps1                 # 使用示例与自测脚本
├── README.md
└── SidAclReplacer.sln
```

## 工作原理

SidAclReplacer 使用 .NET 的 `RawSecurityDescriptor` / `RawAcl` / `CommonAce` 低层 API，在二进制层面原地替换 ACE 中的 SID 字段：

1. 读取文件/目录的安全描述符为二进制形式
2. 解析为 `RawSecurityDescriptor` 进行低层操作
3. 遍历 DACL（可选 SACL）中的每个 ACE
4. 匹配源 SID 的 ACE，构造新 ACE（仅替换 SID，保留所有其他字段）
5. 通过索引器 `acl[i] = newAce` 原地替换，保证 ACE 顺序不变
6. 序列化回二进制并写回磁盘

**为什么不用高层 API？** `FileSecurity.AddAccessRule()` / `RemoveAccessRule()` 会触发 ACE 重排序，破坏规范顺序（Explicit-Deny → Explicit-Allow → Inherited-Deny → Inherited-Allow）。本工具的低层方法避免了这个问题。

## 常见问题

### 需要管理员权限吗？

是的。修改文件/目录的 ACL 需要管理员权限。请以管理员身份运行 PowerShell。

### 替换后 ACE 顺序会变吗？

不会。工具使用 `RawAcl` 索引器原地替换，ACE 顺序完全保持不变。

### 替换无效怎么办？

使用 `-WhatIf -PassThru` 参数预览变更，确认工具能正确识别需要替换的 ACE。如果系统提示 `SeSecurityPrivilege` 不足，说明当前用户缺少读取 SACL 的权限。

### 支持 PowerShell 5.1 吗？

支持。C# 二进制模块编译为 `netstandard2.0`，兼容 Windows PowerShell 5.1 和 PowerShell 7+。如果 DLL 加载失败，会自动回退到纯 PowerShell 脚本实现。

## 许可证

MIT
