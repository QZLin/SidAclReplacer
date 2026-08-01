namespace SidAclReplacer;

/// <summary>
/// SID 替换操作的选项配置。
/// </summary>
public sealed class ReplaceOptions
{
    /// <summary>
    /// 是否递归处理子目录和文件。默认 false。
    /// </summary>
    public bool Recurse { get; set; }

    /// <summary>
    /// 是否也替换继承的 ACE（Inherited ACE）。
    /// 默认 false —— 仅替换显式 ACE。
    /// 注意：继承的 ACE 通常由父对象传播，若父对象未修改，则替换后的继承 ACE
    /// 可能会在下次继承传播时被覆盖。建议配合 -Recurse 使用。
    /// </summary>
    public bool IncludeInherited { get; set; }

    /// <summary>
    /// 是否也替换 SACL（审计规则）中的 SID。
    /// 默认 false。读取/修改 SACL 需要 SeSecurityPrivilege 特权。
    /// </summary>
    public bool IncludeAudit { get; set; }

    /// <summary>
    /// 是否替换所有者（Owner），当 Owner SID 等于源 SID 时。
    /// 默认 false。
    /// </summary>
    public bool ReplaceOwner { get; set; }

    /// <summary>
    /// 是否替换主组（Group），当 Group SID 等于源 SID 时。
    /// 默认 false。
    /// </summary>
    public bool ReplaceGroup { get; set; }

    /// <summary>
    /// 是否跳过重解析点（符号链接、目录联接）。
    /// 默认 true —— 递归时不跟随重解析点，避免循环。
    /// </summary>
    public bool SkipReparsePoints { get; set; } = true;

    /// <summary>
    /// 是否跳过不可访问的文件/目录（静默跳过，不抛异常）。
    /// 默认 true。
    /// </summary>
    public bool IgnoreInaccessible { get; set; } = true;

    /// <summary>
    /// 遇到错误时是否继续处理下一个条目。
    /// 默认 true。
    /// </summary>
    public bool ContinueOnError { get; set; } = true;

    /// <summary>
    /// WhatIf 模式：仅模拟，不实际写入。
    /// </summary>
    public bool WhatIf { get; set; }
}
