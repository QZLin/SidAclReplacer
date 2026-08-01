namespace SidAclReplacer;

/// <summary>
/// 单个路径的 SID 替换结果。
/// </summary>
public sealed class ReplaceResult
{
    /// <summary>处理的路径。</summary>
    public string Path { get; set; } = string.Empty;

    /// <summary>路径类型（File / Directory）。</summary>
    public string EntryType { get; set; } = string.Empty;

    /// <summary>是否成功。</summary>
    public bool Success { get; set; }

    /// <summary>错误信息（失败时）。</summary>
    public string? Error { get; set; }

    /// <summary>DACL 中被替换的 ACE 数量。</summary>
    public int DaclAceReplaced { get; set; }

    /// <summary>SACL 中被替换的 ACE 数量。</summary>
    public int SaclAceReplaced { get; set; }

    /// <summary>Owner 是否被替换。</summary>
    public bool OwnerReplaced { get; set; }

    /// <summary>Group 是否被替换。</summary>
    public bool GroupReplaced { get; set; }

    /// <summary>是否实际写入了磁盘（WhatIf 时为 false）。</summary>
    public bool Written { get; set; }

    /// <summary>处理耗时（毫秒）。</summary>
    public long ElapsedMilliseconds { get; set; }

    public override string ToString()
    {
        var status = Success ? "OK" : "FAIL";
        var parts = new List<string> { $"[{status}] {EntryType}: {Path}" };
        if (DaclAceReplaced > 0) parts.Add($"DACL×{DaclAceReplaced}");
        if (SaclAceReplaced > 0) parts.Add($"SACL×{SaclAceReplaced}");
        if (OwnerReplaced) parts.Add("Owner");
        if (GroupReplaced) parts.Add("Group");
        if (!Written && Success) parts.Add("(dry-run)");
        if (!Success && !string.IsNullOrEmpty(Error)) parts.Add($"→ {Error}");
        return string.Join(" ", parts);
    }
}
