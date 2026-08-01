using System.Management.Automation;
using System.Security.AccessControl;
using System.Security.Principal;

namespace SidAclReplacer;

/// <summary>
/// Remove-AclSid —— 移除 NTFS ACL 中指定 SID 的权限记录。
/// <para>
/// 支持两种模式：
/// <list type="bullet">
///   <item>指定 -TargetSid 移除特定 SID 的所有 ACE</item>
///   <item>指定 -AllUnknownSid 移除所有无法解析为账户名的 SID（孤立 SID）</item>
/// </list>
/// </para>
/// <example>
///   <code>Remove-AclSid -Path C:\Data -TargetSid S-1-5-21-xxx-xxx-xxx-1001 -Recurse</code>
/// </example>
/// <example>
///   <code>Remove-AclSid -Path C:\Data -AllUnknownSid -Recurse -WhatIf</code>
/// </example>
/// </summary>
[Cmdlet("Remove", "AclSid", SupportsShouldProcess = true, DefaultParameterSetName = "ByTargetSid")]
[OutputType(typeof(ReplaceResult))]
public sealed class RemoveSidAclCommand : PSCmdlet
{
    /// <summary>
    /// 目标路径。支持通配符，支持管道输入。
    /// </summary>
    [Parameter(
        Position = 0,
        Mandatory = true,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "ByTargetSid")]
    [Parameter(
        Position = 0,
        Mandatory = true,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "AllUnknown")]
    [Alias("FullName", "PSPath")]
    [ValidateNotNullOrEmpty]
    public string[] Path { get; set; } = Array.Empty<string>();

    /// <summary>
    /// 要移除的 SID。支持 S-1-5-... 格式或 DOMAIN\user 格式。
    /// </summary>
    [Parameter(Mandatory = true, Position = 1, ParameterSetName = "ByTargetSid")]
    [Alias("Sid")]
    public string TargetSid { get; set; } = string.Empty;

    /// <summary>
    /// 移除所有无法被系统解析为账户名的 SID（孤立 SID 清理）。
    /// </summary>
    [Parameter(Mandatory = true, ParameterSetName = "AllUnknown")]
    public SwitchParameter AllUnknownSid { get; set; }

    /// <summary>
    /// 过滤要移除的 ACE 类型。默认同时移除 Allow 和 Deny 两种类型。
    /// </summary>
    [Parameter]
    [ValidateSet("Allow", "Deny")]
    public string[] AccessControlType { get; set; } = new[] { "Allow", "Deny" };

    /// <summary>
    /// 递归处理子目录和文件。
    /// </summary>
    [Parameter]
    public SwitchParameter Recurse { get; set; }

    /// <summary>
    /// 也移除继承的 ACE（默认仅移除显式 ACE）。
    /// </summary>
    [Parameter]
    public SwitchParameter IncludeInherited { get; set; }

    /// <summary>
    /// 不跳过重解析点（默认跳过）。
    /// </summary>
    [Parameter]
    public SwitchParameter FollowReparsePoints { get; set; }

    /// <summary>
    /// 遇到错误时停止（默认继续处理下一个条目）。
    /// </summary>
    [Parameter]
    public SwitchParameter StopOnError { get; set; }

    /// <summary>
    /// 以流式方式输出每个条目的处理结果。
    /// </summary>
    [Parameter]
    public SwitchParameter PassThru { get; set; }

    private AclReplacerService _service = null!;
    private SecurityIdentifier? _targetId;
    private bool _allUnknown;

    protected override void BeginProcessing()
    {
        _allUnknown = AllUnknownSid.IsPresent;

        if (!_allUnknown)
        {
            // 解析目标 SID
            try
            {
                _targetId = SidResolver.Resolve(TargetSid);
            }
            catch (Exception ex)
            {
                ThrowTerminatingError(new ErrorRecord(ex, "InvalidTargetSid", ErrorCategory.InvalidArgument, TargetSid));
                return;
            }
        }

        _service = new AclReplacerService();

        var sidDesc = _allUnknown ? "所有未知 SID" : _targetId!.Value;
        WriteVerbose($"移除模式: {sidDesc}");
        WriteVerbose($"ACE 类型过滤: {string.Join(", ", AccessControlType)}");
        WriteVerbose($"选项: Recurse={Recurse}, IncludeInherited={IncludeInherited}");
    }

    protected override void ProcessRecord()
    {
        foreach (var rawPath in Path)
        {
            // 展开通配符
            IEnumerable<string> resolvedPaths;
            try
            {
                var providerPaths = GetResolvedProviderPathFromPSPath(rawPath, out _);
                resolvedPaths = providerPaths;
            }
            catch (Exception ex)
            {
                WriteError(new ErrorRecord(ex, "PathResolutionFailed", ErrorCategory.ObjectNotFound, rawPath));
                continue;
            }

            foreach (var resolvedPath in resolvedPaths)
            {
                ProcessSinglePath(resolvedPath);
            }
        }
    }

    private void ProcessSinglePath(string path)
    {
        var action = _allUnknown
            ? $"移除所有未知 SID 的 ACE"
            : $"移除 SID {TargetSid} 的所有 ACE";
        var target = path;

        if (!ShouldProcess(target, action))
        {
            // WhatIf 模式：输出模拟结果
            var result = _service.Remove(
                path,
                _targetId,
                _allUnknown,
                includeInherited: IncludeInherited.IsPresent,
                whatIf: true,
                aceTypes: AccessControlType);
            if (PassThru.IsPresent)
                WriteObject(result);
            return;
        }

        if (Recurse.IsPresent)
        {
            foreach (var result in _service.RemoveRecursive(
                path, _targetId, _allUnknown, IncludeInherited.IsPresent,
                FollowReparsePoints.IsPresent, StopOnError.IsPresent,
                PassThru.IsPresent, AccessControlType))
            {
                if (PassThru.IsPresent)
                    WriteObject(result);

                if (!result.Success)
                {
                    WriteWarning(result.ToString());
                    if (StopOnError.IsPresent)
                        return;
                }
                else if (result.DaclAceReplaced > 0)
                {
                    WriteVerbose(result.ToString());
                }
            }
        }
        else
        {
            var result = _service.Remove(
                path, _targetId, _allUnknown,
                includeInherited: IncludeInherited.IsPresent,
                whatIf: false,
                aceTypes: AccessControlType);
            if (PassThru.IsPresent)
                WriteObject(result);

            if (!result.Success)
                WriteWarning(result.ToString());
            else if (result.DaclAceReplaced > 0)
                WriteVerbose(result.ToString());
        }
    }
}