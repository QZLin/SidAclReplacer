namespace SidAclReplacer;

/// <summary>
/// Update-ACL-SID —— NTFS 文件权限 SID 替换 cmdlet。
/// <para>
/// 将文件/目录 ACL 中属于 SourceSid 的 ACE 替换为 TargetSid，
/// 完整保留 ACE 的类型、权限掩码、继承标志和规范顺序。
/// </para>
/// <example>
///   <code>Update-AclSid -Path C:\Data -SourceSid S-1-5-21-100-200-300-1001 -TargetSid S-1-5-21-100-200-300-2002 -Recurse</code>
/// </example>
/// <example>
///   <code>Get-ChildItem C:\Data | Update-AclSid -SourceSid 'OLDDOMAIN\user1' -TargetSid 'NEWDOMAIN\user1' -WhatIf</code>
/// </example>
/// </summary>
[Cmdlet("Update", "AclSid", SupportsShouldProcess = true, DefaultParameterSetName = "ByPath")]
[OutputType(typeof(ReplaceResult))]
public sealed class ReplaceSidAclCommand : PSCmdlet
{
    /// <summary>
    /// 目标路径。支持通配符，支持管道输入。
    /// </summary>
    [Parameter(
        Position = 0,
        Mandatory = true,
        ValueFromPipeline = true,
        ValueFromPipelineByPropertyName = true,
        ParameterSetName = "ByPath")]
    [Alias("FullName", "PSPath")]
    [ValidateNotNullOrEmpty]
    public string[] Path { get; set; } = Array.Empty<string>();

    /// <summary>
    /// 源 SID（要被替换的 SID）。支持 S-1-5-... 格式或 DOMAIN\user 格式。
    /// </summary>
    [Parameter(Mandatory = true, Position = 1)]
    [Alias("From", "OldSid")]
    public string SourceSid { get; set; } = string.Empty;

    /// <summary>
    /// 目标 SID（替换为的 SID）。支持 S-1-5-... 格式或 DOMAIN\user 格式。
    /// </summary>
    [Parameter(Mandatory = true, Position = 2)]
    [Alias("To", "NewSid")]
    public string TargetSid { get; set; } = string.Empty;

    /// <summary>
    /// 递归处理子目录和文件。
    /// </summary>
    [Parameter]
    public SwitchParameter Recurse { get; set; }

    /// <summary>
    /// 也替换继承的 ACE（默认仅替换显式 ACE）。
    /// </summary>
    [Parameter]
    public SwitchParameter IncludeInherited { get; set; }

    /// <summary>
    /// 也替换 SACL（审计规则）中的 SID。需要 SeSecurityPrivilege。
    /// </summary>
    [Parameter]
    public SwitchParameter IncludeAudit { get; set; }

    /// <summary>
    /// 当 Owner 等于源 SID 时，替换 Owner。
    /// </summary>
    [Parameter]
    public SwitchParameter ReplaceOwner { get; set; }

    /// <summary>
    /// 当 Group 等于源 SID 时，替换 Group。
    /// </summary>
    [Parameter]
    public SwitchParameter ReplaceGroup { get; set; }

    /// <summary>
    /// 不跳过重解析点（默认跳过）。
    /// </summary>
    [Parameter]
    public SwitchParameter FollowReparsePoints { get; set; }

    /// <summary>
    /// 遇到错误时继续处理下一个条目（默认开启）。
    /// 使用 -StopOnError 关闭此行为。
    /// </summary>
    [Parameter]
    public SwitchParameter StopOnError { get; set; }

    /// <summary>
    /// 以流式方式输出每个条目的处理结果。
    /// </summary>
    [Parameter]
    public SwitchParameter PassThru { get; set; }

    private AclReplacerService _service = null!;
    private SecurityIdentifier _sourceId = null!;
    private SecurityIdentifier _targetId = null!;
    private ReplaceOptions _options = null!;

    protected override void BeginProcessing()
    {
        // 解析 SID
        try
        {
            _sourceId = SidResolver.Resolve(SourceSid);
        }
        catch (Exception ex)
        {
            ThrowTerminatingError(new ErrorRecord(ex, "InvalidSourceSid", ErrorCategory.InvalidArgument, SourceSid));
            return;
        }

        try
        {
            _targetId = SidResolver.Resolve(TargetSid);
        }
        catch (Exception ex)
        {
            ThrowTerminatingError(new ErrorRecord(ex, "InvalidTargetSid", ErrorCategory.InvalidArgument, TargetSid));
            return;
        }

        if (_sourceId.Equals(_targetId))
        {
            ThrowTerminatingError(new ErrorRecord(
                new ArgumentException("源 SID 与目标 SID 相同，无需替换。"),
                "SameSid", ErrorCategory.InvalidArgument, null));
            return;
        }

        _options = new ReplaceOptions
        {
            Recurse = Recurse.IsPresent,
            IncludeInherited = IncludeInherited.IsPresent,
            IncludeAudit = IncludeAudit.IsPresent,
            ReplaceOwner = ReplaceOwner.IsPresent,
            ReplaceGroup = ReplaceGroup.IsPresent,
            SkipReparsePoints = !FollowReparsePoints.IsPresent,
            ContinueOnError = !StopOnError.IsPresent,
            WhatIf = false, // ShouldProcess 会处理 WhatIf
        };

        _service = new AclReplacerService();

        WriteVerbose($"源 SID: {_sourceId.Value} ({SourceSid})");
        WriteVerbose($"目标 SID: {_targetId.Value} ({TargetSid})");
        WriteVerbose($"选项: Recurse={_options.Recurse}, IncludeInherited={_options.IncludeInherited}, " +
                     $"IncludeAudit={_options.IncludeAudit}, ReplaceOwner={_options.ReplaceOwner}, " +
                     $"ReplaceGroup={_options.ReplaceGroup}");
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
        // ShouldProcess 判断（支持 -WhatIf / -Confirm）
        var action = $"替换 SID: {SourceSid} → {TargetSid}";
        var target = path;

        if (!ShouldProcess(target, action))
        {
            // WhatIf 模式：仍输出模拟结果
            var dryRunOptions = CloneOptions(_options, whatIf: true);
            var result = _service.Replace(path, _sourceId, _targetId, dryRunOptions);
            if (PassThru.IsPresent)
                WriteObject(result);
            continueOnError();
            return;
        }

        // 实际执行
        if (_options.Recurse)
        {
            // 递归：流式输出
            foreach (var result in _service.ReplaceRecursive(path, _sourceId, _targetId, _options))
            {
                if (PassThru.IsPresent)
                    WriteObject(result);

                if (!result.Success)
                {
                    WriteWarning(result.ToString());
                    if (StopOnError.IsPresent)
                        return;
                }
                else if (result.DaclAceReplaced > 0 || result.SaclAceReplaced > 0
                         || result.OwnerReplaced || result.GroupReplaced)
                {
                    WriteVerbose(result.ToString());
                }
            }
        }
        else
        {
            // 单路径
            var result = _service.Replace(path, _sourceId, _targetId, _options);
            if (PassThru.IsPresent)
                WriteObject(result);

            if (!result.Success)
            {
                WriteWarning(result.ToString());
            }
            else if (result.DaclAceReplaced > 0 || result.SaclAceReplaced > 0
                     || result.OwnerReplaced || result.GroupReplaced)
            {
                WriteVerbose(result.ToString());
            }
        }
    }

    private static ReplaceOptions CloneOptions(ReplaceOptions src, bool whatIf)
    {
        return new ReplaceOptions
        {
            Recurse = src.Recurse,
            IncludeInherited = src.IncludeInherited,
            IncludeAudit = src.IncludeAudit,
            ReplaceOwner = src.ReplaceOwner,
            ReplaceGroup = src.ReplaceGroup,
            SkipReparsePoints = src.SkipReparsePoints,
            IgnoreInaccessible = src.IgnoreInaccessible,
            ContinueOnError = src.ContinueOnError,
            WhatIf = whatIf,
        };
    }

    private void continueOnError() { /* placeholder for future hooks */ }
}
