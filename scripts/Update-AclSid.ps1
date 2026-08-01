<#
.SYNOPSIS
    Replace a SID in NTFS file/directory ACLs without breaking the original ACE structure.

.DESCRIPTION
    Update-AclSid walks the ACL (DACL and optionally SACL) of each target file or directory
    and replaces every Access Control Entry (ACE) whose SecurityIdentifier matches -SourceSid
    with a new ACE that uses -TargetSid instead.

    All other ACE properties are preserved byte-for-byte:
      - AceType (Allow / Deny / Callback / ...)
      - AccessMask (the exact rights bitmask)
      - AceFlags (inheritance, propagation, audit flags)
      - IsInherited status
      - Canonical ACE ordering (Explicit-Deny -> Explicit-Allow -> Inherited-Deny -> Inherited-Allow)

    The cmdlet uses the low-level RawSecurityDescriptor / RawAcl / CommonAce API so that
    ACEs are replaced in-place via the indexer (acl[i] = newAce). This avoids the reordering
    side-effect of the high-level FileSystemAccessRule + AddAccessRule/RemoveAccessRule API.

    Owner and Group are NOT touched unless -ReplaceOwner / -ReplaceGroup is specified.

.PARAMETER Path
    Target file or directory path(s). Accepts pipeline input and wildcards.

.PARAMETER SourceSid
    The SID to be replaced. Accepts S-1-5-... string or DOMAIN\user account name.

.PARAMETER TargetSid
    The replacement SID. Accepts S-1-5-... string or DOMAIN\user account name.

.PARAMETER Recurse
    Recursively process all subdirectories and files. Reparse points are skipped by default.

.PARAMETER IncludeInherited
    Also replace inherited ACEs. By default only explicit ACEs are replaced.
    Note: inherited ACEs are normally regenerated from the parent during inheritance
    propagation, so replacing them on a child is only durable if the parent is also
    updated (use -Recurse) or inheritance is broken on the child.

.PARAMETER IncludeAudit
    Also replace SIDs in the SACL (audit rules). Requires SeSecurityPrivilege (admin).

.PARAMETER ReplaceOwner
    Replace the Owner field when it equals the source SID.

.PARAMETER ReplaceGroup
    Replace the Group field when it equals the source SID.

.PARAMETER FollowReparsePoints
    Follow reparse points (symlinks, junctions) during recursion. Default: skip.

.PARAMETER StopOnError
    Stop on the first error instead of continuing to the next entry.

.PARAMETER PassThru
    Output a ReplaceResult object for each processed entry.

.EXAMPLE
    Update-AclSid -Path C:\Data -SourceSid S-1-5-21-100-200-300-1001 -TargetSid S-1-5-21-100-200-300-2002 -Recurse -WhatIf

    Dry-run: show what would be changed without writing.

.EXAMPLE
    Get-ChildItem C:\Data -Recurse | Update-AclSid -SourceSid 'OLDDOMAIN\user1' -TargetSid 'NEWDOMAIN\user1' -PassThru

    Pipeline input, output results for each file.

.EXAMPLE
    Update-AclSid -Path C:\Shared -SourceSid 'S-1-5-21-1-2-3-1001' -TargetSid 'S-1-5-21-1-2-3-2002' -Recurse -ReplaceOwner -ReplaceGroup -IncludeAudit

    Full replacement including owner, group, and audit rules.

.NOTES
    Requires Windows + .NET FileSystemAcl classes.
    Run as Administrator for system directories or to read SACL.
#>
function Update-AclSid {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ByPath')]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Position = 0, Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName, ParameterSetName = 'ByPath')]
        [Alias('FullName', 'PSPath')]
        [ValidateNotNullOrEmpty()]
        [string[]]$Path,

        [Parameter(Mandatory, Position = 1)]
        [Alias('From', 'OldSid')]
        [string]$SourceSid,

        [Parameter(Mandatory, Position = 2)]
        [Alias('To', 'NewSid')]
        [string]$TargetSid,

        [switch]$Recurse,
        [switch]$IncludeInherited,
        [switch]$IncludeAudit,
        [switch]$ReplaceOwner,
        [switch]$ReplaceGroup,
        [switch]$FollowReparsePoints,
        [switch]$StopOnError,
        [switch]$PassThru
    )

    begin {
        # ---------- 加载 ACL 类型 ----------
        $aclTypes = @(
            'System.Security.AccessControl.RawSecurityDescriptor'
            'System.Security.AccessControl.RawAcl'
            'System.Security.AccessControl.CommonAce'
            'System.Security.AccessControl.ObjectCommonAce'
            'System.Security.AccessControl.AceFlags'
            'System.Security.AccessControl.AceType'
            'System.Security.AccessControl.ObjectAceFlags'
            'System.Security.AccessControl.AccessControlSections'
            'System.Security.AccessControl.DirectorySecurity'
            'System.Security.AccessControl.FileSecurity'
            'System.Security.Principal.SecurityIdentifier'
            'System.Security.Principal.NTAccount'
        )
        foreach ($t in $aclTypes) {
            if (-not ($t -as [type])) {
                try {
                    Add-Type -AssemblyName 'System.IO.FileSystem.AccessControl' -ErrorAction Stop
                }
                catch {}
                break
            }
        }

        # ---------- 解析 SID ----------
        function ConvertTo-SecurityIdentifier {
            param([string]$sid_text)
            if ($sid_text -match '^S-1-\d') {
                try {
                    return [System.Security.Principal.SecurityIdentifier]::new($sid_text)
                }
                catch {
                    throw "无法解析 SID 字符串 '$sid_text': $($_.Exception.Message)"
                }
            }
            try {
                $nt = [System.Security.Principal.NTAccount]::new($sid_text)
                return $nt.Translate([System.Security.Principal.SecurityIdentifier])
            }
            catch {
                throw "无法将 '$sid_text' 解析为 SID 或账户名。请使用 S-1-5-... 格式或 DOMAIN\user 格式。"
            }
        }

        try {
            $srcId = ConvertTo-SecurityIdentifier $SourceSid
        }
        catch {
            throw $_
        }
        try {
            $dstId = ConvertTo-SecurityIdentifier $TargetSid
        }
        catch {
            throw $_
        }

        if ($srcId.Value -eq $dstId.Value) {
            throw "源 SID 与目标 SID 相同，无需替换。"
        }

        Write-Verbose "源 SID: $($srcId.Value) ($SourceSid)"
        Write-Verbose "目标 SID: $($dstId.Value) ($TargetSid)"

        # ---------- 核心：在 RawAcl 中原地替换 SID ----------
        function Replace-SidsInRawAcl {
            param(
                [System.Security.AccessControl.RawAcl]$Acl,
                [System.Security.Principal.SecurityIdentifier]$SourceId,
                [System.Security.Principal.SecurityIdentifier]$TargetId,
                [bool]$IncludeInherited
            )
            $changes = 0
            for ($i = 0; $i -lt $Acl.Count; $i++) {
                $ace = $Acl[$i]

                # 跳过继承的 ACE（除非显式要求）
                $isInherited = ($ace.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited) -ne 0
                if (-not $IncludeInherited -and $isInherited) { continue }

                if ($ace -is [System.Security.AccessControl.CommonAce]) {
                    if ($ace.SecurityIdentifier.Value -eq $SourceId.Value) {
                        $newAce = [System.Security.AccessControl.CommonAce]::new(
                            $ace.AceFlags,
                            $ace.AceType,
                            $ace.AccessMask,
                            $TargetId,
                            $ace.IsCallback,
                            $ace.GetOpaque()
                        )
                        $Acl[$i] = $newAce
                        $changes++
                    }
                }
                elseif ($ace -is [System.Security.AccessControl.ObjectCommonAce]) {
                    if ($ace.SecurityIdentifier.Value -eq $SourceId.Value) {
                        $newAce = [System.Security.AccessControl.ObjectCommonAce]::new(
                            $ace.AceFlags,
                            $ace.AceType,
                            $ace.AccessMask,
                            $TargetId,
                            $ace.ObjectAceFlags,
                            $ace.ObjectType,
                            $ace.InheritedObjectAceType,
                            $ace.IsCallback,
                            $ace.GetOpaque()
                        )
                        $Acl[$i] = $newAce
                        $changes++
                    }
                }
            }
            return $changes
        }

        # ---------- 单路径处理 ----------
        function Invoke-SingleReplace {
            param(
                [string]$ResolvedPath,
                [bool]$WhatIfMode
            )
            $sw = [System.Diagnostics.Stopwatch]::StartNew()
            $result = [pscustomobject]@{
                Path                = $ResolvedPath
                EntryType           = ''
                Success             = $false
                Error               = $null
                DaclAceReplaced     = 0
                SaclAceReplaced     = 0
                OwnerReplaced       = $false
                GroupReplaced       = $false
                Written             = $false
                ElapsedMilliseconds = 0
            }

            try {
                $isDir = [System.IO.Directory]::Exists($ResolvedPath)
                $isFile = [System.IO.File]::Exists($ResolvedPath)
                if (-not $isDir -and -not $isFile) {
                    $result.Error = '路径不存在'
                    return $result
                }
                $result.EntryType = if ($isDir) { 'Directory' } else { 'File' }

                # 读取安全描述符
                $sections = [System.Security.AccessControl.AccessControlSections]::Owner `
                    -bor [System.Security.AccessControl.AccessControlSections]::Group `
                    -bor [System.Security.AccessControl.AccessControlSections]::Access
                if ($IncludeAudit) {
                    $sections = $sections -bor [System.Security.AccessControl.AccessControlSections]::Audit
                }

                if ($isDir) {
                    $sd = [System.Security.AccessControl.DirectorySecurity]::new($ResolvedPath, $sections)
                }
                else {
                    $sd = [System.Security.AccessControl.FileSecurity]::new($ResolvedPath, $sections)
                }

                $sdBytes = $sd.GetSecurityDescriptorBinaryForm()
                $rawSd = [System.Security.AccessControl.RawSecurityDescriptor]::new($sdBytes, 0)

                # DACL
                if ($null -ne $rawSd.DiscretionaryAcl) {
                    $result.DaclAceReplaced = Replace-SidsInRawAcl -Acl $rawSd.DiscretionaryAcl -SourceId $srcId -TargetId $dstId -IncludeInherited $IncludeInherited
                }

                # SACL
                if ($IncludeAudit -and $null -ne $rawSd.SystemAcl) {
                    $result.SaclAceReplaced = Replace-SidsInRawAcl -Acl $rawSd.SystemAcl -SourceId $srcId -TargetId $dstId -IncludeInherited $IncludeInherited
                }

                # Owner
                if ($ReplaceOwner -and $null -ne $rawSd.Owner -and $rawSd.Owner.Value -eq $srcId.Value) {
                    $rawSd.Owner = $dstId
                    $result.OwnerReplaced = $true
                }

                # Group
                if ($ReplaceGroup -and $null -ne $rawSd.Group -and $rawSd.Group.Value -eq $srcId.Value) {
                    $rawSd.Group = $dstId
                    $result.GroupReplaced = $true
                }

                $hasChanges = $result.DaclAceReplaced -gt 0 -or $result.SaclAceReplaced -gt 0 -or $result.OwnerReplaced -or $result.GroupReplaced
                if (-not $hasChanges) {
                    $result.Success = $true
                    $result.Written = $false
                    return $result
                }

                if ($WhatIfMode) {
                    $result.Success = $true
                    $result.Written = $false
                    return $result
                }

                # 写回
                $newSdBytes = New-Object byte[] $rawSd.BinaryLength
                $rawSd.GetBinaryForm($newSdBytes, 0)

                if ($isDir) {
                    $newSd = [System.Security.AccessControl.DirectorySecurity]::new()
                    $newSd.SetSecurityDescriptorBinaryForm($newSdBytes)
                    Set-Acl -Path $ResolvedPath -AclObject $newSd
                }
                else {
                    $newSd = [System.Security.AccessControl.FileSecurity]::new()
                    $newSd.SetSecurityDescriptorBinaryForm($newSdBytes)
                    Set-Acl -Path $ResolvedPath -AclObject $newSd
                }

                $result.Success = $true
                $result.Written = $true
            }
            catch [System.Security.AccessControl.PrivilegeNotHeldException] {
                $result.Error = "特权不足（读取 SACL 需要 SeSecurityPrivilege）: $($_.Exception.Message)"
            }
            catch [System.UnauthorizedAccessException] {
                $result.Error = "访问被拒绝（需要管理员权限）: $($_.Exception.Message)"
            }
            catch {
                $result.Error = $_.Exception.Message
            }
            finally {
                $sw.Stop()
                $result.ElapsedMilliseconds = $sw.ElapsedMilliseconds
            }
            return $result
        }

        # ---------- 递归遍历 ----------
        function Invoke-RecursiveReplace {
            param([string]$RootPath, [bool]$WhatIfMode)
            # 根路径
            $r = Invoke-SingleReplace -ResolvedPath $RootPath -WhatIfMode $WhatIfMode
            if ($PassThru) { Write-Output $r }
            if (-not $r.Success) {
                Write-Warning $r.ToString()
                if ($StopOnError) { return }
            }
            elseif ($r.DaclAceReplaced -gt 0 -or $r.SaclAceReplaced -gt 0 -or $r.OwnerReplaced -or $r.GroupReplaced) {
                Write-Verbose $r.ToString()
            }

            if (-not $Recurse) { return }
            if (-not [System.IO.Directory]::Exists($RootPath)) { return }

            $stack = [System.Collections.Generic.Stack[string]]::new()
            $stack.Push($RootPath)

            while ($stack.Count -gt 0) {
                $current = $stack.Pop()

                # 子目录
                $dirs = @()
                try {
                    $dirs = [System.IO.Directory]::EnumerateDirectories($current, '*', [System.IO.SearchOption]::TopDirectoryOnly)
                }
                catch { continue }

                foreach ($dir in $dirs) {
                    if (-not $FollowReparsePoints) {
                        try {
                            $attrs = [System.IO.File]::GetAttributes($dir)
                            if (($attrs -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
                        }
                        catch {}
                    }

                    $r = Invoke-SingleReplace -ResolvedPath $dir -WhatIfMode $WhatIfMode
                    if ($PassThru) { Write-Output $r }
                    if (-not $r.Success) {
                        Write-Warning $r.ToString()
                        if ($StopOnError) { return }
                    }
                    elseif ($r.DaclAceReplaced -gt 0 -or $r.SaclAceReplaced -gt 0 -or $r.OwnerReplaced -or $r.GroupReplaced) {
                        Write-Verbose $r.ToString()
                    }
                    $stack.Push($dir)
                }

                # 文件
                $files = @()
                try {
                    $files = [System.IO.Directory]::EnumerateFiles($current, '*', [System.IO.SearchOption]::TopDirectoryOnly)
                }
                catch { continue }

                foreach ($file in $files) {
                    $r = Invoke-SingleReplace -ResolvedPath $file -WhatIfMode $WhatIfMode
                    if ($PassThru) { Write-Output $r }
                    if (-not $r.Success) {
                        Write-Warning $r.ToString()
                        if ($StopOnError) { return }
                    }
                    elseif ($r.DaclAceReplaced -gt 0 -or $r.SaclAceReplaced -gt 0 -or $r.OwnerReplaced -or $r.GroupReplaced) {
                        Write-Verbose $r.ToString()
                    }
                }
            }
        }
    }

    process {
        foreach ($p in $Path) {
            # 展开通配符
            $resolved = @()
            try {
                $resolved = Resolve-Path -Path $p -ErrorAction Stop | Select-Object -ExpandProperty ProviderPath
            }
            catch {
                Write-Error "无法解析路径 '$p': $($_.Exception.Message)"
                continue
            }

            foreach ($rp in $resolved) {
                $whatIf = -not $PSCmdlet.ShouldProcess($rp, "替换 SID: $SourceSid -> $TargetSid")
                if ($Recurse) {
                    Invoke-RecursiveReplace -RootPath $rp -WhatIfMode $whatIf
                }
                else {
                    $r = Invoke-SingleReplace -ResolvedPath $rp -WhatIfMode $whatIf
                    if ($PassThru) { Write-Output $r }
                    if (-not $r.Success) {
                        Write-Warning $r.ToString()
                    }
                    elseif ($r.DaclAceReplaced -gt 0 -or $r.SaclAceReplaced -gt 0 -or $r.OwnerReplaced -or $r.GroupReplaced) {
                        Write-Verbose $r.ToString()
                    }
                }
            }
        }
    }
}

# 如果直接运行脚本而非 dot-source，支持 -Path 参数调用
# 用法示例：
#   . .\Update-AclSid.ps1
#   Update-AclSid -Path C:\Data -SourceSid S-1-5-21-... -TargetSid S-1-5-21-... -Recurse -WhatIf
