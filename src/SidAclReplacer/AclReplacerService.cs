namespace SidAclReplacer;

/// <summary>
/// NTFS ACL SID 替换核心服务。
/// <para>
/// 设计原则：<b>不破坏原始结构</b>
/// <list type="bullet">
///   <item>使用 <see cref="RawSecurityDescriptor"/> 在二进制层面原地替换 ACE 的 SID 字段，
///         完整保留 AceType / AccessMask / AceFlags / InheritanceFlags / PropagationFlags。</item>
///   <item>不使用高层 API（FileSystemAccessRule + RemoveAccessRule/AddAccessRule），
///         因为高层 API 会触发 ACE 重排序，破坏规范顺序（Explicit-Deny → Explicit-Allow → Inherited-Deny → Inherited-Allow）。</item>
///   <item>不修改与源 SID 无关的任何 ACE。</item>
///   <item>保留 Owner / Group / 控制标志（SE_DACL_PROTECTED 等）。</item>
/// </list>
/// </para>
/// </summary>
public sealed class AclReplacerService
{
    /// <summary>
    /// 对单个路径执行 SID 替换。
    /// </summary>
    public ReplaceResult Replace(
        string path,
        SecurityIdentifier sourceSid,
        SecurityIdentifier targetSid,
        ReplaceOptions options)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var result = new ReplaceResult { Path = path };

        try
        {
            // 1. 判断路径类型
            bool isDir = Directory.Exists(path);
            bool isFile = File.Exists(path);
            if (!isDir && !isFile)
            {
                result.Success = false;
                result.Error = "路径不存在";
                sw.Stop();
                result.ElapsedMilliseconds = sw.ElapsedMilliseconds;
                return result;
            }
            result.EntryType = isDir ? "Directory" : "File";

            // 2. 读取安全描述符的原始二进制形式
            //    使用 AccessControlSections.All 会尝试读取 SACL（需要 SeSecurityPrivilege）
            var sections = AccessControlSections.Owner
                          | AccessControlSections.Group
                          | AccessControlSections.Access;
            if (options.IncludeAudit)
                sections |= AccessControlSections.Audit;

            byte[] sdBytes;
            if (isDir)
            {
                var ds = new DirectorySecurity(path, sections);
                sdBytes = ds.GetSecurityDescriptorBinaryForm();
            }
            else
            {
                var fs = new FileSecurity(path, sections);
                sdBytes = fs.GetSecurityDescriptorBinaryForm();
            }

            // 3. 解析为 RawSecurityDescriptor 进行低层操作
            var rawSd = new RawSecurityDescriptor(sdBytes, 0);

            // 4. 替换 DACL 中的 SID
            if (rawSd.DiscretionaryAcl != null)
            {
                result.DaclAceReplaced = ReplaceSidsInAcl(
                    rawSd.DiscretionaryAcl, sourceSid, targetSid, options.IncludeInherited);
            }

            // 5. 替换 SACL 中的 SID（审计规则）
            if (options.IncludeAudit && rawSd.SystemAcl != null)
            {
                result.SaclAceReplaced = ReplaceSidsInAcl(
                    rawSd.SystemAcl, sourceSid, targetSid, options.IncludeInherited);
            }

            // 6. 替换 Owner
            if (options.ReplaceOwner
                && rawSd.Owner != null
                && rawSd.Owner.Equals(sourceSid))
            {
                rawSd.Owner = targetSid;
                result.OwnerReplaced = true;
            }

            // 7. 替换 Group
            if (options.ReplaceGroup
                && rawSd.Group != null
                && rawSd.Group.Equals(sourceSid))
            {
                rawSd.Group = targetSid;
                result.GroupReplaced = true;
            }

            // 8. 判断是否有变更
            bool hasChanges = result.DaclAceReplaced > 0
                              || result.SaclAceReplaced > 0
                              || result.OwnerReplaced
                              || result.GroupReplaced;

            if (!hasChanges)
            {
                result.Success = true;
                result.Written = false;
                sw.Stop();
                result.ElapsedMilliseconds = sw.ElapsedMilliseconds;
                return result;
            }

            // 9. WhatIf 模式：不写入
            if (options.WhatIf)
            {
                result.Success = true;
                result.Written = false;
                sw.Stop();
                result.ElapsedMilliseconds = sw.ElapsedMilliseconds;
                return result;
            }

            // 10. 序列化回二进制并应用
            byte[] newSdBytes = new byte[rawSd.BinaryLength];
            rawSd.GetBinaryForm(newSdBytes, 0);

            if (isDir)
            {
                var newDs = new DirectorySecurity();
                newDs.SetSecurityDescriptorBinaryForm(newSdBytes);
                new DirectoryInfo(path).SetAccessControl(newDs);
            }
            else
            {
                var newFs = new FileSecurity();
                newFs.SetSecurityDescriptorBinaryForm(newSdBytes);
                new FileInfo(path).SetAccessControl(newFs);
            }

            result.Success = true;
            result.Written = true;
        }
        catch (PrivilegeNotHeldException ex)
        {
            result.Success = false;
            result.Error = $"特权不足（读取 SACL 需要 SeSecurityPrivilege）：{ex.Message}";
        }
        catch (UnauthorizedAccessException ex)
        {
            result.Success = false;
            result.Error = $"访问被拒绝（需要管理员权限或取得所有权）：{ex.Message}";
        }
        catch (Exception ex)
        {
            result.Success = false;
            result.Error = ex.Message;
        }
        finally
        {
            sw.Stop();
            result.ElapsedMilliseconds = sw.ElapsedMilliseconds;
        }

        return result;
    }

    /// <summary>
    /// 递归遍历目录树并对每个条目执行 SID 替换。
    /// 使用栈式 DFS，不跟随重解析点。
    /// </summary>
    public IEnumerable<ReplaceResult> ReplaceRecursive(
        string rootPath,
        SecurityIdentifier sourceSid,
        SecurityIdentifier targetSid,
        ReplaceOptions options,
        CancellationToken cancellationToken = default)
    {
        // 1. 处理根路径
        yield return Replace(rootPath, sourceSid, targetSid, options);

        if (!options.Recurse)
            yield break;

        if (!Directory.Exists(rootPath))
            yield break;

        // 2. DFS 遍历
        var stack = new Stack<string>();
        stack.Push(rootPath);

        while (stack.Count > 0)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var current = stack.Pop();

            // 子目录
            IEnumerable<string> dirs;
            try
            {
                dirs = Directory.EnumerateDirectories(current, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (DirectoryNotFoundException) { continue; }

            foreach (var dir in dirs)
            {
                cancellationToken.ThrowIfCancellationRequested();

                // 跳过重解析点
                if (options.SkipReparsePoints)
                {
                    try
                    {
                        var attrs = File.GetAttributes(dir);
                        if ((attrs & FileAttributes.ReparsePoint) != 0)
                            continue;
                    }
                    catch { /* 忽略属性读取失败 */ }
                }

                var r = Replace(dir, sourceSid, targetSid, options);
                yield return r;

                if (!r.Success && !options.ContinueOnError)
                    yield break;

                stack.Push(dir);
            }

            // 文件
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(current, "*", SearchOption.TopDirectoryOnly);
            }
            catch (UnauthorizedAccessException) { continue; }
            catch (DirectoryNotFoundException) { continue; }

            foreach (var file in files)
            {
                cancellationToken.ThrowIfCancellationRequested();

                var r = Replace(file, sourceSid, targetSid, options);
                yield return r;

                if (!r.Success && !options.ContinueOnError)
                    yield break;
            }
        }
    }

    /// <summary>
    /// 在 RawAcl 中原地替换所有匹配 sourceSid 的 ACE。
    /// 使用索引器赋值（acl[i] = newAce）保证 ACE 顺序不变。
    /// </summary>
    private static int ReplaceSidsInAcl(
        RawAcl acl,
        SecurityIdentifier sourceSid,
        SecurityIdentifier targetSid,
        bool includeInherited)
    {
        int changes = 0;

        for (int i = 0; i < acl.Count; i++)
        {
            var ace = acl[i];

            // 跳过继承的 ACE（除非显式要求）
            if (!includeInherited && (ace.AceFlags & AceFlags.Inherited) != 0)
                continue;

            switch (ace)
            {
                case CommonAce common when common.SecurityIdentifier.Equals(sourceSid):
                    {
                        // 构造新的 CommonAce，保留所有字段，仅替换 SID
                        var newAce = new CommonAce(
                            common.AceFlags,
                            (AceQualifier)(byte)common.AceType,
                            common.AccessMask,
                            targetSid,
                            common.IsCallback,
                            common.GetOpaque());
                        acl[i] = newAce;
                        changes++;
                        break;
                    }

                case ObjectAce obj when obj.SecurityIdentifier.Equals(sourceSid):
                    {
                        // 对象 ACE（含 ObjectAceType / InheritedObjectAceType GUID）
                        var newAce = new ObjectAce(
                            obj.AceFlags,
                            (AceQualifier)(byte)obj.AceType,
                            obj.AccessMask,
                            targetSid,
                            obj.ObjectAceFlags,
                            obj.ObjectAceType,
                            obj.InheritedObjectAceType,
                            obj.IsCallback,
                            obj.GetOpaque());
                        acl[i] = newAce;
                        changes++;
                        break;
                    }

                // 其他 ACE 类型（如 CompoundAce / CustomAce）暂不处理
            }
        }

        return changes;
    }
}
