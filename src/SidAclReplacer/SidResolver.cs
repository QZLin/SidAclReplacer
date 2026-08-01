namespace SidAclReplacer;

/// <summary>
/// 将用户输入（SID 字符串或 DOMAIN\user）解析为 <see cref="SecurityIdentifier"/>。
/// </summary>
internal static class SidResolver
{
    /// <summary>
    /// 解析输入字符串为 SecurityIdentifier。
    /// 支持的输入格式：
    ///   1. SDDL SID 字符串：S-1-5-21-xxxxxxxxxx-xxxxxxxxxx-xxxxxxxxxx-xxxx
    ///   2. NT 账户名：DOMAIN\user 或 user@domain (UPN)
    ///   3. 已知的内置账户：Everyone, Administrators, Users 等（英文，大小写不敏感）
    /// </summary>
    public static SecurityIdentifier Resolve(string input)
    {
        if (string.IsNullOrWhiteSpace(input))
            throw new ArgumentException("SID 或账户名不能为空。", nameof(input));

        input = input.Trim();

        // 1. 尝试直接作为 SID 字符串解析
        if (input.StartsWith("S-1-", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                return new SecurityIdentifier(input);
            }
            catch (ArgumentException ex)
            {
                throw new ArgumentException($"无法解析 SID 字符串 '{input}'：{ex.Message}", ex);
            }
        }

        // 2. 尝试作为 NT 账户名解析 (DOMAIN\user 或 user@domain)
        try
        {
            var ntAccount = new NTAccount(input);
            return (SecurityIdentifier)ntAccount.Translate(typeof(SecurityIdentifier));
        }
        catch (IdentityNotMappedException)
        {
            // 继续尝试内置账户
        }

        // 3. 尝试已知的内置账户（WellKnownSidType）
        var known = TryResolveWellKnown(input);
        if (known != null)
            return known;

        throw new ArgumentException(
            $"无法将 '{input}' 解析为有效的 SID 或账户名。" +
            "请使用 S-1-5-... 格式的 SID 字符串，或 DOMAIN\\user 格式的账户名。",
            nameof(input));
    }

    /// <summary>
    /// 尝试将英文名称映射到 WellKnownSidType。
    /// </summary>
    private static SecurityIdentifier? TryResolveWellKnown(string name)
    {
        // 大小写不敏感匹配
        var map = new Dictionary<string, WellKnownSidType>(StringComparer.OrdinalIgnoreCase)
        {
            ["Everyone"]          = WellKnownSidType.WorldSid,
            ["World"]             = WellKnownSidType.WorldSid,
            ["Authenticated Users"] = WellKnownSidType.AuthenticatedUserSid,
            ["AuthenticatedUsers"]  = WellKnownSidType.AuthenticatedUserSid,
            ["System"]            = WellKnownSidType.LocalSystemSid,
            ["LocalSystem"]       = WellKnownSidType.LocalSystemSid,
            ["Administrators"]    = WellKnownSidType.BuiltinAdministratorsSid,
            ["Users"]             = WellKnownSidType.BuiltinUsersSid,
            ["Guests"]            = WellKnownSidType.BuiltinGuestsSid,
            ["NETWORK SERVICE"]   = WellKnownSidType.NetworkServiceSid,
            ["NetworkService"]    = WellKnownSidType.NetworkServiceSid,
            ["LOCAL SERVICE"]     = WellKnownSidType.LocalServiceSid,
            ["LocalService"]      = WellKnownSidType.LocalServiceSid,
            ["CREATOR OWNER"]     = WellKnownSidType.CreatorOwnerSid,
            ["CreatorOwner"]      = WellKnownSidType.CreatorOwnerSid,
        };

        if (map.TryGetValue(name, out var sidType))
        {
            try
            {
                // BuiltinAdministratorsSid 等需要 domain SID 作为前缀；null 表示内置域
                return new SecurityIdentifier(sidType, null);
            }
            catch
            {
                return null;
            }
        }

        return null;
    }
}
