namespace AuthServer.App;

public static class Constants
{
    public const string TestScope = "test";
    public const string OpenIdScope = "openid";
    public const string EmailScope = "email";
    public const string ProfileScope = "profile";
    public const string DefaultScope = "api";

    public static IEnumerable<string> AllScopes => new[]
    {
        TestScope,
        OpenIdScope,
        EmailScope,
        ProfileScope,
        DefaultScope
    };
}