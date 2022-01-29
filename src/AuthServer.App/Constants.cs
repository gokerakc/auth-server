namespace AuthServer.App;

public static class Constants
{
    // Scopes
    public const string TestScope = "test";
    public const string OpenIdScope = "openid";
    public const string EmailScope = "email";
    public const string ProfileScope = "profile";
    public const string DefaultScope = "api";
    
    // Policy names
    public const string TestPolicyName = "TestPolicy";

    public static string[] AllScopes => new[]
    {
        TestScope,
        OpenIdScope,
        EmailScope,
        ProfileScope,
        DefaultScope
    };
}