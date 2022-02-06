using System.Runtime.Serialization;
using Newtonsoft.Json;
using Newtonsoft.Json.Converters;

namespace AuthServer.App.Models;

public class AuthServerClientRequest
{
    public AuthServerClientRequest(
        string clientId,
        string clientName,
        string secret,
        IList<AuthServerClientGrantType> allowedGrantTypes,
        IList<string> allowedScopes,
        IList<string> redirectUris)
    {
        ClientId = clientId;
        ClientName = clientName;
        Secret = secret;
        AllowedGrantTypes = allowedGrantTypes;
        AllowedScopes = allowedScopes;
        RedirectUris = redirectUris;
    }

    public string ClientId { get; set; }

    public string ClientName { get; set; }

    public string Secret { get; set; }

    [JsonProperty (ItemConverterType = typeof(StringEnumConverter))]
    public IList<AuthServerClientGrantType> AllowedGrantTypes { get; set; }
        
    public IList<string> AllowedScopes { get; set; }

    public IList<string> RedirectUris { get; set; }
        
    // public bool RequirePkce { get; set; } = false;
    //
    // public bool RequireClientSecret { get; set; } = true;
    //
    // public bool RequireConsent { get; set; } = true;
    //
    // public IList<string> PostLogoutRedirectUris { get; set; }
    //
    // public IList<string> AllowedCorsOrigins { get; set; }
    //
    // public bool AllowOfflineAccess { get; set; } = false;
    //
    // public int? UserSsoLifetime { get; set; }
}

public enum AuthServerClientGrantType
{
    [EnumMember(Value = "@implicit")]    
    Implicit,
        
    [EnumMember(Value = "hybrid")]         
    Hybrid,
        
    [EnumMember(Value = "authorization_code")]     
    AuthorizationCode,
        
    [EnumMember(Value = "client_credentials")]
    ClientCredentials,
        
    [EnumMember(Value = "password")]         
    Password 
}