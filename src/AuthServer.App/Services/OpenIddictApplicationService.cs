using AuthServer.App.Models;
using OpenIddict.Abstractions;

namespace AuthServer.App.Services;

public class OpenIddictApplicationService : IOpenIddictApplicationService
{
    private readonly IOpenIddictApplicationManager _applicationManager;

    public OpenIddictApplicationService(IOpenIddictApplicationManager applicationManager)
    {
        _applicationManager = applicationManager;
    }
        
    public async Task Create(AuthServerClientRequest clientRequest)
    {
        if (await _applicationManager.FindByClientIdAsync(clientRequest.ClientId, CancellationToken.None) is null)
        {
            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = clientRequest.ClientId,
                ClientSecret = clientRequest.Secret,
                DisplayName = clientRequest.ClientName,
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,
                    OpenIddictConstants.Permissions.ResponseTypes.Code
                }
            };

            foreach (var scope in clientRequest.AllowedScopes)
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.Prefixes.Scope + scope);
            }
                
            foreach (var redirectUri in clientRequest.RedirectUris)
            {
                descriptor.RedirectUris.Add(new Uri(redirectUri));
            }

            if (clientRequest.AllowedGrantTypes.Contains(AuthServerClientGrantType.AuthorizationCode))
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode);
            }
                
            if (clientRequest.AllowedGrantTypes.Contains(AuthServerClientGrantType.ClientCredentials))
            {
                descriptor.Permissions.Add(OpenIddictConstants.Permissions.GrantTypes.ClientCredentials);
            }
                
            await _applicationManager.CreateAsync(descriptor, CancellationToken.None);
        }
        else
        {
            throw new ArgumentException($"{clientRequest.ClientId} is already exist.");
        }            
    }
}