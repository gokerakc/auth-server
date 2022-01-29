using OpenIddict.Abstractions;

namespace AuthServer.App.Data.Seed;

public class SeedTestClientService : IHostedService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<SeedTestClientService> _logger;

    public SeedTestClientService(IServiceProvider serviceProvider, ILogger<SeedTestClientService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }
    
    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using (var scope = _serviceProvider.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await context.Database.EnsureCreatedAsync(cancellationToken);
            
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();
            if (await manager.FindByClientIdAsync("test", cancellationToken) is not null)
            {
                return;
            }
            
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = "test",
                DisplayName = "Test client",
                ClientSecret = "ONdy2qI4BN",
                RedirectUris = { new Uri("https://oidcdebugger.com/debug"), new Uri("https://oauth.pstmn.io/v1/callback") },
                Permissions =
                {
                    OpenIddictConstants.Permissions.Endpoints.Authorization,
                    OpenIddictConstants.Permissions.Endpoints.Token,

                    OpenIddictConstants.Permissions.GrantTypes.AuthorizationCode,
                    OpenIddictConstants.Permissions.GrantTypes.ClientCredentials,

                    OpenIddictConstants.Permissions.Prefixes.Scope + Constants.DefaultScope,
                    OpenIddictConstants.Permissions.Prefixes.Scope + Constants.OpenIdScope,
                    OpenIddictConstants.Permissions.Prefixes.Scope + Constants.ProfileScope,
                    OpenIddictConstants.Permissions.Prefixes.Scope + Constants.TestScope, 

                    OpenIddictConstants.Permissions.ResponseTypes.Code
                }
            }, cancellationToken);
            
            _logger.LogInformation("Test client has been added.");
        }    
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    
}