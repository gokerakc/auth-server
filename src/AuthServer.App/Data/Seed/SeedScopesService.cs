using OpenIddict.Abstractions;

namespace AuthServer.App.Data.Seed;

public class SeedScopesService : IHostedService
{
    private readonly IServiceProvider _serviceProvider;
    private readonly ILogger<SeedScopesService> _logger;

    public SeedScopesService(IServiceProvider serviceProvider, ILogger<SeedScopesService> logger)
    {
        _serviceProvider = serviceProvider;
        _logger = logger;
    }


    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using (var scope = _serviceProvider.CreateScope())
        {
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
            await dbContext.Database.EnsureCreatedAsync(cancellationToken);

            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictScopeManager>();

            foreach (var scopeName in Constants.AllScopes)
            {
                if (await manager.FindByNameAsync(scopeName, cancellationToken) is not null)
                {
                    continue;
                }
                
                await manager.CreateAsync(new OpenIddictScopeDescriptor
                {
                    Name = scopeName,
                    DisplayName = scopeName

                }, cancellationToken);
                    
                _logger.LogInformation("New scope has been added -> {}.", scopeName);
            }
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}