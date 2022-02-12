using AuthServer.App.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;

namespace AuthServer.App.Data.Seed;

public class SeedRolesService : IHostedService
{
    private readonly IServiceProvider _serviceProvider;

    public SeedRolesService(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        using (var scope = _serviceProvider.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var roles = new string[] {UserRole.AdminUser.ToString(), UserRole.TestUser.ToString(), UserRole.Visitor.ToString()};

            foreach (var role in roles)
            {
                var roleStore = new RoleStore<IdentityRole>(context);

                if (context.Roles.Any(r => r.Name == role))
                {
                    continue;
                }
                
                var newRole = new IdentityRole(role) {NormalizedName = role.ToUpperInvariant()};
                await roleStore.CreateAsync(newRole, cancellationToken);
            }
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}