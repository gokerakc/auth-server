using System.Security.Cryptography.X509Certificates;
using AuthServer.App.Data;
using AuthServer.App.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace AuthServer.App.Extensions;

public static class ApplicationBuilderExtensions
{
    public static WebApplicationBuilder AddOpenIdDict(this WebApplicationBuilder builder)
    {
        builder.Services.AddOpenIddict()

            // Register the OpenIddict core components.
            .AddCore(options =>
            {
                // Configure OpenIddict to use the EF Core stores/models.
                options.UseEntityFrameworkCore()
                    .UseDbContext<ApplicationDbContext>();
            })

            // Register the OpenIddict server components.
            .AddServer(options =>
            {
                options
                    .AllowClientCredentialsFlow()
                    .AllowAuthorizationCodeFlow();
                //.RequireProofKeyForCodeExchange();

                options
                    .SetTokenEndpointUris("/connect/token")
                    .SetAuthorizationEndpointUris("/connect/authorize")
                    .SetCryptographyEndpointUris("/.well-known/openid-configuration/jwks");

                if (builder.Environment.IsDevelopment())
                {
                    options
                        .AddDevelopmentSigningCertificate()
                        .AddDevelopmentEncryptionCertificate()
                        .DisableAccessTokenEncryption();
                }
                else
                {
                    var key = builder.Configuration.GetValue<string>("OAuth:SigningKey");
                    var pfxBytes = Convert.FromBase64String(key);
                    var cert = new X509Certificate2(pfxBytes, (string?)null);

                    options
                        .AddSigningCertificate(cert)
                        .AddEncryptionCertificate(cert)
                        .DisableAccessTokenEncryption();
                }

                // Register scopes (permissions)
                options.RegisterScopes("test", "admin");

                options.RegisterClaims(new[] { "role", "email" });

                // Register the ASP.NET Core host and configure the ASP.NET Core-specific options.
                options
                    .UseAspNetCore()
                    .DisableTransportSecurityRequirement()
                    .EnableTokenEndpointPassthrough()
                    .EnableAuthorizationEndpointPassthrough();
            });

        return builder;
    }

    public static WebApplicationBuilder AddSqlServer(this WebApplicationBuilder builder)
    {
        var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
        builder.Services.AddDbContext<ApplicationDbContext>(dbContextOptions =>
        {
            dbContextOptions.UseSqlServer(connectionString, sqlServerOptions =>
            {
                sqlServerOptions.CommandTimeout(60);
                sqlServerOptions.EnableRetryOnFailure();
            });
    
    
            // Register the entity sets needed by OpenIddict.
            dbContextOptions.UseOpenIddict();
        });

        return builder;
    }

    public static WebApplicationBuilder AddAspNetCoreIdentity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole>(opt => opt.SignIn.RequireConfirmedAccount = true)
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();
        
        return builder;
    }
}