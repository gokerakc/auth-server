using AuthServer.App;
using AuthServer.App.Data;
using AuthServer.App.Data.Seed;
using AuthServer.App.Extensions;
using AuthServer.App.Models;
using AuthServer.App.Services;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Validation.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

//
// App settings configuration 
//
var environment = Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT");
builder.Configuration
    .SetBasePath(Directory.GetCurrentDirectory())
    .AddJsonFile("appsettings.json", false, true)
    .AddJsonFile($"appsettings.{environment}.json", true)
    .AddEnvironmentVariables();

if (string.IsNullOrEmpty(environment) || environment.ToLower() == "development")
{
    builder.Configuration.AddUserSecrets<Program>();
}

//
// Web host configuration
//
var isDevelopment = string.IsNullOrEmpty(environment) || environment.ToLower() == "development";
builder.WebHost.UseKestrel(opt =>
    {
        if (isDevelopment == false)
        {
            opt.ListenAnyIP(80);
        }
    })
    .UseConfiguration(builder.Configuration)
    .UseDefaultServiceProvider((context, options) =>
    {
        options.ValidateScopes = context.HostingEnvironment.IsDevelopment();
    });

//
// Add services to the container
//
builder.Services.AddControllersWithViews()
    .AddNewtonsoftJson();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme, options =>
    {
        options.LoginPath = "/account/login";
    });

builder.Services.AddHealthChecks();

builder.Services.AddAuthorization(opt =>
{
    opt.AddPolicy(Constants.TestPolicyName, policy =>
    {
        policy.AddAuthenticationSchemes(OpenIddictValidationAspNetCoreDefaults.AuthenticationScheme);
        policy.RequireAuthenticatedUser();
        policy.RequireClaim("scope", Constants.TestScope);
    });
});

var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseSqlServer(connectionString,
        providerOptions =>
            providerOptions
                .CommandTimeout(60)
                .EnableRetryOnFailure());

    options.UseOpenIddict();
});

builder.Services.AddIdentity<ApplicationUser, IdentityRole>(opt => opt.SignIn.RequireConfirmedAccount = true)
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

builder.AddOpenIdDict();

builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped<IOpenIddictApplicationService, OpenIddictApplicationService>();

builder.Services.AddHostedService<SeedScopesService>();
builder.Services.AddHostedService<SeedTestClientService>();
builder.Services.AddHostedService<SeedRolesService>();

var app = builder.Build();

//
// Configure the HTTP request pipeline.
//
var forwardOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto |
                       ForwardedHeaders.XForwardedHost,
    RequireHeaderSymmetry = false
};

forwardOptions.KnownNetworks.Clear();
forwardOptions.KnownProxies.Clear();

app.UseForwardedHeaders(forwardOptions);

app.UseHealthChecks("/ready");

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UsePathBase("/oauth");

app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();

app.UseAuthorization();

app.UseEndpoints(endpoints =>
{
    endpoints.MapDefaultControllerRoute();
});

app.Run();
