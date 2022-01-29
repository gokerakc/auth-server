using AuthServer.App.Data.Seed;
using AuthServer.App.Extensions;
using Microsoft.AspNetCore.HttpOverrides;

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
builder.Services.AddControllersWithViews();

builder.AddSqlServer();

builder.AddAspNetCoreIdentity();

builder.AddOpenIdDict();

builder.Services.AddHostedService<InitScopesService>();

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

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UsePathBase("/oauth");

app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
