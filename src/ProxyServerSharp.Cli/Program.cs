using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using ProxyServerSharp.Cli;
using ProxyServerSharp.Configuration;

CommandLine command = CommandLine.Parse(args);

switch (command.Verb)
{
    case Verb.Help:
        CommandLine.WriteUsage();
        return 0;

    case Verb.Version:
        Console.WriteLine($"proxysharp {ThisAssembly.Version}");
        return 0;

    case Verb.HashPassword:
        return PasswordTool.Run(command);

    case Verb.Run:
        break;

    default:
        Console.Error.WriteLine($"Unknown command '{command.Verb}'.");
        return 2;
}

HostApplicationBuilder builder = Host.CreateApplicationBuilder(new HostApplicationBuilderSettings
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory,
});

builder.Configuration.Sources.Clear();
builder.Configuration
    .AddJsonFile(Path.Combine(AppContext.BaseDirectory, "appsettings.json"), optional: true, reloadOnChange: false)
    .AddJsonFile(command.ConfigPath ?? "proxysharp.json", optional: command.ConfigPath is null, reloadOnChange: false)
    .AddEnvironmentVariables("PROXYSHARP_");

builder.Logging.ClearProviders();
builder.Logging.AddSimpleConsole(options =>
{
    options.SingleLine = true;
    options.TimestampFormat = "HH:mm:ss ";
});
builder.Logging.SetMinimumLevel(command.Verbose ? LogLevel.Debug : LogLevel.Information);

ProxyServerOptions options = new();
builder.Configuration.GetSection(ProxyServerOptions.SectionName).Bind(options);
command.ApplyTo(options);

if (options.Listeners.Count == 0)
{
    Console.Error.WriteLine(
        "No listeners configured. Pass --socks5 <port>, --socks4 <port> or --http <port>, "
        + "or point --config at a configuration file.");
    Console.Error.WriteLine();
    CommandLine.WriteUsage(Console.Error);
    return 2;
}

builder.Services.AddSingleton(options);
builder.Services.AddHostedService<ProxyServerService>();

using IHost host = builder.Build();

try
{
    await host.RunAsync().ConfigureAwait(false);
    return 0;
}
catch (InvalidOperationException exception)
{
    Console.Error.WriteLine(exception.Message);
    return 1;
}

/// <summary>Assembly metadata surfaced to the <c>--version</c> output.</summary>
internal static class ThisAssembly
{
    /// <summary>The informational version stamped at build time.</summary>
    internal static string Version =>
        typeof(ThisAssembly).Assembly
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
            .FirstOrDefault()?.InformationalVersion
        ?? "unknown";
}
