using System.Text.Json;
using System.Text.Json.Serialization;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.App;

/// <summary>
/// Loads and saves the desktop app's configuration, in the same JSON shape the console host reads
/// so a configuration can be moved between the two without editing.
/// </summary>
internal static class AppSettingsStore
{
    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() },
    };

    /// <summary>The default configuration file, under the user's roaming profile.</summary>
    internal static string DefaultPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "ProxyServerSharp",
        "proxysharp.json");

    /// <summary>Loads configuration, falling back to a sensible starting point.</summary>
    internal static ProxyServerOptions Load(string? path = null)
    {
        string file = path ?? DefaultPath;

        if (!File.Exists(file))
        {
            return CreateDefault();
        }

        using FileStream stream = File.OpenRead(file);
        using JsonDocument document = JsonDocument.Parse(stream);

        // Accept both the bare options object and the console host's "ProxyServer" wrapper.
        JsonElement root = document.RootElement.TryGetProperty(ProxyServerOptions.SectionName, out JsonElement section)
            ? section
            : document.RootElement;

        return root.Deserialize<ProxyServerOptions>(SerializerOptions) ?? CreateDefault();
    }

    /// <summary>Saves configuration, wrapped so the console host can read the same file.</summary>
    internal static void Save(ProxyServerOptions options, string? path = null)
    {
        ArgumentNullException.ThrowIfNull(options);

        string file = path ?? DefaultPath;
        Directory.CreateDirectory(Path.GetDirectoryName(file)!);

        using FileStream stream = File.Create(file);
        using Utf8JsonWriter writer = new(stream, new JsonWriterOptions { Indented = true });

        writer.WriteStartObject();
        writer.WritePropertyName(ProxyServerOptions.SectionName);
        JsonSerializer.Serialize(writer, options, SerializerOptions);
        writer.WriteEndObject();
    }

    /// <summary>
    /// The starting configuration for a fresh install: loopback only, anonymous, so the app is
    /// immediately usable but is not reachable from the network.
    /// </summary>
    internal static ProxyServerOptions CreateDefault() => new()
    {
        Listeners =
        {
            new ListenerOptions
            {
                Name = "socks5",
                Protocol = ProxyProtocol.Socks5,
                Address = "127.0.0.1",
                Port = 1080,
                Authentication = { AuthenticationMethod.Anonymous },
            },
            new ListenerOptions
            {
                Name = "http",
                Protocol = ProxyProtocol.Http,
                Address = "127.0.0.1",
                Port = 8080,
                Authentication = { AuthenticationMethod.Anonymous },
            },
        },
    };
}
