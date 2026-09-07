using System.Globalization;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Cli;

/// <summary>What the user asked the CLI to do.</summary>
internal enum Verb
{
    /// <summary>Run the proxy server.</summary>
    Run,

    /// <summary>Print usage.</summary>
    Help,

    /// <summary>Print the version.</summary>
    Version,

    /// <summary>Turn a password or token into a storable verifier.</summary>
    HashPassword,
}

/// <summary>
/// The CLI's own argument parsing. Flags are a convenience layer over
/// <see cref="ProxyServerOptions"/>: anything they set could equally be written in the
/// configuration file, and the file is the only way to reach the less common settings.
/// </summary>
internal sealed class CommandLine
{
    private readonly List<ListenerOptions> _listeners = [];
    private readonly List<ProxyUserOptions> _users = [];

    private CommandLine()
    {
    }

    /// <summary>The requested action.</summary>
    internal Verb Verb { get; private set; } = Verb.Run;

    /// <summary>An explicit configuration file path, when <c>--config</c> was given.</summary>
    internal string? ConfigPath { get; private set; }

    /// <summary>Whether debug-level logging was requested.</summary>
    internal bool Verbose { get; private set; }

    /// <summary>The value to hash, for <see cref="Verb.HashPassword"/>.</summary>
    internal string? Secret { get; private set; }

    /// <summary>Parses <paramref name="args"/>, treating anything unrecognised as a request for help.</summary>
    internal static CommandLine Parse(string[] args)
    {
        CommandLine command = new();
        

        for (int i = 0; i < args.Length; i++)
        {
            string arg = args[i];

            switch (arg)
            {
                case "-h" or "--help":
                    command.Verb = Verb.Help;
                    return command;

                case "--version":
                    command.Verb = Verb.Version;
                    return command;

                case "hash-password" or "hash-token":
                    command.Verb = Verb.HashPassword;
                    command.Secret = Next(args, ref i, arg, required: false);
                    return command;

                case "-v" or "--verbose":
                    command.Verbose = true;
                    break;

                case "-c" or "--config":
                    command.ConfigPath = Next(args, ref i, arg);
                    break;

                case "--socks4":
                    command._listeners.Add(CreateListener(ProxyProtocol.Socks4, Next(args, ref i, arg)));
                    break;

                case "--socks5":
                    command._listeners.Add(CreateListener(ProxyProtocol.Socks5, Next(args, ref i, arg)));
                    break;

                case "--http":
                    command._listeners.Add(CreateListener(ProxyProtocol.Http, Next(args, ref i, arg)));
                    break;

                case "--bind":
                    // Applies to every listener declared so far, and to any declared after it.
                    command.BindAddress = Next(args, ref i, arg);
                    break;

                case "--auth":
                    command.AuthenticationMethods = ParseMethods(Next(args, ref i, arg));
                    break;

                case "--user":
                    command._users.Add(ParseUser(Next(args, ref i, arg)));
                    break;

                case "--realm":
                    command.Realm = Next(args, ref i, arg);
                    break;

                case "--tls":
                    command.Tls = true;
                    break;

                case "--tls-cert":
                    command.TlsCertificate = Next(args, ref i, arg);
                    command.Tls = true;
                    break;

                case "--tls-password":
                    command.TlsPassword = Next(args, ref i, arg);
                    break;

                case "--allow":
                    command.Allow.Add(Next(args, ref i, arg));
                    break;

                case "--allow-bind":
                    command.AllowBind = true;
                    break;

                case "--allow-udp":
                    command.AllowUdp = true;
                    break;

                default:
                    // The generic host also reads args; anything with a leading dash that is not
                    // ours is left alone rather than treated as an error.
                    if (arg.StartsWith('-') && !arg.Contains('=', StringComparison.Ordinal))
                    {
                        Console.Error.WriteLine($"Unknown option '{arg}'.");
                        command.Verb = Verb.Help;
                        return command;
                    }

                    break;
            }
        }

        return command;
    }

    private string? BindAddress { get; set; }

    private string? Realm { get; set; }

    private bool Tls { get; set; }

    private string? TlsCertificate { get; set; }

    private string? TlsPassword { get; set; }

    private bool AllowBind { get; set; }

    private bool AllowUdp { get; set; }

    private List<string> Allow { get; } = [];

    private AuthenticationMethod[]? AuthenticationMethods { get; set; }

    /// <summary>Folds the parsed flags into options already bound from configuration.</summary>
    internal void ApplyTo(ProxyServerOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        foreach (ProxyUserOptions user in _users)
        {
            options.Users.Add(user);
        }

        if (_listeners.Count == 0)
        {
            return;
        }

        // Declaring listeners on the command line replaces whatever the configuration file had,
        // rather than adding to it, so "--socks5 1080" cannot collide with a configured 1080.
        options.Listeners.Clear();

        foreach (ListenerOptions listener in _listeners)
        {
            if (BindAddress is not null)
            {
                listener.Address = BindAddress;
            }

            if (Realm is not null)
            {
                listener.Realm = Realm;
            }

            listener.AllowBind = AllowBind;
            listener.AllowUdpAssociate = AllowUdp;

            foreach (string entry in Allow)
            {
                listener.Access.Allow.Add(entry);
            }

            if (Tls)
            {
                listener.Tls.Enabled = true;
                listener.Tls.CertificatePath = TlsCertificate;
                listener.Tls.CertificatePassword = TlsPassword;
                listener.Tls.AllowSelfSigned = TlsCertificate is null;
            }

            foreach (AuthenticationMethod method in ResolveMethods(listener.Protocol))
            {
                listener.Authentication.Add(method);
            }

            options.Listeners.Add(listener);
        }
    }

    /// <summary>
    /// Picks the methods for a listener: the explicit <c>--auth</c> list, or a sensible default
    /// derived from whether any accounts were supplied.
    /// </summary>
    private IEnumerable<AuthenticationMethod> ResolveMethods(ProxyProtocol protocol)
    {
        if (AuthenticationMethods is not null)
        {
            return AuthenticationMethods.Where(m => m.IsValidFor(protocol));
        }

        if (_users.Count == 0)
        {
            return [AuthenticationMethod.Anonymous];
        }

        return protocol switch
        {
            ProxyProtocol.Socks4 => [AuthenticationMethod.UserId],
            ProxyProtocol.Socks5 => [AuthenticationMethod.UsernamePassword],
            _ => [AuthenticationMethod.Basic, AuthenticationMethod.Digest],
        };
    }

    private static ListenerOptions CreateListener(ProxyProtocol protocol, string port) => new()
    {
        Name = $"{protocol.ToString().ToLowerInvariant()}-{port}",
        Protocol = protocol,
        Port = int.Parse(port, CultureInfo.InvariantCulture),
    };

    private static AuthenticationMethod[] ParseMethods(string value) =>
    [
        .. value
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(name => Enum.TryParse(name, ignoreCase: true, out AuthenticationMethod method)
                ? method
                : throw new FormatException(
                    $"Unknown authentication method '{name}'. Valid values: "
                    + string.Join(", ", Enum.GetNames<AuthenticationMethod>()))),
    ];

    /// <summary>Parses <c>--user name:password</c>, hashing the password before it is stored.</summary>
    private static ProxyUserOptions ParseUser(string value)
    {
        int separator = value.IndexOf(':', StringComparison.Ordinal);
        if (separator <= 0 || separator == value.Length - 1)
        {
            throw new FormatException($"--user expects 'name:password', got '{value}'.");
        }

        string username = value[..separator];
        string password = value[(separator + 1)..];

        return new ProxyUserOptions
        {
            Username = username,

            // Digest cannot verify against a one-way hash, so a command-line account keeps the
            // password in memory too. Accounts written to a config file should use PasswordHash.
            Password = password,
            PasswordHash = ProxyServerSharp.Authentication.PasswordHasher.Hash(password),
        };
    }

    private static string Next(string[] args, ref int index, string option, bool required = true)
    {
        if (index + 1 >= args.Length || args[index + 1].StartsWith('-'))
        {
            return required ? throw new FormatException($"{option} expects a value.") : "";
        }

        return args[++index];
    }

    /// <summary>Writes usage text.</summary>
    internal static void WriteUsage(TextWriter? writer = null)
    {
        (writer ?? Console.Out).WriteLine(
            """
            proxysharp - a SOCKS4/4a, SOCKS5 and HTTP(S) proxy server.

            Usage:
              proxysharp [options]
              proxysharp hash-password [<value>]
              proxysharp --help | --version

            Listeners (repeatable; each flag adds one listener):
              --socks4 <port>        Listen for SOCKS4 and SOCKS4a clients.
              --socks5 <port>        Listen for SOCKS5 clients.
              --http <port>          Listen for HTTP clients (CONNECT and absolute-URI).
              --bind <address>       Local address to bind. Default 127.0.0.1.

            Authentication:
              --auth <methods>       Comma-separated: Anonymous, UserId, UsernamePassword,
                                     Basic, Digest, Bearer, Negotiate. Methods that the
                                     listener's protocol cannot express are ignored.
              --user <name:password> Add an account. Repeatable.
              --realm <realm>        Protection space for Basic and Digest. Default ProxyServerSharp.

            Transport:
              --tls                  Terminate TLS with a generated self-signed certificate.
              --tls-cert <path>      Terminate TLS with a PKCS#12 or PEM certificate.
              --tls-password <pass>  Password for --tls-cert.

            Access:
              --allow <cidr>         Only accept clients from this block. Repeatable.
              --allow-bind           Honour the SOCKS5 BIND command.
              --allow-udp            Honour the SOCKS5 UDP ASSOCIATE command.

            General:
              -c, --config <path>    Read configuration from a JSON file.
              -v, --verbose          Log at debug level.

            Without --auth, a listener is anonymous when no --user is given and requires
            credentials when one is. Every setting also has a configuration-file equivalent
            under the "ProxyServer" section; see proxysharp.json.

            Examples:
              proxysharp --socks5 1080 --user alice:hunter2
              proxysharp --http 8080 --auth Digest --user alice:hunter2 --realm home
              proxysharp --http 8443 --tls --auth Basic --user alice:hunter2
              proxysharp --socks5 1080 --socks4 1081 --bind 0.0.0.0 --allow 192.168.1.0/24
            """);
    }
}
