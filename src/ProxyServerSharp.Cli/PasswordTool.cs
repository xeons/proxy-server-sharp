using System.Text;
using ProxyServerSharp.Authentication;

namespace ProxyServerSharp.Cli;

/// <summary>
/// The <c>hash-password</c> command: turns a password or bearer token into the verifier that
/// belongs in a configuration file, so no plaintext secret has to be written down.
/// </summary>
internal static class PasswordTool
{
    internal static int Run(CommandLine command)
    {
        string? secret = string.IsNullOrEmpty(command.Secret) ? Prompt() : command.Secret;

        if (string.IsNullOrEmpty(secret))
        {
            Console.Error.WriteLine("No value supplied.");
            return 2;
        }

        Console.WriteLine(PasswordHasher.Hash(secret));
        Console.Error.WriteLine();
        Console.Error.WriteLine("Add it to your configuration as:");
        Console.Error.WriteLine("""
              "Users": [ { "Username": "alice", "PasswordHash": "<the value above>" } ]

            Use "TokenHashes": [ "<the value above>" ] for a Bearer token instead.

            Note: HTTP Digest cannot verify a one-way hash. An account that must answer a Digest
            challenge needs either "Password" or a precomputed "DigestHa1" entry.
            """);

        return 0;
    }

    /// <summary>Reads a secret without echoing it, falling back to a plain read when redirected.</summary>
    private static string? Prompt()
    {
        Console.Error.Write("Password: ");

        if (Console.IsInputRedirected)
        {
            return Console.ReadLine();
        }

        StringBuilder builder = new();

        while (true)
        {
            ConsoleKeyInfo key = Console.ReadKey(intercept: true);

            switch (key.Key)
            {
                case ConsoleKey.Enter:
                    Console.Error.WriteLine();
                    return builder.ToString();

                case ConsoleKey.Backspace when builder.Length > 0:
                    builder.Length--;
                    break;

                case ConsoleKey.Escape:
                    Console.Error.WriteLine();
                    return null;

                default:
                    if (!char.IsControl(key.KeyChar))
                    {
                        builder.Append(key.KeyChar);
                    }

                    break;
            }
        }
    }
}
