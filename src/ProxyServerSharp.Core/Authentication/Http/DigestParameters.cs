using System.Text;

namespace ProxyServerSharp.Authentication.Http;

/// <summary>
/// The comma-separated <c>auth-param</c> list carried by a Digest credential, parsed with
/// quoted-string escaping handled per RFC 9110 §5.6.4.
/// </summary>
public sealed class DigestParameters
{
    private readonly Dictionary<string, string> _values;

    private DigestParameters(Dictionary<string, string> values) => _values = values;

    /// <summary>The number of parameters parsed.</summary>
    public int Count => _values.Count;

    /// <summary>Gets a parameter, or <see langword="null"/> when it was not sent.</summary>
    public string? this[string name] => _values.GetValueOrDefault(name);

    /// <summary>Parses an <c>auth-param</c> list such as <c>username="bob", nonce="abc"</c>.</summary>
    public static DigestParameters Parse(string input)
    {
        ArgumentNullException.ThrowIfNull(input);

        Dictionary<string, string> values = new(StringComparer.OrdinalIgnoreCase);
        int index = 0;

        while (index < input.Length)
        {
            SkipDelimiters(input, ref index);
            if (index >= input.Length)
            {
                break;
            }

            int nameStart = index;
            while (index < input.Length && input[index] != '=' && input[index] != ',')
            {
                index++;
            }

            string name = input[nameStart..index].Trim();

            if (index >= input.Length || input[index] == ',')
            {
                // A bare token with no value; skip it rather than rejecting the whole credential.
                continue;
            }

            index++; // consume '='
            values[name] = ReadValue(input, ref index);
        }

        return new DigestParameters(values);
    }

    private static void SkipDelimiters(string input, ref int index)
    {
        while (index < input.Length && (input[index] is ' ' or '\t' or ','))
        {
            index++;
        }
    }

    private static string ReadValue(string input, ref int index)
    {
        while (index < input.Length && (input[index] is ' ' or '\t'))
        {
            index++;
        }

        if (index < input.Length && input[index] == '"')
        {
            index++;
            StringBuilder value = new();

            while (index < input.Length && input[index] != '"')
            {
                if (input[index] == '\\' && index + 1 < input.Length)
                {
                    index++;
                }

                value.Append(input[index++]);
            }

            if (index < input.Length)
            {
                index++; // consume the closing quote
            }

            return value.ToString();
        }

        int start = index;
        while (index < input.Length && input[index] != ',')
        {
            index++;
        }

        return input[start..index].Trim();
    }
}
