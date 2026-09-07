using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace ProxyServerSharp.Protocol.Http;

/// <summary>
/// An ordered, case-insensitive, multi-valued header list that preserves the order fields
/// arrived in, so forwarded requests look as close to the original as possible.
/// </summary>
public sealed class HttpHeaders
{
    private readonly List<KeyValuePair<string, string>> _fields = [];

    /// <summary>The number of header fields, counting repeats separately.</summary>
    public int Count => _fields.Count;

    /// <summary>The fields in arrival order.</summary>
    public IReadOnlyList<KeyValuePair<string, string>> Fields => _fields;

    /// <summary>Appends a field, keeping any existing field with the same name.</summary>
    public void Add(string name, string value)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        ArgumentNullException.ThrowIfNull(value);
        _fields.Add(new KeyValuePair<string, string>(name, value));
    }

    /// <summary>Removes every field with <paramref name="name"/>, then appends one with <paramref name="value"/>.</summary>
    public void Set(string name, string value)
    {
        Remove(name);
        Add(name, value);
    }

    /// <summary>Removes every field named <paramref name="name"/>, returning how many went.</summary>
    public int Remove(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);
        return _fields.RemoveAll(f => string.Equals(f.Key, name, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>Whether any field named <paramref name="name"/> is present.</summary>
    public bool Contains(string name) => TryGetFirst(name, out _);

    /// <summary>Gets the first value for <paramref name="name"/>, or <see langword="null"/>.</summary>
    public string? GetFirst(string name) => TryGetFirst(name, out string? value) ? value : null;

    /// <summary>Gets the first value for <paramref name="name"/>.</summary>
    public bool TryGetFirst(string name, [NotNullWhen(true)] out string? value)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        foreach ((string field, string fieldValue) in _fields)
        {
            if (string.Equals(field, name, StringComparison.OrdinalIgnoreCase))
            {
                value = fieldValue;
                return true;
            }
        }

        value = null;
        return false;
    }

    /// <summary>Every value for <paramref name="name"/>, in arrival order.</summary>
    public IEnumerable<string> GetAll(string name)
    {
        ArgumentException.ThrowIfNullOrEmpty(name);

        foreach ((string field, string value) in _fields)
        {
            if (string.Equals(field, name, StringComparison.OrdinalIgnoreCase))
            {
                yield return value;
            }
        }
    }

    /// <summary>Writes the fields plus the terminating blank line into <paramref name="builder"/>.</summary>
    public void WriteTo(StringBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);

        foreach ((string name, string value) in _fields)
        {
            builder.Append(name).Append(": ").Append(value).Append("\r\n");
        }

        builder.Append("\r\n");
    }
}
