namespace ProxyServerSharp.Configuration;

/// <summary>
/// Server-side TLS for a listener. Wrapping an HTTP listener in TLS is what turns it into a
/// true "HTTPS proxy": the client's <c>CONNECT</c> request and its credentials travel encrypted.
/// </summary>
public sealed class TlsOptions
{
    /// <summary>Whether the listener terminates TLS before speaking the proxy protocol.</summary>
    public bool Enabled { get; set; }

    /// <summary>Path to a PKCS#12 (<c>.pfx</c>) or PEM certificate file.</summary>
    public string? CertificatePath { get; set; }

    /// <summary>Path to the PEM private key, when it is not bundled with <see cref="CertificatePath"/>.</summary>
    public string? KeyPath { get; set; }

    /// <summary>Password protecting <see cref="CertificatePath"/>, if any.</summary>
    public string? CertificatePassword { get; set; }

    /// <summary>Thumbprint of a certificate to load from the Windows certificate store instead of a file.</summary>
    public string? CertificateThumbprint { get; set; }

    /// <summary>
    /// Generates an in-memory self-signed certificate when no certificate is configured.
    /// Convenient for a personal proxy on localhost; clients must be told to trust it.
    /// </summary>
    public bool AllowSelfSigned { get; set; }

    /// <summary>Requires the client to present a certificate, giving the listener mutual TLS.</summary>
    public bool RequireClientCertificate { get; set; }
}
