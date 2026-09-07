using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using ProxyServerSharp.Configuration;

namespace ProxyServerSharp.Server;

/// <summary>Resolves the server certificate a TLS-terminating listener presents.</summary>
public static class TlsCertificateLoader
{
    /// <summary>Loads the certificate described by <paramref name="options"/>.</summary>
    /// <exception cref="InvalidOperationException">No usable certificate could be resolved.</exception>
    public static X509Certificate2 Load(TlsOptions options, string listenerName)
    {
        ArgumentNullException.ThrowIfNull(options);

        if (!string.IsNullOrWhiteSpace(options.CertificatePath))
        {
            return LoadFromFile(options);
        }

        if (!string.IsNullOrWhiteSpace(options.CertificateThumbprint))
        {
            return LoadFromStore(options.CertificateThumbprint);
        }

        if (options.AllowSelfSigned)
        {
            return CreateSelfSigned(listenerName);
        }

        throw new InvalidOperationException(
            $"Listener '{listenerName}' enables TLS but configures no certificate. Set Tls:CertificatePath, "
            + "Tls:CertificateThumbprint, or Tls:AllowSelfSigned.");
    }

    private static X509Certificate2 LoadFromFile(TlsOptions options)
    {
        string path = options.CertificatePath!;

        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"TLS certificate '{path}' was not found.", path);
        }

        X509Certificate2 certificate = string.IsNullOrWhiteSpace(options.KeyPath)
            ? X509CertificateLoader.LoadPkcs12FromFile(
                path,
                options.CertificatePassword,
                X509KeyStorageFlags.Exportable)
            : X509Certificate2.CreateFromPemFile(path, options.KeyPath);

        if (!certificate.HasPrivateKey)
        {
            throw new InvalidOperationException($"TLS certificate '{path}' has no private key.");
        }

        // A PEM-loaded certificate cannot be used directly by SChannel on Windows; round-tripping
        // it through PKCS#12 attaches the key in a form SslStream accepts.
        return OperatingSystem.IsWindows() && !string.IsNullOrWhiteSpace(options.KeyPath)
            ? Reimport(certificate)
            : certificate;
    }

    private static X509Certificate2 LoadFromStore(string thumbprint)
    {
        string normalized = thumbprint.Replace(" ", "", StringComparison.Ordinal);

        foreach (StoreLocation location in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            using X509Store store = new(StoreName.My, location);
            store.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection found = store.Certificates.Find(
                X509FindType.FindByThumbprint,
                normalized,
                validOnly: false);

            if (found.Count > 0)
            {
                return found[0];
            }
        }

        throw new InvalidOperationException($"No certificate with thumbprint '{thumbprint}' was found.");
    }

    private static X509Certificate2 CreateSelfSigned(string listenerName)
    {
        using RSA key = RSA.Create(2048);

        CertificateRequest request = new(
            $"CN=ProxyServerSharp {listenerName}",
            key,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1")], false));

        SubjectAlternativeNameBuilder alternativeNames = new();
        alternativeNames.AddDnsName("localhost");
        alternativeNames.AddIpAddress(System.Net.IPAddress.Loopback);
        alternativeNames.AddIpAddress(System.Net.IPAddress.IPv6Loopback);
        request.CertificateExtensions.Add(alternativeNames.Build());

        DateTimeOffset now = DateTimeOffset.UtcNow;
        using X509Certificate2 certificate = request.CreateSelfSigned(now.AddDays(-1), now.AddYears(1));

        return Reimport(certificate);
    }

    /// <summary>
    /// Exports and reloads a certificate as PKCS#12 so its private key is in the form
    /// <see cref="System.Net.Security.SslStream"/> requires on every platform.
    /// </summary>
    private static X509Certificate2 Reimport(X509Certificate2 certificate)
    {
        byte[] pkcs12 = certificate.Export(X509ContentType.Pkcs12);

        // SChannel cannot use an ephemeral key set for a server credential, so on Windows the key
        // has to land in a real key container; elsewhere ephemeral keeps nothing on disk.
        X509KeyStorageFlags flags = OperatingSystem.IsWindows()
            ? X509KeyStorageFlags.Exportable
            : X509KeyStorageFlags.EphemeralKeySet;

        return X509CertificateLoader.LoadPkcs12(pkcs12, password: null, flags);
    }
}
