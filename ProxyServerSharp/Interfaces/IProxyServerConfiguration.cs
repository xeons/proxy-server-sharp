using ProxyServerSharp.Enums;

namespace ProxyServerSharp.Interfaces
{
    public interface IProxyServerConfiguration
    {
        int Port { get; set; }
        int TransferUnitSize { get; set; }
        AuthenticationType AuthenticationType { get; set; }
    }
}
