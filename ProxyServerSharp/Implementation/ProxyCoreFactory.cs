using ProxyServerSharp.Enums;
using ProxyServerSharp.Interfaces;
using System;

namespace ProxyServerSharp.Implementation
{
    public class ProxyCoreFactory
    {
        public static IProxyCore Create(IProxyServerConfiguration configuration, ProxyType proxyType)
        {
            switch(proxyType)
            {
                case ProxyType.Socks4:
                    return new Socks4ProxyCore(configuration);
                case ProxyType.Socks5:
                    return new Socks5ProxyCore(configuration);

                default:
                    throw new NotImplementedException();
            }
        }
    }
}
