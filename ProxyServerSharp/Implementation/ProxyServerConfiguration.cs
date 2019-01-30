using ProxyServerSharp.Enums;
using ProxyServerSharp.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProxyServerSharp.Implementation
{
    public class ProxyServerConfiguration : IProxyServerConfiguration
    {
        public int Port { get; set; }
        public int TransferUnitSize { get; set; }
        public AuthenticationType AuthenticationType { get; set; }
    }
}
