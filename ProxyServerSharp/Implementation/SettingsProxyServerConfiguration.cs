using ProxyServerSharp.Enums;
using ProxyServerSharp.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProxyServerSharp.Implementation
{
    class SettingsProxyServerConfiguration : IProxyServerConfiguration
    {
        public int Port { get => Properties.Settings.Default.Port; set => Properties.Settings.Default.Port = value; }
        public int TransferUnitSize { get => Properties.Settings.Default.TransferUnitSize; set => Properties.Settings.Default.TransferUnitSize = value; }
        public AuthenticationType AuthenticationType { get => throw new NotImplementedException(); set => throw new NotImplementedException(); }
    }
}
