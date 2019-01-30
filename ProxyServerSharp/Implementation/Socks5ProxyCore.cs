using ProxyServerSharp.Interfaces;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProxyServerSharp.Implementation
{
    public class Socks5ProxyCore : IProxyCore
    {
        public event LocalConnectEventHandler LocalConnect;
        public event LocalDisconnectEventHandler LocalDisconnect;
        public event LocalSentEventHandler LocalSent;
        public event LocalReceiveEventHandler LocalReceive;
        public event RemoteConnectEventHandler RemoteConnect;
        public event RemoteDisconnectEventHandler RemoteDisconnect;
        public event RemoteSendEventHandler RemoteSend;
        public event RemoteReceivedEventHandler RemoteReceive;

        private readonly int _port;
        private readonly int _transferUnitSize;

        public Socks5ProxyCore(IProxyServerConfiguration configuration)
        {
            _port = configuration.Port;
            _transferUnitSize = configuration.TransferUnitSize;
        }

        public void Shutdown()
        {
            throw new NotImplementedException();
        }

        public void Start()
        {
            throw new NotImplementedException();
        }
    }
}
