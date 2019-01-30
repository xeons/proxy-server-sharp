using System;
using System.Collections.Generic;
using System.Text;

namespace ProxyServerSharp.Interfaces
{
    public delegate void LocalConnectEventHandler(object sender, System.Net.IPEndPoint iep);
    public delegate void LocalDisconnectEventHandler(object sender);
    public delegate void LocalSentEventHandler(object sender);
    public delegate void LocalReceiveEventHandler(object sender);
    public delegate void RemoteConnectEventHandler(object sender, System.Net.IPEndPoint iep);
    public delegate void RemoteDisconnectEventHandler(object sender);
    public delegate void RemoteSendEventHandler(object sender);
    public delegate void RemoteReceivedEventHandler(object sender);

    public interface IProxyCore
    {
        event LocalConnectEventHandler LocalConnect;
        event LocalDisconnectEventHandler LocalDisconnect;
        event LocalSentEventHandler LocalSent;
        event LocalReceiveEventHandler LocalReceive;
        event RemoteConnectEventHandler RemoteConnect;
        event RemoteDisconnectEventHandler RemoteDisconnect;
        event RemoteSendEventHandler RemoteSend;
        event RemoteReceivedEventHandler RemoteReceive;

        void Start();
        void Shutdown();
    }
}
