using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace ProxyServerSharp.Implementation
{
    public class ConnectionInfo
    {
        public Socket LocalSocket { get; set; }
        public Thread LocalThread { get; set; }
        public Socket RemoteSocket { get; set; }
        public Thread RemoteThread { get; set; }
    }
}
