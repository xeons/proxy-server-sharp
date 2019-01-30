using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using ProxyServerSharp.Interfaces;

namespace ProxyServerSharp.Implementation
{
    class Socks4ProxyCore: IProxyCore
    {
        private readonly int _port;
        private readonly int _transferUnitSize;

        private Socket _serverSocket;

        private bool _running;
        private Thread _acceptThread;
        private List<ConnectionInfo> _connections =
            new List<ConnectionInfo>();

        public Socks4ProxyCore(IProxyServerConfiguration configuration) 
        { 
            _port = configuration.Port;
            _transferUnitSize = configuration.TransferUnitSize;
        }

        public event LocalConnectEventHandler LocalConnect;
        public event LocalDisconnectEventHandler LocalDisconnect;
        public event LocalSentEventHandler LocalSent;
        public event LocalReceiveEventHandler LocalReceive;
        public event RemoteConnectEventHandler RemoteConnect;
        public event RemoteDisconnectEventHandler RemoteDisconnect;
        public event RemoteSendEventHandler RemoteSend;
        public event RemoteReceivedEventHandler RemoteReceive;

        public void Start()
        {
            SetupServerSocket();

            _running = true;

            _acceptThread = new Thread(AcceptConnections);
            _acceptThread.IsBackground = true;
            _acceptThread.Start();
        }

        public void Shutdown()
        {
            _running = false;
            foreach(ConnectionInfo connection in _connections)
            {
                connection.LocalSocket.Shutdown(SocketShutdown.Both);
                connection.LocalSocket.Close();
                connection.RemoteSocket.Shutdown(SocketShutdown.Both);
                connection.RemoteSocket.Close();
            }
        }

        private void SetupServerSocket()
        {
            IPEndPoint myEndpoint = new IPEndPoint(IPAddress.Loopback, 
                _port);

            // Create the socket, bind it, and start listening
            _serverSocket = new Socket(myEndpoint.Address.AddressFamily,
                SocketType.Stream, ProtocolType.Tcp);
            _serverSocket.Bind(myEndpoint);
            _serverSocket.Listen((int)SocketOptionName.MaxConnections);
        }

        private void AcceptConnections()
        {
            while (_running)
            {
                // Accept a connection
                ConnectionInfo connection = new ConnectionInfo();

                Socket socket = _serverSocket.Accept();

                if(_running == false)
                {
                    break;
                }

                connection.LocalSocket = socket;
                connection.RemoteSocket = new Socket(AddressFamily.InterNetwork,
                    SocketType.Stream, ProtocolType.Tcp);

                // Create the thread for the receives.
                connection.LocalThread = new Thread(ProcessLocalConnection);
                connection.LocalThread.IsBackground = true;
                connection.LocalThread.Start(connection);

                LocalConnect?.Invoke(this, (IPEndPoint)socket.RemoteEndPoint);

                // Store the socket
                lock (_connections) _connections.Add(connection);
            }
        }

        private void ProcessLocalConnection(object state)
        {
            ConnectionInfo connection = (ConnectionInfo)state;
            int bytesRead = 0;

            byte[] buffer = new byte[_transferUnitSize];
            try
            {
                // we are setting up the socks!
                bytesRead = connection.LocalSocket.Receive(buffer);

                Console.WriteLine("ProcessLocalConnection::Receive bytesRead={0}", bytesRead);
                for (int i = 0; i < bytesRead; i++)
                    Console.Write("{0:X2} ", buffer[i]);
                Console.Write("\n");

                if (bytesRead > 0)
                {
                    if (buffer[0] == 0x04 && buffer[1] == 0x01)
                    {
                        int remotePort = buffer[2] << 8 | buffer[3];
                        byte[] ipAddressBuffer = new byte[4];
                        Buffer.BlockCopy(buffer, 4, ipAddressBuffer, 0, 4);
                        
                        IPEndPoint remoteEndPoint = new IPEndPoint(new IPAddress(ipAddressBuffer), remotePort);

                        connection.RemoteSocket.Connect(remoteEndPoint);
                        if (connection.RemoteSocket.Connected)
                        {
                            Console.WriteLine("Connected to remote!");

                            RemoteConnect?.Invoke(this, remoteEndPoint);

                            byte[] socksResponse = new byte[] {
                                0x00, 0x5a,
                                buffer[2], buffer[3], // port
                                buffer[4], buffer[5], buffer[6], buffer[7] // IP
                            };
                            connection.LocalSocket.Send(socksResponse);

                            // Create the thread for the receives.
                            connection.RemoteThread = new Thread(ProcessRemoteConnection);
                            connection.RemoteThread.IsBackground = true;
                            connection.RemoteThread.Start(connection);
                        } 
                        else 
                        {
                            Console.WriteLine("Connection failed.");
                            byte[] socksResponse = new byte[] {
                                0x04, 
                                0x5b,
                                buffer[2], buffer[3], // port
                                buffer[4], buffer[5], buffer[6], buffer[7] // IP
                            };
                            connection.LocalSocket.Send(socksResponse);
                            return;

                        }
                    }
                }
                else if (bytesRead == 0) return;

                // start receiving actual data
                while (true)
                {
                    bytesRead = connection.LocalSocket.Receive(buffer);
                    if (bytesRead == 0) {
                        Console.WriteLine("Local connection closed!");
                        break;
                    } else {
                        connection.RemoteSocket.Send(buffer, bytesRead, SocketFlags.None);
                    }
                }
            }
            catch (Exception exc)
            {
                Console.WriteLine("Exception: " + exc);
            }
            finally
            {
                connection.LocalSocket.Close();
                connection.RemoteSocket.Close();
                lock (_connections) _connections.Remove(connection);
            }
        }

        private void ProcessRemoteConnection(object state)
        {
            ConnectionInfo connection = (ConnectionInfo)state;
            int bytesRead = 0;

            byte[] buffer = new byte[_transferUnitSize];
            try
            {
                // start receiving actual data
                while (true)
                {
                    bytesRead = connection.RemoteSocket.Receive(buffer);
                    if (bytesRead == 0) {
                        Console.WriteLine("Remote connection closed!");
                        break;
                    } else {
                        connection.LocalSocket.Send(buffer, bytesRead, SocketFlags.None);
                    }
                }
            }
            catch (SocketException exc)
            {
                Console.WriteLine("Socket exception: " + exc.SocketErrorCode);
            }
            catch (Exception exc)
            {
                Console.WriteLine("Exception: " + exc);
            }
            finally
            {
                Console.WriteLine("ProcessRemoteConnection Cleaning up...");
                connection.LocalSocket.Close();
                connection.RemoteSocket.Close();
                lock (_connections) 
                    _connections.Remove(connection);
            }
        }
    }

}
