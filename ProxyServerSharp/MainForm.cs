using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;
using ProxyServerSharp.Implementation;
using ProxyServerSharp.Interfaces;

namespace ProxyServerSharp
{
    public partial class MainForm : Form
    {
        Socks4ProxyCore _proxyCore;

        public MainForm()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            for (int i = 8; i < 16; i++)
                transferUnitSizeComboBox.Items.Add(Math.Pow(2, i).ToString());

            transferUnitSizeComboBox.SelectedIndex = 4;
        }

        void server_RemoteConnect(object sender, System.Net.IPEndPoint iep)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new MethodInvoker(delegate()
                {
                    debugTextBox.AppendText("Connecting to " + iep.ToString() + "\r\n");
                }));
            }
        }

        void server_LocalConnect(object sender, System.Net.IPEndPoint iep)
        {
            if (this.InvokeRequired)
            {
                this.BeginInvoke(new MethodInvoker(delegate()
                {
                    debugTextBox.AppendText("Connection from " + iep.ToString() + "\r\n");
                }));
            }
        }

        private void startProxyButton_Click(object sender, EventArgs e)
        {
            if (startProxyButton.Text == "Start")
            {
                _proxyCore = new Socks4ProxyCore(int.Parse(portTextBox.Text),
                    int.Parse((string)transferUnitSizeComboBox.SelectedItem));
                _proxyCore.LocalConnect += new LocalConnectEventHandler(server_LocalConnect);
                _proxyCore.RemoteConnect += new RemoteConnectEventHandler(server_RemoteConnect);
                _proxyCore.Start();
                statusLabel.Text = "Started";
                startProxyButton.Text = "Stop";
            }
            else
            {
                //
            }
        }
    }
}
