using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace ProxyServerSharp
{
    public partial class MainForm : Form
    {
        SOCKS4Server server;

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
                server = new SOCKS4Server(int.Parse(portTextBox.Text),
                    int.Parse((string)transferUnitSizeComboBox.SelectedItem));
                server.LocalConnect += new ConnectEventHandler(server_LocalConnect);
                server.RemoteConnect += new ConnectEventHandler(server_RemoteConnect);
                server.Start();
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
