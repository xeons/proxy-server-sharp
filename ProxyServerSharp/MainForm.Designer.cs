namespace ProxyServerSharp
{
    partial class MainForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.startProxyButton = new System.Windows.Forms.Button();
            this.statusCaptionLabel = new System.Windows.Forms.Label();
            this.statusLabel = new System.Windows.Forms.Label();
            this.debugTextBox = new System.Windows.Forms.TextBox();
            this.transferUnitSizeLabel = new System.Windows.Forms.Label();
            this.transferUnitSizeComboBox = new System.Windows.Forms.ComboBox();
            this.portLabel = new System.Windows.Forms.Label();
            this.portTextBox = new System.Windows.Forms.TextBox();
            this.SuspendLayout();
            // 
            // startProxyButton
            // 
            this.startProxyButton.Location = new System.Drawing.Point(448, 168);
            this.startProxyButton.Name = "startProxyButton";
            this.startProxyButton.Size = new System.Drawing.Size(64, 24);
            this.startProxyButton.TabIndex = 0;
            this.startProxyButton.Text = "Start";
            this.startProxyButton.UseVisualStyleBackColor = true;
            this.startProxyButton.Click += new System.EventHandler(this.startProxyButton_Click);
            // 
            // statusCaptionLabel
            // 
            this.statusCaptionLabel.AutoSize = true;
            this.statusCaptionLabel.Location = new System.Drawing.Point(8, 8);
            this.statusCaptionLabel.Name = "statusCaptionLabel";
            this.statusCaptionLabel.Size = new System.Drawing.Size(40, 13);
            this.statusCaptionLabel.TabIndex = 1;
            this.statusCaptionLabel.Text = "Status:";
            // 
            // statusLabel
            // 
            this.statusLabel.AutoSize = true;
            this.statusLabel.Location = new System.Drawing.Point(56, 8);
            this.statusLabel.Name = "statusLabel";
            this.statusLabel.Size = new System.Drawing.Size(33, 13);
            this.statusLabel.TabIndex = 2;
            this.statusLabel.Text = "Idle...";
            // 
            // debugTextBox
            // 
            this.debugTextBox.Location = new System.Drawing.Point(8, 32);
            this.debugTextBox.Multiline = true;
            this.debugTextBox.Name = "debugTextBox";
            this.debugTextBox.ScrollBars = System.Windows.Forms.ScrollBars.Vertical;
            this.debugTextBox.Size = new System.Drawing.Size(504, 128);
            this.debugTextBox.TabIndex = 3;
            // 
            // transferUnitSizeLabel
            // 
            this.transferUnitSizeLabel.AutoSize = true;
            this.transferUnitSizeLabel.Location = new System.Drawing.Point(8, 172);
            this.transferUnitSizeLabel.Name = "transferUnitSizeLabel";
            this.transferUnitSizeLabel.Size = new System.Drawing.Size(128, 13);
            this.transferUnitSizeLabel.TabIndex = 4;
            this.transferUnitSizeLabel.Text = "Transfer Unit Size (bytes):";
            // 
            // transferUnitSizeComboBox
            // 
            this.transferUnitSizeComboBox.FormattingEnabled = true;
            this.transferUnitSizeComboBox.Location = new System.Drawing.Point(144, 168);
            this.transferUnitSizeComboBox.Name = "transferUnitSizeComboBox";
            this.transferUnitSizeComboBox.Size = new System.Drawing.Size(120, 21);
            this.transferUnitSizeComboBox.TabIndex = 5;
            // 
            // portLabel
            // 
            this.portLabel.AutoSize = true;
            this.portLabel.Location = new System.Drawing.Point(8, 196);
            this.portLabel.Name = "portLabel";
            this.portLabel.Size = new System.Drawing.Size(29, 13);
            this.portLabel.TabIndex = 6;
            this.portLabel.Text = "Port:";
            // 
            // portTextBox
            // 
            this.portTextBox.Location = new System.Drawing.Point(144, 192);
            this.portTextBox.Name = "portTextBox";
            this.portTextBox.Size = new System.Drawing.Size(72, 20);
            this.portTextBox.TabIndex = 7;
            this.portTextBox.Text = "1080";
            this.portTextBox.TextAlign = System.Windows.Forms.HorizontalAlignment.Center;
            // 
            // MainForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(537, 222);
            this.Controls.Add(this.portTextBox);
            this.Controls.Add(this.portLabel);
            this.Controls.Add(this.transferUnitSizeComboBox);
            this.Controls.Add(this.transferUnitSizeLabel);
            this.Controls.Add(this.debugTextBox);
            this.Controls.Add(this.statusLabel);
            this.Controls.Add(this.statusCaptionLabel);
            this.Controls.Add(this.startProxyButton);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.FixedSingle;
            this.Name = "MainForm";
            this.Text = "SOCKS4 Server ";
            this.Load += new System.EventHandler(this.Form1_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.Button startProxyButton;
        private System.Windows.Forms.Label statusCaptionLabel;
        private System.Windows.Forms.Label statusLabel;
        private System.Windows.Forms.TextBox debugTextBox;
        private System.Windows.Forms.Label transferUnitSizeLabel;
        private System.Windows.Forms.ComboBox transferUnitSizeComboBox;
        private System.Windows.Forms.Label portLabel;
        private System.Windows.Forms.TextBox portTextBox;
    }
}

