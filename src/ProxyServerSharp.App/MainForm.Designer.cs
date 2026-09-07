namespace ProxyServerSharp.App;

partial class MainForm
{
    private readonly System.ComponentModel.IContainer components = new System.ComponentModel.Container();

    private ToolStrip _toolStrip;
    private ToolStripButton _startButton;
    private ToolStripButton _stopButton;
    private ToolStripSeparator _toolSeparator;
    private ToolStripButton _saveButton;
    private ToolStripButton _reloadButton;
    private StatusStrip _statusStrip;
    private ToolStripStatusLabel _statusLabel;
    private ToolStripStatusLabel _connectionsLabel;
    private ToolStripStatusLabel _trafficLabel;
    private TabControl _tabs;

    private TabPage _listenersTab;
    private SplitContainer _listenerSplit;
    private DataGridView _listenerGrid;
    private Panel _listenerButtons;
    private Button _addListenerButton;
    private Button _removeListenerButton;
    private TableLayoutPanel _listenerDetail;
    private Label _authLabel;
    private CheckedListBox _authList;
    private Label _realmLabel;
    private TextBox _realmBox;
    private Label _allowLabel;
    private TextBox _allowBox;
    private Label _digestLabel;
    private TextBox _digestBox;
    private CheckBox _tlsCheck;
    private CheckBox _bindCheck;
    private CheckBox _udpCheck;
    private Label _hintLabel;

    private TabPage _usersTab;
    private DataGridView _userGrid;
    private Panel _userButtons;
    private Button _addUserButton;
    private Button _removeUserButton;
    private Label _userHint;

    private TabPage _connectionsTab;
    private DataGridView _connectionGrid;

    private TabPage _logTab;
    private TextBox _logBox;
    private Panel _logButtons;
    private Button _clearLogButton;
    private CheckBox _verboseCheck;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            components.Dispose();
        }

        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        _toolStrip = new ToolStrip();
        _startButton = new ToolStripButton();
        _stopButton = new ToolStripButton();
        _toolSeparator = new ToolStripSeparator();
        _saveButton = new ToolStripButton();
        _reloadButton = new ToolStripButton();
        _statusStrip = new StatusStrip();
        _statusLabel = new ToolStripStatusLabel();
        _connectionsLabel = new ToolStripStatusLabel();
        _trafficLabel = new ToolStripStatusLabel();
        _tabs = new TabControl();
        _listenersTab = new TabPage();
        _listenerSplit = new SplitContainer();
        _listenerGrid = new DataGridView();
        _listenerButtons = new Panel();
        _addListenerButton = new Button();
        _removeListenerButton = new Button();
        _listenerDetail = new TableLayoutPanel();
        _authLabel = new Label();
        _authList = new CheckedListBox();
        _realmLabel = new Label();
        _realmBox = new TextBox();
        _allowLabel = new Label();
        _allowBox = new TextBox();
        _digestLabel = new Label();
        _digestBox = new TextBox();
        _tlsCheck = new CheckBox();
        _bindCheck = new CheckBox();
        _udpCheck = new CheckBox();
        _hintLabel = new Label();
        _usersTab = new TabPage();
        _userGrid = new DataGridView();
        _userButtons = new Panel();
        _addUserButton = new Button();
        _removeUserButton = new Button();
        _userHint = new Label();
        _connectionsTab = new TabPage();
        _connectionGrid = new DataGridView();
        _logTab = new TabPage();
        _logBox = new TextBox();
        _logButtons = new Panel();
        _clearLogButton = new Button();
        _verboseCheck = new CheckBox();

        SuspendLayout();
        _toolStrip.SuspendLayout();
        _statusStrip.SuspendLayout();
        _tabs.SuspendLayout();
        _listenersTab.SuspendLayout();
        ((System.ComponentModel.ISupportInitialize)_listenerSplit).BeginInit();
        _listenerSplit.Panel1.SuspendLayout();
        _listenerSplit.Panel2.SuspendLayout();
        _listenerSplit.SuspendLayout();
        ((System.ComponentModel.ISupportInitialize)_listenerGrid).BeginInit();
        _listenerButtons.SuspendLayout();
        _listenerDetail.SuspendLayout();
        _usersTab.SuspendLayout();
        ((System.ComponentModel.ISupportInitialize)_userGrid).BeginInit();
        _userButtons.SuspendLayout();
        _connectionsTab.SuspendLayout();
        ((System.ComponentModel.ISupportInitialize)_connectionGrid).BeginInit();
        _logTab.SuspendLayout();
        _logButtons.SuspendLayout();

        // Tool strip
        _toolStrip.Items.AddRange(new ToolStripItem[]
        {
            _startButton, _stopButton, _toolSeparator, _saveButton, _reloadButton,
        });
        _toolStrip.Location = new Point(0, 0);
        _toolStrip.Name = "_toolStrip";
        _toolStrip.Size = new Size(1000, 25);
        _toolStrip.GripStyle = ToolStripGripStyle.Hidden;

        _startButton.DisplayStyle = ToolStripItemDisplayStyle.Text;
        _startButton.Name = "_startButton";
        _startButton.Text = "Start";
        _startButton.ToolTipText = "Bind every enabled listener and begin accepting clients.";
        _startButton.Click += OnStartClicked;

        _stopButton.DisplayStyle = ToolStripItemDisplayStyle.Text;
        _stopButton.Name = "_stopButton";
        _stopButton.Text = "Stop";
        _stopButton.Enabled = false;
        _stopButton.Click += OnStopClicked;

        _saveButton.DisplayStyle = ToolStripItemDisplayStyle.Text;
        _saveButton.Name = "_saveButton";
        _saveButton.Text = "Save configuration";
        _saveButton.Click += OnSaveClicked;

        _reloadButton.DisplayStyle = ToolStripItemDisplayStyle.Text;
        _reloadButton.Name = "_reloadButton";
        _reloadButton.Text = "Reload";
        _reloadButton.Click += OnReloadClicked;

        // Status strip
        _statusStrip.Items.AddRange(new ToolStripItem[] { _statusLabel, _connectionsLabel, _trafficLabel });
        _statusStrip.Location = new Point(0, 578);
        _statusStrip.Name = "_statusStrip";
        _statusStrip.Size = new Size(1000, 22);

        _statusLabel.Name = "_statusLabel";
        _statusLabel.Text = "Stopped";
        _statusLabel.Spring = true;
        _statusLabel.TextAlign = ContentAlignment.MiddleLeft;

        _connectionsLabel.Name = "_connectionsLabel";
        _connectionsLabel.Text = "0 connections";

        _trafficLabel.Name = "_trafficLabel";
        _trafficLabel.Text = "0 B";
        _trafficLabel.BorderSides = ToolStripStatusLabelBorderSides.Left;

        // Tabs
        _tabs.Controls.Add(_listenersTab);
        _tabs.Controls.Add(_usersTab);
        _tabs.Controls.Add(_connectionsTab);
        _tabs.Controls.Add(_logTab);
        _tabs.Dock = DockStyle.Fill;
        _tabs.Location = new Point(0, 25);
        _tabs.Name = "_tabs";
        _tabs.SelectedIndex = 0;
        _tabs.Size = new Size(1000, 553);

        // Listeners tab
        _listenersTab.Controls.Add(_listenerSplit);
        _listenersTab.Location = new Point(4, 24);
        _listenersTab.Name = "_listenersTab";
        _listenersTab.Padding = new Padding(6);
        _listenersTab.Size = new Size(992, 525);
        _listenersTab.Text = "Listeners";
        _listenersTab.UseVisualStyleBackColor = true;

        _listenerSplit.Dock = DockStyle.Fill;
        _listenerSplit.Location = new Point(6, 6);
        _listenerSplit.Name = "_listenerSplit";
        _listenerSplit.Size = new Size(980, 513);
        _listenerSplit.SplitterDistance = 620;
        _listenerSplit.Panel1.Controls.Add(_listenerGrid);
        _listenerSplit.Panel1.Controls.Add(_listenerButtons);
        _listenerSplit.Panel2.Controls.Add(_listenerDetail);

        _listenerGrid.AllowUserToAddRows = false;
        _listenerGrid.AllowUserToDeleteRows = false;
        _listenerGrid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        _listenerGrid.Dock = DockStyle.Fill;
        _listenerGrid.EditMode = DataGridViewEditMode.EditOnEnter;
        _listenerGrid.Location = new Point(0, 32);
        _listenerGrid.MultiSelect = false;
        _listenerGrid.Name = "_listenerGrid";
        _listenerGrid.RowHeadersVisible = false;
        _listenerGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _listenerGrid.Size = new Size(620, 481);
        _listenerGrid.SelectionChanged += OnListenerSelectionChanged;

        _listenerButtons.Controls.Add(_addListenerButton);
        _listenerButtons.Controls.Add(_removeListenerButton);
        _listenerButtons.Dock = DockStyle.Top;
        _listenerButtons.Location = new Point(0, 0);
        _listenerButtons.Name = "_listenerButtons";
        _listenerButtons.Size = new Size(620, 32);

        _addListenerButton.Location = new Point(0, 3);
        _addListenerButton.Name = "_addListenerButton";
        _addListenerButton.Size = new Size(110, 25);
        _addListenerButton.Text = "Add listener";
        _addListenerButton.UseVisualStyleBackColor = true;
        _addListenerButton.Click += OnAddListenerClicked;

        _removeListenerButton.Location = new Point(116, 3);
        _removeListenerButton.Name = "_removeListenerButton";
        _removeListenerButton.Size = new Size(110, 25);
        _removeListenerButton.Text = "Remove";
        _removeListenerButton.UseVisualStyleBackColor = true;
        _removeListenerButton.Click += OnRemoveListenerClicked;

        _listenerDetail.ColumnCount = 1;
        _listenerDetail.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100F));
        _listenerDetail.Controls.Add(_authLabel, 0, 0);
        _listenerDetail.Controls.Add(_authList, 0, 1);
        _listenerDetail.Controls.Add(_realmLabel, 0, 2);
        _listenerDetail.Controls.Add(_realmBox, 0, 3);
        _listenerDetail.Controls.Add(_digestLabel, 0, 4);
        _listenerDetail.Controls.Add(_digestBox, 0, 5);
        _listenerDetail.Controls.Add(_allowLabel, 0, 6);
        _listenerDetail.Controls.Add(_allowBox, 0, 7);
        _listenerDetail.Controls.Add(_tlsCheck, 0, 8);
        _listenerDetail.Controls.Add(_bindCheck, 0, 9);
        _listenerDetail.Controls.Add(_udpCheck, 0, 10);
        _listenerDetail.Controls.Add(_hintLabel, 0, 11);
        _listenerDetail.Dock = DockStyle.Fill;
        _listenerDetail.Location = new Point(0, 0);
        _listenerDetail.Name = "_listenerDetail";
        _listenerDetail.Padding = new Padding(8, 0, 0, 0);
        _listenerDetail.RowCount = 12;
        _listenerDetail.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _listenerDetail.RowStyles.Add(new RowStyle(SizeType.Absolute, 130F));
        _listenerDetail.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _listenerDetail.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _listenerDetail.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _listenerDetail.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _listenerDetail.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _listenerDetail.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _listenerDetail.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _listenerDetail.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _listenerDetail.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        _listenerDetail.RowStyles.Add(new RowStyle(SizeType.Percent, 100F));
        _listenerDetail.Size = new Size(356, 513);

        _authLabel.AutoSize = true;
        _authLabel.Name = "_authLabel";
        _authLabel.Text = "Authentication methods";
        _authLabel.Margin = new Padding(3, 6, 3, 3);

        _authList.CheckOnClick = true;
        _authList.Dock = DockStyle.Fill;
        _authList.IntegralHeight = false;
        _authList.Name = "_authList";
        _authList.ItemCheck += OnAuthenticationItemCheck;

        _realmLabel.AutoSize = true;
        _realmLabel.Name = "_realmLabel";
        _realmLabel.Text = "Realm (HTTP Basic and Digest)";
        _realmLabel.Margin = new Padding(3, 8, 3, 3);

        _realmBox.Dock = DockStyle.Fill;
        _realmBox.Name = "_realmBox";
        _realmBox.TextChanged += OnListenerDetailChanged;

        _digestLabel.AutoSize = true;
        _digestLabel.Name = "_digestLabel";
        _digestLabel.Text = "Digest algorithms, strongest first (comma separated)";
        _digestLabel.Margin = new Padding(3, 8, 3, 3);

        _digestBox.Dock = DockStyle.Fill;
        _digestBox.Name = "_digestBox";
        _digestBox.PlaceholderText = "SHA-256, MD5";
        _digestBox.TextChanged += OnListenerDetailChanged;

        _allowLabel.AutoSize = true;
        _allowLabel.Name = "_allowLabel";
        _allowLabel.Text = "Allowed client addresses (comma separated CIDR)";
        _allowLabel.Margin = new Padding(3, 8, 3, 3);

        _allowBox.Dock = DockStyle.Fill;
        _allowBox.Name = "_allowBox";
        _allowBox.PlaceholderText = "empty means any";
        _allowBox.TextChanged += OnListenerDetailChanged;

        _tlsCheck.AutoSize = true;
        _tlsCheck.Name = "_tlsCheck";
        _tlsCheck.Text = "Terminate TLS (self-signed certificate)";
        _tlsCheck.Margin = new Padding(3, 10, 3, 3);
        _tlsCheck.UseVisualStyleBackColor = true;
        _tlsCheck.CheckedChanged += OnListenerDetailChanged;

        _bindCheck.AutoSize = true;
        _bindCheck.Name = "_bindCheck";
        _bindCheck.Text = "Allow SOCKS5 BIND";
        _bindCheck.UseVisualStyleBackColor = true;
        _bindCheck.CheckedChanged += OnListenerDetailChanged;

        _udpCheck.AutoSize = true;
        _udpCheck.Name = "_udpCheck";
        _udpCheck.Text = "Allow SOCKS5 UDP ASSOCIATE";
        _udpCheck.UseVisualStyleBackColor = true;
        _udpCheck.CheckedChanged += OnListenerDetailChanged;

        _hintLabel.Dock = DockStyle.Fill;
        _hintLabel.ForeColor = SystemColors.GrayText;
        _hintLabel.Name = "_hintLabel";
        _hintLabel.Margin = new Padding(3, 10, 3, 3);

        // Users tab
        _usersTab.Controls.Add(_userGrid);
        _usersTab.Controls.Add(_userHint);
        _usersTab.Controls.Add(_userButtons);
        _usersTab.Location = new Point(4, 24);
        _usersTab.Name = "_usersTab";
        _usersTab.Padding = new Padding(6);
        _usersTab.Size = new Size(992, 525);
        _usersTab.Text = "Users";
        _usersTab.UseVisualStyleBackColor = true;

        _userGrid.AllowUserToAddRows = false;
        _userGrid.AllowUserToDeleteRows = false;
        _userGrid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        _userGrid.Dock = DockStyle.Fill;
        _userGrid.EditMode = DataGridViewEditMode.EditOnEnter;
        _userGrid.MultiSelect = false;
        _userGrid.Name = "_userGrid";
        _userGrid.RowHeadersVisible = false;
        _userGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;

        _userHint.Dock = DockStyle.Bottom;
        _userHint.ForeColor = SystemColors.GrayText;
        _userHint.Height = 56;
        _userHint.Name = "_userHint";
        _userHint.Padding = new Padding(2, 6, 2, 2);
        _userHint.Text =
            "Passwords are stored as a PBKDF2-SHA256 verifier. Digest cannot verify a one-way hash, "
            + "so ticking \"Allow digest\" also keeps the password itself in the configuration file.";

        _userButtons.Controls.Add(_addUserButton);
        _userButtons.Controls.Add(_removeUserButton);
        _userButtons.Dock = DockStyle.Top;
        _userButtons.Name = "_userButtons";
        _userButtons.Size = new Size(980, 32);

        _addUserButton.Location = new Point(0, 3);
        _addUserButton.Name = "_addUserButton";
        _addUserButton.Size = new Size(110, 25);
        _addUserButton.Text = "Add user";
        _addUserButton.UseVisualStyleBackColor = true;
        _addUserButton.Click += OnAddUserClicked;

        _removeUserButton.Location = new Point(116, 3);
        _removeUserButton.Name = "_removeUserButton";
        _removeUserButton.Size = new Size(110, 25);
        _removeUserButton.Text = "Remove";
        _removeUserButton.UseVisualStyleBackColor = true;
        _removeUserButton.Click += OnRemoveUserClicked;

        // Connections tab
        _connectionsTab.Controls.Add(_connectionGrid);
        _connectionsTab.Location = new Point(4, 24);
        _connectionsTab.Name = "_connectionsTab";
        _connectionsTab.Padding = new Padding(6);
        _connectionsTab.Size = new Size(992, 525);
        _connectionsTab.Text = "Connections";
        _connectionsTab.UseVisualStyleBackColor = true;

        _connectionGrid.AllowUserToAddRows = false;
        _connectionGrid.AllowUserToDeleteRows = false;
        _connectionGrid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
        _connectionGrid.Dock = DockStyle.Fill;
        _connectionGrid.Name = "_connectionGrid";
        _connectionGrid.ReadOnly = true;
        _connectionGrid.RowHeadersVisible = false;
        _connectionGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;

        // Log tab
        _logTab.Controls.Add(_logBox);
        _logTab.Controls.Add(_logButtons);
        _logTab.Location = new Point(4, 24);
        _logTab.Name = "_logTab";
        _logTab.Padding = new Padding(6);
        _logTab.Size = new Size(992, 525);
        _logTab.Text = "Log";
        _logTab.UseVisualStyleBackColor = true;

        _logBox.Dock = DockStyle.Fill;
        _logBox.Font = new Font("Consolas", 9F);
        _logBox.Multiline = true;
        _logBox.Name = "_logBox";
        _logBox.ReadOnly = true;
        _logBox.ScrollBars = ScrollBars.Both;
        _logBox.WordWrap = false;

        _logButtons.Controls.Add(_clearLogButton);
        _logButtons.Controls.Add(_verboseCheck);
        _logButtons.Dock = DockStyle.Top;
        _logButtons.Name = "_logButtons";
        _logButtons.Size = new Size(980, 32);

        _clearLogButton.Location = new Point(0, 3);
        _clearLogButton.Name = "_clearLogButton";
        _clearLogButton.Size = new Size(110, 25);
        _clearLogButton.Text = "Clear";
        _clearLogButton.UseVisualStyleBackColor = true;
        _clearLogButton.Click += (_, _) => _logBox.Clear();

        _verboseCheck.AutoSize = true;
        _verboseCheck.Location = new Point(124, 7);
        _verboseCheck.Name = "_verboseCheck";
        _verboseCheck.Text = "Verbose (debug level)";
        _verboseCheck.UseVisualStyleBackColor = true;
        _verboseCheck.CheckedChanged += OnVerboseChanged;

        // Form
        AutoScaleDimensions = new SizeF(7F, 15F);
        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new Size(1000, 600);
        Controls.Add(_tabs);
        Controls.Add(_statusStrip);
        Controls.Add(_toolStrip);
        MinimumSize = new Size(820, 520);
        Name = "MainForm";
        StartPosition = FormStartPosition.CenterScreen;
        Text = "ProxyServerSharp";
        Load += OnFormLoad;
        FormClosing += OnFormClosing;

        _logButtons.ResumeLayout(false);
        _logButtons.PerformLayout();
        _logTab.ResumeLayout(false);
        _logTab.PerformLayout();
        ((System.ComponentModel.ISupportInitialize)_connectionGrid).EndInit();
        _connectionsTab.ResumeLayout(false);
        _userButtons.ResumeLayout(false);
        ((System.ComponentModel.ISupportInitialize)_userGrid).EndInit();
        _usersTab.ResumeLayout(false);
        _listenerDetail.ResumeLayout(false);
        _listenerDetail.PerformLayout();
        _listenerButtons.ResumeLayout(false);
        ((System.ComponentModel.ISupportInitialize)_listenerGrid).EndInit();
        _listenerSplit.Panel1.ResumeLayout(false);
        _listenerSplit.Panel2.ResumeLayout(false);
        ((System.ComponentModel.ISupportInitialize)_listenerSplit).EndInit();
        _listenerSplit.ResumeLayout(false);
        _listenersTab.ResumeLayout(false);
        _tabs.ResumeLayout(false);
        _statusStrip.ResumeLayout(false);
        _statusStrip.PerformLayout();
        _toolStrip.ResumeLayout(false);
        _toolStrip.PerformLayout();
        ResumeLayout(false);
        PerformLayout();
    }
}
