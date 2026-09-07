using System.ComponentModel;
using Microsoft.Extensions.Logging;
using ProxyServerSharp.Configuration;
using ProxyServerSharp.Diagnostics;
using ProxyServerSharp.Server;

namespace ProxyServerSharp.App;

/// <summary>
/// The desktop front-end: edit listeners and accounts, start and stop the server, and watch
/// connections and log output while it runs.
/// </summary>
/// <remarks>
/// All the protocol work lives in ProxyServerSharp.Core, so this form only builds a
/// <see cref="ProxyServerHost"/>, subscribes to its events and marshals them onto the UI thread.
/// The original version wired socket callbacks straight into the form.
/// </remarks>
public partial class MainForm : Form
{
    private const int MaxLogLines = 2000;

    private readonly BindingList<ListenerRow> _listenerRows = [];
    private readonly BindingList<UserRow> _userRows = [];
    private readonly UiLoggerProvider _logProvider = new();
    private readonly ILoggerFactory _loggerFactory;
    private readonly System.Windows.Forms.Timer _refreshTimer;
    private readonly Queue<string> _logLines = new();

    private ProxyServerHost? _server;
    private bool _suspendDetailUpdates;

    /// <summary>Creates the form and its logging pipeline.</summary>
    public MainForm()
    {
        InitializeComponent();

        _loggerFactory = LoggerFactory.Create(builder =>
        {
            builder.AddProvider(_logProvider);
            builder.SetMinimumLevel(LogLevel.Debug);
        });

        _logProvider.EntryWritten += OnLogEntryWritten;

        _refreshTimer = new System.Windows.Forms.Timer(components) { Interval = 1000 };
        _refreshTimer.Tick += OnRefreshTick;
    }

    private bool IsRunning => _server is not null;

    private void OnFormLoad(object? sender, EventArgs e)
    {
        BuildListenerGrid();
        BuildUserGrid();
        BuildConnectionGrid();
        PopulateAuthenticationList();

        LoadConfiguration(AppSettingsStore.Load());
        UpdateDetailPanel();
    }

    private void OnFormClosing(object? sender, FormClosingEventArgs e)
    {
        if (IsRunning)
        {
            StopServer();
        }

        _refreshTimer.Stop();
        _logProvider.EntryWritten -= OnLogEntryWritten;
        _loggerFactory.Dispose();
    }

    // ---- configuration ----------------------------------------------------

    private void LoadConfiguration(ProxyServerOptions options)
    {
        _listenerRows.Clear();
        foreach (ListenerOptions listener in options.Listeners)
        {
            _listenerRows.Add(new ListenerRow(listener));
        }

        _userRows.Clear();
        foreach (ProxyUserOptions user in options.Users)
        {
            _userRows.Add(new UserRow(user));
        }

        if (_listenerRows.Count > 0)
        {
            _listenerGrid.CurrentCell = _listenerGrid.Rows[0].Cells[1];
        }
    }

    private ProxyServerOptions BuildConfiguration()
    {
        ProxyServerOptions options = new();

        foreach (ListenerRow row in _listenerRows)
        {
            options.Listeners.Add(row.ToOptions());
        }

        foreach (UserRow row in _userRows)
        {
            options.Users.Add(row.ToOptions());
        }

        return options;
    }

    private void OnSaveClicked(object? sender, EventArgs e)
    {
        try
        {
            AppSettingsStore.Save(BuildConfiguration());
            _statusLabel.Text = $"Saved to {AppSettingsStore.DefaultPath}";
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            MessageBox.Show(this, exception.Message, "Could not save", MessageBoxButtons.OK, MessageBoxIcon.Warning);
        }
    }

    private void OnReloadClicked(object? sender, EventArgs e)
    {
        LoadConfiguration(AppSettingsStore.Load());
        UpdateDetailPanel();
        _statusLabel.Text = "Configuration reloaded.";
    }

    // ---- server lifetime --------------------------------------------------

    private void OnStartClicked(object? sender, EventArgs e)
    {
        if (IsRunning)
        {
            return;
        }

        // Commit any cell still being edited, so a port typed but not tabbed out of is honoured.
        _listenerGrid.EndEdit();
        _userGrid.EndEdit();

        ProxyServerHost server = new(BuildConfiguration(), _loggerFactory);
        server.ListenerFailed += OnListenerFailed;

        try
        {
            server.StartAsync().GetAwaiter().GetResult();
        }
        catch (Exception exception) when (exception is InvalidOperationException or FormatException)
        {
            server.ListenerFailed -= OnListenerFailed;
            server.DisposeAsync().AsTask().GetAwaiter().GetResult();

            MessageBox.Show(this, exception.Message, "Could not start", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        _server = server;
        _refreshTimer.Start();

        _startButton.Enabled = false;
        _stopButton.Enabled = true;
        _listenerGrid.ReadOnly = true;
        _userGrid.ReadOnly = true;
        _listenerDetail.Enabled = false;
        _addListenerButton.Enabled = false;
        _removeListenerButton.Enabled = false;

        _statusLabel.Text = string.Join(
            "   ",
            server.Listeners.Select(l => $"{l.Options.Protocol} {l.EndPoint}"));
    }

    private void OnStopClicked(object? sender, EventArgs e) => StopServer();

    private void StopServer()
    {
        if (_server is null)
        {
            return;
        }

        _refreshTimer.Stop();
        _server.ListenerFailed -= OnListenerFailed;
        _server.StopAsync().GetAwaiter().GetResult();
        _server.DisposeAsync().AsTask().GetAwaiter().GetResult();
        _server = null;

        _startButton.Enabled = true;
        _stopButton.Enabled = false;
        _listenerGrid.ReadOnly = false;
        _userGrid.ReadOnly = false;
        _listenerDetail.Enabled = true;
        _addListenerButton.Enabled = true;
        _removeListenerButton.Enabled = true;

        _connectionGrid.Rows.Clear();
        _statusLabel.Text = "Stopped";
        _connectionsLabel.Text = "0 connections";
        _trafficLabel.Text = "0 B";
    }

    private void OnListenerFailed(object? sender, ProxyListenerEventArgs e) =>
        BeginInvoke(() => MessageBox.Show(
            this,
            $"Listener '{e.ListenerName}' could not start:\r\n\r\n{e.Error}",
            "Listener failed",
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning));

    // ---- live view --------------------------------------------------------

    private void OnRefreshTick(object? sender, EventArgs e)
    {
        if (_server is null)
        {
            return;
        }

        IReadOnlyCollection<ProxyConnection> active = _server.Connections.Active;
        _connectionGrid.SuspendLayout();
        _connectionGrid.Rows.Clear();

        long total = 0;
        foreach (ProxyConnection connection in active)
        {
            total += connection.Counters.Total;
            _connectionGrid.Rows.Add(
                connection.Id,
                connection.ListenerName,
                connection.Protocol.ToString(),
                connection.ClientEndPoint.ToString(),
                connection.Identity?.Name ?? "",
                connection.Destination?.ToString() ?? "",
                connection.State.ToString(),
                FormatBytes(connection.Counters.ClientToRemote),
                FormatBytes(connection.Counters.RemoteToClient),
                $"{connection.Duration.TotalSeconds:F0}s");
        }

        _connectionGrid.ResumeLayout();

        _connectionsLabel.Text = $"{active.Count} connection(s), {_server.Connections.TotalAccepted} total";
        _trafficLabel.Text = FormatBytes(total);
    }

    private void OnLogEntryWritten(object? sender, LogEntry entry)
    {
        if (IsDisposed || !IsHandleCreated)
        {
            return;
        }

        // Log lines arrive on connection threads; hop to the UI thread to touch the text box.
        BeginInvoke(() => AppendLogLine(entry.ToString()));
    }

    private void AppendLogLine(string line)
    {
        _logLines.Enqueue(line);

        if (_logLines.Count > MaxLogLines)
        {
            // Rewriting the whole box is only acceptable because it happens once per trimmed
            // line, at which point the box already holds thousands of lines.
            while (_logLines.Count > MaxLogLines)
            {
                _logLines.Dequeue();
            }

            _logBox.Lines = [.. _logLines];
        }
        else
        {
            _logBox.AppendText(line + Environment.NewLine);
        }
    }

    private void OnVerboseChanged(object? sender, EventArgs e) =>
        _logProvider.MinimumLevel = _verboseCheck.Checked ? LogLevel.Debug : LogLevel.Information;

    // ---- listener editing -------------------------------------------------

    private void BuildListenerGrid()
    {
        _listenerGrid.AutoGenerateColumns = false;
        _listenerGrid.Columns.Add(new DataGridViewCheckBoxColumn
        {
            DataPropertyName = nameof(ListenerRow.Enabled),
            HeaderText = "On",
            FillWeight = 30,
        });
        _listenerGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(ListenerRow.Name),
            HeaderText = "Name",
            FillWeight = 90,
        });
        _listenerGrid.Columns.Add(new DataGridViewComboBoxColumn
        {
            DataPropertyName = nameof(ListenerRow.Protocol),
            HeaderText = "Protocol",
            DataSource = Enum.GetValues<ProxyProtocol>(),
            FillWeight = 70,
        });
        _listenerGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(ListenerRow.Address),
            HeaderText = "Address",
            FillWeight = 90,
        });
        _listenerGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(ListenerRow.Port),
            HeaderText = "Port",
            FillWeight = 50,
        });
        _listenerGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(ListenerRow.AuthenticationSummary),
            HeaderText = "Authentication",
            ReadOnly = true,
            FillWeight = 130,
        });

        _listenerGrid.DataSource = _listenerRows;
    }

    private void PopulateAuthenticationList()
    {
        _authList.Items.Clear();
        foreach (AuthenticationMethod method in Enum.GetValues<AuthenticationMethod>())
        {
            _authList.Items.Add(method);
        }
    }

    private ListenerRow? SelectedListener =>
        _listenerGrid.CurrentRow is { Index: >= 0 } row && row.Index < _listenerRows.Count
            ? _listenerRows[row.Index]
            : null;

    private void OnListenerSelectionChanged(object? sender, EventArgs e) => UpdateDetailPanel();

    /// <summary>Mirrors the selected listener into the detail panel, and greys out what does not apply.</summary>
    private void UpdateDetailPanel()
    {
        ListenerRow? listener = SelectedListener;

        _suspendDetailUpdates = true;
        try
        {
            bool has = listener is not null;
            _listenerDetail.Enabled = has && !IsRunning;

            if (listener is null)
            {
                for (int i = 0; i < _authList.Items.Count; i++)
                {
                    _authList.SetItemChecked(i, false);
                }

                _realmBox.Text = "";
                _digestBox.Text = "";
                _allowBox.Text = "";
                _hintLabel.Text = "";
                return;
            }

            bool isHttp = listener.Protocol == ProxyProtocol.Http;
            bool isSocks5 = listener.Protocol == ProxyProtocol.Socks5;

            for (int i = 0; i < _authList.Items.Count; i++)
            {
                AuthenticationMethod method = (AuthenticationMethod)_authList.Items[i];
                _authList.SetItemChecked(i, listener.Authentication.Contains(method));
            }

            _realmBox.Text = listener.Realm;
            _realmBox.Enabled = isHttp;
            _digestBox.Text = string.Join(", ", listener.DigestAlgorithms);
            _digestBox.Enabled = isHttp;
            _allowBox.Text = string.Join(", ", listener.Allow);
            _tlsCheck.Checked = listener.Tls;
            _tlsCheck.Enabled = isHttp;
            _bindCheck.Checked = listener.AllowBind;
            _bindCheck.Enabled = isSocks5;
            _udpCheck.Checked = listener.AllowUdpAssociate;
            _udpCheck.Enabled = isSocks5;

            _hintLabel.Text = DescribeProtocol(listener.Protocol);
        }
        finally
        {
            _suspendDetailUpdates = false;
        }
    }

    private static string DescribeProtocol(ProxyProtocol protocol) => protocol switch
    {
        ProxyProtocol.Socks4 =>
            "SOCKS4 and SOCKS4a. The only credential is the USERID field, which is an identifier "
            + "rather than a secret: pick UserId to require a known account, or Anonymous to accept any. "
            + "Pair it with an address allow list.",
        ProxyProtocol.Socks5 =>
            "SOCKS5 (RFC 1928). Offers no-auth and RFC 1929 username/password. The password travels "
            + "in the clear, as the RFC specifies, so keep this on loopback or a trusted network.",
        _ =>
            "HTTP proxy: CONNECT tunnelling plus absolute-URI forwarding. Basic and Bearer send a "
            + "reusable secret, so enable TLS with them; Digest never puts the password on the wire; "
            + "Negotiate uses the Windows login and needs no account password at all.",
    };

    private void OnAuthenticationItemCheck(object? sender, ItemCheckEventArgs e)
    {
        if (_suspendDetailUpdates || SelectedListener is not { } listener)
        {
            return;
        }

        AuthenticationMethod method = (AuthenticationMethod)_authList.Items[e.Index];

        // ItemCheck fires before the item's state changes, so act on the new value.
        if (e.NewValue == CheckState.Checked)
        {
            if (!listener.Authentication.Contains(method))
            {
                listener.Authentication.Add(method);
            }
        }
        else
        {
            listener.Authentication.Remove(method);
        }

        _listenerGrid.InvalidateRow(_listenerGrid.CurrentRow!.Index);
    }

    private void OnListenerDetailChanged(object? sender, EventArgs e)
    {
        if (_suspendDetailUpdates || SelectedListener is not { } listener)
        {
            return;
        }

        listener.Realm = _realmBox.Text;
        listener.DigestAlgorithms = SplitList(_digestBox.Text);
        listener.Allow = SplitList(_allowBox.Text);
        listener.Tls = _tlsCheck.Checked;
        listener.AllowBind = _bindCheck.Checked;
        listener.AllowUdpAssociate = _udpCheck.Checked;
    }

    private void OnAddListenerClicked(object? sender, EventArgs e)
    {
        int port = 1080 + _listenerRows.Count;
        _listenerRows.Add(new ListenerRow(new ListenerOptions
        {
            Name = $"listener-{_listenerRows.Count + 1}",
            Protocol = ProxyProtocol.Socks5,
            Address = "127.0.0.1",
            Port = port,
            Authentication = { AuthenticationMethod.Anonymous },
        }));

        _listenerGrid.CurrentCell = _listenerGrid.Rows[^1].Cells[1];
    }

    private void OnRemoveListenerClicked(object? sender, EventArgs e)
    {
        if (SelectedListener is { } listener)
        {
            _listenerRows.Remove(listener);
            UpdateDetailPanel();
        }
    }

    // ---- user editing -----------------------------------------------------

    private void BuildUserGrid()
    {
        _userGrid.AutoGenerateColumns = false;
        _userGrid.Columns.Add(new DataGridViewCheckBoxColumn
        {
            DataPropertyName = nameof(UserRow.Enabled),
            HeaderText = "On",
            FillWeight = 25,
        });
        _userGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(UserRow.Username),
            HeaderText = "Username",
            FillWeight = 100,
        });
        _userGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(UserRow.Password),
            HeaderText = "Password",
            FillWeight = 120,
        });
        _userGrid.Columns.Add(new DataGridViewCheckBoxColumn
        {
            DataPropertyName = nameof(UserRow.AllowDigest),
            HeaderText = "Allow digest",
            FillWeight = 60,
        });
        _userGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(UserRow.ListenerNames),
            HeaderText = "Listeners (blank = all)",
            FillWeight = 120,
        });

        _userGrid.DataSource = _userRows;
    }

    private void OnAddUserClicked(object? sender, EventArgs e)
    {
        _userRows.Add(new UserRow(new ProxyUserOptions { Username = $"user{_userRows.Count + 1}" }));
        _userGrid.CurrentCell = _userGrid.Rows[^1].Cells[1];
    }

    private void OnRemoveUserClicked(object? sender, EventArgs e)
    {
        if (_userGrid.CurrentRow is { Index: >= 0 } row && row.Index < _userRows.Count)
        {
            _userRows.RemoveAt(row.Index);
        }
    }

    // ---- helpers ----------------------------------------------------------

    private void BuildConnectionGrid()
    {
        foreach (string header in new[]
        {
            "#", "Listener", "Protocol", "Client", "User", "Destination", "State", "Sent", "Received", "Age",
        })
        {
            _connectionGrid.Columns.Add(new DataGridViewTextBoxColumn { HeaderText = header });
        }

        _connectionGrid.Columns[0].FillWeight = 35;
        _connectionGrid.Columns[6].FillWeight = 60;
    }

    private static List<string> SplitList(string value) =>
        [.. value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

    private static string FormatBytes(long bytes) => bytes switch
    {
        < 1024 => $"{bytes} B",
        < 1024 * 1024 => $"{bytes / 1024.0:F1} KB",
        < 1024L * 1024 * 1024 => $"{bytes / (1024.0 * 1024):F1} MB",
        _ => $"{bytes / (1024.0 * 1024 * 1024):F2} GB",
    };
}
