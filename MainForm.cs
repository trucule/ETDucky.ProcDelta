using ETDucky.ProcDelta.Models;
using ETDucky.ProcDelta.Services;

namespace ETDucky.ProcDelta;

/// <summary>
/// Three-tab WinForms shell: Record (capture a known-good baseline),
/// Compare (capture a failing run and diff against a loaded baseline, or
/// diff two saved baselines offline), Help (built-in primer on the
/// workflow).
///
/// No Designer file; every layout decision is in this file so reviewers
/// can read both the layout and the logic in one place.
/// </summary>
public sealed class MainForm : Form
{
    // ── Palette (matches ProviderExplorer for visual family coherence) ──
    private static readonly Color BgPage = Color.FromArgb(18, 18, 24);
    private static readonly Color BgCard = Color.FromArgb(30, 30, 42);
    private static readonly Color BgInput = Color.FromArgb(26, 26, 38);
    private static readonly Color Accent = Color.FromArgb(0, 180, 219);
    private static readonly Color Subtle = Color.FromArgb(50, 50, 65);
    private static readonly Color TextPrimary = Color.FromArgb(220, 220, 230);
    private static readonly Color TextMuted = Color.FromArgb(120, 120, 140);
    private static readonly Color Success = Color.FromArgb(34, 197, 94);
    private static readonly Color Warning = Color.FromArgb(217, 140, 0);
    private static readonly Color Danger = Color.FromArgb(239, 68, 68);

    private const int ControlPanelRows = 7;
    private const int ControlPanelHeight = ControlPanelRows * 32 + 32;

    private readonly TabControl _tabs;

    /// <summary>Which mode owns the currently-running capture (if any).</summary>
    private enum CaptureMode { None, Record, Compare }

    // Active capture state. Only ONE capture can run at a time: the
    // kernel session, app session, tracker and active session all belong
    // to whichever mode started it (_mode). Each mode additionally keeps
    // its OWN completed-session reference (_recSession / _cmpSession), so
    // saving a recorded baseline can never pick up a later compare run's
    // data (and vice versa).
    private CaptureMode _mode = CaptureMode.None;
    private ProcessTracker? _tracker;
    private EnvironmentalCapture? _capture;
    private AppRuntimeCapture? _appCapture;
    private CaptureSession? _session;       // the session of the running (or last) capture
    private CaptureSession? _recSession;    // last Record-mode session
    private CaptureSession? _cmpSession;    // last Compare-mode session
    private RegistryValueCache? _recValues; // registry hashes belonging to _recSession
    private System.Windows.Forms.Timer? _statusTimer;
    private string _launchNote = string.Empty;

    public MainForm()
    {
        Text = "ET Ducky ProcDelta";
        ClientSize = new Size(1200, 760);
        MinimumSize = new Size(900, 600);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = BgPage;
        ForeColor = TextPrimary;
        Font = new Font("Segoe UI", 9f);

        // Reclaim kernel-session slots stranded by a previous crashed run
        // (sessions survive process death; names are randomised per start,
        // so only a prefix sweep can find them).
        try { EnvironmentalCapture.CleanupOrphanedSessions(); } catch { }

        // Load the multi-resolution app.ico from the assembly's embedded
        // resources and assign to Form.Icon. Loading from a stream (rather
        // than ExtractAssociatedIcon on the .exe path) is the only approach
        // that works in single-file published builds, where
        // Assembly.Location returns empty.
        try
        {
            var asm = typeof(MainForm).Assembly;
            var resName = asm.GetName().Name + ".app.ico";
            using var stream = asm.GetManifestResourceStream(resName);
            if (stream != null) Icon = new System.Drawing.Icon(stream);
        }
        catch { /* best-effort title-bar icon */ }

        _tabs = new TabControl
        {
            Dock = DockStyle.Fill,
            Appearance = TabAppearance.Normal,
            SizeMode = TabSizeMode.Normal,
        };
        _tabs.TabPages.Add(BuildRecordTab());
        _tabs.TabPages.Add(BuildCompareTab());
        _tabs.TabPages.Add(BuildHelpTab());
        Controls.Add(_tabs);
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        base.OnFormClosing(e);
        try { _capture?.Dispose(); } catch { }
        try { _appCapture?.Dispose(); } catch { }
        try { _statusTimer?.Stop(); _statusTimer?.Dispose(); } catch { }
    }

    // =========================================================================
    // TAB 1 — RECORD
    // =========================================================================

    private TextBox? _recPattern;
    private TextBox? _recAppName;
    private TextBox? _recDescription;
    private TextBox? _recLaunch;
    private Button? _recStartBtn;
    private Button? _recStopBtn;
    private Button? _recSaveBtn;
    private Label? _recStatus;
    private ListBox? _recLiveList;
    private CheckBox? _recIncludeUser;

    private TabPage BuildRecordTab()
    {
        var page = new TabPage("Record") { BackColor = BgPage };

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            BackColor = BgPage,
            Padding = new Padding(8),
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, ControlPanelHeight));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        // ── Control panel ──
        var ctrl = NewControlPanel();

        ctrl.Controls.Add(NewMutedLabel("Process pattern:"), 0, 0);
        _recPattern = NewTextBox("e.g. AdobeCollabSync.exe  (| for multiple, * and ? wildcards ok; filled from Launch when empty)");
        ctrl.Controls.Add(_recPattern, 1, 0);

        _recStartBtn = NewButton("● Start", primary: true);
        _recStartBtn.Click += async (_, _) => await StartRecordingAsync();
        ctrl.Controls.Add(_recStartBtn, 2, 0);

        _recStopBtn = NewButton("■ Stop");
        _recStopBtn.Enabled = false;
        _recStopBtn.Click += async (_, _) => await StopCaptureAsync();
        ctrl.Controls.Add(_recStopBtn, 3, 0);

        ctrl.Controls.Add(NewMutedLabel("App name:"), 0, 1);
        _recAppName = NewTextBox("e.g. Adobe Acrobat");
        ctrl.SetColumnSpan(_recAppName, 3);
        ctrl.Controls.Add(_recAppName, 1, 1);

        ctrl.Controls.Add(NewMutedLabel("What you did:"), 0, 2);
        _recDescription = NewTextBox("e.g. Launched Acrobat, signed in, synced one PDF");
        ctrl.SetColumnSpan(_recDescription, 3);
        ctrl.Controls.Add(_recDescription, 1, 2);

        ctrl.Controls.Add(NewMutedLabel("Launch (optional):"), 0, 3);
        _recLaunch = NewTextBox("Executable to start after the capture is up; its process tree is tracked");
        ctrl.Controls.Add(_recLaunch, 1, 3);
        var recBrowse = NewButton("Browse…");
        recBrowse.Click += (_, _) => BrowseForExecutable(_recLaunch, _recPattern);
        ctrl.Controls.Add(recBrowse, 2, 3);
        ctrl.Controls.Add(new Panel { Dock = DockStyle.Fill, BackColor = BgCard }, 3, 3);

        _recStatus = new Label
        {
            Dock = DockStyle.Fill,
            ForeColor = TextMuted,
            TextAlign = ContentAlignment.MiddleLeft,
            Text = "Type a process name (or pick an executable to launch) and click Start. The tool records everything the matching processes touch.",
        };
        ctrl.SetColumnSpan(_recStatus, 4);
        ctrl.Controls.Add(_recStatus, 0, 4);

        // Off by default: the operator's account name is not needed for
        // the diff and the baseline is a file users are told to share.
        _recIncludeUser = NewCheckBox("Include my username in the baseline");
        ctrl.SetColumnSpan(_recIncludeUser, 4);
        ctrl.Controls.Add(_recIncludeUser, 0, 5);

        _recSaveBtn = NewButton("⤓ Save baseline…");
        _recSaveBtn.Enabled = false;
        _recSaveBtn.Click += (_, _) => SaveBaseline();
        ctrl.SetColumnSpan(_recSaveBtn, 4);
        ctrl.Controls.Add(_recSaveBtn, 0, 6);

        root.Controls.Add(ctrl, 0, 0);

        // ── Status spacer ──
        var spacer = new Panel { Dock = DockStyle.Fill, BackColor = BgPage };
        root.Controls.Add(spacer, 0, 1);

        // ── Live access list (tail of the capture) ──
        var listPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = BgCard,
        };
        listPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        listPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        listPanel.Controls.Add(new Label
        {
            Text = "LIVE ACCESSES (tail)",
            Dock = DockStyle.Fill,
            ForeColor = TextMuted,
            Font = new Font("Segoe UI", 8f, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(10, 0, 0, 0),
        }, 0, 0);

        _recLiveList = new ListBox
        {
            Dock = DockStyle.Fill,
            BackColor = BgPage,
            ForeColor = TextPrimary,
            BorderStyle = BorderStyle.None,
            Font = new Font("Consolas", 9f),
            IntegralHeight = false,
        };
        listPanel.Controls.Add(_recLiveList, 0, 1);

        root.Controls.Add(listPanel, 0, 2);

        page.Controls.Add(root);
        return page;
    }

    private async Task StartRecordingAsync()
    {
        if (_recPattern is null || _recAppName is null || _recDescription is null || _recLaunch is null) return;

        if (_mode != CaptureMode.None)
        {
            MessageBox.Show(this, "A capture is already running. Stop it before starting another.",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var launch = _recLaunch.Text.Trim();
        var pattern = _recPattern.Text.Trim();
        if (string.IsNullOrEmpty(pattern) && launch.Length > 0)
        {
            pattern = ProcessLauncher.PatternFor(launch);
            _recPattern.Text = pattern;
        }
        if (string.IsNullOrEmpty(pattern))
        {
            MessageBox.Show(this, "Process pattern is required (or pick an executable to launch).", "ProcDelta",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (!StartCapture(pattern, _recDescription.Text.Trim(), launch, CaptureMode.Record)) return;

        _recSession = _session;
        _recValues = _capture?.RegistryValues;

        SetRecordControlsRunning(true);
        StartStatusTimer();
        await Task.CompletedTask;
    }

    /// <summary>
    /// Shared capture bring-up for both modes. Returns false (after showing
    /// the appropriate error dialog) when the capture could not start.
    /// Any previous capture's objects are disposed first so a worker
    /// thread does not leak per run.
    /// </summary>
    private bool StartCapture(string pattern, string actionDescription, string launchPath, CaptureMode mode)
    {
        try { _appCapture?.Dispose(); } catch { }
        try { _capture?.Dispose(); } catch { }
        _appCapture = null;
        _capture = null;
        _launchNote = string.Empty;

        try
        {
            _tracker = new ProcessTracker(pattern);
            _session = new CaptureSession
            {
                ProcessPattern = pattern,
                ActionDescription = actionDescription,
            };
            _capture = new EnvironmentalCapture(_tracker, _session);
            _capture.Faulted += OnKernelCaptureFaulted;
            _capture.Start();

            // App-runtime capture is best-effort. If it fails to start
            // (e.g. one of the user-mode providers is unavailable on this
            // SKU), continue with kernel-only capture rather than aborting.
            try
            {
                _appCapture = new AppRuntimeCapture(_tracker, _session);
                _appCapture.Faulted += OnAppCaptureFaulted;
                _appCapture.Start();
            }
            catch { _appCapture = null; }
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show(this,
                "Access denied. The ProcDelta must run as Administrator.",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
        catch (InvalidOperationException ex)
        {
            MessageBox.Show(this,
                "Could not start the kernel session: " + ex.Message + Environment.NewLine + Environment.NewLine +
                "The tool uses a private kernel session and normally coexists with other ETW tools, " +
                "but the host limit is 8 concurrent kernel sessions. Stop one or more other ETW capture " +
                "tools and try again.",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Capture failed to start: {ex.GetType().Name}: {ex.Message}",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return false;
        }

        _mode = mode;

        if (!string.IsNullOrEmpty(launchPath))
        {
            var result = ProcessLauncher.Launch(launchPath, null);
            _launchNote = result.Note;
            if (!result.Started)
            {
                MessageBox.Show(this, result.Note, "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
        }
        return true;
    }

    /// <summary>
    /// The kernel pump died while a capture was supposed to be running.
    /// Raised from a background thread: marshal to the UI, tell the
    /// operator, and shut the capture down instead of letting the status
    /// line tick "Running..." over a dead session forever.
    /// </summary>
    private void OnKernelCaptureFaulted(string message)
    {
        if (IsDisposed) return;
        try
        {
            BeginInvoke(async () =>
            {
                var label = _mode == CaptureMode.Compare ? _cmpStatus : _recStatus;
                await StopCaptureAsync();
                if (label != null)
                {
                    label.ForeColor = Danger;
                    label.Text = "CAPTURE STOPPED: " + message;
                }
            });
        }
        catch { /* form tearing down */ }
    }

    /// <summary>
    /// The app-runtime pump died. Kernel capture continues (this surface
    /// is best-effort), but the operator should know it went dark.
    /// </summary>
    private void OnAppCaptureFaulted(string message)
    {
        if (IsDisposed) return;
        try
        {
            BeginInvoke(() =>
            {
                var label = _mode == CaptureMode.Compare ? _cmpStatus : _recStatus;
                if (label != null)
                {
                    label.ForeColor = Warning;
                    label.Text = "App-runtime capture stopped (kernel capture continues): " + message;
                }
            });
        }
        catch { /* form tearing down */ }
    }

    private async Task StopCaptureAsync()
    {
        if (_capture is null || _mode == CaptureMode.None) return;
        var stoppedMode = _mode;
        _mode = CaptureMode.None;

        try { await _capture.StopAsync(); } catch { }
        try { if (_appCapture is not null) await _appCapture.StopAsync(); } catch { }
        StopStatusTimer();
        SetRecordControlsRunning(false);
        SetCompareControlsRunning(false);
        UpdateStatusLabels();

        // Enable the follow-up action for the mode that OWNED the capture
        // (not whichever tab happens to be selected).
        if (stoppedMode == CaptureMode.Record && _recSaveBtn != null) _recSaveBtn.Enabled = true;
        if (stoppedMode == CaptureMode.Compare && _cmpDiffBtn != null) _cmpDiffBtn.Enabled = true;

        // Surface dropped events: a lossy capture means an incomplete
        // baseline / comparison and the operator should know.
        var lost = _capture.EventsLost;
        if (lost > 0)
        {
            var label = stoppedMode == CaptureMode.Compare ? _cmpStatus : _recStatus;
            if (label != null)
            {
                label.ForeColor = Warning;
                label.Text = $"Capture stopped, but {lost:N0} event(s) were dropped by ETW (buffers full). " +
                             "The capture may be incomplete; consider re-recording.";
            }
        }
    }

    private void SetRecordControlsRunning(bool running)
    {
        if (_recStartBtn != null) _recStartBtn.Enabled = !running;
        if (_recStopBtn != null) _recStopBtn.Enabled = running;
        if (_recPattern != null) _recPattern.Enabled = !running;
        if (_recAppName != null) _recAppName.Enabled = !running;
        if (_recLaunch != null) _recLaunch.Enabled = !running;
        if (_recSaveBtn != null) _recSaveBtn.Enabled = false;
        // Only one capture may run at a time: lock out the other tab's Start.
        if (_cmpStartBtn != null) _cmpStartBtn.Enabled = !running && _loadedBaseline != null;
    }

    private void SaveBaseline()
    {
        if (_recSession is null || _recPattern is null || _recAppName is null || _recDescription is null) return;
        if (_recSession.TotalEventCount == 0)
        {
            MessageBox.Show(this, "Nothing was captured; no matching processes ran during the recording window.",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var baseline = BaselineRecorder.Build(
            _recSession,
            _recAppName.Text.Trim(),
            _recPattern.Text.Trim(),
            _recDescription.Text.Trim(),
            _recValues,
            includeOperator: _recIncludeUser?.Checked == true);

        // Pre-save review: entries that name people, servers or customer
        // folders are listed so the operator can decide before the file
        // exists on disk. Nothing is removed automatically.
        var findings = BaselineScrubber.FindSensitive(baseline);
        if (findings.Count > 0)
        {
            const int previewMax = 10;
            var preview = string.Join(Environment.NewLine,
                findings.Take(previewMax).Select(f => $"  {f.Kind}: {Truncate(f.Target, 90)}   [{f.Reason}]"));
            var more = findings.Count > previewMax
                ? Environment.NewLine + $"  ... and {findings.Count - previewMax} more"
                : string.Empty;
            var answer = MessageBox.Show(this,
                $"{findings.Count} of {baseline.Entries.Count} entries may identify people, servers or customers:" +
                Environment.NewLine + Environment.NewLine + preview + more + Environment.NewLine + Environment.NewLine +
                "They will be saved as they are. Review the file before sharing it." + Environment.NewLine + Environment.NewLine +
                "Save anyway?",
                "ProcDelta", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (answer != DialogResult.Yes) return;
        }

        using var dlg = new SaveFileDialog
        {
            Title = "Save baseline",
            Filter = "ProcDelta baseline (*.baseline.json)|*.baseline.json|JSON (*.json)|*.json",
            FileName = SafeFilename(baseline.AppName) + ".baseline.json",
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;

        try
        {
            BaselineLoader.Save(baseline, dlg.FileName);
            if (_recStatus != null)
            {
                _recStatus.ForeColor = Success;
                _recStatus.Text = $"Saved {baseline.Entries.Count:N0} aggregated accesses to {dlg.FileName}";
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Save failed: {ex.GetType().Name}: {ex.Message}",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    // =========================================================================
    // TAB 2 — COMPARE
    // =========================================================================

    private TextBox? _cmpBaselinePath;
    private Label? _cmpBaselineSummary;
    private TextBox? _cmpPattern;
    private TextBox? _cmpLaunch;
    private Button? _cmpStartBtn;
    private Button? _cmpStopBtn;
    private Button? _cmpDiffBtn;
    private Button? _cmpExportBtn;
    private Button? _cmpOfflineBtn;
    private Label? _cmpStatus;
    private RichTextBox? _cmpReport;
    private CheckBox? _cmpProbeNetwork;
    private CheckBox? _cmpShowValues;
    private Baseline? _loadedBaseline;
    private DiagnosisReport? _lastReport;

    private TabPage BuildCompareTab()
    {
        var page = new TabPage("Compare") { BackColor = BgPage };

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            BackColor = BgPage,
            Padding = new Padding(8),
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, ControlPanelHeight));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        // ── Control panel ──
        var ctrl = NewControlPanel();

        ctrl.Controls.Add(NewMutedLabel("Baseline file:"), 0, 0);
        _cmpBaselinePath = NewTextBox("Click Load and pick a .baseline.json file");
        _cmpBaselinePath.ReadOnly = true;
        ctrl.Controls.Add(_cmpBaselinePath, 1, 0);

        var loadBtn = NewButton("Load…");
        loadBtn.Click += (_, _) => LoadBaseline();
        ctrl.Controls.Add(loadBtn, 2, 0);
        ctrl.Controls.Add(new Panel { Dock = DockStyle.Fill, BackColor = BgCard }, 3, 0);

        _cmpBaselineSummary = new Label
        {
            Dock = DockStyle.Fill,
            ForeColor = TextMuted,
            TextAlign = ContentAlignment.MiddleLeft,
            Text = "No baseline loaded.",
        };
        ctrl.SetColumnSpan(_cmpBaselineSummary, 4);
        ctrl.Controls.Add(_cmpBaselineSummary, 0, 1);

        ctrl.Controls.Add(NewMutedLabel("Process pattern:"), 0, 2);
        _cmpPattern = NewTextBox("(auto-filled from baseline when loaded)");
        ctrl.Controls.Add(_cmpPattern, 1, 2);

        _cmpStartBtn = NewButton("● Start", primary: true);
        _cmpStartBtn.Enabled = false;
        _cmpStartBtn.Click += async (_, _) => await StartCompareCaptureAsync();
        ctrl.Controls.Add(_cmpStartBtn, 2, 2);

        _cmpStopBtn = NewButton("■ Stop");
        _cmpStopBtn.Enabled = false;
        _cmpStopBtn.Click += async (_, _) => await StopCaptureAsync();
        ctrl.Controls.Add(_cmpStopBtn, 3, 2);

        ctrl.Controls.Add(NewMutedLabel("Launch (optional):"), 0, 3);
        _cmpLaunch = NewTextBox("Executable to start after the capture is up; its process tree is tracked");
        ctrl.Controls.Add(_cmpLaunch, 1, 3);
        var cmpBrowse = NewButton("Browse…");
        cmpBrowse.Click += (_, _) => BrowseForExecutable(_cmpLaunch, _cmpPattern);
        ctrl.Controls.Add(cmpBrowse, 2, 3);
        ctrl.Controls.Add(new Panel { Dock = DockStyle.Fill, BackColor = BgCard }, 3, 3);

        _cmpStatus = new Label
        {
            Dock = DockStyle.Fill,
            ForeColor = TextMuted,
            TextAlign = ContentAlignment.MiddleLeft,
            Text = "Load a baseline, then have the user perform the same action while you click Start, then Stop. Or diff two saved baselines offline.",
        };
        ctrl.SetColumnSpan(_cmpStatus, 4);
        ctrl.Controls.Add(_cmpStatus, 0, 4);

        // Both off by default. A baseline is untrusted input: with the
        // defaults, nothing in it can make this tool open a socket, touch a
        // UNC path, or print a registry value into the report.
        _cmpProbeNetwork = NewCheckBox("Probe network targets (TCP connects, DNS, UNC paths)");
        ctrl.SetColumnSpan(_cmpProbeNetwork, 2);
        ctrl.Controls.Add(_cmpProbeNetwork, 0, 5);

        _cmpShowValues = NewCheckBox("Show registry values in report");
        ctrl.SetColumnSpan(_cmpShowValues, 2);
        ctrl.Controls.Add(_cmpShowValues, 2, 5);

        _cmpDiffBtn = NewButton("Δ Run diff");
        _cmpDiffBtn.Enabled = false;
        _cmpDiffBtn.Click += async (_, _) => await RunDiffAsync();
        ctrl.SetColumnSpan(_cmpDiffBtn, 2);
        ctrl.Controls.Add(_cmpDiffBtn, 0, 6);

        _cmpExportBtn = NewButton("⤓ Export…");
        _cmpExportBtn.Enabled = false;
        _cmpExportBtn.Click += (_, _) => ExportReport();
        ctrl.Controls.Add(_cmpExportBtn, 2, 6);

        _cmpOfflineBtn = NewButton("Diff files…");
        _cmpOfflineBtn.Click += async (_, _) => await RunOfflineDiffAsync();
        ctrl.Controls.Add(_cmpOfflineBtn, 3, 6);

        root.Controls.Add(ctrl, 0, 0);

        var spacer = new Panel { Dock = DockStyle.Fill, BackColor = BgPage };
        root.Controls.Add(spacer, 0, 1);

        var reportPanel = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 2,
            BackColor = BgCard,
        };
        reportPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        reportPanel.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        reportPanel.Controls.Add(new Label
        {
            Text = "DIAGNOSIS REPORT",
            Dock = DockStyle.Fill,
            ForeColor = TextMuted,
            Font = new Font("Segoe UI", 8f, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            Padding = new Padding(10, 0, 0, 0),
        }, 0, 0);

        _cmpReport = new RichTextBox
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            BackColor = BgCard,
            ForeColor = TextPrimary,
            BorderStyle = BorderStyle.None,
            Font = new Font("Consolas", 9f),
            Text = "Run a diff to populate this panel.",
        };
        reportPanel.Controls.Add(_cmpReport, 0, 1);

        root.Controls.Add(reportPanel, 0, 2);

        page.Controls.Add(root);
        return page;
    }

    private void LoadBaseline()
    {
        if (_cmpBaselinePath is null || _cmpBaselineSummary is null || _cmpPattern is null || _cmpStartBtn is null) return;

        using var dlg = new OpenFileDialog
        {
            Title = "Load baseline",
            Filter = "ProcDelta baseline (*.baseline.json)|*.baseline.json|JSON (*.json)|*.json|All (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;

        var loaded = BaselineLoader.TryLoad(dlg.FileName, out var error);
        if (loaded is null)
        {
            MessageBox.Show(this, error, "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        _loadedBaseline = loaded;
        _cmpBaselinePath.Text = dlg.FileName;
        _cmpPattern.Text = loaded.ProcessPattern;
        _cmpBaselineSummary.ForeColor = TextMuted;
        _cmpBaselineSummary.Text =
            $"{loaded.AppName}{(string.IsNullOrEmpty(loaded.AppVersion) ? "" : " " + loaded.AppVersion)}  ·  recorded {loaded.RecordedAtUtc:yyyy-MM-dd} on {loaded.RecordedOn}{(string.IsNullOrEmpty(loaded.RecordedBy) ? "" : " by " + loaded.RecordedBy)}  ·  " +
            $"{loaded.Entries.Count:N0} aggregated accesses  ·  action: \"{loaded.ActionDescription}\"";
        _cmpStartBtn.Enabled = _mode == CaptureMode.None;
    }

    private async Task StartCompareCaptureAsync()
    {
        if (_cmpPattern is null || _cmpLaunch is null || _loadedBaseline is null) return;

        if (_mode != CaptureMode.None)
        {
            MessageBox.Show(this, "A capture is already running. Stop it before starting another.",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var launch = _cmpLaunch.Text.Trim();
        var pattern = _cmpPattern.Text.Trim();
        if (string.IsNullOrEmpty(pattern) && launch.Length > 0)
        {
            pattern = ProcessLauncher.PatternFor(launch);
            _cmpPattern.Text = pattern;
        }
        if (string.IsNullOrEmpty(pattern))
        {
            MessageBox.Show(this, "Process pattern is required.", "ProcDelta",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        if (!StartCapture(pattern, _loadedBaseline.ActionDescription, launch, CaptureMode.Compare)) return;

        _cmpSession = _session;

        SetCompareControlsRunning(true);
        StartStatusTimer();
        await Task.CompletedTask;
    }

    private void SetCompareControlsRunning(bool running)
    {
        if (_cmpStartBtn != null) _cmpStartBtn.Enabled = !running && _loadedBaseline != null;
        if (_cmpStopBtn != null) _cmpStopBtn.Enabled = running;
        if (_cmpLaunch != null) _cmpLaunch.Enabled = !running;
        if (_cmpDiffBtn != null) _cmpDiffBtn.Enabled = false;
        if (_cmpExportBtn != null) _cmpExportBtn.Enabled = false;
        if (_cmpOfflineBtn != null) _cmpOfflineBtn.Enabled = !running;
        // Only one capture may run at a time: lock out the other tab's Start.
        if (_recStartBtn != null) _recStartBtn.Enabled = !running;
    }

    private async Task RunDiffAsync()
    {
        if (_loadedBaseline is null || _cmpSession is null || _cmpReport is null || _cmpBaselinePath is null) return;

        // The diff re-reads registry values, walks ACLs and TCP-probes
        // unreachable hosts (3s timeout each): run it off the UI thread
        // so the window never freezes, even on candidate-heavy reports.
        var baseline = _loadedBaseline;
        var session = _cmpSession;
        var baselinePath = _cmpBaselinePath.Text;
        var options = new InspectOptions(
            AllowNetwork: _cmpProbeNetwork?.Checked == true,
            ShowRegistryValues: _cmpShowValues?.Checked == true);

        if (_cmpDiffBtn != null) _cmpDiffBtn.Enabled = false;
        if (_cmpStatus != null)
        {
            _cmpStatus.ForeColor = TextMuted;
            _cmpStatus.Text = "Running diff (probing live state)…";
        }

        try
        {
            _lastReport = await Task.Run(() => DiffEngine.Compare(baseline, session, baselinePath, options));
        }
        catch (Exception ex)
        {
            if (_cmpStatus != null)
            {
                _cmpStatus.ForeColor = Danger;
                _cmpStatus.Text = $"Diff failed: {ex.GetType().Name}: {ex.Message}";
            }
            if (_cmpDiffBtn != null) _cmpDiffBtn.Enabled = true;
            return;
        }

        ShowReport(_lastReport);
        if (_cmpDiffBtn != null) _cmpDiffBtn.Enabled = true;
    }

    /// <summary>
    /// Diff two saved baselines without any live inspection: the loaded
    /// baseline is the reference, the file picked here stands in for the
    /// broken machine.
    /// </summary>
    private async Task RunOfflineDiffAsync()
    {
        if (_cmpReport is null) return;

        if (_loadedBaseline is null || _cmpBaselinePath is null)
        {
            MessageBox.Show(this, "Load the reference baseline first, then pick the baseline recorded on the broken machine.",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dlg = new OpenFileDialog
        {
            Title = "Pick the baseline recorded on the broken machine",
            Filter = "ProcDelta baseline (*.baseline.json)|*.baseline.json|JSON (*.json)|*.json|All (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;

        var against = BaselineLoader.TryLoad(dlg.FileName, out var error);
        if (against is null)
        {
            MessageBox.Show(this, error, "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        var reference = _loadedBaseline;
        var referencePath = _cmpBaselinePath.Text;
        if (_cmpStatus != null)
        {
            _cmpStatus.ForeColor = TextMuted;
            _cmpStatus.Text = "Running offline diff…";
        }

        try
        {
            _lastReport = await Task.Run(() => DiffEngine.CompareBaselines(reference, against, referencePath));
        }
        catch (Exception ex)
        {
            if (_cmpStatus != null)
            {
                _cmpStatus.ForeColor = Danger;
                _cmpStatus.Text = $"Diff failed: {ex.GetType().Name}: {ex.Message}";
            }
            return;
        }

        ShowReport(_lastReport);
    }

    private void ShowReport(DiagnosisReport report)
    {
        if (_cmpReport != null) _cmpReport.Text = DiffEngine.RenderPlainText(report);
        if (_cmpExportBtn != null) _cmpExportBtn.Enabled = true;
        if (_cmpStatus != null)
        {
            var n = report.Candidates.Count;
            var coverage = report.BaselineEntryCount > 0 ? $" Coverage {Math.Round(report.Coverage * 100)}%." : string.Empty;
            var lowCoverage = report.BaselineEntryCount > 0 && report.Coverage < DiagnosisReport.LowCoverageThreshold;
            _cmpStatus.ForeColor = lowCoverage ? Danger : n == 0 ? Success : Warning;
            _cmpStatus.Text = n == 0
                ? "Diff complete: no environmental differences detected vs baseline." + coverage
                : $"Diff complete: {n} candidate(s) found. Top candidates appear first in the report below.{coverage}"
                  + (lowCoverage ? " Low coverage: the runs may not be comparable." : string.Empty);
        }
    }

    private void ExportReport()
    {
        if (_lastReport is null) return;
        using var dlg = new SaveFileDialog
        {
            Title = "Export diagnosis report",
            Filter = "Markdown (*.md)|*.md|Text (*.txt)|*.txt",
            FileName = $"{SafeFilename(_lastReport.AppName)}-diagnosis-{DateTime.Now:yyyyMMdd-HHmmss}.md",
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            var markdown = dlg.FileName.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)
                ? DiffEngine.RenderPlainText(_lastReport)
                : DiffEngine.RenderMarkdown(_lastReport);
            File.WriteAllText(dlg.FileName, markdown);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Export failed: {ex.GetType().Name}: {ex.Message}",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    // =========================================================================
    // TAB 3 — HELP
    // =========================================================================

    private static TabPage BuildHelpTab()
    {
        var page = new TabPage("Help") { BackColor = BgPage };
        var textBox = new TextBox
        {
            Dock = DockStyle.Fill,
            Multiline = true,
            ReadOnly = true,
            ScrollBars = ScrollBars.Vertical,
            BackColor = BgPage,
            ForeColor = TextPrimary,
            BorderStyle = BorderStyle.None,
            Font = new Font("Consolas", 9.5f),
            WordWrap = true,
        };

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("ProcDelta: Workflow");
        sb.AppendLine("===================");
        sb.AppendLine();
        sb.AppendLine("This tool diagnoses why an application fails on one machine but works on");
        sb.AppendLine("another. The diagnosis is deterministic: no AI, no cloud, no inference.");
        sb.AppendLine("Just a comparison between two real captures.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Step 1: Record (on a working machine)");
        sb.AppendLine("-------------------------------------");
        sb.AppendLine("Type the executable name to watch (e.g. AdobeCollabSync.exe). Use the");
        sb.AppendLine("pipe character to watch several names at once: Acrobat.exe|AcroCEF.exe.");
        sb.AppendLine("Wildcards work too: Acro* matches Acrobat.exe and AcroCEF.exe.");
        sb.AppendLine();
        sb.AppendLine("Or pick the executable in the Launch field. The tool starts it after the");
        sb.AppendLine("capture is up, at your normal (non-administrator) integrity level, and");
        sb.AppendLine("tracks its whole process tree. No pattern guessing and no confusion with");
        sb.AppendLine("an instance that was already running.");
        sb.AppendLine();
        sb.AppendLine("Add a short description of what you're about to do. Click Start. Perform");
        sb.AppendLine("the action exactly as a user would (launch the app, sign in, open a doc).");
        sb.AppendLine("Click Stop. The tool will have captured every registry, file, network");
        sb.AppendLine("and DNS access made by the tracked process tree, with every result each");
        sb.AppendLine("one returned. Click Save baseline and pick a filename.");
        sb.AppendLine();
        sb.AppendLine("The baseline JSON is portable: it normalises user-profile paths, user-hive");
        sb.AppendLine("registry keys (SIDs), generated names (GUIDs, hashes, temp files), and");
        sb.AppendLine("resolved addresses (keyed by hostname) so it works on any host.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Step 2: Compare (on the broken machine)");
        sb.AppendLine("---------------------------------------");
        sb.AppendLine("Switch to the Compare tab. Click Load and pick the baseline JSON. The");
        sb.AppendLine("process pattern auto-fills from the baseline. Click Start, have the user");
        sb.AppendLine("perform the same action that fails for them, click Stop, then click Run");
        sb.AppendLine("diff. The report lists every environmental access that disagreed between");
        sb.AppendLine("the baseline and this run, ranked by severity.");
        sb.AppendLine();
        sb.AppendLine("Diff files: if you recorded a baseline on the broken machine instead, load");
        sb.AppendLine("the known-good one, click Diff files and pick the other. No capture runs");
        sb.AppendLine("and nothing on this machine is inspected.");
        sb.AppendLine();
        sb.AppendLine("Severities:");
        sb.AppendLine();
        sb.AppendLine("  HIGH    Regression: the baseline ever succeeded, this run never did.");
        sb.AppendLine("  MEDIUM  Missing dependency (baseline access never attempted in this run)");
        sb.AppendLine("          or value drift between baseline and this host.");
        sb.AppendLine("  LOW     Novel failure not present in baseline. May be unrelated.");
        sb.AppendLine();
        sb.AppendLine("The report header says how comparable the two runs are (coverage: how");
        sb.AppendLine("much of the baseline this run also did), whether the app version and");
        sb.AppendLine("Windows build match, and how many baseline accesses happened after the");
        sb.AppendLine("point this run reached (those are not listed as missing). Candidates");
        sb.AppendLine("within two seconds of a tracked root process exiting are marked.");
        sb.AppendLine();
        sb.AppendLine("For each candidate the report shows what failed, what the baseline observed");
        sb.AppendLine("instead, which process made the access, and what's at that target on the");
        sb.AppendLine("broken machine right now (the Live State line). Many candidates under one");
        sb.AppendLine("key, folder or host are shown as one group.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Command line");
        sb.AppendLine("------------");
        sb.AppendLine("The same capture and diff run headless, for MECM, Intune or an RMM:");
        sb.AppendLine();
        sb.AppendLine("  ETDucky.ProcDelta.exe record  --launch \"C:\\...\\app.exe\" --out app.baseline.json");
        sb.AppendLine("  ETDucky.ProcDelta.exe compare --baseline app.baseline.json --launch ... --report out.md");
        sb.AppendLine("  ETDucky.ProcDelta.exe diff    --baseline good.json --against broken.json --report out.md");
        sb.AppendLine("  ETDucky.ProcDelta.exe replay  --etl trace.etl --pattern app.exe --out app.baseline.json");
        sb.AppendLine("  ETDucky.ProcDelta.exe help");
        sb.AppendLine();
        sb.AppendLine("Use --pattern and --duration instead of --launch to watch an app you start");
        sb.AppendLine("yourself. From cmd use start /wait; from PowerShell use Start-Process -Wait.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("What gets captured");
        sb.AppendLine("------------------");
        sb.AppendLine("Kernel-mode providers (private kernel session):");
        sb.AppendLine();
        sb.AppendLine("  Microsoft-Windows-Kernel-Process   process start, stop, exit code");
        sb.AppendLine("  Microsoft-Windows-Kernel-FileIO    Create/Delete with NTSTATUS result");
        sb.AppendLine("  Microsoft-Windows-Kernel-Registry  Query/Set/Open/Create with NTSTATUS result");
        sb.AppendLine("                                     + value content SHA-256 on first encounter");
        sb.AppendLine("  Microsoft-Windows-Kernel-Network   TCP connects, keyed by hostname when the");
        sb.AppendLine("                                     DNS answer was seen");
        sb.AppendLine();
        sb.AppendLine("User-mode providers (second session, best-effort):");
        sb.AppendLine();
        sb.AppendLine("  Microsoft-Windows-Services         service start/stop, SCM errors");
        sb.AppendLine("  Microsoft-Windows-WinINet          HTTP/HTTPS requests, proxy, cert errors");
        sb.AppendLine("  Microsoft-Windows-CAPI2            certificate chain validation");
        sb.AppendLine("  Microsoft-Windows-DNS-Client       name resolution results and failures");
        sb.AppendLine("  .NET CLR Runtime                   managed exceptions, assembly load failures");
        sb.AppendLine();
        sb.AppendLine("The status line shows how many events each user-mode provider delivered,");
        sb.AppendLine("so a provider that is silent on a host is visible, and how many events ETW");
        sb.AppendLine("dropped, while the capture is still running.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Privacy and network");
        sb.AppendLine("-------------------");
        sb.AppendLine("The tool makes no network connection on its own. The only outbound");
        sb.AppendLine("connections are the TCP probes and DNS lookups during Run diff, and only");
        sb.AppendLine("while \"Probe network targets\" is checked. The same checkbox gates UNC and");
        sb.AppendLine("network drive paths, because opening a file on a share authenticates as");
        sb.AppendLine("you. It is off by default.");
        sb.AppendLine();
        sb.AppendLine("A baseline is a file you may have received from someone else. With the");
        sb.AppendLine("defaults, nothing in it can make this tool connect anywhere or print a");
        sb.AppendLine("registry value. \"Show registry values in report\" is off by default; the");
        sb.AppendLine("report then shows each value's type, size and SHA-256 hash, which is");
        sb.AppendLine("enough to compare against the baseline.");
        sb.AppendLine();
        sb.AppendLine("Baselines contain paths, registry key and value names, hosts and ports,");
        sb.AppendLine("and SHA-256 hashes of registry values. They do not contain registry value");
        sb.AppendLine("content. URLs are reduced to scheme, host and path at capture time; query");
        sb.AppendLine("strings and fragments are never recorded. .NET exception messages are not");
        sb.AppendLine("recorded. Your username is not recorded unless \"Include my username in");
        sb.AppendLine("the baseline\" is checked. Before saving, the tool lists entries that");
        sb.AppendLine("contain '@', UNC paths, or paths outside the standard Windows folders so");
        sb.AppendLine("you can review them. The only file written without being asked is a crash");
        sb.AppendLine("log under %LOCALAPPDATA%\\ETDucky.ProcDelta, and only if the tool crashes.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Limitations");
        sb.AppendLine("-----------");
        sb.AppendLine("- Uses a private kernel session. Coexists with PerfView, xperf, the");
        sb.AppendLine("  ET Ducky agent, and other ETW tools. Windows allows up to 8 concurrent");
        sb.AppendLine("  kernel sessions per host; only if every slot is taken does Start fail.");
        sb.AppendLine("  Sessions stranded by a crash are cleaned up at next launch.");
        sb.AppendLine();
        sb.AppendLine("- Administrator required. The manifest requests elevation; without it,");
        sb.AppendLine("  the kernel session can't open. The application under test is started");
        sb.AppendLine("  at your normal integrity level when you use Launch without arguments.");
        sb.AppendLine();
        sb.AppendLine("- The baseline captures behaviour at the time of recording. If the app's");
        sb.AppendLine("  behaviour is environment-dependent on the recording machine too (e.g.");
        sb.AppendLine("  the working user is signed in to a service the recorded baseline assumes),");
        sb.AppendLine("  the baseline encodes that state. Recording on a clean machine that has");
        sb.AppendLine("  just completed initial app setup tends to produce the most portable");
        sb.AppendLine("  baselines.");

        textBox.Text = sb.ToString();
        page.Controls.Add(textBox);
        return page;
    }

    // =========================================================================
    // STATUS TIMER (drives live-list updates + status label refresh)
    // =========================================================================

    private void StartStatusTimer()
    {
        StopStatusTimer();
        _statusTimer = new System.Windows.Forms.Timer { Interval = 500 };
        _statusTimer.Tick += (_, _) => UpdateStatusLabels();
        _statusTimer.Start();
    }

    private void StopStatusTimer()
    {
        if (_statusTimer != null)
        {
            try { _statusTimer.Stop(); _statusTimer.Dispose(); } catch { }
            _statusTimer = null;
        }
    }

    private void UpdateStatusLabels()
    {
        if (_session is null || _tracker is null) return;

        var trackedNow = _tracker.TrackedCount;
        var totalSeen = _session.MatchedPidCount;
        var elapsed = _session.Duration;
        var rows = _session.TotalEventCount;
        var lost = _capture?.EventsLost ?? 0;

        var msg = $"Running for {elapsed.TotalSeconds:0.0}s. Tracked PIDs: {trackedNow} now, {totalSeen} seen total. {rows:N0} accesses captured, {lost:N0} dropped.";
        if (_appCapture != null) msg += $"  User-mode: {_appCapture.DeliveredSummary}.";
        if (totalSeen == 0)
            msg += "  Waiting for the pattern to match; start (or restart) the target app now.";
        if (_launchNote.Length > 0)
            msg += "  " + _launchNote;

        var color = lost > 0 ? Warning : TextMuted;
        if (_recStatus != null && _tabs.SelectedIndex == 0) { _recStatus.ForeColor = color; _recStatus.Text = msg; }
        if (_cmpStatus != null && _tabs.SelectedIndex == 1) { _cmpStatus.ForeColor = color; _cmpStatus.Text = msg; }

        if (_recLiveList != null && _tabs.SelectedIndex == 0)
        {
            // Tail of the most recent accesses, oldest at top: a locked
            // snapshot, so the ETW threads can keep appending while we
            // paint without tearing the underlying collection.
            var tail = _session.SnapshotTail();

            _recLiveList.BeginUpdate();
            _recLiveList.Items.Clear();
            foreach (var a in tail)
            {
                _recLiveList.Items.Add(FormatLiveRow(a));
            }
            if (_recLiveList.Items.Count > 0) _recLiveList.TopIndex = _recLiveList.Items.Count - 1;
            _recLiveList.EndUpdate();
        }
    }

    private static string FormatLiveRow(EnvironmentalAccess a)
    {
        var kind = a.Kind.ToString().PadRight(8);
        var op = a.Operation.PadRight(12);
        var res = a.Result.PadRight(22);
        return $"{a.TimestampUtc:HH:mm:ss.fff}  {kind} {op} {res} {a.Target}";
    }

    // =========================================================================
    // SHARED UI HELPERS
    // =========================================================================

    private void BrowseForExecutable(TextBox? launchBox, TextBox? patternBox)
    {
        if (launchBox is null) return;
        using var dlg = new OpenFileDialog
        {
            Title = "Pick the executable to launch and track",
            Filter = "Executables (*.exe)|*.exe|All (*.*)|*.*",
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        launchBox.Text = dlg.FileName;
        if (patternBox != null && string.IsNullOrWhiteSpace(patternBox.Text))
            patternBox.Text = ProcessLauncher.PatternFor(dlg.FileName);
    }

    private static TableLayoutPanel NewControlPanel()
    {
        var ctrl = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 4,
            RowCount = ControlPanelRows,
            BackColor = BgCard,
            Padding = new Padding(10),
        };
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        for (var i = 0; i < ControlPanelRows; i++) ctrl.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        return ctrl;
    }

    private static Label NewMutedLabel(string text) => new()
    {
        Text = text,
        ForeColor = TextMuted,
        TextAlign = ContentAlignment.MiddleLeft,
        Dock = DockStyle.Fill,
    };

    private static TextBox NewTextBox(string placeholder) => new()
    {
        Dock = DockStyle.Fill,
        BackColor = BgInput,
        ForeColor = TextPrimary,
        BorderStyle = BorderStyle.FixedSingle,
        Font = new Font("Consolas", 9f),
        PlaceholderText = placeholder,
    };

    private static CheckBox NewCheckBox(string text) => new()
    {
        Text = text,
        Dock = DockStyle.Fill,
        ForeColor = TextPrimary,
        BackColor = BgCard,
        Checked = false,
        AutoSize = false,
        TextAlign = ContentAlignment.MiddleLeft,
    };

    private static string Truncate(string s, int n)
        => s.Length <= n ? s : string.Concat(s.AsSpan(0, n), "…");

    private static Button NewButton(string text, bool primary = false)
    {
        var b = new Button
        {
            Text = text,
            Dock = DockStyle.Fill,
            Height = 28,
            Margin = new Padding(4),
            BackColor = primary ? Accent : Subtle,
            ForeColor = primary ? Color.White : TextPrimary,
            FlatStyle = FlatStyle.Flat,
            Font = new Font("Segoe UI", 9f),
        };
        b.FlatAppearance.BorderSize = 0;
        return b;
    }

    private static string SafeFilename(string input)
    {
        var invalid = System.IO.Path.GetInvalidFileNameChars();
        var s = string.Concat(input.Select(c => invalid.Contains(c) ? '_' : c));
        if (string.IsNullOrWhiteSpace(s)) s = "baseline";
        return s;
    }
}
