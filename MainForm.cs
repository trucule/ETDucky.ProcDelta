using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using ETDucky.ProcDelta.Models;
using ETDucky.ProcDelta.Services;

namespace ETDucky.ProcDelta;

/// <summary>
/// Three-tab WinForms shell: Record (capture a known-good baseline),
/// Compare (capture a failing run and diff against a loaded baseline),
/// Help (built-in primer on the workflow).
///
/// No Designer file — every layout decision is in this file so reviewers
/// can read both the layout and the logic in one place.
/// </summary>
public sealed class MainForm : Form
{
    // ── Palette (matches ProviderExplorer for visual family coherence) ──
    private static readonly Color BgPage      = Color.FromArgb(18, 18, 24);
    private static readonly Color BgCard      = Color.FromArgb(30, 30, 42);
    private static readonly Color BgInput     = Color.FromArgb(26, 26, 38);
    private static readonly Color Accent      = Color.FromArgb(0, 180, 219);
    private static readonly Color Subtle      = Color.FromArgb(50, 50, 65);
    private static readonly Color TextPrimary = Color.FromArgb(220, 220, 230);
    private static readonly Color TextMuted   = Color.FromArgb(120, 120, 140);
    private static readonly Color Border      = Color.FromArgb(40, 40, 55);
    private static readonly Color Success     = Color.FromArgb(34, 197, 94);
    private static readonly Color Warning     = Color.FromArgb(217, 140, 0);
    private static readonly Color Danger      = Color.FromArgb(239, 68, 68);

    private readonly TabControl _tabs;

    // Active capture state (shared between Record + Compare tabs).
    private ProcessTracker? _tracker;
    private EnvironmentalCapture? _capture;
    private AppRuntimeCapture?    _appCapture;
    private CaptureSession? _session;
    private System.Windows.Forms.Timer? _statusTimer;

    public MainForm()
    {
        Text          = "ET Ducky ProcDelta";
        ClientSize    = new Size(1200, 720);
        MinimumSize   = new Size(900, 560);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor     = BgPage;
        ForeColor     = TextPrimary;
        Font          = new Font("Segoe UI", 9f);

        // Load the multi-resolution app.ico from the assembly's embedded
        // resources and assign to Form.Icon — this drives the title bar,
        // taskbar, and Alt+Tab thumbnail. Loading from a stream (rather
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
            Dock       = DockStyle.Fill,
            Appearance = TabAppearance.Normal,
            SizeMode   = TabSizeMode.Normal,
        };
        _tabs.TabPages.Add(BuildRecordTab());
        _tabs.TabPages.Add(BuildCompareTab());
        _tabs.TabPages.Add(BuildHelpTab());
        Controls.Add(_tabs);
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        base.OnFormClosing(e);
        try { _capture?.Dispose(); }    catch { }
        try { _appCapture?.Dispose(); } catch { }
        try { _statusTimer?.Stop(); _statusTimer?.Dispose(); } catch { }
    }

    // =========================================================================
    // TAB 1 — RECORD
    // =========================================================================

    private TextBox? _recPattern;
    private TextBox? _recAppName;
    private TextBox? _recDescription;
    private Button?  _recStartBtn;
    private Button?  _recStopBtn;
    private Button?  _recSaveBtn;
    private Label?   _recStatus;
    private ListBox? _recLiveList;

    private TabPage BuildRecordTab()
    {
        var page = new TabPage("Record") { BackColor = BgPage };

        var root = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 1,
            RowCount    = 3,
            BackColor   = BgPage,
            Padding     = new Padding(8),
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 200));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        root.RowStyles.Add(new RowStyle(SizeType.Percent,  100));

        // ── Control panel ──
        var ctrl = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 4,
            RowCount    = 5,
            BackColor   = BgCard,
            Padding     = new Padding(10),
        };
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        for (var i = 0; i < 5; i++) ctrl.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));

        ctrl.Controls.Add(NewMutedLabel("Process pattern:"), 0, 0);
        _recPattern = NewTextBox("e.g. AdobeCollabSync.exe  (use | for multiple)");
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

        _recStatus = new Label
        {
            Dock      = DockStyle.Fill,
            ForeColor = TextMuted,
            TextAlign = ContentAlignment.MiddleLeft,
            Text      = "Type a process name and click Start. The tool will watch for matching processes to spawn and record everything they touch.",
        };
        ctrl.SetColumnSpan(_recStatus, 4);
        ctrl.Controls.Add(_recStatus, 0, 3);

        _recSaveBtn = NewButton("⤓ Save baseline…");
        _recSaveBtn.Enabled = false;
        _recSaveBtn.Click += (_, _) => SaveBaseline();
        ctrl.SetColumnSpan(_recSaveBtn, 4);
        ctrl.Controls.Add(_recSaveBtn, 0, 4);

        root.Controls.Add(ctrl, 0, 0);

        // ── Status spacer ──
        var spacer = new Panel { Dock = DockStyle.Fill, BackColor = BgPage };
        root.Controls.Add(spacer, 0, 1);

        // ── Live access list (tail of the capture) ──
        var listPanel = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 1,
            RowCount    = 2,
            BackColor   = BgCard,
        };
        listPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        listPanel.RowStyles.Add(new RowStyle(SizeType.Percent,  100));

        listPanel.Controls.Add(new Label
        {
            Text      = "LIVE ACCESSES (tail)",
            Dock      = DockStyle.Fill,
            ForeColor = TextMuted,
            Font      = new Font("Segoe UI", 8f, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            Padding   = new Padding(10, 0, 0, 0),
        }, 0, 0);

        _recLiveList = new ListBox
        {
            Dock        = DockStyle.Fill,
            BackColor   = BgPage,
            ForeColor   = TextPrimary,
            BorderStyle = BorderStyle.None,
            Font        = new Font("Consolas", 9f),
            IntegralHeight = false,
        };
        listPanel.Controls.Add(_recLiveList, 0, 1);

        root.Controls.Add(listPanel, 0, 2);

        page.Controls.Add(root);
        return page;
    }

    private async Task StartRecordingAsync()
    {
        if (_recPattern is null || _recAppName is null || _recDescription is null) return;

        var pattern = _recPattern.Text.Trim();
        if (string.IsNullOrEmpty(pattern))
        {
            MessageBox.Show(this, "Process pattern is required.", "ProcDelta",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        try
        {
            _tracker = new ProcessTracker(pattern);
            _session = new CaptureSession
            {
                ProcessPattern    = pattern,
                ActionDescription = _recDescription.Text.Trim(),
            };
            _capture = new EnvironmentalCapture(_tracker, _session);
            _capture.Start();

            // App-runtime capture is best-effort. If it fails to start
            // (e.g. one of the user-mode providers is unavailable on this
            // SKU), continue with kernel-only capture rather than aborting.
            try
            {
                _appCapture = new AppRuntimeCapture(_tracker, _session);
                _appCapture.Start();
            }
            catch { _appCapture = null; }
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show(this,
                "Access denied. The ProcDelta must run as Administrator.",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }
        catch (InvalidOperationException ex)
        {
            MessageBox.Show(this,
                "Could not start the kernel session: " + ex.Message + Environment.NewLine + Environment.NewLine +
                "The tool uses a private kernel session and normally coexists with other ETW tools, " +
                "but the host limit is 8 concurrent kernel sessions. Stop one or more other ETW capture " +
                "tools and try again.",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Capture failed to start: {ex.GetType().Name}: {ex.Message}",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        SetRecordControlsRunning(true);
        StartStatusTimer();
        await Task.CompletedTask;
    }

    private async Task StopCaptureAsync()
    {
        if (_capture is null) return;
        try { await _capture.StopAsync(); }    catch { }
        try { if (_appCapture is not null) await _appCapture.StopAsync(); } catch { }
        _appCapture = null;
        StopStatusTimer();
        SetRecordControlsRunning(false);
        SetCompareControlsRunning(false);
        UpdateStatusLabels();

        // After Record-mode stop, enable Save. After Compare-mode stop,
        // enable Run Diff. We can tell which mode we're in by which tab
        // is active.
        if (_tabs.SelectedIndex == 0 && _recSaveBtn != null) _recSaveBtn.Enabled = true;
        if (_tabs.SelectedIndex == 1 && _cmpDiffBtn != null) _cmpDiffBtn.Enabled = true;
    }

    private void SetRecordControlsRunning(bool running)
    {
        if (_recStartBtn != null) _recStartBtn.Enabled = !running;
        if (_recStopBtn  != null) _recStopBtn.Enabled  = running;
        if (_recPattern  != null) _recPattern.Enabled  = !running;
        if (_recAppName  != null) _recAppName.Enabled  = !running;
        if (_recSaveBtn  != null) _recSaveBtn.Enabled  = false;
    }

    private void SaveBaseline()
    {
        if (_session is null || _recPattern is null || _recAppName is null || _recDescription is null) return;
        if (_session.Accesses.Count == 0)
        {
            MessageBox.Show(this, "Nothing was captured — no matching processes ran during the recording window.",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var baseline = BaselineRecorder.Build(
            _session,
            _recAppName.Text.Trim(),
            _recPattern.Text.Trim(),
            _recDescription.Text.Trim(),
            _capture?.RegistryValues);

        using var dlg = new SaveFileDialog
        {
            Title      = "Save baseline",
            Filter     = "ProcDelta baseline (*.baseline.json)|*.baseline.json|JSON (*.json)|*.json",
            FileName   = SafeFilename(baseline.AppName) + ".baseline.json",
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
    private Label?   _cmpBaselineSummary;
    private TextBox? _cmpPattern;
    private Button?  _cmpStartBtn;
    private Button?  _cmpStopBtn;
    private Button?  _cmpDiffBtn;
    private Button?  _cmpExportBtn;
    private Label?   _cmpStatus;
    private RichTextBox? _cmpReport;
    private Baseline? _loadedBaseline;
    private DiagnosisReport? _lastReport;

    private TabPage BuildCompareTab()
    {
        var page = new TabPage("Compare") { BackColor = BgPage };

        var root = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 1,
            RowCount    = 3,
            BackColor   = BgPage,
            Padding     = new Padding(8),
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 200));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));
        root.RowStyles.Add(new RowStyle(SizeType.Percent,  100));

        // ── Control panel ──
        var ctrl = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 4,
            RowCount    = 5,
            BackColor   = BgCard,
            Padding     = new Padding(10),
        };
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 130));
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        ctrl.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        for (var i = 0; i < 5; i++) ctrl.RowStyles.Add(new RowStyle(SizeType.Absolute, 32));

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
            Dock      = DockStyle.Fill,
            ForeColor = TextMuted,
            TextAlign = ContentAlignment.MiddleLeft,
            Text      = "No baseline loaded.",
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

        _cmpStatus = new Label
        {
            Dock      = DockStyle.Fill,
            ForeColor = TextMuted,
            TextAlign = ContentAlignment.MiddleLeft,
            Text      = "Load a baseline, then have the user perform the same action while you click Start → Stop.",
        };
        ctrl.SetColumnSpan(_cmpStatus, 4);
        ctrl.Controls.Add(_cmpStatus, 0, 3);

        _cmpDiffBtn = NewButton("Δ Run diff");
        _cmpDiffBtn.Enabled = false;
        _cmpDiffBtn.Click += (_, _) => RunDiff();
        ctrl.SetColumnSpan(_cmpDiffBtn, 2);
        ctrl.Controls.Add(_cmpDiffBtn, 0, 4);

        _cmpExportBtn = NewButton("⤓ Export report…");
        _cmpExportBtn.Enabled = false;
        _cmpExportBtn.Click += (_, _) => ExportReport();
        ctrl.SetColumnSpan(_cmpExportBtn, 2);
        ctrl.Controls.Add(_cmpExportBtn, 2, 4);

        root.Controls.Add(ctrl, 0, 0);

        var spacer = new Panel { Dock = DockStyle.Fill, BackColor = BgPage };
        root.Controls.Add(spacer, 0, 1);

        var reportPanel = new TableLayoutPanel
        {
            Dock        = DockStyle.Fill,
            ColumnCount = 1,
            RowCount    = 2,
            BackColor   = BgCard,
        };
        reportPanel.RowStyles.Add(new RowStyle(SizeType.Absolute, 26));
        reportPanel.RowStyles.Add(new RowStyle(SizeType.Percent,  100));

        reportPanel.Controls.Add(new Label
        {
            Text      = "DIAGNOSIS REPORT",
            Dock      = DockStyle.Fill,
            ForeColor = TextMuted,
            Font      = new Font("Segoe UI", 8f, FontStyle.Bold),
            TextAlign = ContentAlignment.MiddleLeft,
            Padding   = new Padding(10, 0, 0, 0),
        }, 0, 0);

        _cmpReport = new RichTextBox
        {
            Dock        = DockStyle.Fill,
            ReadOnly    = true,
            BackColor   = BgCard,
            ForeColor   = TextPrimary,
            BorderStyle = BorderStyle.None,
            Font        = new Font("Consolas", 9f),
            Text        = "Run a diff to populate this panel.",
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
            Title  = "Load baseline",
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
            $"{loaded.AppName}  ·  recorded {loaded.RecordedAtUtc:yyyy-MM-dd} on {loaded.RecordedOn} by {loaded.RecordedBy}  ·  " +
            $"{loaded.Entries.Count:N0} aggregated accesses  ·  action: \"{loaded.ActionDescription}\"";
        _cmpStartBtn.Enabled = true;
    }

    private async Task StartCompareCaptureAsync()
    {
        if (_cmpPattern is null || _loadedBaseline is null) return;
        var pattern = _cmpPattern.Text.Trim();
        if (string.IsNullOrEmpty(pattern))
        {
            MessageBox.Show(this, "Process pattern is required.", "ProcDelta",
                MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        try
        {
            _tracker = new ProcessTracker(pattern);
            _session = new CaptureSession
            {
                ProcessPattern    = pattern,
                ActionDescription = _loadedBaseline.ActionDescription,
            };
            _capture = new EnvironmentalCapture(_tracker, _session);
            _capture.Start();

            // App-runtime capture is best-effort (same rationale as the
            // Record tab path above).
            try
            {
                _appCapture = new AppRuntimeCapture(_tracker, _session);
                _appCapture.Start();
            }
            catch { _appCapture = null; }
        }
        catch (UnauthorizedAccessException)
        {
            MessageBox.Show(this, "Access denied. Run as Administrator.", "ProcDelta",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, $"Capture failed: {ex.GetType().Name}: {ex.Message}",
                "ProcDelta", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }

        SetCompareControlsRunning(true);
        StartStatusTimer();
        await Task.CompletedTask;
    }

    private void SetCompareControlsRunning(bool running)
    {
        if (_cmpStartBtn   != null) _cmpStartBtn.Enabled   = !running && _loadedBaseline != null;
        if (_cmpStopBtn    != null) _cmpStopBtn.Enabled    = running;
        if (_cmpDiffBtn    != null) _cmpDiffBtn.Enabled    = false;
        if (_cmpExportBtn  != null) _cmpExportBtn.Enabled  = false;
    }

    private void RunDiff()
    {
        if (_loadedBaseline is null || _session is null || _cmpReport is null || _cmpBaselinePath is null) return;

        _lastReport = DiffEngine.Compare(_loadedBaseline, _session, _cmpBaselinePath.Text);
        var markdown = DiffEngine.RenderMarkdown(_lastReport);
        _cmpReport.Text = markdown;

        if (_cmpExportBtn != null) _cmpExportBtn.Enabled = true;
        if (_cmpStatus    != null)
        {
            var n = _lastReport.Candidates.Count;
            _cmpStatus.ForeColor = n == 0 ? Success : Warning;
            _cmpStatus.Text = n == 0
                ? "Diff complete — no environmental differences detected vs baseline."
                : $"Diff complete — {n} candidate(s) found. Top candidates appear first in the report below.";
        }
    }

    private void ExportReport()
    {
        if (_lastReport is null) return;
        using var dlg = new SaveFileDialog
        {
            Title    = "Export diagnosis report",
            Filter   = "Markdown (*.md)|*.md|Text (*.txt)|*.txt",
            FileName = $"{SafeFilename(_lastReport.AppName)}-diagnosis-{DateTime.Now:yyyyMMdd-HHmmss}.md",
        };
        if (dlg.ShowDialog(this) != DialogResult.OK) return;
        try
        {
            File.WriteAllText(dlg.FileName, DiffEngine.RenderMarkdown(_lastReport));
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

    private TabPage BuildHelpTab()
    {
        var page = new TabPage("Help") { BackColor = BgPage };
        var textBox = new TextBox
        {
            Dock        = DockStyle.Fill,
            Multiline   = true,
            ReadOnly    = true,
            ScrollBars  = ScrollBars.Vertical,
            BackColor   = BgPage,
            ForeColor   = TextPrimary,
            BorderStyle = BorderStyle.None,
            Font        = new Font("Consolas", 9.5f),
            WordWrap    = true,
        };

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("ProcDelta — Workflow");
        sb.AppendLine("=======================");
        sb.AppendLine();
        sb.AppendLine("This tool diagnoses why an application fails on one machine but works on");
        sb.AppendLine("another. The diagnosis is deterministic — no AI, no cloud, no inference.");
        sb.AppendLine("Just a comparison between two real captures.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Step 1 — Record (on a working machine)");
        sb.AppendLine("---------------------------------------");
        sb.AppendLine("Type the executable name to watch (e.g. AdobeCollabSync.exe). Use the");
        sb.AppendLine("pipe character to watch several names at once: Acrobat.exe|AcroCEF.exe.");
        sb.AppendLine();
        sb.AppendLine("Add a short description of what you're about to do. Click Start. Perform");
        sb.AppendLine("the action exactly as a user would (launch the app, sign in, open a doc).");
        sb.AppendLine("Click Stop. The tool will have captured every registry, file, and network");
        sb.AppendLine("access made by the tracked process tree, with the success/failure status");
        sb.AppendLine("of each one. Click Save baseline and pick a filename.");
        sb.AppendLine();
        sb.AppendLine("The baseline JSON is portable: it normalises user-profile paths and the");
        sb.AppendLine("machine name to tokens (<USER>, <APPDATA>, etc.) so it works on any host.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Step 2 — Compare (on the broken machine)");
        sb.AppendLine("-----------------------------------------");
        sb.AppendLine("Switch to the Compare tab. Click Load and pick the baseline JSON. The");
        sb.AppendLine("process pattern auto-fills from the baseline. Click Start, have the user");
        sb.AppendLine("perform the same action that fails for them, click Stop, then click Run");
        sb.AppendLine("diff. The report panel lists every environmental access that disagreed");
        sb.AppendLine("between the baseline and this run, ranked by severity.");
        sb.AppendLine();
        sb.AppendLine("Severities:");
        sb.AppendLine();
        sb.AppendLine("  HIGH    Regression — baseline succeeded, this run failed. Causal candidate.");
        sb.AppendLine("  MEDIUM  Missing dependency or value drift between baseline and this host.");
        sb.AppendLine("  LOW     Novel failure not present in baseline. May be unrelated.");
        sb.AppendLine();
        sb.AppendLine("For each candidate the report shows what failed, what the baseline observed");
        sb.AppendLine("instead, and what's at that target on the broken machine right now (the");
        sb.AppendLine("Live State line). The Live State line is what an admin uses to fix the");
        sb.AppendLine("problem — \"this registry value is missing on this machine, populate it.\"");
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
        sb.AppendLine("  Microsoft-Windows-Kernel-Network   TCP connect attempts (IPv4 and IPv6)");
        sb.AppendLine();
        sb.AppendLine("User-mode providers (second session, best-effort):");
        sb.AppendLine();
        sb.AppendLine("  Microsoft-Windows-Services         service start/stop, SCM errors");
        sb.AppendLine("  Microsoft-Windows-WinINet          HTTP/HTTPS requests, proxy, cert errors");
        sb.AppendLine("  Microsoft-Windows-CAPI2            certificate chain validation");
        sb.AppendLine("  .NET CLR Runtime                   managed exceptions + assembly loads");
        sb.AppendLine();
        sb.AppendLine("WMI, Group Policy, AppX, and provider-specific event surfaces are not");
        sb.AppendLine("in scope for v1.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Privacy");
        sb.AppendLine("-------");
        sb.AppendLine("No data leaves the recording machine. Baselines are saved as JSON to a");
        sb.AppendLine("location you pick. For registry values the tool also captures a SHA-256");
        sb.AppendLine("hash of each value's bytes on first encounter — the hash lets diff detect");
        sb.AppendLine("drift between machines without storing the value content itself.");
        sb.AppendLine();
        sb.AppendLine();
        sb.AppendLine("Limitations");
        sb.AppendLine("-----------");
        sb.AppendLine("- Uses a private kernel session. Coexists with PerfView, xperf, the");
        sb.AppendLine("  ET Ducky agent, and other ETW tools. Windows allows up to 8 concurrent");
        sb.AppendLine("  kernel sessions per host; only if every slot is taken does Start fail.");
        sb.AppendLine();
        sb.AppendLine("- Administrator required. The manifest requests elevation; without it,");
        sb.AppendLine("  the kernel session can't open.");
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
        var totalSeen  = _session.MatchedPids.Count;
        var elapsed    = _session.Duration;
        var rows       = _session.Accesses.Count;

        var msg = $"Running for {elapsed.TotalSeconds:0.0}s. Tracked PIDs: {trackedNow} now, {totalSeen} seen total. {rows:N0} accesses captured.";
        if (totalSeen == 0)
            msg += "  Waiting for the pattern to match — start (or restart) the target app now.";

        if (_recStatus != null && _tabs.SelectedIndex == 0) _recStatus.Text = msg;
        if (_cmpStatus != null && _tabs.SelectedIndex == 1) _cmpStatus.Text = msg;

        if (_recLiveList != null && _tabs.SelectedIndex == 0)
        {
            // Tail the last 50 accesses, oldest at top.
            var tail = _session.Accesses.Count > 50
                ? _session.Accesses.GetRange(_session.Accesses.Count - 50, 50)
                : new List<EnvironmentalAccess>(_session.Accesses);

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
        var op   = a.Operation.PadRight(12);
        var res  = a.Result.PadRight(22);
        return $"{a.TimestampUtc:HH:mm:ss.fff}  {kind} {op} {res} {a.Target}";
    }

    // =========================================================================
    // SHARED UI HELPERS
    // =========================================================================

    private static Label NewMutedLabel(string text) => new()
    {
        Text      = text,
        ForeColor = TextMuted,
        TextAlign = ContentAlignment.MiddleLeft,
        Dock      = DockStyle.Fill,
    };

    private static TextBox NewTextBox(string placeholder) => new()
    {
        Dock            = DockStyle.Fill,
        BackColor       = BgInput,
        ForeColor       = TextPrimary,
        BorderStyle     = BorderStyle.FixedSingle,
        Font            = new Font("Consolas", 9f),
        PlaceholderText = placeholder,
    };

    private static Button NewButton(string text, bool primary = false)
    {
        var b = new Button
        {
            Text      = text,
            Dock      = DockStyle.Fill,
            Height    = 28,
            Margin    = new Padding(4),
            BackColor = primary ? Accent : Subtle,
            ForeColor = primary ? Color.White : TextPrimary,
            FlatStyle = FlatStyle.Flat,
            Font      = new Font("Segoe UI", 9f),
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