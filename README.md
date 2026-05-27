# ET Ducky ProcDelta

A standalone Windows tool for **differential environmental diagnosis** of
application failures. Record a known-good run of an app on a working
machine, run the same action on a broken machine, and get a deterministic
report of every environmental difference that could explain why it failed.

Source-available under [PolyForm Shield 1.0.0](LICENSE). No AI, no cloud,
no telemetry, no agent.

## What it does

Three tabs:

- **Record** — pick a process name (e.g. `AdobeCollabSync.exe`), describe
  what you're about to do, click Start, perform the action on a working
  machine, click Stop. Save the resulting `.baseline.json` file.
- **Compare** — on the broken machine, load the baseline, perform the same
  action, click Run Diff. The report panel lists every registry / file /
  network access that disagreed between the baseline and this run, ranked
  by severity, with the live state of the affected resource alongside it.
- **Help** — built-in workflow and limitations primer.

The diagnosis is deterministic: same inputs, same output. The diff engine
is a small set of classification rules over (Kind, Target, Operation,
Result) tuples — no AI inference, no heuristics that change between runs.

## Why this exists

Most application-crash investigation on Windows is interactive guesswork.
Procmon traces are dense and noisy. Crash dumps tell you the symptom but
not the environmental cause. Logs only contain what the app's authors
thought to log.

The ProcDelta captures the kernel's view of what the application
actually tried to do — every registry value it queried, every file it
opened, every host it tried to reach, with the success/failure status of
each one — and surfaces only the entries that disagree with a known-good
baseline. That diff is usually short (a handful of entries even on a
chatty app) and points directly at the environmental misalignment a
sysadmin needs to fix.

Typical findings:

- A registry value present on working machines is missing on the broken one.
- An NTFS ACL on a known path grants Modify on baselines, Read-only here.
- A required network host resolves and accepts TCP on baselines, fails
  here (proxy block, DNS misconfig, cert validation issue).
- A scheduled task or service started on the baseline but didn't on this
  host.

## Download

Pre-built signed Windows executables are published on the [Releases](../../releases)
page. Download `ETDucky.ProcDelta.exe`, right-click → Properties → Unblock
(mark-of-the-web), then run.

The app requires Administrator. The manifest requests elevation; you'll
see one UAC prompt at launch.

## Build from source

Requirements: Windows 10+, .NET 10 SDK.

```powershell
git clone https://github.com/trucule/ETDucky.ProcDelta.git
cd ETDucky.ProcDelta
dotnet build -c Release
```

Single-file self-contained publish:

```powershell
dotnet publish -c Release -r win-x64 `
  -p:SelfContained=true `
  -p:PublishSingleFile=true `
  -p:IncludeNativeLibrariesForSelfExtract=true
```

## How it works

### Capture

A WinForms shell drives a kernel-mode ETW session with four providers
enabled:

| Provider | Captured |
|---|---|
| `Microsoft-Windows-Kernel-Process` | spawn / exit + exit codes |
| `Microsoft-Windows-Kernel-FileIO` | Create / Delete with NTSTATUS result |
| `Microsoft-Windows-Kernel-Registry` | Query / Set / Open / Create / Delete with NTSTATUS result |
| `Microsoft-Windows-Kernel-Network` | TCP connect attempts (IPv4 + IPv6) |

A second non-kernel session captures four user-mode manifest providers
for application-runtime context:

| Provider | Captured |
|---|---|
| `Microsoft-Windows-Services` | Service start/stop, SCM errors |
| `Microsoft-Windows-WinINet` | HTTP/HTTPS requests (proxy, cert, connection failures) |
| `Microsoft-Windows-CAPI2` | Certificate chain validation failures |
| `.NET Common Language Runtime` | Managed unhandled exceptions, assembly-load failures |

Both sessions share the same `ProcessTracker` and write to the same
`CaptureSession`, so app-runtime accesses end up in the diff alongside
kernel accesses without any special handling.

The kernel session is a **private kernel session** (System Trace Provider
Group, Windows 8+), not the legacy NT Kernel Logger. The tool coexists
with PerfView, xperf, the ET Ducky agent, and other ETW capture tools;
the per-host limit is 8 concurrent kernel sessions.

A `ProcessTracker` keeps the live set of "tracked" PIDs. A PID joins on
two conditions: its image filename matches the operator-supplied pattern,
or its parent PID is already tracked (so service spawns are followed
automatically). Every event from either session is filtered against this
set before hitting the recorder.

Paths are normalised at capture time — user-profile and system folders
become tokens (`<USER>`, `<APPDATA>`, `<LOCALAPPDATA>`, `<PROGRAMFILES>`,
`<WINDOWS>`, `<SYSTEM32>`, etc.) so baselines port between machines.

### Baseline

Raw events aggregate by (Kind, Target, Operation, Detail). Each unique
combination becomes one row with an access count and the most recent
observed result. The result is serialised to JSON with a schemaVersion
field. Typical size: 50–200 KB.

For every (key, value name) the tracked process queries or writes, the
recorder also does a user-mode read-back, SHA-256 hashes the bytes, and
attaches the hash + registry type name to the baseline entry. The value
bytes themselves are never stored — only the hash. The hash lets the
diff engine detect drift between the baseline and the broken machine
without exposing the value content. No PII or app data leaves the
recording host.

### Diff

For each access in the live capture, the diff engine looks up the same
key in the baseline:

| Baseline | Live | Classification | Severity |
|---|---|---|---|
| SUCCESS | non-SUCCESS | **Regression** | High |
| present, hash X | present, hash Y | **Value drift** | Medium |
| present | missing | **Missing dependency** | Medium |
| not present | non-SUCCESS | **Novel failure** | Low |
| same on both sides | — | (suppressed) | — |

Each candidate is enriched with what the `LiveStateInspector` finds at
that target on the broken machine right now (registry value content +
ACL, file presence + ACL + size, TCP probe to the host:port). That live
state is the actionable line in the report.

Ranking: severity first (regressions before novel failures), then
"near-exit" (accesses within the last 2 seconds of tracked-process
activity rank higher inside their severity bucket), then alphabetically
by target for determinism.

### Report

Rendered as Markdown. Severity-bucketed, candidates numbered within each
bucket, full context per candidate (baseline result, live result, live
state). Exportable from the Compare tab for attaching to tickets.

## Architecture

```
ETDucky.ProcDelta/
├── MainForm.cs              Three tabs: Record / Compare / Help
├── Program.cs
├── app.manifest             requireAdministrator
├── app.ico
├── Models/
│   ├── EnvironmentalAccess.cs  One observed access (registry/file/net/process)
│   ├── Baseline.cs              Serialisable, schema-versioned, aggregated
│   ├── CaptureSession.cs        In-flight capture state (raw events)
│   └── DiagnosisReport.cs       Output of a diff run
└── Services/
    ├── ProcessTracker.cs        Pattern-matched PID tracking + child follow
    ├── EnvironmentalCapture.cs  Kernel ETW subscriptions + per-PID filter
    ├── BaselineRecorder.cs      Raw events → aggregated Baseline
    ├── BaselineLoader.cs        JSON save/load with schemaVersion gate
    ├── DiffEngine.cs            Baseline vs live → DiagnosisReport + Markdown
    ├── LiveStateInspector.cs    Re-reads registry / file / net live
    └── PathNormalizer.cs        Profile paths ↔ portable tokens
```

No external services. No ETDucky.Core reference. Standalone.

## Caveats

- **Windows-only.** ETW is a Windows subsystem.
- **Administrator required.** Kernel sessions can't start otherwise.
- **8 kernel sessions per host.** The tool uses a private kernel
  session, so it coexists with PerfView, xperf, the ET Ducky agent,
  and other ETW capture tools. Only when all 8 slots are full does
  Start fail.
- **Limited app-runtime coverage.** v1 captures the four highest-payoff
  user-mode providers (Services / WinINet / CAPI2 / .NET CLR Runtime).
  WMI, Group Policy, AppX, and provider-specific event surfaces are not
  in scope yet.
- **Baselines encode the recorder's environment.** If the working
  machine's "working" state depends on something not visible to ETW
  (an in-memory app cache, a session token), the baseline encodes only
  the visible part. Recording on a freshly-set-up machine produces the
  most portable baselines.

## Relationship to ET Ducky

ET Ducky (https://etducky.com) is a commercial cross-platform diagnostic
agent that uses ETW on Windows and eBPF on Linux for continuous,
fleet-wide kernel observability with AI-driven root-cause analysis. The
ProcDelta is the standalone, manual, single-machine version of one
investigation pattern the commercial agent automates.

The two are independent repositories.

## License

[PolyForm Shield License 1.0.0](LICENSE). Source-available, free for any
use **except** building a product or service that competes with ET Ducky
LLC. The license text is short and plain-English — read it before forking
for commercial use.

Contributions submitted as pull requests are accepted under the same
license. By submitting a PR you confirm you have the right to license
your contribution this way.

## Contributing

PRs welcome. The codebase is small and the diff classification rules are
intentionally simple. Useful directions:

- Additional providers (Microsoft-Windows-Services for SCM events,
  Microsoft-Windows-WinINet for proxy issues, Microsoft-Windows-CAPI2
  for certificate-chain failures).
- Value-content capture and hashing in the recorder so value drift
  becomes a first-class classification.
- A "starter pack" of pre-recorded baselines for common enterprise
  apps (Outlook, Teams, Chrome, Acrobat) recorded on clean Windows 11
  test VMs.
