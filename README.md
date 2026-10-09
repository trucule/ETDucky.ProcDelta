# ET Ducky ProcDelta

ProcDelta is a Windows tool for differential environmental diagnosis of
application failures. You record a known-good run of an application on a
machine where it works, run the same action on a machine where it fails,
and get a deterministic report of every environmental difference between
the two runs. The report ranks the differences by how likely each one is
to explain the failure and shows the live state of each affected resource
on the failing machine.

The tool is open source under the [Apache License 2.0](LICENSE). It runs
locally. There is no AI, no cloud service and no telemetry. The tool makes
no network connection on its own; the only outbound connections are the TCP
probes and DNS lookups during a diff, and those run only when the operator
enables them. See [Network and privacy](#network-and-privacy).

## What it does

The window has three tabs. The same code also runs from a command line.

**Record** captures a baseline. You give the tool a process name, or an
executable to launch, describe what you are about to do, click Start,
perform the action on a working machine and click Stop. The tool saves a
`.baseline.json` file.

**Compare** captures a run on the failing machine and diffs it against a
loaded baseline. The report lists every registry, file, network and DNS
access that disagreed between the two runs, ranked by severity, with the
live state of the affected resource on this machine. The same tab can diff
two saved baselines without a capture, for the case where the failing
machine recorded its own baseline.

**Help** holds a primer on the workflow and the tool's limits.

**Command line.** `record`, `compare`, `diff` and `replay` run the capture
and the diff without the window, so the tool can be deployed through MECM,
Intune or an RMM and the files collected centrally.

The diagnosis is deterministic. The diff engine applies a small set of
classification rules to per-result counts of (Kind, Target, Operation,
Detail) tuples. Nothing in the classification changes between runs.

## Why this exists

ProcDelta records the kernel's view of what the application tried to do:
the registry values it queried, the files it opened, the hosts it resolved
and connected to, and the success or failure status of each one. The diff
keeps only the entries that disagree with a known-good baseline. On a
typical application that list is short and points at the environmental
difference an administrator needs to fix.

Findings the tool is built to surface:

- A registry value that exists on working machines is missing on the
  failing one.
- An NTFS ACL on a known path grants Modify on the baseline and Read on
  the failing machine.
- A hostname that resolves and accepts TCP connections on the baseline
  fails on the failing machine because of a proxy rule, a DNS setting or a
  certificate problem.
- A service or scheduled task started on the baseline and did not start on
  the failing machine.
- The application image is a different file version on the two machines.

## Download

Signed Windows executables are published on the [Releases](../../releases)
page as `ETDucky.ProcDelta.exe`, a portable single-file build. Download it,
open its Properties, tick Unblock to clear the mark of the web, and run it.
Nothing is installed. Delete the file to remove it.

The tool requires Administrator because kernel ETW sessions require it. The
manifest requests elevation, so Windows shows one UAC prompt at launch. An
application started through the Launch field runs at your normal integrity
level. The tool starts it through `explorer.exe` so it does not inherit the
tool's elevation.

## Build from source

Requirements: Windows 10 version 2004 (build 19041) or later, and the .NET
10 SDK.

```powershell
git clone https://github.com/trucule/ETDucky.ProcDelta.git
cd ETDucky.ProcDelta
dotnet build -c Release
```

Single-file self-contained publish:

```powershell
dotnet publish -c Release -r win-x64 `
  -p:SelfContained=true `
  -p:PublishSingleFile=true
```

Native libraries are not bundled for self-extraction. The csproj sets
`IncludeNativeLibrariesForSelfExtract` to false, so the executable writes
nothing to `%TEMP%` at startup. The runtime's optional native files land
beside the exe in the publish folder and are not shipped. The PDB is
embedded, so a crash log carries line numbers.

Run the tests:

```powershell
dotnet test tests/ETDucky.ProcDelta.Tests/ETDucky.ProcDelta.Tests.csproj -c Release
```

Packages are restored in locked mode in CI against the committed
`packages.lock.json` files. A dependency that resolves differently from the
lock file fails the build. Update a lock file by running `dotnet restore`
and committing the result.

## Command line

```
ETDucky.ProcDelta.exe record  --out app.baseline.json (--pattern <names> | --launch <exe>) [--duration <sec>]
                              [--app <name>] [--action <text>] [--include-user]
ETDucky.ProcDelta.exe compare --baseline app.baseline.json --report out.md [--pattern <names> | --launch <exe>]
                              [--duration <sec>] [--json out.json] [--probe-network] [--show-values] [--fail-on-findings]
ETDucky.ProcDelta.exe diff    --baseline good.baseline.json --against broken.baseline.json --report out.md
ETDucky.ProcDelta.exe replay  --etl trace.etl --pattern <names> --out app.baseline.json
```

`--pattern` takes process names separated by `|`, with `*` and `?`
wildcards. `--launch` starts the executable after the capture is up and
tracks its process tree. With `--launch` and no `--duration`, the capture
ends when the launched tree has exited. `--args` passes arguments to the
launched executable; the application then inherits the tool's elevation,
and the output says so.

The executable is a GUI-subsystem binary, so a console does not wait for it
on its own. Use `start /wait` from cmd or `Start-Process -Wait` from
PowerShell. Output goes to the parent console when there is one.

Exit codes: 0 ok, 1 usage, 2 failed, 3 findings (with `--fail-on-findings`).
`record` and `compare` need Administrator. `diff` and `replay` do not.

## How it works

### Capture

A WinForms shell drives a kernel ETW session with four providers enabled:

| Provider | Captured |
|---|---|
| `Microsoft-Windows-Kernel-Process` | Process start and exit, with exit code |
| `Microsoft-Windows-Kernel-FileIO` | Create and Delete, with the NTSTATUS result |
| `Microsoft-Windows-Kernel-Registry` | Query, Set, Open, Create and Delete, with the NTSTATUS result |
| `Microsoft-Windows-Kernel-Network` | TCP connect attempts, IPv4 and IPv6 |

A second session captures five user-mode providers for application-runtime
context:

| Provider | Captured |
|---|---|
| `Microsoft-Windows-Services` | Service start and stop, SCM errors |
| `Microsoft-Windows-WinINet` | HTTP and HTTPS requests, proxy, certificate and connection failures. The URL is reduced to scheme, host and path. |
| `Microsoft-Windows-CAPI2` | Certificate chain validation failures |
| `Microsoft-Windows-DNS-Client` | Name resolution results and failures. The answers key TCP targets by hostname. |
| `.NET Common Language Runtime` | Managed exceptions by type, and assembly load failures, through the typed CLR parser in TraceEvent |

Both sessions share one `ProcessTracker` and write into one
`CaptureSession`, so app-runtime accesses land in the diff beside kernel
accesses. The status line shows how many events each user-mode provider
delivered and how many events ETW dropped while the capture is running.

The kernel session is a private kernel session (System Trace Provider
Group, Windows 8 and later). It coexists with PerfView, xperf, the ET Ducky
agent and other ETW capture tools. The host limit is 8 concurrent kernel
sessions.

The `ProcessTracker` keeps the live set of tracked PIDs. A PID joins the set
when its image filename matches the operator's pattern or when its parent
is already tracked, so a service that spawns children is followed. Every
event from either session is filtered against this set before it is
recorded. When a root process joins, the tracker reads its image path and
file version off the process so the baseline carries the application
version.

Paths are normalised at capture time. User profile and system folders
become tokens (`<USER>`, `<APPDATA>`, `<LOCALAPPDATA>`, `<PROGRAMFILES>`,
`<WINDOWS>`, `<SYSTEM32>` and others) so baselines port between machines.
Generated segments become stable tokens as well: a GUID becomes `<GUID>`,
sixteen or more hex digits become `<HEX>`, and any `.tmp` file becomes
`<TMP>.tmp`. Without this a temp file created under a new random name on
every run would appear as a different dependency on every capture. Registry
paths keep their GUIDs because a CLSID is a stable identifier. The
recording user's SID under `\REGISTRY\USER` folds into
`HKEY_CURRENT_USER`, and `ControlSetNNN` folds to `CurrentControlSet`. A
process start records the parent's image name. The parent PID differs on
every run and is left out of the key.

Network targets are recorded as `ip:port` during capture and rewritten to
`host:port` when the baseline is built, using the DNS answers seen during
the same capture. Two machines resolving the same content-delivery name
receive different addresses, and keying by hostname makes those connects
comparable.

### Baseline

Events aggregate incrementally during capture by (Kind, Target, Operation,
Detail), so memory stays flat on chatty applications. Each unique
combination becomes one row with a count per distinct result, first- and
last-seen offsets measured from the first tracked access, and the image
names of the processes that made it. The file also carries the
application's image path and file version, the Windows build and the span
of tracked activity. The schema version is 2. Version 1 files load and are
upgraded in memory. A typical file is 50 to 200 KB.

For every registry value the tracked process queries or writes, the
recorder reads the value back in user mode, hashes the stored bytes with
SHA-256 and attaches the hash and the registry type name to the entry. The
value bytes are not stored. REG_EXPAND_SZ values are hashed unexpanded, so
a value such as `%USERPROFILE%\cache` hashes the same on every machine.

### Diff

The diff engine looks up each live access in the baseline and classifies
it on per-result counts, so the outcome cannot change with the order in
which results arrived:

| Baseline | Live | Classification | Severity |
|---|---|---|---|
| ever succeeded | never succeeded | Regression | High |
| present, hash X | present, hash Y | Value drift | Medium |
| ever succeeded | missing | Missing dependency | Medium |
| not present | never succeeded | Novel failure | Low |
| succeeded on both sides, or failed on both sides | | suppressed | |

"Succeeded" follows NT_SUCCESS, which covers success and informational
statuses. One exception is documented in `ResultSemantics`: a registry
QueryValue that returns BUFFER_OVERFLOW or BUFFER_TOO_SMALL is a size
probe, the normal first half of a two-call read, and counts as a success.

The diff runs in both directions. Live accesses are classified against the
baseline, and baseline accesses with no live counterpart become missing
dependency candidates. The second pass is how a failed TCP connect
surfaces: the kernel emits connect events only for successful connections,
so on the failing machine a blocked host shows up as a baseline connect
this run never made. The second pass is phase-aware. A baseline access
first seen after the point the live run reached, plus two seconds of
grace, is counted in the report header and left out of the candidate list,
so a short live run does not report everything the baseline did later as
missing.

Each candidate is enriched with what the `LiveStateInspector` finds at the
target on the failing machine at report time: the registry value's type,
size and hash, a file's presence, size and ACL, or a TCP probe to the host
and port. The TCP probe and any check of a network path run only when the
operator enables network probing. Registry value content is shown only
when the operator enables it.

Ranking is by severity, then by whether the access happened within two
seconds before a tracked root process exited, then alphabetically by
target. The near-exit marker is applied only when a root process did exit
during the capture.

### Report

The report is rendered as Markdown for export and as plain text for the
window. The header states the process pattern, the recorded action, the
hosts and Windows builds on both sides, the application image and version
on both sides with a note when they differ, both capture durations, the
coverage (how many baseline accesses this run also made, with a warning
below 50 percent), the number of baseline accesses that fell after the
point this run reached, whether a root process exited, and the positions of
the network and registry gates.

Candidates are grouped by severity and numbered. Each one shows the
operation, the per-result counts on both sides, the processes that made
the access, when the baseline first saw it, and the live state. Three or
more candidates under one registry key, folder or host are rendered as one
group with one line per member.

## Network and privacy

The tool makes no network connection on its own. There is no telemetry, no
update check, no crash upload and no listener. The only code that opens a
socket is the probe in `LiveStateInspector`, and it runs only while "Probe
network targets" on the Compare tab, or `--probe-network` on the command
line, is set. The same switch gates UNC paths, redirector device paths and
mapped network drives, because opening a file on a share authenticates as
the operator. Both are off by default, and the report header records
their position.

A baseline is a file you may have received from someone else. Treat it as
untrusted input. With the defaults, nothing in it can make the tool
connect anywhere or print a registry value. "Show registry values in
report" is off by default. The report then shows each value's type, byte
length and SHA-256 hash, which is the same hash form the baseline carries.

A baseline contains:

- file and image paths, with user and system folders replaced by tokens
  and generated segments replaced by stable tokens
- registry key paths and value names, with the recording user's SID folded
  to `HKEY_CURRENT_USER`
- SHA-256 hashes and type names of registry values, never the content
- hosts and ports the application resolved and connected to
- URLs reduced to scheme, host and path at capture time; query strings,
  fragments and userinfo are never recorded
- .NET exception types and the names of assemblies that failed to load,
  never exception messages
- service names, certificate subjects, process image names
- the application's image path and file version, and the Windows build
- the recording machine's hostname, and the operator's username only when
  "Include my username in the baseline" or `--include-user` is set

Before saving, the window lists entries that contain `@`, UNC paths, or
paths outside the standard Windows folders, so the operator can review
them. The exported report contains the same classes of data plus whatever
live state the enabled options allowed.

Windows may contact certificate revocation and SmartScreen services on the
first run of a signed executable. That is operating-system behaviour. The
only file the tool writes without being asked is a crash log under
`%LOCALAPPDATA%\ETDucky.ProcDelta`, written only if the tool crashes.

## Architecture

```
ETDucky.ProcDelta/
|-- MainForm.cs              Three tabs: Record, Compare, Help
|-- Program.cs               Window, or Cli when arguments are given; crash log
|-- Cli.cs                   record, compare, diff, replay
|-- app.manifest             requireAdministrator
|-- app.ico
|-- Models/
|   |-- EnvironmentalAccess.cs  One observed access (registry, file, network, process)
|   |-- Baseline.cs              Serialisable, schema-versioned, aggregated (v2)
|   |-- CaptureSession.cs        In-flight aggregation: per-result counts, offsets, images, DNS remap
|   `-- DiagnosisReport.cs       Output of a diff run
|-- Services/
|   |-- ProcessTracker.cs        Pattern-matched PID tracking, child follow, root image version
|   |-- ProcessLauncher.cs       Launch-and-track at the user's integrity level
|   |-- EnvironmentalCapture.cs  Kernel ETW subscriptions and per-PID filter; .etl replay
|   |-- AppRuntimeCapture.cs     User-mode providers (Services, WinINet, CAPI2, DNS-Client, CLR)
|   |-- DnsCache.cs              DNS answers seen during capture, ip:port to host:port
|   |-- ResultSemantics.cs       NT_SUCCESS, benign size probes, per-result counts
|   |-- RegistryValueCache.cs    Background read-back and SHA-256 of registry values
|   |-- RegistryPaths.cs         Hive path parsing and value bytes, shared by both sides
|   |-- TargetScrubber.cs        URL scrubbing at capture time
|   |-- HostInfo.cs              Windows build
|   |-- BaselineRecorder.cs      Aggregated session to Baseline
|   |-- BaselineLoader.cs        JSON save and load; v1 upgraded in memory
|   |-- BaselineScrubber.cs      Pre-save review for names, servers, customer paths
|   |-- DiffEngine.cs            Baseline vs live to DiagnosisReport and Markdown; offline diff
|   |-- LiveStateInspector.cs    Re-reads registry, file and network state behind InspectOptions
|   `-- PathNormalizer.cs        Profile paths and volatile segments to portable tokens
`-- tests/
    `-- ETDucky.ProcDelta.Tests/ xunit over every pure component
```

The project has no external services and no reference to ETDucky.Core. It
builds on its own.

## Caveats

- Windows only. ETW is a Windows subsystem.
- Administrator required. Kernel sessions cannot start otherwise.
- The host limit is 8 concurrent kernel sessions. The tool uses a private
  kernel session and coexists with other ETW capture tools. Start fails
  only when all 8 slots are in use. Sessions stranded by a crash are
  cleaned up at the next launch.
- Five user-mode providers are captured: Services, WinINet, CAPI2,
  DNS-Client and the .NET CLR. WMI, Group Policy, AppX and
  provider-specific event surfaces are not in scope.
- Baselines encode the recorder's environment. If the working machine's
  state depends on something ETW cannot see, such as an in-memory cache or
  a session token, the baseline encodes only the visible part. A machine
  that has just completed initial application setup produces the most
  portable baselines.
- Baselines from version 2.0.0 load, but URL targets, REG_EXPAND_SZ hashes
  and process-start entries are recorded differently now and show as noise
  against a 2.0.0 file. Re-record them.

## Relationship to ET Ducky

ET Ducky (https://etducky.com) is a commercial endpoint management and
diagnostic agent that uses ETW on Windows and eBPF on Linux for continuous
fleet-wide kernel observability with AI-assisted root-cause analysis.
ProcDelta is the standalone, manual, single-machine version of one
investigation pattern the agent automates. The two are independent
repositories.

## License

[Apache License 2.0](LICENSE). Free for any use, commercial or otherwise,
with a patent grant and trademark protection. See LICENSE for the full
terms.

Contributions submitted as pull requests are accepted under the same
license. By submitting a pull request you confirm you have the right to
license your contribution this way.

## Contributing

Pull requests are welcome. The codebase is small and the diff
classification rules are simple on purpose. Useful directions:

- Additional providers, such as WMI-Activity, Group Policy and AppX
  deployment.
- A recorded `.etl` fixture and a replay test so the capture callbacks
  are covered end to end.
- A starter set of baselines for common enterprise applications, recorded
  on clean Windows 11 test machines.
