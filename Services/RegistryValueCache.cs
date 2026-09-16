using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// Captures a SHA-256 hash and a type name for every distinct (key,
/// valueName) tuple observed during a recording. Used by
/// <see cref="BaselineRecorder"/> to populate <c>ValueHash</c> and
/// <c>ValueType</c> on baseline entries, and by <see cref="DiffEngine"/>
/// to detect value drift between baseline and live capture.
///
/// Strategy: kernel ETW does not include value content in its registry
/// events, so we do a user-mode read-back on first encounter of each
/// (key, valueName). The read is queued to a single background worker
/// rather than performed on the ETW dispatch thread — registry round-trips
/// on the dispatch thread during an app-startup burst can stall the pump
/// long enough for the session's buffers to fill and drop events. The
/// few-milliseconds queue latency doesn't change the "value at first
/// touch" semantic in any way that matters for a baseline.
///
/// Privacy: only the hash is stored. The value bytes themselves never
/// leave this service.
///
/// Read failures (ACL-blocked, value deleted by the time we look, type
/// not representable as bytes) are silent — the entry simply gets no
/// ValueHash and the diff engine treats it as "value hashing not
/// available" rather than as a drift signal.
///
/// Key paths are expected in the normalized form produced by
/// <see cref="PathNormalizer.NormalizeRegistry"/> (HKEY_* hive names),
/// which is also what baseline entries carry — so lookups by
/// <see cref="BaselineRecorder"/> hit without translation.
/// </summary>
[SupportedOSPlatform("windows")]
public sealed class RegistryValueCache : IDisposable
{
    private readonly ConcurrentDictionary<string, HashedValue> _hashes = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, byte> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentQueue<(string Key, string Value, string ComposedKey)> _queue = new();
    private readonly SemaphoreSlim _signal = new(0);
    private readonly CancellationTokenSource _cts = new();
    private readonly Task _worker;

    public RegistryValueCache()
    {
        _worker = Task.Run(WorkerLoopAsync);
    }

    /// <summary>
    /// Schedule a read for (keyName, valueName) if not already cached or
    /// queued. Returns immediately — safe to call from the ETW dispatch
    /// thread at event rate.
    /// </summary>
    public void Observe(string keyName, string valueName)
    {
        if (string.IsNullOrEmpty(keyName) || string.IsNullOrEmpty(valueName)) return;
        var k = Compose(keyName, valueName);
        if (_hashes.ContainsKey(k)) return;
        if (!_pending.TryAdd(k, 0)) return; // already queued

        _queue.Enqueue((keyName, valueName, k));
        _signal.Release();
    }

    /// <summary>
    /// Returns the cached (hash, type) for the given (key, valueName),
    /// or null if no value was captured.
    /// </summary>
    public HashedValue? Get(string keyName, string valueName)
    {
        if (string.IsNullOrEmpty(keyName) || string.IsNullOrEmpty(valueName)) return null;
        return _hashes.TryGetValue(Compose(keyName, valueName), out var v) ? v : null;
    }

    /// <summary>
    /// Wait (bounded) for all queued reads to finish. Call at capture stop,
    /// before the recorder consumes the cache.
    /// </summary>
    public async Task DrainAsync(TimeSpan timeout)
    {
        var sw = Stopwatch.StartNew();
        while (!_pending.IsEmpty && sw.Elapsed < timeout)
        {
            await Task.Delay(25).ConfigureAwait(false);
        }
    }

    public void Dispose()
    {
        try { _cts.Cancel(); } catch { }
        try { _signal.Release(); } catch { }

        // Observe the worker. It was started with Task.Run into a field nothing ever
        // read, so a fault inside WorkerLoopAsync was captured into the Task and
        // discarded: registry reads would stop happening and the only symptom would be
        // values quietly never appearing in the cache. Waiting here both drains the
        // shutdown and surfaces the exception. Bounded — shutdown must not hang on it.
        var stopped = false;
        try { stopped = _worker.Wait(TimeSpan.FromSeconds(2)); }
        catch (AggregateException) { stopped = true; /* faulted or cancelled — observed */ }
        catch (Exception) { }

        if (stopped)
        {
            _cts.Dispose();
            _signal.Dispose();
        }
    }

    private async Task WorkerLoopAsync()
    {
        var ct = _cts.Token;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await _signal.WaitAsync(ct).ConfigureAwait(false);
                while (_queue.TryDequeue(out var item))
                {
                    try
                    {
                        var hashed = ReadAndHash(item.Key, item.Value);
                        if (hashed is not null) _hashes[item.ComposedKey] = hashed;
                    }
                    catch
                    {
                        // Read failures are expected (ACL-blocked, ephemeral
                        // keys, values that disappear between the kernel
                        // event and our read). The entry stays unhashed.
                    }
                    finally
                    {
                        _pending.TryRemove(item.ComposedKey, out _);
                    }
                }
            }
        }
        catch (OperationCanceledException) { /* shutdown */ }
    }

    private static HashedValue? ReadAndHash(string keyName, string valueName)
    {
        var (root, subPath) = SplitRegistryPath(keyName);
        if (root is null) return null;

        using var key = root.OpenSubKey(subPath, writable: false);
        if (key is null) return null;

        var raw = key.GetValue(valueName, defaultValue: null);
        if (raw is null) return null;

        var kind = key.GetValueKind(valueName);
        var bytes = ToBytes(raw, kind);
        if (bytes is null) return null;

        var hash = SHA256.HashData(bytes);
        var hex = "sha256:" + Convert.ToHexString(hash).ToLowerInvariant();
        return new HashedValue(hex, kind.ToString());
    }

    /// <summary>
    /// Compute a hash for the value as it exists on the LIVE host right
    /// now. Used by the diff engine to compare against a baseline hash.
    /// Returns null when the value can't be read (including paths that
    /// still contain unresolvable tokens like &lt;SID&gt;).
    /// </summary>
    public static HashedValue? HashLiveValue(string keyName, string valueName)
    {
        if (string.IsNullOrEmpty(keyName) || string.IsNullOrEmpty(valueName)) return null;
        if (PathNormalizer.ContainsToken(keyName)) return null;
        try
        {
            return ReadAndHash(keyName, valueName);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// NUL is illegal in both registry key paths and value names, so it is
    /// a collision-proof separator. (The previous separator was an empty
    /// string, which let ("…\Foo","Bar") collide with ("…\FooB","ar") and
    /// silently attribute one value's hash to another tuple.)
    /// </summary>
    private static string Compose(string keyName, string valueName)
        => keyName + "\0" + valueName;

    /// <summary>
    /// Render a registry value into a deterministic byte sequence so the
    /// hash is stable across machines for "same" values. Strings → UTF-8.
    /// DWORDs/QWORDs → little-endian bytes. Multi-string → joined with
    /// NUL. Binary → as-is.
    /// </summary>
    private static byte[]? ToBytes(object value, RegistryValueKind kind)
    {
        return kind switch
        {
            RegistryValueKind.String => Encoding.UTF8.GetBytes((string)value),
            RegistryValueKind.ExpandString => Encoding.UTF8.GetBytes((string)value),
            RegistryValueKind.MultiString => Encoding.UTF8.GetBytes(string.Join("\0", (string[])value)),
            RegistryValueKind.DWord => BitConverter.GetBytes(Convert.ToInt32(value, CultureInfo.InvariantCulture)),
            RegistryValueKind.QWord => BitConverter.GetBytes(Convert.ToInt64(value, CultureInfo.InvariantCulture)),
            RegistryValueKind.Binary => (byte[])value,
            _ => null,
        };
    }

    /// <summary>
    /// Same hive-path parsing the LiveStateInspector uses. Copied here to
    /// keep the cache decoupled from the inspector. Accepts both the
    /// normalized HKEY_* form (current captures) and the native
    /// \REGISTRY\… form (legacy baselines).
    /// </summary>
    private static (RegistryKey? Root, string SubPath) SplitRegistryPath(string fullPath)
    {
        if (string.IsNullOrEmpty(fullPath)) return (null, "");

        var p = fullPath
            .Replace("\\REGISTRY\\MACHINE", "HKEY_LOCAL_MACHINE", StringComparison.OrdinalIgnoreCase)
            .Replace("\\REGISTRY\\USER", "HKEY_USERS", StringComparison.OrdinalIgnoreCase);

        var currentSid = System.Security.Principal.WindowsIdentity.GetCurrent().User?.Value;
        if (currentSid is not null)
        {
            var hkcuPrefix = $"HKEY_USERS\\{currentSid}";
            if (p.StartsWith(hkcuPrefix, StringComparison.OrdinalIgnoreCase))
                p = "HKEY_CURRENT_USER" + p.Substring(hkcuPrefix.Length);
        }

        var split = p.IndexOf('\\');
        if (split <= 0) return (null, "");
        var hiveName = p.Substring(0, split);
        var sub = p.Substring(split + 1);

        RegistryKey? root = hiveName.ToUpperInvariant() switch
        {
            "HKEY_LOCAL_MACHINE" => Registry.LocalMachine,
            "HKEY_CURRENT_USER" => Registry.CurrentUser,
            "HKEY_USERS" => Registry.Users,
            "HKEY_CLASSES_ROOT" => Registry.ClassesRoot,
            "HKEY_CURRENT_CONFIG" => Registry.CurrentConfig,
            _ => null,
        };
        return (root, sub);
    }
}

/// <summary>Cached pair: SHA-256 hash string + registry type name.</summary>
public sealed record HashedValue(string Hash, string TypeName);
