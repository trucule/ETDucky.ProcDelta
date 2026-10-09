using System.Globalization;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// One place that decides what "succeeded" means, for the capture layer
/// (turning an NTSTATUS into a result string), the diff engine (classifying
/// per-result counts) and the report (describing them).
///
/// NT_SUCCESS semantics: an NTSTATUS with the severity bits 00 (success) or
/// 01 (informational) is a success. Warnings (10) and errors (11) are not,
/// with one documented exception: a registry QueryValue that returns
/// BUFFER_OVERFLOW or BUFFER_TOO_SMALL is a size probe, the normal first
/// half of every two-call read, and is counted as a success.
/// </summary>
public static class ResultSemantics
{
    public const string Success = "SUCCESS";

    /// <summary>NT_SUCCESS: severity success or informational.</summary>
    public static bool NtSuccess(int status) => status >= 0;

    /// <summary>Result string for an NTSTATUS: "SUCCESS" or a symbolic name.</summary>
    public static string ResultFor(int status)
        => NtSuccess(status) ? Success : NtStatusName(status);

    /// <summary>True for "SUCCESS" and for a process exit with code 0.</summary>
    public static bool IsSuccess(string result)
        => string.Equals(result, Success, StringComparison.OrdinalIgnoreCase)
        || string.Equals(result, "ExitCode=0", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// A failure code that is routine for the operation and carries no
    /// diagnostic signal. Registry size probes only, for now.
    /// </summary>
    public static bool IsBenign(string result, string operation)
    {
        if (!string.Equals(operation, "QueryValue", StringComparison.OrdinalIgnoreCase)) return false;
        return string.Equals(result, "BUFFER_OVERFLOW", StringComparison.OrdinalIgnoreCase)
            || string.Equals(result, "BUFFER_TOO_SMALL", StringComparison.OrdinalIgnoreCase);
    }

    public static bool CountsAsSuccess(string result, string operation)
        => IsSuccess(result) || IsBenign(result, operation);

    /// <summary>True when at least one observed result counts as a success.</summary>
    public static bool EverSucceeded(IEnumerable<KeyValuePair<string, int>> results, string operation)
    {
        foreach (var kv in results)
        {
            if (kv.Value > 0 && CountsAsSuccess(kv.Key, operation)) return true;
        }
        return false;
    }

    /// <summary>True when at least one observed result is a real failure.</summary>
    public static bool EverFailed(IEnumerable<KeyValuePair<string, int>> results, string operation)
    {
        foreach (var kv in results)
        {
            if (kv.Value > 0 && !CountsAsSuccess(kv.Key, operation)) return true;
        }
        return false;
    }

    /// <summary>"SUCCESS x12, OBJECT_NAME_NOT_FOUND x1", most frequent first.</summary>
    public static string Describe(IEnumerable<KeyValuePair<string, int>> results)
    {
        var parts = results
            .Where(kv => kv.Value > 0)
            .OrderByDescending(kv => kv.Value)
            .ThenBy(kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .Select(kv => kv.Value == 1 ? kv.Key : $"{kv.Key} x{kv.Value.ToString(CultureInfo.InvariantCulture)}")
            .ToList();
        return parts.Count == 0 ? "(none)" : string.Join(", ", parts);
    }

    /// <summary>
    /// Canonicalise an outcome value from a user-mode provider so the same
    /// code compares equal between baseline and live even when one OS
    /// build's manifest renders it decimal and another hex ("2147954407"
    /// vs "0x80072EE7"). Zero in any spelling is "SUCCESS"; other numerics
    /// become "0xXXXXXXXX"; non-numeric strings pass through unchanged.
    /// </summary>
    public static string NormalizeOutcome(string v)
    {
        var s = v.Trim();
        if (s.Length == 0) return Success;
        if (s.Equals(Success, StringComparison.OrdinalIgnoreCase)) return Success;

        ulong parsed;
        if (s.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
        {
            if (!ulong.TryParse(s.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out parsed))
                return v;
        }
        else if (long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var dec))
        {
            parsed = unchecked((ulong)dec);
        }
        else
        {
            return v;
        }

        if (parsed == 0) return Success;
        return $"0x{unchecked((uint)parsed):X8}";
    }

    /// <summary>Symbolic name for the NTSTATUS values the tool sees most; hex otherwise.</summary>
    public static string NtStatusName(int status)
    {
        var u = unchecked((uint)status);
        return u switch
        {
            0u => Success,
            0x00000103u => "PENDING",
            0x00000104u => "REPARSE",
            0x00000105u => "MORE_ENTRIES",
            0x40000000u => "OBJECT_NAME_EXISTS",
            0x80000005u => "BUFFER_OVERFLOW",
            0x8000001Au => "NO_MORE_ENTRIES",
            0xC000000Du => "INVALID_PARAMETER",
            0xC000000Fu => "NO_SUCH_FILE",
            0xC0000011u => "END_OF_FILE",
            0xC0000017u => "NO_MEMORY",
            0xC0000018u => "CONFLICTING_ADDRESSES",
            0xC0000022u => "ACCESS_DENIED",
            0xC0000023u => "BUFFER_TOO_SMALL",
            0xC0000034u => "OBJECT_NAME_NOT_FOUND",
            0xC0000035u => "OBJECT_NAME_COLLISION",
            0xC000003Au => "OBJECT_PATH_NOT_FOUND",
            0xC000003Bu => "OBJECT_PATH_SYNTAX_BAD",
            0xC0000043u => "SHARING_VIOLATION",
            0xC0000056u => "DELETE_PENDING",
            0xC0000061u => "PRIVILEGE_NOT_HELD",
            0xC000007Bu => "INVALID_IMAGE_FORMAT",
            0xC000007Fu => "DISK_FULL",
            0xC00000BAu => "FILE_IS_A_DIRECTORY",
            0xC0000103u => "NOT_A_DIRECTORY",
            0xC0000121u => "CANNOT_DELETE",
            0xC000014Du => "REGISTRY_IO_FAILED",
            0xC000017Cu => "KEY_DELETED",
            0xC0000225u => "NOT_FOUND",
            _ => $"0x{u:X8}",
        };
    }
}
