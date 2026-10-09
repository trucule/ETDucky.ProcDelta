using ETDucky.ProcDelta.Models;

namespace ETDucky.ProcDelta.Services;

/// <summary>
/// File accesses that belong to the storage stack rather than to the
/// application. Filter drivers run on the calling thread, so their own
/// opens are attributed to the tracked process, and whether they happen
/// at all depends on cache state. Two identical runs then differ by these
/// entries, so they are kept out of baselines and out of comparisons.
/// Also knows how alternate data stream paths relate to their file.
/// </summary>
public static class StorageArtifacts
{
    /// <summary>
    /// The Windows Overlay Filter keeps the compressed bytes of a CompactOS
    /// or "compact /c" file in this alternate data stream and opens it on
    /// the first uncached read of the file. The file itself is still
    /// recorded as the application's dependency.
    /// </summary>
    private const string WofCompressedData = ":WofCompressedData";

    private static readonly char[] PathSeparators = { '\\', '/' };

    /// <summary>True when the access is the storage stack's own work and not a dependency of the application.</summary>
    public static bool IsStorageArtifact(AccessKind kind, string target)
    {
        if (kind != AccessKind.File || string.IsNullOrEmpty(target)) return false;
        return target.EndsWith(WofCompressedData, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The file a path refers to once any alternate data stream suffix is
    /// removed: <c>C:\dir\file.txt:Zone.Identifier</c> gives
    /// <c>C:\dir\file.txt</c>. A path without a stream is returned as is.
    /// The drive colon at index 1 is never treated as a stream separator.
    /// </summary>
    public static string FileOfStream(string path)
    {
        if (string.IsNullOrEmpty(path)) return path;
        var lastSeparator = path.LastIndexOfAny(PathSeparators);
        var colon = path.IndexOf(':', Math.Max(2, lastSeparator + 1));
        return colon > 0 ? path.Substring(0, colon) : path;
    }
}
