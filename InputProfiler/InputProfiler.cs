/*
   * InputProfiler Module
   * =============================================
   * Project: Mango
   * Purpose: Performs intelligent classification and profiling of input data
   *          to enable Mango's adaptive cryptographic behavior.
   *
   *          This module supports:
   *            • Static Classification: Uses magic bytes and format hints to match input to known types
   *            • Encrypted Classification: Encrypts input with known profiles to find the best scoring match
   *            • Fallback Handling: Defaults to a high-quality general-purpose profile when no match is found
   *            • Seamless integration with pre-baked god-sequences (e.g., Natural, Random, Combined)
   *
   *          Powers Mango's adaptive encryption by dynamically selecting
   *          the best InputProfile, ensuring cryptographic performance is tailored
   *          to the structure and content of each input.
   *
   * Author: [Luke Tomasello, luke@tomasello.com]
   * Created: November 2024
   * License: [MIT]
   * =============================================
   */

using Mango.AnalysisCore;
using Mango.Cipher;
using Mango.Common;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using static Mango.Common.MangoPaths;
using static Mango.Common.Scoring;
namespace Mango.Adaptive;
#if true
public enum EncryptionPerformanceMode
{
    Fast,
    Best
}

public static class InputProfiler
{
    public static InputProfile GetInputProfile(byte[] input, OperationModes weightingMode, ScoringModes scoringMode,
        EncryptionPerformanceMode performance = EncryptionPerformanceMode.Best)
    {
        EnsureProfilesLoaded();

        string classification = GetClassificationKey(input, performance);

        if (BestProfiles.TryGetValue(classification, out var profile))
            return profile;

        classification = FindBestProfileByEncryption(input, weightingMode, scoringMode, performance);
        if (BestProfiles.TryGetValue(classification, out profile))
            return profile;

        throw new InvalidOperationException(
            $"No fallback profile found. Classification attempted: {classification}");
    }
    public static InputProfile CreateInputProfile(string? name, byte[] sequence, byte[] tRs, int globalRounds, double aggregateScore = 0.0)
    {
        name ??= "Dynamic";

        if (sequence.Length != tRs.Length)
            throw new ArgumentException("Sequence and tRs must be of equal length.");

        var sequenceWithRounds = new (byte ID, byte TR)[sequence.Length];
        for (int i = 0; i < sequence.Length; i++)
            sequenceWithRounds[i] = (sequence[i], tRs[i]);

        return new InputProfile(name, sequenceWithRounds, globalRounds, aggregateScore);
    }
    public static InputProfile CreateInputProfile(string? name, (byte ID, byte TR)[] sequenceWithRounds, int globalRounds, double aggregateScore = 0.0)
    {
        name ??= "Dynamic";
        return new InputProfile(name, sequenceWithRounds, globalRounds, aggregateScore);
    }
    // 🧬 High-Fidelity Classification Key:
    // We use the full TSV byte array (Base64-encoded) as the signature to preserve
    // maximum structural fidelity. Reducing the TSV to a hash or integer risks
    // collapsing distinct inputs into the same classification bucket, undermining
    // the precision of profile selection. This ensures that even subtle input
    // differences lead to appropriately distinct profile lookups.
    private static string GetClassificationKey(byte[] input, EncryptionPerformanceMode performance)
    {
        var tsv = TomaselloSignatureVector.Compute(input);
        string signatureKey = Convert.ToBase64String(tsv);
        return $"{signatureKey}:{performance}";
    }

    private static string FindBestProfileByEncryption(byte[] input,
        OperationModes weightMode,
        ScoringModes scoringMode,
        EncryptionPerformanceMode performance)
    {
        const double tolerance = 0.98;
        const string fallbackProfile = "Default.Best";
        const string password = "sample-password";

        string cacheKey = GetClassificationKey(input, performance);

        lock (CacheLock)
        {
            if (ProfileMatchCache.TryGetValue(cacheKey, out var cachedProfile))
            {
                CacheOrder.Remove(cacheKey);
                CacheOrder.AddFirst(cacheKey);
                return cachedProfile;
            }
        }

        var options = new CryptoLibOptions(salt: MangoSalt);
        var analysisCore = new CryptoAnalysisCore(weightMode);
        var cryptoLib = new CryptoLib(password, options);

        string bestMatch = fallbackProfile;
        double bestScore = 0;

        foreach (var (name, profile) in BestProfiles)
        {
            if (performance == EncryptionPerformanceMode.Fast && name.EndsWith(".Best", StringComparison.OrdinalIgnoreCase))
                continue;
            if (performance == EncryptionPerformanceMode.Best && name.EndsWith(".Fast", StringComparison.OrdinalIgnoreCase))
                continue;

            var encrypted = cryptoLib.Encrypt(profile.Sequence, profile.GlobalRounds, input);
            var payload = cryptoLib.GetPayloadOnly(encrypted);

            var (avalanche, keydep) = ProcessAvalancheAndKeyDependency(cryptoLib, input, password, profile);

            var results = analysisCore.RunCryptAnalysis(payload, avalanche, keydep, input);
            var score = analysisCore.CalculateAggregateScore(results, scoringMode);

            // ✅ Robust Match Guard:
            // This tolerance check ensures that we only select a profile if it not only
            // performs best on this input, but also meets or exceeds a historical threshold
            // (its known aggregate performance). This prevents selecting profiles that may
            // have scored unusually well on a single input by chance but underperform generally.
            // Especially important when caching classification results using TSV fingerprints.
            if (score >= profile.AggregateScore * tolerance && score > bestScore)
            {
                bestMatch = name;
                bestScore = score;
            }
        }

        lock (CacheLock)
        {
            ProfileMatchCache[cacheKey] = bestMatch;
            CacheOrder.AddFirst(cacheKey);
            if (CacheOrder.Count > CacheCapacity)
            {
                var oldest = CacheOrder.Last!;
                ProfileMatchCache.Remove(oldest.Value);
                CacheOrder.RemoveLast();
            }
        }

        return bestMatch;
    }

    private static readonly int CacheCapacity = 16;
    private static readonly Dictionary<string, string> ProfileMatchCache = new();
    private static readonly LinkedList<string> CacheOrder = new();
    private static readonly object CacheLock = new();
    private static readonly Dictionary<string, InputProfile> BestProfiles = new(StringComparer.OrdinalIgnoreCase);
    private static volatile bool _profilesLoaded;
    private static readonly object ProfilesLock = new object();

    private static void EnsureProfilesLoaded()
    {
        if (_profilesLoaded) return;

        lock (ProfilesLock)
        {
            if (_profilesLoaded) return;

            var path = Path.Combine(GetProgectDataDirectory(), "InputProfiles.json");
            if (!File.Exists(path))
                throw new FileNotFoundException("Required InputProfiles.json file is missing.", path);

            var json = File.ReadAllText(path);
            var rawDict = JsonSerializer.Deserialize<Dictionary<string, InputProfileDto>>(json);
            if (rawDict != null)
            {
                foreach (var (name, dto) in rawDict)
                {
                    var sequence = dto.Sequence.Select(pair => (ID: pair[0], TR: pair[1])).ToArray();
                    BestProfiles[name] = new InputProfile(name, sequence, dto.GlobalRounds, dto.AggregateScore);
                }
            }

            _profilesLoaded = true;
        }
    }

    public static void RefreshProfiles()
    {
        lock (ProfilesLock)
        {
            var path = Path.Combine(GetProgectDataDirectory(), "InputProfiles.json");
            if (!File.Exists(path))
                throw new FileNotFoundException("Required InputProfiles.json file is missing.", path);

            var json = File.ReadAllText(path);
            var rawDict = JsonSerializer.Deserialize<Dictionary<string, InputProfileDto>>(json);

            if (rawDict == null)
                throw new InvalidDataException("Failed to deserialize InputProfiles.json: result was null.");

            BestProfiles.Clear();

            foreach (var (name, dto) in rawDict)
            {
                var sequence = dto.Sequence.Select(pair => (ID: pair[0], TR: pair[1])).ToArray();
                BestProfiles[name] = new InputProfile(name, sequence, dto.GlobalRounds, dto.AggregateScore);
            }

            _profilesLoaded = true;

            lock (CacheLock)
            {
                ProfileMatchCache.Clear();
                CacheOrder.Clear();
            }
        }
    }

    /// <summary>
    /// Produces a 32-byte structure-preserving signature ("TSV") from raw input data.
    /// Unlike traditional cryptographic hashes, the TSV retains high-level semantic features 
    /// (e.g., text structure, binary density, telemetry traits), enabling transform-layer adaptivity.
    /// Mango uses this as a shaping vector for input-aware cryptography, without decoding its meaning.
    /// </summary>
    static class TomaselloSignatureVector
    {
        static bool _debugOutput = false;
        /// <summary>
        /// Computes the Tomasello Signature Vector (TSV) for the given input.
        /// Analyzes characteristics like entropy, repetition, printability, and format hints
        /// to populate a 32-byte vector that reflects the structural essence of the data.
        /// Designed to be fast, consistent, and opaque to consumers.
        /// </summary>
        /// <param name="data">The raw input data to analyze.</param>
        /// <returns>A 32-byte TSV fingerprint representing the input's structural profile.</returns>
        public static byte[] Compute(ReadOnlySpan<byte> data)
        {
            Span<byte> result = stackalloc byte[32];

            // --- Designator bytes (0–15) ---
            if (LooksAsciiText(data)) result[0] |= 1 << 0;
            if (LooksLikeHtml(data)) result[0] |= 1 << 1;
            if (LooksCodeLike(data)) result[0] |= 1 << 2;
            if (LooksBinary(data)) result[1] |= 1 << 0;
            if (LooksHighEntropy(data)) result[1] |= 1 << 1;
            if (LooksExecutable(data)) result[3] |= 1 << 0;
            if (LooksStructuredTelemetry(data)) result[5] |= 1 << 0;

            // --- Attribute bytes (16–31) ---
            result[16] = (byte)(EstimateEntropy(data) * 255); // normalized
            result[17] = (byte)Math.Min(Math.Sqrt(MeasureTokenVariance(data)) * 10, 255);
            result[18] = (byte)Math.Min(Math.Sqrt(MeasureRepetition(data)) * 10, 255);

            return result.ToArray();
        }

        static bool LooksAsciiText(ReadOnlySpan<byte> data)
        {
            int printable = 0, total = Math.Min(data.Length, 2048);
            for (int i = 0; i < total; i++)
            {
                byte b = data[i];
                if (b >= 0x20 && b <= 0x7E || b == 0x0A || b == 0x0D || b == 0x09)
                    printable++;
            }
            if (_debugOutput) Console.WriteLine($"[TextCheck] Printable ratio: {(double)printable / total:P1}");
            return printable > total * 0.85;
        }

        static bool LooksLikeHtml(ReadOnlySpan<byte> data)
        {
            var text = System.Text.Encoding.UTF8.GetString(data[..Math.Min(data.Length, 4096)]);
            bool found = text.Contains("<html") || text.Contains("<div") || text.Contains("<!DOCTYPE html");
            if (_debugOutput) Console.WriteLine($"[HTMLCheck] HTML tags found: {found}");
            return found;
        }

        static bool LooksCodeLike(ReadOnlySpan<byte> data)
        {
            var text = System.Text.Encoding.UTF8.GetString(data[..Math.Min(data.Length, 4096)]);
            bool found = text.Contains("public") || text.Contains("class") || text.Contains("#include") || text.Contains("def ");
            if (_debugOutput) Console.WriteLine($"[CodeCheck] Code-like patterns found: {found}");
            return found;
        }

        static bool LooksBinary(ReadOnlySpan<byte> data)
        {
            int zeroes = 0;
            for (int i = 0; i < Math.Min(data.Length, 1024); i++)
                if (data[i] == 0x00) zeroes++;
            if (_debugOutput) Console.WriteLine($"[BinaryCheck] Zero bytes: {zeroes}");
            return zeroes > 10;
        }

        static bool LooksHighEntropy(ReadOnlySpan<byte> data)
        {
            double entropy = EstimateEntropy(data);
            if (_debugOutput) Console.WriteLine($"[EntropyCheck] Normalized entropy: {entropy:F3}");
            return entropy > 0.85;
        }

        static bool LooksExecutable(ReadOnlySpan<byte> data)
        {
            bool mz = data.Length > 2 && data[0] == 0x4D && data[1] == 0x5A;
            if (_debugOutput) Console.WriteLine($"[ExecCheck] MZ header: {mz}");
            return mz;
        }

        static bool LooksStructuredTelemetry(ReadOnlySpan<byte> data)
        {
            double entropy = EstimateEntropy(data);
            int repetition = MeasureRepetition(data);
            int printable = 0;
            int count = Math.Min(data.Length, 2048);
            for (int i = 0; i < count; i++)
            {
                byte b = data[i];
                if (b >= 0x20 && b <= 0x7E || b == 0x0A || b == 0x0D || b == 0x09)
                    printable++;
            }
            double printableRatio = printable / (double)count;

            bool looksStructured = printableRatio > 0.95 && entropy > 0.3 && entropy < 0.65 && repetition > 50;
            if (_debugOutput) Console.WriteLine($"[TelemetryCheck] Looks structured telemetry: {looksStructured}");
            return looksStructured;
        }

        static double EstimateEntropy(ReadOnlySpan<byte> data)
        {
            Span<int> counts = stackalloc int[256];
            int len = Math.Min(data.Length, 8192);
            for (int i = 0; i < len; i++) counts[data[i]]++;

            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] == 0) continue;
                double p = (double)counts[i] / len;
                entropy -= p * Math.Log2(p);
            }
            return entropy / 8.0; // normalize to [0,1]
        }

        static int MeasureTokenVariance(ReadOnlySpan<byte> data)
        {
            int words = 0, totalLen = 0, currentLen = 0;
            for (int i = 0; i < Math.Min(data.Length, 2048); i++)
            {
                byte b = data[i];
                if (b == ' ' || b == '\n' || b == '\r' || b == '\t')
                {
                    if (currentLen > 0) { words++; totalLen += currentLen; currentLen = 0; }
                }
                else currentLen++;
            }
            if (words == 0) return 0;
            int avg = totalLen / words;
            int score = Math.Abs(avg - 5) * 10;
            if (_debugOutput) Console.WriteLine($"[TokenVar] Word count: {words}, AvgLen: {avg}, Score: {score}");
            return score;
        }

        static int MeasureRepetition(ReadOnlySpan<byte> data)
        {
            int repeats = 0;
            for (int i = 1; i < Math.Min(data.Length, 2048); i++)
                if (data[i] == data[i - 1]) repeats++;
            if (_debugOutput) Console.WriteLine($"[RepeatCheck] Repeat count: {repeats}");
            return repeats;
        }
    }
}


#else
public enum EncryptionPerformanceMode
{
    /// <summary>
    /// Prioritizes speed of encryption/decryption, potentially at the expense of maximum security.
    /// May use simpler algorithms, fewer rounds, or less robust key derivation.
    /// </summary>
    Fast,

    /// <summary>
    /// Prioritizes the highest level of security, potentially at the expense of performance.
    /// May use more complex algorithms, more rounds, or more robust key derivation.
    /// </summary>
    Best
}
public class InputProfiler
{
    /// <summary>
    /// Selects the best-fit InputProfile for the provided input.
    /// Prioritizes fast static classification (e.g., file signatures),
    /// falls back to encrypted match against known profiles, and ultimately
    /// uses the default profile if no match is found.
    /// </summary>
    public static InputProfile GetInputProfile(byte[] input, OperationModes weightingMode, ScoringModes scoringMode,
        EncryptionPerformanceMode performance = EncryptionPerformanceMode.Best)
    {
        EnsureProfilesLoaded();

        // 🧠 Step 1: Attempt static classification based on known file signatures
        var classification = ClassificationWorker(input);
        if (BestProfiles.TryGetValue(classification, out var profile))
            return profile;

        // 🔍 Step 2: If static classification fails, evaluate encrypted fit
        classification = FindBestProfileByEncryption(input, weightingMode, scoringMode, performance);
        if (BestProfiles.TryGetValue(classification, out profile))
            return profile;

        // 🚨 Step 3: Final fallback (should never occur if Default.Best exists)
        throw new InvalidOperationException(
            $"No fallback profile found. Classification attempted: {classification}");
    }
    public static InputProfile CreateInputProfile(string? name,
        byte[] sequence,
        byte[] tRs,
        int globalRounds,
        double aggregateScore = 0.0)
    {
        name ??= "Dynamic";

        if (sequence.Length != tRs.Length)
            throw new ArgumentException("Sequence and tRs must be of equal length.");

        var sequenceWithRounds = new (byte ID, byte TR)[sequence.Length];
        for (int i = 0; i < sequence.Length; i++)
            sequenceWithRounds[i] = (sequence[i], tRs[i]);

        return new InputProfile(name, sequenceWithRounds, globalRounds, aggregateScore);
    }
    public static InputProfile CreateInputProfile(
        string? name,
        (byte ID, byte TR)[] sequenceWithRounds,
        int globalRounds,
        double aggregateScore = 0.0)
    {
        name ??= "Dynamic";
        return new InputProfile(name, sequenceWithRounds, globalRounds, aggregateScore);
    }

    private static readonly int CacheCapacity = 16;
    private static readonly Dictionary<string, string> ProfileMatchCache = new();
    private static readonly LinkedList<string> CacheOrder = new();
    private static readonly object CacheLock = new();

    private static string FindBestProfileByEncryption(byte[] input,
        OperationModes weightMode,
        ScoringModes scoringMode,
        EncryptionPerformanceMode performance)
    {
        const double tolerance = 0.98;
        const string fallbackProfile = "Default.Best";
        const string password = "sample-password";

        byte[] inputHash = SHA256.HashData(input);
        string cacheKey = Convert.ToBase64String(inputHash) + ":" + performance;

        lock (CacheLock)
        {
            if (ProfileMatchCache.TryGetValue(cacheKey, out var cachedProfile))
            {
                CacheOrder.Remove(cacheKey);
                CacheOrder.AddFirst(cacheKey);
                return cachedProfile;
            }
        }

        var options = new CryptoLibOptions(
            salt: MangoSalt
        );
        var analysisCore = new CryptoAnalysisCore(weightMode);
        var cryptoLib = new CryptoLib(password, options);

        string bestMatch = fallbackProfile;
        double bestScore = 0;

        foreach (var (name, profile) in BestProfiles)
        {
            // 📛 Filter profiles by performance mode
            if (performance == EncryptionPerformanceMode.Fast && name.EndsWith(".Best", StringComparison.OrdinalIgnoreCase))
                continue;
            if (performance == EncryptionPerformanceMode.Best && name.EndsWith(".Fast", StringComparison.OrdinalIgnoreCase))
                continue;

            var encrypted = cryptoLib.Encrypt(profile.Sequence, profile.GlobalRounds, input);
            var payload = cryptoLib.GetPayloadOnly(encrypted);

            var (avalanche, keydep) = ProcessAvalancheAndKeyDependency(cryptoLib, input, password, profile);

            var results = analysisCore.RunCryptAnalysis(payload, avalanche, keydep, input);
            var score = analysisCore.CalculateAggregateScore(results, scoringMode);

            if (score >= profile.AggregateScore * tolerance && score > bestScore)
            {
                bestMatch = name;
                bestScore = score;
            }
        }

        lock (CacheLock)
        {
            ProfileMatchCache[cacheKey] = bestMatch;
            CacheOrder.AddFirst(cacheKey);
            if (CacheOrder.Count > CacheCapacity)
            {
                var oldest = CacheOrder.Last!;
                ProfileMatchCache.Remove(oldest.Value);
                CacheOrder.RemoveLast();
            }
        }

        return bestMatch;
    }

    private class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();

        public bool Equals(byte[]? x, byte[]? y) =>
            x != null && y != null && x.SequenceEqual(y);

        public int GetHashCode(byte[] obj)
        {
            unchecked
            {
                int hash = 17;
                foreach (var b in obj)
                    hash = hash * 31 + b;
                return hash;
            }
        }
    }

    private static string ClassificationWorker(byte[] data)
    {
        var fileType = KnownFileType(data);
        var classification = RemapFileType(data, fileType);
        return classification;
    }
    private static string RemapFileType(byte[] data, string fileType)
    {
        switch (fileType)
        {
            case "HTML":
            case "TXT":
            case "CSV":
            case "XML":
            case "SQL":
            case "SVG":
                return "Natural";

            case "JPG":
            case "PNG":
            case "GIF":
            case "BMP":
            case "MP4":
            case "MKV":
            case "MP3":
            case "WAV":
                return "Media";

            case "ZIP":
            case "RAR":
            case "7Z":
            case "GZ":
                return "Random/Encrypted";

            case "EXE":
            case "DLL":
            case "ISO":
            case "PDF":
                return "Other";

            default:
                var alphaWhite = ComputePercentAlphaNumericPunct(data);
                if (alphaWhite > 0.90)
                    return "Natural";

                return "Other";
        }
    }
    private static string KnownFileType(byte[] data)
    {
        if (data!.Length < 4) return "Unknown";

        // PDF (Header: "%PDF-")
        if (data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46)
            return "PDF";

        // ZIP (Header: "PK\x03\x04")
        if (data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04)
            return "ZIP";

        // EXE/DLL (MZ header)
        if (data[0] == 0x4D && data[1] == 0x5A)
            return "EXE";

        // HTML (common start: "<!DO" or "<htm")
        if (data[0] == 0x3C && data[1] == 0x21 && data[2] == 0x44 && data[3] == 0x4F)
            return "HTML";
        if (data[0] == 0x3C && data[1] == 0x68 && data[2] == 0x74 && data[3] == 0x6D)
            return "HTML";

        // JPG (JPEG SOI - Start of Image)
        if (data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF)
            return "JPG"; // ✅ Return specific file type

        // PNG (Header: "\x89PNG\r\n\x1A\n")
        if (data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47)
            return "PNG"; // ✅ Return specific file type

        // MKV (Matroska Video File)
        if (data[0] == 0x1A && data[1] == 0x45 && data[2] == 0xDF && data[3] == 0xA3)
            return "MKV";

        // WAV (Waveform Audio File Format)
        if (data.Length >= 12 &&
            data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46 && // "RIFF"
            data[8] == 0x57 && data[9] == 0x41 && data[10] == 0x56 && data[11] == 0x45) // "WAVE"
            return "WAV";

        // MSI (Microsoft Installer - PE format with MZ Header)
        if (data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 && data[3] == 0xE0)
            return "MSI";

        return "Unknown";
    }
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static double ComputePercentAlphaNumericPunct(byte[] data)
    {
        int count = 0;
        foreach (var b in data)
        {
            if ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || // Alphabetic
                (b >= '0' && b <= '9') ||                           // Numeric
                (b == ' ' || b == '\t' || b == '\n' || b == '\r') || // Whitespace
                (b >= 33 && b <= 47) || (b >= 58 && b <= 64) ||      // Punctuation ranges
                (b >= 91 && b <= 96) || (b >= 123 && b <= 126))
            {
                count++;
            }
        }

        return count / (double)data.Length;
    }

    private static readonly Dictionary<string, InputProfile> BestProfiles = new(StringComparer.OrdinalIgnoreCase);
    private static volatile bool _profilesLoaded;
    private static readonly object ProfilesLock = new object();
    private static void EnsureProfilesLoaded()
    {
        if (!_profilesLoaded)
        {
            lock (ProfilesLock)
            {
                if (!_profilesLoaded)
                {
                    var path = Path.Combine(GetProgectDataDirectory(), "InputProfiles.json");
                    if (!File.Exists(path))
                        throw new FileNotFoundException("Required InputProfiles.json file is missing.", path);

                    var json = File.ReadAllText(path);
                    var rawDict = JsonSerializer.Deserialize<Dictionary<string, InputProfileDto>>(json);
                    if (rawDict != null)
                    {
                        foreach (var (name, dto) in rawDict)
                        {
                            var sequence = dto.Sequence
                                .Select(pair =>
                                {
                                    if (pair.Count != 2)
                                        throw new InvalidDataException($"Invalid tuple in sequence for profile '{name}'");

                                    return (ID: pair[0], TR: pair[1]);
                                })
                                .ToArray();

                            BestProfiles[name] = new InputProfile(name, sequence, dto.GlobalRounds, dto.AggregateScore);
                        }
                    }

                    _profilesLoaded = true;
                }
            }

        }
    }
    public static void RefreshProfiles()
    {
        lock (ProfilesLock)
        {
            var path = Path.Combine(GetProgectDataDirectory(), "InputProfiles.json");
            if (!File.Exists(path))
                throw new FileNotFoundException("Required InputProfiles.json file is missing.", path);

            var json = File.ReadAllText(path);
            var rawDict = JsonSerializer.Deserialize<Dictionary<string, InputProfileDto>>(json);

            if (rawDict == null)
                throw new InvalidDataException("Failed to deserialize InputProfiles.json: result was null.");

            BestProfiles.Clear();

            foreach (var (name, dto) in rawDict)
            {
                var sequence = dto.Sequence
                    .Select(pair =>
                    {
                        if (pair.Count != 2)
                            throw new InvalidDataException($"Invalid tuple in sequence for profile '{name}'");

                        return (ID: pair[0], TR: pair[1]);
                    })
                    .ToArray();

                BestProfiles[name] = new InputProfile(name, sequence, dto.GlobalRounds, dto.AggregateScore);
            }

            _profilesLoaded = true;

            lock (CacheLock)
            {
                ProfileMatchCache.Clear();
                CacheOrder.Clear();
            }
        }
    }
}
#endif