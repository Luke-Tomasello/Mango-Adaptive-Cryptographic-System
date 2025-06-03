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
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Mango.Common;
using static Mango.Common.Scoring;

namespace Mango.Adaptive;

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

    private static readonly Dictionary<string, InputProfile> BestProfiles = new();
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
                    var path = Path.Combine(AppContext.BaseDirectory, "InputProfiles.json");
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
    public class InputProfileDto
    {
        public List<List<byte>> Sequence { get; set; } = new();
        public int GlobalRounds { get; set; }
        public double AggregateScore { get; set; }
    }
    public static void RefreshProfiles()
    {
        lock (ProfilesLock)
        {
            var path = Path.Combine(AppContext.BaseDirectory, "InputProfiles.json");
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