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
using System.Text.Json;
using static Mango.Common.MangoPaths;
using static Mango.Common.Scoring;
namespace Mango.Adaptive;

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

            var encrypted = cryptoLib.Encrypt(profile, input);
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
}
