/*
 * Utilities Module
 * =============================================
 * Project: Mango
 * Purpose: System-wide utility support for Mango's cryptographic workbench,
 *          including core components used throughout the Workbench, Analyzer,
 *          and Cipher layers.
 *
 *          This module includes:
 *            • Global and transform-specific state management
 *            • Input classification and entropy profiling
 *            • CutList filtering, validation, and persistence
 *            • LocalEnvironment setup and teardown
 *            • Periodic logging, debug tools, and byte array helpers
 *
 *          While not domain-specific, this module provides the foundational
 *          scaffolding for adaptive workflows and sequence optimization.
 *
 * Author: [Luke Tomasello, luke@tomasello.com]
 * Created: November 2024
 * License: [MIT]
 * =============================================
 */

using Mango.Analysis;
using Mango.Cipher;
using Mango.Reporting;
using Mango.Workbench;
using System.Buffers.Binary;
using System.Data.SQLite;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using static Mango.Utilities.SequenceHelper;
using static Mango.Utilities.TestInputGenerator;

namespace Mango.Utilities;

public enum OperationModes
{
    None = 0x01,

    /// <summary>
    /// Focuses on cryptographic accuracy and performance.
    /// </summary>
    Cryptographic = 0x02,
    Cryptographic_New = 0x04,

    /// <summary>
    /// Enables exploratory mode for experimenting with sequences.
    /// </summary>
    Exploratory = 0x08,
    Exploratory_New = 0x10,

    /// <summary>
    /// Ensures input data is fully neutralized before further transformation.
    /// This mode prioritizes eliminating all structural patterns, periodicity, and biases,
    /// effectively "flattening" the data into a maximally uniform state. 
    /// The goal is to prepare input for subsequent transformations that rely on predictable 
    /// patterns (e.g., PatternInjectorTx).
    /// 
    /// Key Focus:
    /// ✅ Maximizes entropy to resemble pure randomness.
    /// ✅ Eliminates frequency imbalances and sliding window correlations.
    /// ✅ Ensures no residual periodicity remains in the data.
    /// 
    /// Ideal use case:
    /// - As a preprocessing step before injecting structured patterns.
    /// - When input data exhibits strong biases that interfere with cryptographic operations.
    /// </summary>
    Flattening = 0x20
}

public partial class CutListHelper
{
    private static Dictionary<string, Dictionary<int, byte[]>> _cutMatrixCache = new();
    private string _key = null!;
    private int _activeDataIndex;

    public CutListHelper(string mungeFileName)
    {
        messages = new List<string>(); // start fresh
        Init(mungeFileName);
    }

    private void Init(string file)
    {
        var parts = Path.GetFileNameWithoutExtension(file).Split('-');
        if (parts.Length < 4)
            throw new Exception("Invalid Munge filename format.");

        _key = GenerateCutListKey(file);

        if (!_cutMatrixCache.ContainsKey(_key))
        {
            if (File.Exists(file))
            {
                messages.Add($"⚠️ Cutlist key missing for {_key}, generating from file...");
                ProcessContenderFile(file);

                if (!_cutMatrixCache.ContainsKey(_key))
                    throw new Exception($"Failed to populate CutMatrixCache from {file}");
            }
            else
            {
                messages.Add(
                    $"⚠️ No contender file found for {_key}. Using fallback: ALL transforms remain valid (no cuts applied).");

                _cutMatrixCache[_key] = new Dictionary<int, byte[]>();

                foreach (var (id, info) in _cryptoLib!.TransformRegistry)
                    _cutMatrixCache[_key][id] = new byte[4] { 1, 1, 1, 1 }; // everything is VALID (uncut)
            }
        }

        _activeDataIndex = GetIndexFromFileName(file);
    }

    public bool IsCut(int transformId)
    {
        return _cutMatrixCache.ContainsKey(_key) &&
               _cutMatrixCache[_key].ContainsKey(transformId) &&
               _cutMatrixCache[_key][transformId][_activeDataIndex] != 1;
    }
}

public partial class CutListHelper
{
    private static CryptoLib? _cryptoLib;
    private static List<string> messages = new();
    private const string _where = ".";
    private const string _dbname = "CutList.json";
#if DEBUG
    private static bool _fileLocking = false;
#else
        private static bool _fileLocking = true;
#endif
    public static void Compile(CryptoLib? cryptoLib)
    {
        _cryptoLib = cryptoLib;
        messages = new List<string>(); // fresh each run

        // 🔄 1. Load existing persistent cutlist (if any)
        LoadCutlistFromJson();

        var searchPattern = "Contenders,-L?-P?-D?-MC-ST.txt";
        var directoryPath = _where;

        var contenderFiles = Directory.GetFiles(directoryPath, searchPattern)
            .Where(IsEligibleContenderFile)
            .ToList();

        if (contenderFiles.Count == 0)
        {
            messages.Add("No valid contender files found. Ensure Munge has been run.");
            return;
        }

        // 🧠 2. Process all contender files — overwrite/augment CutMatrixCache
        var filesProcessed = 0;
        foreach (var filePath in contenderFiles)
        {
            ProcessContenderFile(filePath);
            filesProcessed++;
        }

        // ✅ 3. Validation & checks
        ValidateAndFinalizeCutList();
        SanityCheck();

        // 💾 4. Write JSON for persistence, and optionally TXT for human inspection
        WriteCutlistToJson();

        messages.Add("\n=== Processing Complete ===");
    }

    private static string GenerateCutListKey(string fileName)
    {
        var fileNameParts = Path.GetFileNameWithoutExtension(fileName).Split('-');
        if (fileNameParts.Length < 4)
            throw new Exception("Invalid filename format.");

        var level = fileNameParts[1]; // L1, L2, etc..
        var passSount = fileNameParts[2]; // sequence must pass PassCount metrics to be considered
        var dataType = fileNameParts[3]; // Data type: Combined, Random, etc..

        return $"{level}-{passSount}-{dataType}";
    }

    private static string GetDataTypeFromFileName(string fileName)
    {
        var fileNameParts = Path.GetFileNameWithoutExtension(fileName).Split('-');
        if (fileNameParts.Length < 4) throw new ArgumentException($"Invalid filename format: {fileName}");

        return fileNameParts[3];
    }

    private int GetIndexFromFileName(string fileName)
    {
        var fileNameParts = Path.GetFileNameWithoutExtension(fileName).Split('-');
        if (fileNameParts.Length < 4) throw new ArgumentException($"Invalid filename format: {fileName}");

        return fileNameParts[3] switch
        {
            "DC" => 0,
            "DN" => 1,
            "DR" => 2,
            "DS" => 3,
            _ => throw new Exception($"Unknown DataType in file name: {fileNameParts[3]}")
        };
    }

    private static void ProcessContenderFile(string file)
    {
        try
        {
            messages.Add($"Processing: {file}");

            var key = GenerateCutListKey(file);
            var dataType = GetDataTypeFromFileName(file);

            if (!_cutMatrixCache.ContainsKey(key))
            {
                _cutMatrixCache[key] = new Dictionary<int, byte[]>();

                foreach (var (id, info) in _cryptoLib!.TransformRegistry)
                    _cutMatrixCache[key][id] = new byte[4] { 0, 0, 0, 0 }; // default "cut"
            }

            var transformsInTopSequences = new HashSet<int>();
            var lines = File.ReadLines(file)
                .Where(line => line.StartsWith("Sequence:"))
                .Take(10).ToList();

            if (lines.Count < 10)
                messages.Add(
                    $"⚠️ Only {lines.Count} contender(s) found in {file}. Cut matrix will reflect limited data.");

            foreach (var line in lines)
            {
                var sequence = line.Substring("Sequence:".Length).Trim();
                var transforms = sequence.Split("->", StringSplitOptions.TrimEntries);

                foreach (var transform in transforms)
                {
                    var entry = _cryptoLib!.TransformRegistry.FirstOrDefault(kvp => kvp.Value.Name == transform);
                    if (entry.Key != 0)
                        if (!transformsInTopSequences.Contains(entry.Key))
                            transformsInTopSequences.Add(entry.Key);
                }
            }

            foreach (var id in _cryptoLib!.TransformRegistry.Keys)
            {
                var dataIndex = dataType switch
                {
                    "DC" => 0,
                    "DN" => 1,
                    "DR" => 2,
                    "DS" => 3,
                    _ => throw new Exception($"Unknown DataType: {dataType}")
                };

                var usedInTop10 = transformsInTopSequences.Contains(id);
                _cutMatrixCache[key][id][dataIndex] = usedInTop10 ? (byte)0x01 : (byte)0x00;
            }

            messages.Add($"✅ Processed {transformsInTopSequences.Count} unique transforms.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error processing file {file}: {ex.Message}");
        }
    }

    private static void SanityCheck()
    {
        messages.Add("\n🔍 Running Sanity Check...");

        var searchPattern = "Contenders,-L?-P?-D?-MC-ST.txt";
        var directoryPath = _where;

        var contenderFiles = Directory.GetFiles(directoryPath, searchPattern)
            .Where(IsEligibleContenderFile)
            .ToList();

        foreach (var filePath in contenderFiles)
        {
            var key = GenerateCutListKey(filePath);
            var dataType = GetDataTypeFromFileName(filePath);

            if (!_cutMatrixCache.ContainsKey(key))
                throw new Exception($"❌ Sanity Check Failed: Missing key in cutlist → {key}");

            var transformsInTopSequences = new HashSet<int>();
            var lines = File.ReadLines(filePath)
                .Where(line => line.StartsWith("Sequence:"))
                .Take(10).ToList();

            foreach (var line in lines)
            {
                var sequence = line.Substring("Sequence:".Length).Trim();
                var transforms = sequence.Split("->", StringSplitOptions.TrimEntries);

                foreach (var transform in transforms)
                {
                    var entry = _cryptoLib!.TransformRegistry.FirstOrDefault(kvp => kvp.Value.Name == transform);
                    if (entry.Key != 0)
                        if (!transformsInTopSequences.Contains(entry.Key))
                            transformsInTopSequences.Add(entry.Key);
                }
            }

            foreach (var transformId in transformsInTopSequences)
            {
                var dataIndex = dataType switch
                {
                    "DC" => 0,
                    "DN" => 1,
                    "DR" => 2,
                    "DS" => 3,
                    _ => throw new Exception($"Unknown DataType in file name: {dataType}")
                };

                if (!_cutMatrixCache[key].ContainsKey(transformId) ||
                    _cutMatrixCache[key][transformId][dataIndex] != 0x01)
                    throw new Exception(
                        $"❌ Sanity Check Failed: Transform '{_cryptoLib!.TransformRegistry[transformId].Name}' from {key} is missing or marked incorrectly.");
            }
        }

        messages.Add("✅ Sanity check completed. All top 10 transforms accounted for.");
    }

    private static void ValidateAndFinalizeCutList()
    {
        foreach (var entry in _cutMatrixCache)
            foreach (var idEntry in entry.Value)
                if (idEntry.Value.Length != 4)
                    throw new Exception($"Invalid data length for TransformId {idEntry.Key} in key {entry.Key}");

        messages.Add("✅ All cutlist fields validated.");
        return;
    }

    public static bool IsEligibleContenderFile(string file)
    {
        return !file.Contains("-P0-") && !file.Contains("-P1-") && !file.Contains("-L1-") && !file.Contains("-L2-");
    }

    public int WillCut(List<byte> sequence)
    {
        var cutCount = 0;

        foreach (var id in sequence)
            if (IsCut(id))
                cutCount++;

        return cutCount;
    }

    private static void WriteCutlistToJson()
    {
        var outputPath = Path.Combine(AppContext.BaseDirectory, _dbname);

        try
        {
            if (_fileLocking && File.Exists(outputPath)) // 🔓 Force unlock
                File.SetAttributes(outputPath, FileAttributes.Normal);

            // Serialize the CutMatrixCache to JSON with indented formatting
            var json = JsonSerializer.Serialize(
                _cutMatrixCache,
                new JsonSerializerOptions
                {
                    WriteIndented = true
                });

            File.WriteAllText(outputPath, json);

            // 🔒 Re-lock the file if file locking is enabled
            if (_fileLocking) File.SetAttributes(outputPath, FileAttributes.ReadOnly);

            messages.Add($"✅ Cutlist successfully written to {outputPath}");
        }
        catch (Exception ex)
        {
            messages.Add($"❌ Error writing cutlist to JSON: {ex.Message}");
        }
    }

    public static void LoadCutlistFromJson()
    {
        _cutMatrixCache = new Dictionary<string, Dictionary<int, byte[]>>();
        var jsonPath = Path.Combine(AppContext.BaseDirectory, _dbname);

        if (File.Exists(jsonPath))
            try
            {
                var json = File.ReadAllText(jsonPath);
                var parsed = JsonSerializer.Deserialize<Dictionary<string, Dictionary<int, byte[]>>>(json);

                if (parsed != null)
                {
                    foreach (var entry in parsed)
                        _cutMatrixCache[entry.Key] = entry.Value;

                    messages.Add($"✅ CutList loaded from JSON: {jsonPath}");
                }
                else
                {
                    messages.Add("⚠️ CutList JSON was empty or malformed.");
                }
            }
            catch (Exception ex)
            {
                messages.Add($"❌ Error loading cutlist.json: {ex.Message}");
            }
        else
            messages.Add("ℹ️ No cutlist.json found. Will fall back to contender files if available.");
    }

    public static bool AnyWork()
    {
        var searchPattern = "Contenders,-L?-P?-D?-M?-S?.txt";
        var directoryPath = _where;

        var contenderFilesExist = Directory.Exists(directoryPath) &&
                                  Directory.GetFiles(directoryPath, searchPattern).Length > 0;

        var jsonPath = Path.Combine(AppContext.BaseDirectory, _dbname);
        var cutlistJsonExists = File.Exists(jsonPath);

        return contenderFilesExist || cutlistJsonExists;
    }
}

public partial class CutListHelper
{
    /// <summary>
    /// Verifies consistency between three sources of transform data:
    /// 1️⃣ The filtered `transforms` list passed to the function (already cut-filtered).
    /// 2️⃣ The original contender file contents on disk (./Contenders directory).
    /// 3️⃣ The in-memory `CutMatrixCache` for the active cutlist context.
    /// 
    /// ✅ This verification ensures that:
    /// - The cutlist logic (via `IsCut()`) produces correct filtering.
    /// - The file on disk accurately reflects the cut-filtered output.
    /// - The `CutMatrixCache` and the filtered input remain in sync.
    ///
    /// ⚠️ EXPECTED BEHAVIOR:
    /// - On the first Munge pass (pre-cutlist), the disk file will NOT match the cut-filtered list.
    /// - On subsequent runs (post-cutlist application), all sources should converge and match.
    ///
    /// 🧪 Usage: Typically called within debug mode or testing blocks to guard against regressions.
    ///
    /// </summary>
    /// <param name="contenderFileName">Path to the contender output file (e.g., Contenders,-L3...)</param>
    /// <param name="transforms">The current working list of transforms, after applying `IsCut()` filtering</param>
    /// <param name="diff_cutlist_vs_file">Outputs transform IDs found only in file OR only in filtered list</param>
    /// <param name="diff_cutlist_vs_table">Outputs transform IDs found only in CutMatrixCache OR filtered list</param>
    /// <returns>True if all sources match, false if any discrepancies are found</returns>
    public static bool VerifyCutList(string contenderFileName, List<byte> transforms,
        out List<byte> diff_cutlist_vs_file, out List<byte> diff_cutlist_vs_table)
    {
        // Early exit if contender file doesn't exist (likely first-run scenario)
        if (!File.Exists(contenderFileName))
        {
            messages.Add(
                $"⚠️ Skipping Cut List verification: {contenderFileName} not found (expected for new levels).");
            diff_cutlist_vs_file = new List<byte>();
            diff_cutlist_vs_table = new List<byte>();
            return true; // Graceful pass
        }

        messages.Add($"\n🔍 Verifying Cut List for {contenderFileName}...");

        diff_cutlist_vs_file = new List<byte>();
        diff_cutlist_vs_table = new List<byte>();

        try
        {
            // 1️⃣ Fresh from file
            var fileActual = CalculateTransformsFromFile(contenderFileName);

            // 2️⃣ Fresh from in-memory CutMatrixCache
            var tableActual = CalculateTransformsFromTable(contenderFileName);

            // Sort all lists for clean diffs
            var sortedInput = transforms.OrderBy(x => x).ToList();
            fileActual = fileActual.OrderBy(x => x).ToList();
            tableActual = tableActual.OrderBy(x => x).ToList();

            // Compare input vs file
            diff_cutlist_vs_file = sortedInput.Except(fileActual).Concat(fileActual.Except(sortedInput)).OrderBy(x => x)
                .ToList();

            // Compare input vs table
            diff_cutlist_vs_table = sortedInput.Except(tableActual).Concat(tableActual.Except(sortedInput))
                .OrderBy(x => x).ToList();

            var allMatch = !diff_cutlist_vs_file.Any() && !diff_cutlist_vs_table.Any();

            if (allMatch)
            {
                messages.Add($"✅ Cut List Verification Passed for {contenderFileName}. All lists match.");
                return true;
            }
            else
            {
                messages.Add($"❌ Cut List Verification Failed for {contenderFileName}.");

                messages.Add("--- Diff: CutList vs File ---");
                messages.Add(string.Join(", ", diff_cutlist_vs_file));

                messages.Add("--- Diff: CutList vs Table ---");
                messages.Add(string.Join(", ", diff_cutlist_vs_table));

                return false;
            }
        }
        catch (Exception ex)
        {
            messages.Add($"❌ Error verifying cut list for {contenderFileName}: {ex.Message}");
            return false;
        }
    }

    private static List<byte> CalculateTransformsFromFile(string contenderFileName)
    {
        var filePath = Path.Combine(_where, Path.GetFileName(contenderFileName));
        var transformsInTopSequences = new HashSet<int>();

        var lines = File.ReadLines(filePath)
            .Where(line => line.StartsWith("Sequence:"))
            .Take(10)
            .ToList();

        foreach (var line in lines)
        {
            var sequence = line.Substring("Sequence:".Length).Trim();
            var transforms = sequence.Split("->", StringSplitOptions.TrimEntries);

            foreach (var transform in transforms)
            {
                var entry = _cryptoLib!.TransformRegistry.FirstOrDefault(kvp => kvp.Value.Name == transform);
                if (entry.Key != 0)
                    transformsInTopSequences.Add(entry.Key);
            }
        }

        return transformsInTopSequences.Select(id => (byte)id).ToList();
    }

    private static List<byte> CalculateTransformsFromTable(string contenderFileName)
    {
        var key = GenerateCutListKey(contenderFileName);
        var dataType = GetDataTypeFromFileName(contenderFileName);

        var dataIndex = dataType switch
        {
            "DC" => 0,
            "DN" => 1,
            "DR" => 2,
            "DS" => 3,
            _ => throw new Exception($"Unknown DataType in file name: {dataType}")
        };

        var inMemoryTransforms = new List<byte>();

        if (_cutMatrixCache.ContainsKey(key))
            foreach (var kvp in _cutMatrixCache[key])
                if (kvp.Value[dataIndex] == 1)
                    inMemoryTransforms.Add((byte)kvp.Key);

        return inMemoryTransforms;
    }
}

// ✅ Helper class to compare byte arrays
public class ByteArrayComparer : IEqualityComparer<byte[]>
{
    public bool Equals(byte[]? x, byte[]? y)
    {
        if (x == null || y == null) return false;
        return x.SequenceEqual(y);
    }

    public int GetHashCode(byte[]? obj)
    {
        if (obj == null) return 0;
        return obj.Aggregate(17, (current, b) => current * 31 + b);
    }
}

public class PeriodicLogger
{
    private readonly TimeSpan interval;
    private DateTime lastLogTime;

    public PeriodicLogger(int seconds)
    {
        interval = TimeSpan.FromSeconds(seconds);
        lastLogTime = DateTime.UtcNow;
    }

    public bool ShouldLog()
    {
        return DateTime.UtcNow - lastLogTime >= interval;
    }

    public void WriteLine(string message)
    {
        if (DateTime.UtcNow - lastLogTime >= interval)
        {
            Console.WriteLine($"[{DateTime.UtcNow:T}] {message}");
            lastLogTime = DateTime.UtcNow;
        }
    }
}

public class LocalEnvironment : IDisposable
{
    public StateManager Rsm { get; }
    public ParsedSequence ParsedSequence { get; } = null!;

    // 🆕 Overload 1: Clone ExecutionEnvironment without a sequence
    public LocalEnvironment(ExecutionEnvironment localEnv)
    {
        Rsm = new StateManager(localEnv);
        Rsm.PushAllGlobals(); // ✅ Clone all global settings
        Rsm.PushAllTransformRounds(); // ✅ Push all current transform rounds
        Rsm.PushGlobalRounds(localEnv.Crypto.Options.Rounds); // ✅ Push default global rounds
    }

    // 🆕 Overload 2: Clone ExecutionEnvironment and apply additional settings
    public LocalEnvironment(ExecutionEnvironment localEnv, Dictionary<string, string> settings)
        : this(localEnv) // ✅ Calls first overload to initialize base environment
    {
        // ✅ Apply settings from dictionary
        foreach (var (key, value) in settings) localEnv.Globals.UpdateSetting(key, value);
    }

    public LocalEnvironment(ExecutionEnvironment localEnv, string sequence)
        : this(localEnv, sequence.Split(" -> ").ToList())
    {
    }

    public LocalEnvironment(ExecutionEnvironment localEnv, List<string> sequence)
    {
        Rsm = new StateManager(localEnv);

        // ✅ Parse sequence
        SequenceHelper seqHelper = new(localEnv.Crypto);
        ParsedSequence = seqHelper.ParseSequenceFull(sequence,
            SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes);

        // ✅ Extract & apply global rounds (GR)
        var globalRounds = ParsedSequence.SequenceAttributes.TryGetValue("GR", out var grValue) &&
                           int.TryParse(grValue, out var parsedGR)
            ? parsedGR
            : localEnv.Crypto.Options.Rounds;

        Rsm.PushAllGlobals();
        Rsm.PushAllTransformRounds();
        Rsm.PushGlobalRounds(globalRounds);

        // ✅ Apply per-transform TR values
        var (success, errorMessage) = UtilityHelpers.SetTransformRounds(
            localEnv.Crypto,
            ParsedSequence.Transforms.Select(t => (t.Name, (int)t.ID, t.TR)).ToList()
        );
        if (!success) throw new InvalidOperationException($"Failed to set transform rounds: {errorMessage}");

        // ✅ Apply right-side attributes (Rounds)
        SequenceAttributesHandler sah = new(localEnv);
        sah.ApplyAttributes(ParsedSequence.SequenceAttributes);
    }

    public void Dispose()
    {
        Rsm.PopAllGlobals();
        Rsm.PopAllTransformRounds();
        Rsm.PopGlobalRounds();
    }
}
#if false
    #region InputProfiler
    /*
     * DataEvaluator - High-Speed File Classification & Entropy Analysis
     * -------------------------------------------------------------------
     * Author: [Your Name or Team Name]
     * Organization: Mango Systems
     * License: MIT (or specify your license)
     * Created: [Initial Date]
     * Updated: [Last Modification Date]
     *
     * Description:
     * ------------
     * DataEvaluator is a high-performance tool for classifying and analyzing binary files.
     * It leverages Mango Systems' **Multi-Sample Model (MSM)** to rapidly determine 
     * whether a file is **Natural, Random/Encrypted, or Other** based on structured heuristics.
     *
     * MSM Mode (Default):
     * -------------------
     * ✅ Smart sampling strategy for high-speed classification.
     * ✅ Utilizes a **Finite-State Machine (FSM)** for efficient data recognition.
     * ✅ Avoids unnecessary full-file scans, delivering **100x performance improvements**.
     *
     * Classic Mode (-classic):
     * ------------------------
     * 🛑 Legacy mode for full-file analysis.
     * 🛑 Uses exhaustive entropy and pattern detection across large chunks.
     * 🛑 Significantly slower than MSM but available for edge cases.
     *
     * Features:
     * ---------
     * ✅ Instant classification for known file types (e.g., ZIP, PDF, EXE, PNG).
     * ✅ Intelligent sampling for unknown files to minimize processing.
     * ✅ Multi-Sample Model (MSM) ensures reliable data classification with minimal CPU impact.
     * ✅ Supports batch processing and benchmarking across multiple files.
     *
     * Command-Line Usage:
     * -------------------
     * Syntax:
     *     DataEvaluator <file path|-regression> [iterations] [-classic] [-verbose]
     *
     * Parameters:
     *  - <file path>: Path to a single file for analysis.
     *  - -regression: Runs analysis on all *.bin files in the current directory.
     *  - [iterations]: Number of times to benchmark each file (default: 10).
     *  - -classic: Enables full-file legacy analysis (slow but exhaustive).
     *  - -verbose: Outputs detailed per-sample statistics.
     *
     * Example Usage:
     * --------------
     *     DataEvaluator myfile.bin 100
     *     DataEvaluator -regression -classic -verbose
     *
     * Performance Gains (MSM vs. Classic):
     * ------------------------------------
     * ✅ Pre-MSM: Large files required full scans, often exceeding seconds per file.
     * ✅ Post-MSM: Strategic sampling enables **sub-millisecond** classification.
     * ✅ **100x speed-up** achieved through targeted optimizations.
     *
     * Notes:
     * ------
     * - **Known file types are instantly classified** without deeper analysis.
     * - **MSM heuristics dynamically adapt to unknown files**, requiring minimal reads.
     * - Classic mode (-classic) is only recommended if MSM mode is inconclusive.
     *
     * Future Enhancements:
     * --------------------
     * - Improved mixed-content detection (e.g., partially encrypted documents).
     * - Expanded support for additional file signatures.
     * - ML-based classification for further refinements.
     *
     */
    public record InputProfile(
        string Name,                         // e.g., "Combined", "Natural", etc. — Workbench-friendly label
        (byte ID, byte TR)[] Sequence,       // Transform sequence with rounds baked in
        int GlobalRounds                     // Required by core + Workbench for configuration
    );
    class InputProfiler
    {
        private static readonly Dictionary<string, InputProfile> BestProfiles = new()
        {
            // 🔥 Baseline Comparison: Munge(A)(6) 5 transforms Score: 88.6481693442 / .gs Aggregate Score: 88.7583871621
            // ChunkedFbTx(ID:40)(TR:1) -> NibbleSwapShuffleInvTx(ID:14)(TR:1) -> NibbleSwapShuffleFwdTx(ID:13)(TR:1) -> MicroBlockSwapInvTx(ID:38)(TR:2) -> ButterflyWithPairsInvTx(ID:30)(TR:1) | (GR:6)
            { "Combined", new InputProfile("Combined", new (byte, byte)[] {
                (40,1), (14,1), (13,1), (38,2), (30,1) }, 6) },

            // 🔥 Baseline Comparison: Munge(A)(9) 4 transforms Score: 82.5238611079 / .gs Aggregate Score: 85.9289932009
            // NibbleInterleaverInvTx(ID:40)(TR:4) -> ButterflyTx(ID:8)(TR:1) -> ChunkedFbTx(ID:41)(TR:2) -> MaskBasedSBoxFwdTx(ID:16)(TR:1) | (GR:1)
            { "Natural", new InputProfile("Natural", new (byte, byte)[] {
                (40,4), (8,1), (41,2), (16,1) }, 1) },

            // 🔥 Baseline Comparison: Munge(A)(9) 4 transforms Score: 95.3058486979 / .gs Aggregate Score: 95.3669619537
            // MicroBlockSwapFwdTx(ID:37)(TR:2) -> MicroBlockSwapInvTx(ID:38)(TR:3) -> ChunkedFbTx(ID:41)(TR:1) -> BitFlipButterflyInvTx(ID:34)(TR:1) | (GR:1)
            { "Sequence", new InputProfile("Sequence", new (byte, byte)[] {
                (37,2), (38,3), (41,1), (34,1) }, 1) },

            // 🔥 Baseline Comparison: Munge(A)(9) 4 transforms Score: 88.7070084653 / .gs Aggregate Score: 89.1429701554
            // ButterflyWithPairsFwdTx(ID:29)(TR:1) -> NibbleInterleaverInvTx(ID:40)(TR:2) -> ChunkedFbTx(ID:41)(TR:1) -> NibbleInterleaverInvTx(ID:40)(TR:2) | (GR:1)
            { "Random", new InputProfile("Random", new (byte, byte)[] {
                (29,1), (40,2), (41,1), (40,2) }, 1) }
        };

        public static InputProfile GetInputProfile(byte[] input)
        {
            string classification = ClassificationWorker(input);

            // 🔥 Normalize classification to InputType-consistent naming
            classification = classification switch
            {
                "Random/Encrypted" => "Random",
                "Media" => "Combined",
                _ when Enum.TryParse<InputType>(classification, out _) => classification,
                _ => "Combined"
            };

            if (!BestProfiles.TryGetValue(classification, out var profile))
                throw new InvalidOperationException($"No best profile defined for classification: {classification}");

            return profile;
        }

        static string ClassificationWorker(byte[] data)
        {
            int iterations = 1;
            bool useSampleMode = true;
            bool verbose = false;

            //Console.WriteLine($"\nAnalyzing: {filePath} ({data.Length} bytes)");
            //Console.WriteLine($"Running {iterations} iterations for benchmarking...\n");

            var stopwatch = new Stopwatch();
            Dictionary<string, int> classificationCounts = new();
            long totalTimeMs = 0;
            string classification = null;

            for (int i = 0; i < iterations; i++)
            {
                stopwatch.Restart();

                double avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow;
                Dictionary<int, (double, double, double, double, double, double, double)>? windowResults = null;

                if (useSampleMode)
                {
                    (classification, avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow, windowResults)
 = AnalyzeDataMSM(data, i, verbose);
                }
                else
                {
                    (classification, avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow, _) =
 AnalyzeDataClassic(data, i);
                }

                stopwatch.Stop();

                totalTimeMs += stopwatch.ElapsedMilliseconds;
                if (!classificationCounts.ContainsKey(classification))
                    classificationCounts[classification] = 0;
                classificationCounts[classification]++;
            }

            return classification;
            //FormatAnalysisResults(filePath, data.Length, iterations, classificationCounts, totalTimeMs, verbose);
        }
        //static void FormatAnalysisResults(string filePath, int totalBytes, int iterations, Dictionary<string, int> classificationCounts, long totalTimeMs, bool verbose)
        //{
        //    Console.WriteLine("\n===== Analysis Results =====");
        //    Console.WriteLine($"Analyzing: {filePath} ({totalBytes} bytes)");
        //    Console.WriteLine($"Iterations: {iterations}\n");

        //    foreach (var entry in classificationCounts.OrderByDescending(kv => kv.Value))
        //    {
        //        Console.WriteLine($"- {entry.Key}: {entry.Value} times");
        //    }

        //    Console.WriteLine($"\nAverage Execution Time: {totalTimeMs / (double)iterations:F4} ms");
        //}
        static double ComputeEntropy(byte[] data)
        {
            int[] counts = new int[256];
            foreach (byte b in data) counts[b]++;
            double entropy = 0;
            foreach (int count in counts)
            {
                if (count == 0) continue;
                double probability = count / (double)data.Length;
                entropy -= probability * Math.Log2(probability);
            }
            return entropy;
        }
        static double ComputeUniqueness(byte[] data)
        {
            return data.Distinct().Count() / (double)data.Length;
        }
        static double ComputePeriodicity(byte[] data)
        {
            int periodicityCount = 0;
            for (int i = 0; i < data.Length - 1; i++)
                if (data[i] == data[i + 1]) periodicityCount++;
            return periodicityCount / (double)data.Length;
        }
        static double ComputeByteDeviation(byte[] data)
        {
            int[] counts = new int[256];
            foreach (byte b in data) counts[b]++;
            double avg = counts.Average();
            double stddev = Math.Sqrt(counts.Average(x => Math.Pow(x - avg, 2)));
            return stddev / avg;
        }
        static double ComputeSlidingWindowSimilarity(byte[] data)
        {
            int matchCount = 0, totalCount = 0;
            for (int i = 0; i < data.Length - 8; i += 8)
            {
                if (data[i] == data[i + 4]) matchCount++;
                totalCount++;
            }
            return matchCount / (double)totalCount;
        }
        private static bool IsSequenceData(byte[] window)
        {
            if (window == null || window.Length < 3) // Need at least 3 bytes
                return false;

            // Calculate the initial stride, handling potential overflow/underflow.
            int stride = (window[1] - window[0] + 256) % 256;

            // Stride of 0 is NOT a sequence (all bytes the same).
            if (stride == 0)
                return false;

            const int strideTolerance = 2; // Allow stride variations up to ±2

            // Check for consistent stride across the entire window.
            for (int i = 2; i < window.Length; i++)
            {
                int currentStride = (window[i] - window[i - 1] + 256) % 256;
                if (Math.Abs(currentStride - stride) > strideTolerance)
                {
                    return false; // Inconsistent stride beyond allowed tolerance
                }
            }

            return true; // Consistent stride found within tolerance
        }

        private static double ComputePercentAlphaAndWhite(byte[] data)
        {
            int count = data.Count(b => (b >= 'a' && b <= 'z') || b == ' ');
            return count / (double)data.Length;
        }
        private static double ComputeRLECompressionRatio(byte[] data)
        {
            if (data.Length == 0) return 1.0; // Avoid division by zero

            List<(byte value, int count)> rleEncoded = new();
            byte lastByte = data[0];
            int count = 1;

            for (int i = 1; i < data.Length; i++)
            {
                if (data[i] == lastByte)
                {
                    count++;
                }
                else
                {
                    rleEncoded.Add((lastByte, count));
                    lastByte = data[i];
                    count = 1;
                }
            }
            rleEncoded.Add((lastByte, count)); // Final sequence

            double compressedSize = rleEncoded.Count * 2; // Each entry = (byte, count)
            return compressedSize / data.Length; // RLE Compression Ratio
        }
        static (string classification, double randomScore, double naturalScore) Score(double avgEntropy, double avgUniqueness, double avgByteDeviation, double avgPeriodicity, double avgSlidingWindow)
        {
            double randomScore = 0, naturalScore = 0;

            // Entropy Contribution (Boost Random if >7.0, Override Natural if >7.2)
            randomScore += Math.Min(1.5, (avgEntropy - 7.0) / 0.4);  // Boosts when >7.0, caps at 1.5
            naturalScore += Math.Max(0.0, (6.5 - avgEntropy) / 0.5);  // Penalizes if entropy <6.5

            // Strong override: If entropy is >7.2, random wins outright
            if (avgEntropy > 7.2) naturalScore = 0;

            // Uniqueness Contribution
            randomScore += Math.Min(1.0, avgUniqueness / 0.9); // High uniqueness → favors random

            // Byte Deviation Contribution
            randomScore += 1.0 - Math.Min(1.0, avgByteDeviation / 0.5); // Adjusted threshold

            // Periodicity Contribution
            naturalScore += Math.Min(1.0, avgPeriodicity / 0.07); // Loosened sensitivity

            // Sliding Window Contribution
            naturalScore += Math.Min(1.0, avgSlidingWindow / 0.07); // Loosened threshold

            // Normalize scores (keep it between 0 and 1)
            randomScore = Math.Min(1.0, Math.Max(0.0, randomScore));
            naturalScore = Math.Min(1.0, Math.Max(0.0, naturalScore));

            // Determine classification
            string classification = (randomScore >= 0.8) ? "Random/Encrypted" :
                (naturalScore >= 0.8) ? "Natural" :
                "Combined";

            return (classification, randomScore, naturalScore);
        }
        static (string classification, double avgEntropy, double avgUniqueness, double avgByteDeviation, double avgPeriodicity, double avgSlidingWindow, Dictionary<int, (double, double, double, double, double)>? windowResults) AnalyzeDataClassic(byte[] data, int iteration)
        {
            const int sampleSize = 4096;
            var random = new Random();
            List<byte[]> samples = new()
            {
                data.Take(Math.Min(sampleSize, data.Length)).ToArray(), // Start
                data.Skip(Math.Max(0, data.Length / 2 - sampleSize / 2)).Take(sampleSize).ToArray(), // Middle
                data.Skip(Math.Max(0, data.Length - sampleSize)).Take(sampleSize).ToArray(), // End
                data.OrderBy(_ => random.Next()).Take(sampleSize).ToArray() // Random bytes
            };

            double avgEntropy = samples.Average(ComputeEntropy);
            double avgUniqueness = samples.Average(ComputeUniqueness);
            double avgPeriodicity = samples.Average(ComputePeriodicity);
            double avgByteDeviation = samples.Average(ComputeByteDeviation);
            double avgSlidingWindow = samples.Average(ComputeSlidingWindowSimilarity);

            var (classification, _, _) =
 Score(avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow);

            return (classification, avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow, null);
        }
        #region AnalyzeDataMSM

        enum State
        {
            START,
            CHECK_ALPHA_WHITE,
            CHECK_ENTROPY,
            CHECK_RLE,
            FULL_ANALYSIS,
            CLASSIFY_NATURAL,
            CLASSIFY_RANDOM,
            CHECK_SEQUENCE,
            CLASSIFY_OTHER
        }
        static (string classification, double avgEntropy, double avgUniqueness, double avgByteDeviation, double avgPeriodicity, double avgSlidingWindow, Dictionary<int, (double, double, double, double, double, double, double)>? windowResults) AnalyzeDataMSM(byte[] data, int iteration, bool verbose)
        {
            int dataSize = data.Length;
            int windowSize = Math.Min(1024, dataSize); // If file is smaller than default, adjust window size
            int stepSize = 512;
            Dictionary<int, (double, double, double, double, double, double, double)> windowResults = new();

            // === Integration Before FSM ===
            string fileType = KnownFileType(data);
            if (fileType != "Unknown")
            {
                string classification = "Other"; // Default for structured file types

                switch (fileType)
                {
                    case "HTML":
                    case "TXT":
                    case "CSV":
                    case "XML":
                    case "SQL":
                    case "SVG":
                        classification = "Natural";
                        break;

                    case "JPG":
                    case "PNG":
                    case "GIF":
                    case "BMP":
                    case "MP4":
                    case "MKV":
                    case "MP3":
                    case "WAV":
                        classification = "Media";
                        break;

                    case "ZIP":
                    case "RAR":
                    case "7Z":
                    case "GZ":
                        classification = "Random/Encrypted";
                        break;

                    case "EXE":
                    case "DLL":
                    case "ISO":
                    case "PDF":
                        classification = "Other";
                        break;
                }
                if (iteration == 0)
                    Console.WriteLine($"[Known File Type Detected] {fileType} → Classified as {classification}");
                return (classification, 0, 0, 0, 0, 0, null);
            }

            List<int> sampleOffsets = new() { 0, dataSize - windowSize, dataSize / 2 };
            for (int i = 1; i <= 2; i++)
            {
                int nextStart = i * windowSize;
                int nextEnd = dataSize - ((i + 1) * windowSize);
                if (nextStart + windowSize <= dataSize) sampleOffsets.Add(nextStart);
                if (nextEnd >= 0) sampleOffsets.Add(nextEnd);
            }

            Dictionary<string, int> classificationStreak = new();
            int sequenceWindows = 0, randomWindows = 0, naturalWindows = 0, combinedWindows = 0;

            for (int start = 0; start + windowSize <= data.Length; start += stepSize)
            {
                byte[] window = data.Skip(start).Take(windowSize).ToArray();


                double alphaWhite = 0.0, entropy = 0.0, rleRatio = 1.0;
                double periodicity = 0.0, uniqueness = 0.0, byteDeviation = 0.0, slidingWindow = 0.0;

                string classification = "Other";
                bool done = false;
                State state = State.START;

                while (!done)
                {
                    switch (state)
                    {
                        case State.START:
                            state = State.CHECK_SEQUENCE;
                            break;

                        case State.CHECK_SEQUENCE:
                            if (IsSequenceData(window))
                            {
                                sequenceWindows++;
                            }
                            combinedWindows++;
                            state = State.CHECK_ALPHA_WHITE;
                            break;

                        case State.CHECK_ALPHA_WHITE:
                            alphaWhite = ComputePercentAlphaAndWhite(window);
                            if (alphaWhite > 0.90) { classification = "Natural"; state =
 State.CLASSIFY_NATURAL; naturalWindows++; break; }
                            if (alphaWhite < 10) { state = State.CHECK_ENTROPY; break; }
                            state = State.CHECK_ENTROPY;
                            break;

                        case State.CHECK_ENTROPY:
                            entropy = ComputeEntropy(window);
                            if (entropy > 7.5) { classification = "Random/Encrypted"; state =
 State.CLASSIFY_RANDOM; randomWindows++; break; }
                            if (entropy < 6.5) { classification = "Natural"; state =
 State.CLASSIFY_NATURAL; naturalWindows++; break; }
                            state = State.CHECK_RLE;
                            break;

                        case State.CHECK_RLE:
                            rleRatio = ComputeRLECompressionRatio(window);
                            if (rleRatio <= 0.5) { classification = "Natural"; state =
 State.CLASSIFY_NATURAL; naturalWindows++; break; }
                            state = State.FULL_ANALYSIS;
                            break;

                        case State.FULL_ANALYSIS:
                            periodicity = ComputePeriodicity(window);
                            uniqueness = ComputeUniqueness(window);
                            byteDeviation = ComputeByteDeviation(window);
                            slidingWindow = ComputeSlidingWindowSimilarity(window);
                            classification = "Other";
                            state = State.CLASSIFY_OTHER;
                            break;

                        case State.CLASSIFY_NATURAL:
                        case State.CLASSIFY_RANDOM:
                        case State.CLASSIFY_OTHER:
                            done = true;
                            break;
                    }
                }

                // ✅ Always store results for the processed window before moving to the next one
                windowResults[start] =
 (entropy, periodicity, uniqueness, byteDeviation, slidingWindow, rleRatio, alphaWhite);
            }

            double avgEntropy = windowResults.Values.Average(v => v.Item1);
            double avgPeriodicity = windowResults.Values.Average(v => v.Item2);
            double avgUniqueness = windowResults.Values.Average(v => v.Item3);
            double avgByteDeviation = windowResults.Values.Average(v => v.Item4);
            double avgSlidingWindow = windowResults.Values.Average(v => v.Item5);

            // === Combined Classification Rules (Refined) ===

            // 1. Calculate weighted scores (as before, but no combinedScore yet).
            double sequenceScore = sequenceWindows * 3.0;  // Sequence gets highest weight
            double randomScore = randomWindows * 1.0;
            double naturalScore = naturalWindows * 2.0;   // Natural is in the middle

            // 2. Determine the dominant classification (if any).
            string dominantClassification = "Other"; // Default
            double dominantScore = 0.0;

            if (sequenceScore >= randomScore && sequenceScore >= naturalScore && sequenceScore > 0)
            {
                dominantClassification = "Sequence";
                dominantScore = sequenceScore;
            }
            else if (naturalScore >= randomScore && naturalScore > 0)
            {
                dominantClassification = "Natural";
                dominantScore = naturalScore;
            }
            else if (randomScore > 0)
            {
                dominantClassification = "Random/Encrypted";
                dominantScore = randomScore;
            }

            // Calculate totalWindows outside the call to IsCombinedData
            int totalWindows = sequenceWindows + randomWindows + naturalWindows;

            // 3. Check for Combined Data.  Pass totalWindows!
            if (IsCombinedData(sequenceWindows, randomWindows, naturalWindows, combinedWindows, totalWindows, sequenceScore, randomScore, naturalScore, avgEntropy))
            {
                return ("Combined", avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow, windowResults);
            }

            //var (classification, _, _) = Score(avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow);

            // 4. If not combined, return the dominant classification (or "Other" if none).
            return (dominantClassification, avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow, windowResults);

        }

        // === Step 1: Known File Type Check (Instant Classification) ===
        static string KnownFileType(byte[] data)
        {
            if (data.Length < 4) return "Unknown";

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
                return "JPG";  // ✅ Return specific file type

            // PNG (Header: "\x89PNG\r\n\x1A\n")
            if (data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47)
                return "PNG";  // ✅ Return specific file type

            // MKV (Matroska Video File)
            if (data[0] == 0x1A && data[1] == 0x45 && data[2] == 0xDF && data[3] == 0xA3)
                return "MKV";

            // WAV (Waveform Audio File Format)
            if (data.Length >= 12 &&
                data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46 &&  // "RIFF"
                data[8] == 0x57 && data[9] == 0x41 && data[10] == 0x56 && data[11] == 0x45)  // "WAVE"
                return "WAV";

            // MSI (Microsoft Installer - PE format with MZ Header)
            if (data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 && data[3] == 0xE0)
                return "MSI";

            return "Unknown";
        }
        private static bool IsCombinedData(int sequenceWindows, int randomWindows, int naturalWindows, int combinedWindows, int totalWindows, double sequenceScore, double randomScore, double naturalScore, double avgEntropy)
        {
            // 1. Require a minimum proportion of "combinable" windows.
            // 🔹 Adaptive threshold for Combined classification
            double adaptiveCombinedThreshold =
 (avgEntropy > 7.5) ? 0.55 : 0.40; // Stricter for high entropy, looser for low
            if (combinedWindows < totalWindows * adaptiveCombinedThreshold && totalWindows > 0)
            {
                return false;
            }

            const double sequenceConfidenceFloor = 5.0; // Minimum required strength for Sequence to dominate
            const double sequenceDominanceMargin = 0.2; // Adaptive margin

            if (sequenceScore > sequenceConfidenceFloor &&
                sequenceScore > randomScore + naturalScore + (randomScore + naturalScore) * sequenceDominanceMargin)
            {
                return false; // Sequence truly dominates
            }

            // 3. Check for dominance of other types (using counts).
            const double dominanceThreshold = 0.8;
            if (naturalWindows > totalWindows * dominanceThreshold) return false;
            if (randomWindows > totalWindows * dominanceThreshold) return false;

            // 4. Require at least two types to be *present* in significant amounts.
            int numSignificantTypes = 0;
            const double significantTypeThreshold = 0.1;
            int relevantTotal = (combinedWindows > 0) ? combinedWindows : totalWindows;

            if (sequenceWindows >= totalWindows * significantTypeThreshold) numSignificantTypes++;
            if (naturalWindows >= relevantTotal * significantTypeThreshold) numSignificantTypes++;
            if (randomWindows >= relevantTotal * significantTypeThreshold) numSignificantTypes++;

            if (numSignificantTypes < 2)
            {
                return false;
            }

            return true; // Meets the criteria for combined data
        }
        #endregion AnalyzeDataMSM
    }
    #endregion InputProfiler
#endif
public class StateManager
{
    private static readonly Stack<KeyValuePair<int, int>> _transformRoundStack = new();
    private static readonly Stack<int> _globalRoundStack = new(); // ✅ Separate stack for global rounds
    private static readonly Stack<KeyValuePair<string, object?>> _globalStateStack = new();

    private static readonly List<(object caller, string fullCallerInfo, string stackTrace)> _transformPushTracking =
        new(); // ✅ Tracks who pushed, full caller info, and stack trace

    private CryptoLib _cryptoLib;
    private const int StackFull = 1024;
    private readonly int _transformCount;
    private const string GlobalRoundsSetting = "Options.Rounds"; // ✅ Reflection target
    private ExecutionEnvironment _localEnv;
    private static readonly object _stackLock = new(); // 🔹 Shared lock for all stacks
    private readonly object _context = new(); // 🔹 ensure push/pop must belong to the same instance
    private readonly int _globalStateFrameSize; // how big of stack frame for each push/pop for global settings state

    public StateManager(ExecutionEnvironment localEnv)
    {
        _cryptoLib = localEnv.Crypto ?? throw new ArgumentException("cryptoLib cannot be null.");
        _localEnv = localEnv ?? throw new ArgumentException("localEnv cannot be null.");
        _transformCount = _cryptoLib.TransformRegistry.Count; // ✅ Precompute transform count
        _globalStateFrameSize = GlobalStateFrameSize();
    }

    #region Global Variables

    /// <summary>
    /// Saves the current value of a specific global setting and updates it.
    /// </summary>
    public void PushGlobal(string key, object? newValue)
    {
        lock (_stackLock)
        {
            _pushGlobal(key, newValue);
        }
    }

    private void _pushGlobal(string key, object? newValue)
    {
        CheckStackOverflow(_globalStateStack);

        var propInfo = typeof(GlobalsInstance).GetProperty(key, BindingFlags.Public | BindingFlags.Instance);
        if (propInfo == null)
            throw new InvalidOperationException($"Global setting '{key}' not found.");

        var currentValue = propInfo.GetValue(this)!;
        _globalStateStack.Push(new KeyValuePair<string, object?>(key, currentValue));
        if (propInfo != null)
        {
            var sequenceHandler = new SequenceAttributesHandler(_localEnv);
            var convertedValue = sequenceHandler.ConvertValue(propInfo.PropertyType, newValue);
            _localEnv.Globals.UpdateSetting(key, convertedValue); // ✅ Ensures correct type
        }
    }

    /// <summary>
    /// Restores the most recent pushed global setting.
    /// </summary>
    public void PopGlobal()
    {
        lock (_stackLock)
        {
            _popGlobal();
        }
    }

    private void _popGlobal()
    {
        if (_globalStateStack.Count == 0)
            throw new InvalidOperationException("No saved global states to restore.");

        var (key, previousValue) = _globalStateStack.Pop();
        _localEnv.Globals.UpdateSetting(key, previousValue);
    }

    /// <summary>
    /// Saves all global settings annotated with [GlobalSetting] before modification.
    /// </summary>
    public void PushAllGlobals()
    {
        lock (_stackLock)
        {
            _pushAllGlobals();
        }
    }

    private void _pushAllGlobals()
    {
        CheckStackOverflow(_globalStateStack);
        foreach (var propInfo in typeof(GlobalsInstance).GetProperties(BindingFlags.Public | BindingFlags.Instance)
                     .Where(p => p.GetCustomAttribute<Handlers.GlobalSettingAttribute>() != null))
        {
            var currentValue = propInfo.GetValue(_localEnv.Globals)!;
            _globalStateStack.Push(new KeyValuePair<string, object?>(propInfo.Name, currentValue));
        }
    }

    /// <summary>
    /// Restores all previously pushed global settings.
    /// </summary>
    public void PopAllGlobals()
    {
        lock (_stackLock)
        {
            _popAllGlobals();
        }
    }

    private void _popAllGlobals()
    {
        if (_globalStateStack.Count == 0)
            throw new InvalidOperationException("Global states stack empty.");
        if (_globalStateStack.Count < _globalStateFrameSize)
            throw new InvalidOperationException("Global states stack imbalance.");

        for (var ix = 0; ix < _globalStateFrameSize; ix++)
        {
            var (key, previousValue) = _globalStateStack.Pop();
            _localEnv.Globals.UpdateSetting(key, previousValue);
        }
    }

    #endregion Global Variables

    #region Global Rounds

    /// <summary>
    /// Saves the current global round value and updates it to a new value.
    /// </summary>
    /// <param name="new_value">The new global round value.</param>
    public void PushGlobalRounds(int new_value)
    {
        lock (_stackLock)
        {
            _pushGlobalRounds(new_value);
        }
    }

    private void _pushGlobalRounds(int new_value)
    {
        CheckStackOverflow(_globalRoundStack); // ✅ Prevent overflow

        var propInfo = typeof(CryptoLibOptions).GetProperty(GlobalRoundsSetting.Split('.')[1]);
        if (propInfo == null)
            throw new InvalidOperationException($"Property '{GlobalRoundsSetting}' not found.");

        var currentRounds = (int)propInfo.GetValue(_cryptoLib.Options)!;
        _globalRoundStack.Push(currentRounds); // ✅ Save current value
        propInfo.SetValue(_cryptoLib.Options, new_value); // ✅ Update to new value
    }

    /// <summary>
    /// Restores the last saved global round value.
    /// </summary>
    public void PopGlobalRounds()
    {
        lock (_stackLock)
        {
            _popGlobalRounds();
        }
    }

    private void _popGlobalRounds()
    {
        if (_globalRoundStack.Count == 0)
            throw new InvalidOperationException("No saved global round states to restore.");

        var propInfo = typeof(CryptoLibOptions).GetProperty(GlobalRoundsSetting.Split('.')[1]);
        if (propInfo == null)
            throw new InvalidOperationException($"Property '{GlobalRoundsSetting}' not found.");

        var previousRounds = _globalRoundStack.Pop();
        propInfo.SetValue(_cryptoLib.Options, previousRounds); // ✅ Restore previous value
    }

    /// <summary>
    /// Increments the global round value and returns the new value.
    /// </summary>
    public int IncGlobalRound()
    {
        lock (_stackLock)
        {
            return _incGlobalRound();
        }
    }

    private int _incGlobalRound()
    {
        _localEnv.Globals.UpdateSetting("Rounds", _localEnv.Globals.Rounds + 1);
        return _localEnv.Globals.Rounds;
    }

    /// <summary>
    /// Gets or sets the global round value.
    /// </summary>
    public int GlobalRounds
    {
        get
        {
            lock (_stackLock)
            {
                return _getGlobalRounds;
            }
        }
        set
        {
            lock (_stackLock)
            {
                _setGlobalRounds(value);
            }
        }
    }

    private int _getGlobalRounds => _localEnv.Globals.Rounds;

    private void _setGlobalRounds(int value)
    {
        _localEnv.Globals.UpdateSetting("Rounds", value);
    }
    //// Pre-increment (increments, *then* returns the new value)
    //public static StateManager operator ++(StateManager sm)
    //{
    //    sm.IncGlobalRound(); // Increment first.
    //    return sm;          // Return incremented value.
    //}

    //// Post-increment (returns the original value, *then* increments)
    //// Notice the dummy 'int' parameter.  This is how C# knows it's post-increment.
    //public static StateManager operator ++(StateManager sm, int _)
    //{
    //    StateManager temp = new StateManager(sm._localEnv);  // Create a copy (important for thread safety and correctness).
    //    temp.GlobalRounds = sm.GlobalRounds;        // Copy the *original* value.
    //    sm.IncGlobalRound();                       // Increment the original object.
    //    return temp;                              // Return the *original* value (the copy).
    //}

    #endregion Global Rounds

    #region Transform Rounds

    public void GetTransformStackInfo(out int stackSize, out int stackDepth)
    {
        lock (_stackLock)
        {
            _getTransformStackInfo(out stackSize, out stackDepth);
        }
    }

    private void _getTransformStackInfo(out int stackSize, out int stackDepth)
    {
        stackSize = StackFull;
        stackDepth = _transformRoundStack.Count;
    }

    /// <summary>
    /// Saves the round values of all transforms.
    /// </summary>
    public void PushAllTransformRounds()
    {
        lock (_stackLock)
        {
            var (caller, fullCallerInfo) = GetCallerInfo(_context, 1);

            _transformPushTracking.Add((caller, fullCallerInfo, Environment.StackTrace));

            LogStatus($"PUSH - Caller: {fullCallerInfo}, Stack Depth BEFORE: {_transformRoundStack.Count}");

            if (_transformRoundStack.Count % _transformCount != 0)
                HandleError(
                    $"Stack imbalance detected BEFORE push. Expected a multiple of {_transformCount}, but found {_transformRoundStack.Count}.");

            // ✅ Normal stack push operation
            _pushAllTransformRounds();

            LogStatus($"PUSH - Stack Depth AFTER: {_transformRoundStack.Count}");
        }
    }

    private void _pushAllTransformRounds()
    {
        CheckStackOverflow(_transformRoundStack); // ✅ Prevent overflow
        foreach (var transform in _cryptoLib.TransformRegistry.Values)
            _transformRoundStack.Push(new KeyValuePair<int, int>(transform.Id, transform.Rounds));
    }

    /// <summary>
    /// Restores the round values of all transforms.
    /// </summary>
    public void PopAllTransformRounds()
    {
        lock (_stackLock)
        {
            var (caller, fullCallerInfo) = GetCallerInfo(_context, 1);

            LogStatus($"POP - Caller: {fullCallerInfo}, Stack Depth BEFORE: {_transformRoundStack.Count}");

            var available = _transformRoundStack.Count;
            var required = _transformCount;

            if (available < required)
                HandleError($"Pop attempted by {fullCallerInfo}: Required {required}, but only {available} available.");

            if (_transformPushTracking.Count == 0)
                HandleError($"Pop operation attempted by {fullCallerInfo}, but no pushes exist.");

            var index = _transformPushTracking.FindLastIndex(entry => entry.caller == caller);
            if (index != -1)
                _transformPushTracking.RemoveAt(index); // ✅ Removes the most recent push by this caller
            else
                HandleError($"Pop operation attempted by {fullCallerInfo}, but no matching push found.");

            // ✅ Normal stack pop operation
            _popAllTransformRounds();

            LogStatus($"POP - Stack Depth AFTER: {_transformRoundStack.Count}");
        }
    }

    private void _popAllTransformRounds()
    {
        var stackSize = _transformRoundStack.Count;
        if (stackSize < _transformCount)
            HandleError(
                $"Stack is unbalanced: Expected {_transformCount} elements, but only {stackSize} remain. This suggests a mismatch between push and pop operations.");

        for (var i = 0; i < _transformCount; i++)
        {
            var (savedId, savedRounds) = _transformRoundStack.Pop();
            if (!_cryptoLib.TransformRegistry.TryGetValue(savedId, out var transform))
                HandleError($"Transform ID {savedId} not found in registry during PopAllTransformRounds().");
            transform!.Rounds = (byte)savedRounds;
        }
    }

    private void LogStatus(string message)
    {
#if false
            // Ensure message starts with "[DEBUG] " and wrap in yellow color tags
            ColorConsole.WriteLine($"<yellow>[DEBUG] {message}</yellow>");
#endif
    }

    private void HandleError(string errorMsg)
    {
        // Ensure console message starts with "[ERROR] " and wrap in red color tags
        ColorConsole.WriteLine($"<red>[ERROR] {errorMsg}</red>");

#if DEBUG
        Console.WriteLine("\n<Yellow>Press any key to continue...</Yellow>");
        Console.ReadKey();
#endif

        // Throw exception without formatting (raw message for stack trace clarity)
        throw new InvalidOperationException(errorMsg);
    }

    #endregion Transform Rounds

    #region Tools

    private static int GlobalStateFrameSize()
    {
        return typeof(GlobalsInstance).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Count(p => p.GetCustomAttribute<Handlers.GlobalSettingAttribute>() != null);
    }

    private static (object caller, string fullCallerInfo) GetCallerInfo(object context, int framesUp = 1)
    {
        var frame = new StackFrame(framesUp + 1, true);
        var method = frame.GetMethod();
        return (context, $"{method!.DeclaringType?.Name}.{method.Name} (Line {frame.GetFileLineNumber()})");
    }

    private void CheckStackOverflow<T>(Stack<T> stack)
    {
        if (stack.Count >= StackFull)
            throw new InvalidOperationException("Stack overflow: Too many nested push operations.");
    }

    #endregion Tools
}

[Flags]
public enum DebugFlags
{
    None = 0x00,
    TransformHashing = 0x01,
    SequenceFailed = 0x02,
    StatusMessage = 0x04,
    ReversibleSequence = 0x08,
    RunMangoInstance = 0x10,
    TransformApplication = 0x20,
    AggregateScores = 0x40
}

// 🔹 IMPORTANT: These string values must match the normalized `classification` values
//              returned by InputProfiler.GetInputProfile() in the Mango.Adaptive library.
public enum InputType
{
    Combined,
    Random,
    Sequence,
    Natural
}

// Updated Globals class to include the Mode setting
public class GlobalsInstance
{
    //  properties for global access
    [Handlers.GlobalSetting] public int Rounds { get; set; } = 9;
    [Handlers.GlobalSetting] public int MaxSequenceLen { get; set; } = 3;
    [Handlers.GlobalSetting] public InputType InputType { get; set; } = InputType.Random;
    [Handlers.GlobalSetting] public int PassCount { get; set; } = 0;
    [Handlers.GlobalSetting] public int DesiredContenders { get; set; } = 1000;
    [Handlers.GlobalSetting] public bool Quiet { get; set; } = true;

    [Handlers.GlobalSetting]
    public int FlushThreshold { get; set; } =
        50000; // Number of items before flushing console output and registering contenders

    [Handlers.GlobalSetting]
    public bool SqlCompact { get; set; } =
        false; // Compact true outputs SQL queries in CSV, otherwise, a line based format is used

    // ✅ If UseMetricScoring == true:
    // Applies traditional metric scoring: rescaled scores are weighted and logarithmically scaled.
    // Metrics that exceed their thresholds are capped to avoid over-contributing.
    // ✅ If UseMetricScoring == false (the new default):
    // Uses weighted practical scoring: banded scores (Perfect, Pass, NearMiss, Fail) reflect cryptographic robustness more realistically.
    // Prioritizes metrics based on importance, not raw scale, providing clearer separation of weak vs strong sequences.
    [Handlers.GlobalSetting] public bool UseMetricScoring { get; set; } = false;

    [Handlers.GlobalSetting] public OperationModes Mode { get; set; } = OperationModes.Cryptographic;

    #region Batch Mode Processing

    [Handlers.GlobalSetting(false, true, true)] // need to be able to set this through the commandline, don't save
    public bool CreateMungeFailDB { get; set; } = false;

    [Handlers.GlobalSetting(false, true, true)] // need to be able to set this through the commandline, don't save
    public bool CreateBTRFailDB { get; set; } = true; // BTR is always in creation mode

    [Handlers.GlobalSetting(false, true, true)] // need to be able to set this through the commandline, don't save
    public bool ExitJobComplete { get; set; } = false;

    [Handlers.GlobalSetting(false, true, true)] // need to be able to set this through the commandline, don't save
    public bool LogMungeOutput { get; set; } = false;

    public bool BatchMode { get; set; } = false; // never saved, never shown
    public string Commandline { get; set; } = null!; // never saved, never shown
    public Dictionary<string, string[]> FunctionParms = new(StringComparer.OrdinalIgnoreCase);

    #endregion Batch Mode Processing

    [Handlers.GlobalSetting(true)]
    public ReportHelper.ReportFormat ReportFormat { get; set; } = ReportHelper.ReportFormat.SCR;

    [Handlers.GlobalSetting(true)] public string ReportFilename { get; set; } = null!;

    [Handlers.GlobalSetting("ReportFormat", "ReportFilename")]
    public string Reporting { get; set; } = null!;

    private const string SettingsFile = "GlobalSettings.json";

    public const string Password = "sample-password";
    public byte[] Input { get; set; } = null!;

    // ================================================================
    // Benchmarking Constants & Calibration Variables
    // ================================================================
    //
    // BenchmarkBaselineTime: 
    //   The fixed reference time (in milliseconds) to perform one 
    //   MaskedCascadeSubFwdFbTx operation on 4096 bytes of Random data, 
    //   measured on the developer's machine. Used for normalization.
    //
    // BenchmarkBaselineSize:
    //   The input size (in bytes) used during the original baseline 
    //   benchmarking process. All future measurements will scale 
    //   relative to this size.
    //
    // CurrentBenchmarkTime:
    //   The actual measured benchmark time on the current machine, 
    //   gathered during Mango's startup. This is used to compute 
    //   a speed factor relative to the developer's machine.
    //
    // benchmark Transform: MaskedCascadeSubFwdFbTx (ID: 35) | Avg time per op: 0.0305 ms
    public double BenchmarkBaselineTime { get; set; } = 0.0; // MaskedCascadeSubFwdFbTx benchmark, from dev machine
    public double BenchmarkBaselineSize { get; } = 4096.0; // 4096 bytes of Random data
    public double CurrentBenchmarkTime { get; set; } = 0.0;

    private readonly bool _allowSaving;
    private readonly CryptoLib? _cryptoLib;
    private readonly ExecutionEnvironment _localEnv;
    public GlobalsInstance(ExecutionEnvironment localEnv, bool allowSaving = false)
    {
        _cryptoLib = localEnv.Crypto;
        _localEnv = localEnv;
        _allowSaving = allowSaving;
    }
#if true
    public void Dupe(GlobalsInstance? source, CryptoLibOptions? options = null)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        var properties = typeof(GlobalsInstance).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.IsDefined(typeof(Handlers.GlobalSettingAttribute)));

        foreach (var property in properties)
        {
            var attribute = property.GetCustomAttribute<Handlers.GlobalSettingAttribute>();

            // 🚨 Skip settings that should NOT be copied over
            //if (attribute?.IsNoSave == true || attribute?.IsInternal == true)
            //    continue;

            if (attribute == null)
                continue; // ✅ Skip properties without GlobalSettingAttribute

            try
            {
                var value = property.GetValue(source);

                // ✅ If `options` is provided, prefer its values where applicable
                if (options != null)
                    if (property.Name == nameof(Rounds))
                        value = options.Rounds;

                UpdateSetting(property.Name, value); // ✅ Ensures side effects (trigger actions) are applied
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to copy setting {property.Name}. Error: {ex.Message}");
            }
        }
    }

#else
        public void Dupe(GlobalsInstance source)
        {
            if (source == null)
                throw new ArgumentNullException(nameof(source));

            var properties = typeof(GlobalsInstance).GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Where(p => p.IsDefined(typeof(GlobalSettingAttribute)));

            foreach (var property in properties)
            {
                var attribute = property.GetCustomAttribute<GlobalSettingAttribute>();

                // 🚨 Skip settings that should NOT be copied over
                //if (attribute?.IsNoSave == true || attribute?.IsInternal == true)
                //    continue;

                try
                {
                    object value = property.GetValue(source);
                    UpdateSetting(property.Name, value); // ✅ Ensures side effects (trigger actions) are applied
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: Failed to copy setting {property.Name}. Error: {ex.Message}");
                }
            }
        }
#endif
    // Load settings from file
    public void Load()
    {
        // Ensure settings file exists (if missing, create it but continue execution)
        if (!File.Exists(SettingsFile)) Save(); // Create default settings file if none exists

        var json = File.ReadAllText(SettingsFile);
        var settings = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(json);

        HashSet<string>
            loadedSettings =
                new(StringComparer.OrdinalIgnoreCase); // ✅ Track all explicitly set keys (case-insensitive)

        if (settings != null)
        {
            var properties = typeof(GlobalsInstance).GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Where(p => p.IsDefined(typeof(Handlers.GlobalSettingAttribute)))
                .ToDictionary(p => p.Name, p => p, StringComparer.OrdinalIgnoreCase);

            foreach (var (key, jsonElement) in settings)
            {
                if (!properties.TryGetValue(key, out var property))
                {
                    Console.WriteLine($"Warning: Ignoring unknown setting '{key}' from settings file.");
                    continue;
                }

                var attribute = property.GetCustomAttribute<Handlers.GlobalSettingAttribute>();
                if (attribute?.IsNoSave == true)
                {
                    Console.WriteLine($"Warning: Ignoring non-persistent setting '{key}' from settings file.");
                    continue; // 🔥 Skip `IsNoSave: true` settings
                }

                try
                {
                    object? value = jsonElement.ValueKind switch
                    {
                        JsonValueKind.Number => jsonElement.GetInt32(),
                        JsonValueKind.True or JsonValueKind.False => jsonElement.GetBoolean(),
                        JsonValueKind.String => jsonElement.GetString(),
                        JsonValueKind.Null => null, // ✅ Handle null case (valid for null strings)
                        _ => throw new InvalidOperationException("Unsupported setting type.")
                    };

                    UpdateSetting(key, value);
                    loadedSettings.Add(key); // ✅ Track the setting as explicitly set (case-insensitive)
                }
                catch (Exception ex)
                {
                    Console.WriteLine($"Warning: Failed to load setting {key}. Error: {ex.Message}");
                }
            }
        }

        // ✅ Final Pass: Ensure ALL valid GlobalSettings are explicitly set
        foreach (var property in typeof(GlobalsInstance).GetProperties(BindingFlags.Public | BindingFlags.Instance)
                     .Where(p => p.IsDefined(typeof(Handlers.GlobalSettingAttribute))))
        {
            var attribute = property.GetCustomAttribute<Handlers.GlobalSettingAttribute>();

            // 🚨 Skip settings that are Debug, NoSave, or Internal
            if (attribute?.IsDebugOnly == true || attribute?.IsNoSave == true || attribute?.IsInternal == true)
                continue;

            if (!loadedSettings.Contains(property.Name))
            {
                var value = property.GetValue(this); // Get the default value from Globals
                UpdateSetting(property.Name, value); // ✅ Apply it
            }
        }
    }

    // Save settings to file
    public void Save()
    {
        if (_allowSaving == false) return;

        var settings = new Dictionary<string, object>();

        var properties = typeof(GlobalsInstance).GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Where(p => p.IsDefined(typeof(Handlers.GlobalSettingAttribute)))
            .ToList();

        var compoundKeys = new HashSet<string>(); // ✅ Prevent duplicate compound settings

        foreach (var property in properties)
        {
            var attribute = property.GetCustomAttribute<Handlers.GlobalSettingAttribute>();

            if (attribute?.IsNoSave == true) continue; // 🔥 Skip saving `IsNoSave: true` settings

            // 🔍 **Handle compound settings first**
            if (attribute?.RelatedProperties?.Length > 0)
            {
                if (compoundKeys.Contains(property.Name))
                    continue; // ✅ Skip duplicate compound entries

                compoundKeys.Add(property.Name);

                var compoundValues = attribute.RelatedProperties
                    .Select(rp => properties.FirstOrDefault(p => p.Name == rp)?.GetValue(this)?.ToString() ?? "")
                    .ToArray();

                settings[property.Name] = string.Join(",", compoundValues); // ✅ Store as comma-separated values
            }
            else
            {
                var value = property.GetValue(this) ?? GetDefaultFromCryptoLib(property.Name);
                settings[property.Name] = (property.PropertyType.IsEnum ? value.ToString() : value)!;
            }
        }

        var json = JsonSerializer.Serialize(settings, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(SettingsFile, json);
    }

    // Update a specific setting
    public void UpdateSetting(string key, object? value)
    {
        //Console.WriteLine($"[DEBUG] Updating {key} with value: {value} ({value?.GetType().Name})");

        if (_cryptoLib == null)
            throw new InvalidOperationException(
                $"Cannot update setting '{key}' because CryptoLib instance is required but was null.");

        var properties = typeof(GlobalsInstance).GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Where(p => p.IsDefined(typeof(Handlers.GlobalSettingAttribute)))
            .ToDictionary(p => p.Name, p => p, StringComparer.OrdinalIgnoreCase);

        if (!properties.TryGetValue(key, out var property)) throw new ArgumentException($"Unknown key: {key}");

        // 🔥 Ensure correct type conversion before setting
        var sequenceHandler = new SequenceAttributesHandler(_localEnv);
        var convertedValue = sequenceHandler.ConvertValue(property.PropertyType, value);

        //Console.WriteLine($"[DEBUG] Converted {key}: {convertedValue} ({convertedValue?.GetType().Name})");

        property.SetValue(this, convertedValue); // ✅ Now `InputType` will be set as an enum instead of a string

        TriggerSpecialActions(key, convertedValue);
    }


    // Handles special triggers when specific global settings are changed
    private void TriggerSpecialActions(string key, object? value)
    {
        switch (key.ToLowerInvariant())
        {
            case "inputtype":
                Input = GenerateTestInput(_localEnv);
                // 🎯 Dynamically set GlobalRounds by re-invoking UpdateSetting with "rounds"
                switch (_localEnv.Globals.InputType)
                {
                    case InputType.Combined:
                        UpdateSetting("rounds", "6"); // verified 4/10/2025
                        break;
                    case InputType.Natural:
                        UpdateSetting("rounds", "3"); // verified 4/10/2025
                        break;
                    case InputType.Random:
                        UpdateSetting("rounds", "3"); // verified 4/10/2025
                        break;
                    case InputType.Sequence:
                        UpdateSetting("rounds", "5"); // verified 4/10/2025
                        break;
                    default:
                        throw new InvalidOperationException(
                            $"Unknown InputType detected during adaptive rounds assignment: {_localEnv.Globals.InputType}");
                }

                break;

            case "mode":
                if (value is OperationModes parsedMode)
                //if (_cryptoLib.Options == null)
                //{
                //    throw new InvalidOperationException("CryptoLib.Options is null. Ensure it is properly initialized before setting Mode.");
                //}
                //else
                {
                    _localEnv.Globals.Mode = parsedMode;
                    MetricInfoHelper.AdjustWeights(_localEnv, parsedMode); // Adjust weights if necessary
                }
                else
                {
                    ColorConsole.WriteLine($"<Red>Invalid value for Mode:</Red> <Green>{value}</Green>");
                }

                break;

            case "rounds":
                if (value is int newRounds)
                {
                    if (_cryptoLib!.Options == null)
                        throw new InvalidOperationException(
                            "CryptoLib.Options is null. Ensure it is properly initialized before setting Rounds.");

                    _localEnv.Globals.Rounds = newRounds;
                    _cryptoLib.Options.Rounds = newRounds;
                }
                else
                {
                    ColorConsole.WriteLine($"<Red>Invalid value for Rounds:</Red> <Green>{value}</Green>");
                }

                break;
        }
    }

    // Fallback logic to get default value from CryptoLib
    private object GetDefaultFromCryptoLib(string key)
    {
        return (key switch
        {
            "TRounds" => _cryptoLib!.Options.Rounds,
            "SessionIV" => _cryptoLib!.Options.SessionIv,
            _ => GetDefaultForUnknownSetting(key)
        })!;
    }

    // ✅ Return logical default based on type
    private object? GetDefaultForUnknownSetting(string key)
    {
        var property = typeof(GlobalsInstance).GetProperty(key, BindingFlags.Instance | BindingFlags.Public);
        if (property == null) return ""; // If no matching property, return empty string (safe default for unknowns)

        var type = property.PropertyType;
        if (type == typeof(string)) return null;
        if (type == typeof(int)) return 0;
        if (type == typeof(bool)) return false;
        if (type.IsEnum) return Enum.GetValues(type).GetValue(0); // Default to first enum value

        return null; // Fallback (shouldn't be hit unless we add unsupported types)
    }
}

/// <summary>
/// The ExecutionEnvironment class encapsulates all necessary execution state, 
/// ensuring that each process or thread operates in an isolated context. 
/// 
/// This class provides:
/// - A dedicated instance of CryptoLib, preventing shared-state issues.
/// - A unique GlobalsInstance per environment, eliminating conflicts from static global variables.
/// 
/// The primary goal is to replace static dependencies, enabling multi-threaded 
/// execution without race conditions or unintended side effects. 
/// 
/// By using ExecutionEnvironment, each thread can safely run with its own 
/// independent state, while only the designated main instance (allowSaving = true) 
/// persists settings to disk.
/// 
/// Note: CryptoLib is intentionally left uninitialized (null) to surface 
/// potential issues early rather than masking them with a default instance.
/// </summary>
///
public class ExecutionEnvironment
{
    public CryptoLib Crypto { get; }
    public GlobalsInstance Globals { get; }
    private CryptoAnalysis? _cryptoAnalysis = null;
    public CryptoAnalysis CryptoAnalysis => _cryptoAnalysis ??= new CryptoAnalysis();

    /// <summary>
    /// ✅ Primary constructor: Initializes a fresh execution environment.
    /// - Creates a new `CryptoLib` instance using the provided options.
    /// - Creates a new `GlobalsInstance` tied to this environment.
    /// - Calls `InitDefaults` to synchronize key settings.
    /// </summary>
    /// <param name="options">Configuration options for the cryptographic library.</param>
    /// <param name="allowSaving">Indicates whether this environment is allowed to save settings.</param>
    public ExecutionEnvironment(CryptoLibOptions? options, bool allowSaving = false)
    {
        // 🛑 Clone options FIRST to ensure nothing is shared
        var clonedOptions = options?.Dupe();

        Crypto = new CryptoLib(GlobalsInstance.Password, clonedOptions);

        Globals = new GlobalsInstance(this, allowSaving);

        // ✅ Ensure settings are fully initialized (allocates input, loads weight tables, syncs globals & crypto)
        InitDefaults(Globals, Crypto);
    }

    /// <summary>
    /// ✅ Copy constructor: Clones an existing execution environment.
    /// - Creates a new `CryptoLib` based on the source environment’s options.
    /// - Duplicates all global settings from the source environment.
    /// - Applies additional overrides if provided.
    /// </summary>
    /// <param name="existingEnv">The source environment to clone.</param>
    /// <param name="settings">Optional settings to override after duplication.</param>
    public ExecutionEnvironment(ExecutionEnvironment existingEnv, Dictionary<string, string>? settings = null)
        // establish the baseline environment. Duplicated environments may not 'allowSaving'
        : this(existingEnv.Crypto.Options, false)
    {
        // ✅ Clone all global settings from the existing environment
        Globals.Dupe(existingEnv.Globals, existingEnv.Crypto.Options);

        // ✅ Apply any provided setting overrides after duplication
        if (settings != null) ApplySettings(settings);
    }

    /// <summary>
    /// ✅ Initializes core global settings that require synchronization.
    /// - Ensures `InputType` is allocated.
    /// - Loads the appropriate weight table for the selected `Mode`.
    /// - Syncs cryptographic rounds between `Globals` and `CryptoLib`.
    /// </summary>
    /// <param name="instance">The `GlobalsInstance` to configure.</param>
    /// <param name="cryptoLib">The `CryptoLib` instance associated with this environment.</param>
    private void InitDefaults(GlobalsInstance instance, CryptoLib cryptoLib)
    {
        instance.UpdateSetting("inputtype", instance.InputType); // ✅ Allocates input buffer
        instance.UpdateSetting("rounds", cryptoLib!.Options.Rounds); // ✅ Syncs round count
    }

    private void ApplySettings(Dictionary<string, string> settings)
    {
        foreach (var (key, value) in settings)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new FormatException($"❌ ERROR: Missing or invalid value for '{key}' in settings file!");

            // ✅ Check if the setting exists in Globals (only update valid ones)
            if (!MemberExists(Globals, key))
                continue;

            var processedValue = value;

            // ✅ Convert single-character values to full enum names dynamically
            if (key == "InputType" && value.Length == 1)
            {
                processedValue = Enum.GetNames(typeof(InputType))
                                     .FirstOrDefault(name => name.StartsWith(value, StringComparison.OrdinalIgnoreCase))
                                 ?? throw new FormatException(
                                     $"❌ ERROR: Unrecognized InputType '{value}' in settings file!");
            }
            else if (key == "Mode" && value.Length == 1)
            {
                processedValue = Enum.GetNames(typeof(OperationModes))
                                     .FirstOrDefault(name => name.StartsWith(value, StringComparison.OrdinalIgnoreCase))
                                 ?? throw new FormatException(
                                     $"❌ ERROR: Unrecognized Mode '{value}' in settings file!");
            }
            else if (key == "UseMetricScoring")
            {
                if (value != "T" && value != "F")
                    throw new FormatException(
                        $"❌ ERROR: Invalid UseMetricScoring value in settings file! (Expected 'T' or 'F', got '{value}')");

                processedValue = value == "T" ? "true" : "false"; // ✅ Convert to expected boolean string
            }

            // ✅ Apply setting ONLY if it belongs in Globals
            var sequenceHandler = new SequenceAttributesHandler(this);
            var convertedValue =
                sequenceHandler.ConvertValue(typeof(GlobalsInstance).GetProperty(key)!.PropertyType, processedValue);
            Globals.UpdateSetting(key, convertedValue);
        }
    }

    private bool MemberExists(object? obj, string memberName)
    {
        if (obj == null) return false; // ✅ Safely return if the object is null

        var type = obj.GetType();
        return type.GetField(memberName,
                   BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic) != null
               || type.GetProperty(memberName,
                   BindingFlags.Instance | BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic) != null;
    }

}

#region Sequence Attributes Handler

public class SequenceAttributesHandler
{
    private readonly CryptoLib _cryptoLib;
    private readonly ExecutionEnvironment _localEnv;

    public SequenceAttributesHandler(ExecutionEnvironment localEnv)
    {
        _cryptoLib = localEnv.Crypto ?? throw new ArgumentNullException(nameof(localEnv.Crypto));
        _localEnv = localEnv ?? throw new ArgumentNullException(nameof(localEnv));
    }

    public void ApplyAttributes(Dictionary<string, string> attributes)
    {
        foreach (var kvp in attributes)
        {
            var key = kvp.Key;
            if (key.Equals("GR", StringComparison.OrdinalIgnoreCase))
                key = "Rounds";

            var value = kvp.Value;

            // 🔍 Retrieve property info dynamically
            var globalSetting = typeof(GlobalsInstance).GetProperty(key, BindingFlags.Public | BindingFlags.Instance);
            if (globalSetting == null)
                throw new ArgumentException($"Unknown sequence-wide property: {key}");

            // ✅ Convert the value properly before setting it
            var convertedValue = ConvertValue(globalSetting.PropertyType, value);
            _localEnv.Globals.UpdateSetting(key, convertedValue);
        }
    }
#if false
        private object ConvertValue(string key, object value)
        {
            var properties = typeof(GlobalsInstance).GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Where(p => p.IsDefined(typeof(GlobalSettingAttribute)))
                .ToDictionary(p => p.Name, p => p.PropertyType, StringComparer.OrdinalIgnoreCase);

            if (!properties.TryGetValue(key, out Type expectedType))
                throw new ArgumentException($"Unknown global setting: {key}");

            if (value.GetType() == expectedType)
                return value; // ✅ Already the correct type

            if (expectedType.IsEnum && value is string stringValue)
            {
                if (Enum.TryParse(expectedType, stringValue, true, out object result))
                    return result;
            }

            return Convert.ChangeType(value, expectedType); // ✅ Safely convert types (e.g., string to int)
        }
#endif
#if true
    public object? ConvertValue(Type targetType, object? value)
    {
        if (value == null)
        {
            if (targetType.IsValueType)
            {
                // 🚀 Ensure value types (including enums) are always valid
                var instance = Activator.CreateInstance(targetType);
                if (instance == null)
                    throw new InvalidOperationException(
                        $"❌ CRITICAL ERROR: Failed to create an instance of {targetType.Name}. This must be explicitly handled.");

                // 🚀 If it's an enum, verify that the default value is valid
                if (targetType.IsEnum && !Enum.IsDefined(targetType, instance))
                    throw new InvalidOperationException(
                        $"❌ CRITICAL ERROR: The default value '{instance}' is not a valid {targetType.Name} enum value.");

                return instance; // ✅ Guaranteed to be a valid value
            }

            return null!; // ✅ Null is acceptable for reference types
        }

        if (value.GetType() == targetType)
            return value; // ✅ Already the correct type

        if (targetType.IsEnum && value is string stringValue)
        {
            if (Enum.TryParse(targetType, stringValue, true, out var result))
                return result;
            throw new ArgumentException(
                $"❌ CRITICAL ERROR: Invalid enum value '{stringValue}' for type {targetType.Name}");
        }

        return Convert.ChangeType(value, targetType);
    }

#else
        public object ConvertValue(Type targetType, object value)
        {
            if (value == null)
            {
                if (targetType.IsValueType)
                    return Activator.CreateInstance(targetType)!; // Default for value types
                return null!; // Default for reference types
            }

            if (value.GetType() == targetType)
                return value; // ✅ Already the correct type

            if (targetType.IsEnum && value is string stringValue)
            {
                if (Enum.TryParse(targetType, stringValue, true, out object result))
                    return result;
                throw new ArgumentException($"Invalid enum value '{stringValue}' for type {targetType.Name}");
            }

            return Convert.ChangeType(value, targetType);
        }
#endif
    public object? ConvertValue(Type targetType, string value)
    {
        if (targetType.IsEnum)
        {
            if (!Enum.TryParse(targetType, value, true, out var parsedEnum))
                throw new ArgumentException(
                    $"Invalid value '{value}' for {targetType.Name}. Allowed values: {string.Join(", ", Enum.GetNames(targetType))}");
            return parsedEnum;
        }
        else if (targetType == typeof(int))
        {
            if (!int.TryParse(value, out var parsedInt))
                throw new ArgumentException($"Invalid integer value '{value}' for {targetType.Name}");
            return parsedInt;
        }
        else if (targetType == typeof(bool))
        {
            if (!bool.TryParse(value, out var parsedBool))
                throw new ArgumentException($"Invalid boolean value '{value}' for {targetType.Name}");
            return parsedBool;
        }
        else
        {
            return value; // Assume it's a valid string value
        }
    }
}

#endregion Sequence Attributes Handler

public static class TestInputGenerator
{
    private static readonly object _initLock = new();
    private static bool _isInitialized = false;

    private static byte[] _randomData = Array.Empty<byte>();
    private static byte[] _naturalData = Array.Empty<byte>();
    private static byte[] _sequenceData = Array.Empty<byte>();
    private static byte[] _combinedData = Array.Empty<byte>();

    public static void InitializeInputData()
    {
        lock (_initLock)
        {
            if (_isInitialized)
                return;

            var randoms_filename = "randoms.bin";
            var natural_filename = "Frankenstein.bin";
            var natural_source = "Frankenstein.txt";

            // 🚀 Load or generate Random Data
            if (!File.Exists(randoms_filename))
            {
                Console.WriteLine($"[WARN] {randoms_filename} not found. Generating new random data...");
                _randomData = new byte[4096];
                using (var rng = RandomNumberGenerator.Create())
                {
                    rng.GetBytes(_randomData);
                }

                File.WriteAllBytes(randoms_filename, _randomData);
            }
            else
            {
                _randomData = File.ReadAllBytes(randoms_filename);
            }

            ValidateBuffer(_randomData, 4096, randoms_filename);

            // 🚀 Load or create Natural Data
            if (!File.Exists(natural_filename))
            {
                if (!File.Exists(natural_source))
                    throw new FileNotFoundException(
                        $"❌ CRITICAL ERROR: {natural_source} not found. Cannot create {natural_filename}.");

                var textContent = File.ReadAllText(natural_source);
                _naturalData = Encoding.UTF8.GetBytes(textContent);
                File.WriteAllBytes(natural_filename, _naturalData);
            }
            else
            {
                _naturalData = File.ReadAllBytes(natural_filename);
            }

            ValidateBuffer(_naturalData, 4096, natural_filename);

            // 🚀 Generate Sequence Data
            _sequenceData = Enumerable.Range(0, 4096).Select(i => (byte)i).ToArray();
            ValidateBuffer(_sequenceData, 4096, "Sequence Data");

            // 🚀 Generate Combined Data using equal thirds approach
            var sliceSize = 4096 / 3;
            var natural = _naturalData.Take(sliceSize);
            var sequence = _sequenceData.Take(sliceSize);
            var random = _randomData.Take(sliceSize);

            _combinedData = natural.Concat(sequence).Concat(random).ToArray();

            if (_combinedData.Length < 4096)
                Array.Resize(ref _combinedData, 4096);
            else if (_combinedData.Length > 4096) _combinedData = _combinedData.Take(4096).ToArray();

            _isInitialized = true;
        }
    }

    public static byte[] GenerateTestInput(int size, InputType type = InputType.Natural)
    {
        if (!_isInitialized)
            throw new InvalidOperationException(
                "❌ CRITICAL ERROR: Test input data has not been initialized. Call InitializeInputData() first.");

        var sourceData = type switch
        {
            InputType.Random => _randomData,
            InputType.Natural => _naturalData,
            InputType.Sequence => _sequenceData,
            InputType.Combined => _combinedData,
            _ => throw new ArgumentException($"❌ CRITICAL ERROR: Invalid input type specified: {type}")
        };

        ValidateBuffer(sourceData, size, $"Requested {type} Data");

        return sourceData.Take(size).ToArray();
    }

    public static byte[] GenerateTestInput(ExecutionEnvironment localEnv)
    {
        return GenerateTestInput(4096, localEnv.Globals.InputType);
    }

    private static void ValidateBuffer(byte[] buffer, int expectedSize, string sourceName)
    {
        if (buffer == null || buffer.Length == 0)
            throw new InvalidOperationException($"❌ CRITICAL ERROR: {sourceName} buffer is null or empty.");

        if (buffer.Length < expectedSize)
            throw new ArgumentException(
                $"❌ CRITICAL ERROR: Requested size ({expectedSize}) exceeds available {sourceName} data ({buffer.Length}).");
    }
}

public static class MetricInfoHelper
{
    private static readonly Dictionary<OperationModes, Dictionary<string, double>> modeWeights = new()
    {
        {
            OperationModes.Cryptographic, new Dictionary<string, double>
            {
                { "Entropy", 0.3 },
                { "BitVariance", 0.2 },
                { "SlidingWindow", 0.1 }, // De-emphasized
                { "FrequencyDistribution", 0.1 }, // De-emphasized
                { "PeriodicityCheck", 0.1 },
                { "MangosCorrelation", 0.3 },
                { "PositionalMapping", 0.3 },
                { "AvalancheScore", 0.4 }, // Emphasized
                { "KeyDependency", 0.3 } // Important for cryptographic robustness
            }
        },
        {
            OperationModes.Cryptographic_New, new Dictionary<string, double>
            {
                { "AvalancheScore", 0.1860 },
                { "Entropy", 0.1395 },
                { "MangosCorrelation", 0.1395 },
                { "PositionalMapping", 0.1395 },
                { "KeyDependency", 0.1395 },
                { "BitVariance", 0.1163 },
                { "SlidingWindow", 0.0465 },
                { "FrequencyDistribution", 0.0465 },
                { "PeriodicityCheck", 0.0465 }
            }
        },
        {
            OperationModes.Exploratory, new Dictionary<string, double>
            {
                { "Entropy", 0.2 },
                { "BitVariance", 0.2 },
                { "SlidingWindow", 0.3 }, // Emphasized
                { "FrequencyDistribution", 0.3 }, // Emphasized
                { "PeriodicityCheck", 0.1 },
                { "MangosCorrelation", 0.2 },
                { "PositionalMapping", 0.2 },
                { "AvalancheScore", 0.2 }, // De-emphasized
                { "KeyDependency", 0.2 } // Secondary in exploratory analysis
            }
        },
        {
            OperationModes.Exploratory_New, new Dictionary<string, double>
            {
                { "Entropy", 0.000 },
                { "BitVariance", 0.000 },
                { "SlidingWindow", 0.000 },
                { "FrequencyDistribution", 0.000 },
                { "PeriodicityCheck", 0.000 },
                { "MangosCorrelation", 0.000 },
                { "PositionalMapping", 0.000 },
                { "AvalancheScore", 0.000 },
                { "KeyDependency", 0.000 }
            }
        },
        {
            OperationModes.Flattening, new Dictionary<string, double>
            {
                { "Entropy", 1.5 }, // 🚀 More weight to ensure full entropy neutralization.
                { "BitVariance", 1.0 }, // 🔥 Maintain uniform bit variance.
                { "SlidingWindow", 1.5 }, // 🔥 Ensure local patterns do not persist.
                { "FrequencyDistribution", 1.0 }, // ✅ Keep bytes evenly distributed.
                { "PeriodicityCheck", 1.0 }, // ✅ Ensure no periodic patterns remain.
                { "MangosCorrelation", 0.001 },
                { "PositionalMapping", 0.001 },
                { "AvalancheScore", 0.001 },
                { "KeyDependency", 0.001 }
            }
        },
        {
            OperationModes.None, new Dictionary<string, double>
            {
                { "Entropy", 1.0 },
                { "BitVariance", 1.0 },
                { "SlidingWindow", 1.0 },
                { "FrequencyDistribution", 1.0 },
                { "PeriodicityCheck", 1.0 },
                { "MangosCorrelation", 1.0 },
                { "PositionalMapping", 1.0 },
                { "AvalancheScore", 1.0 },
                { "KeyDependency", 1.0 }
            }
        }
    };

    public static bool TryGetWeights(OperationModes mode, out Dictionary<string, double> weights)
    {
        return modeWeights.TryGetValue(mode, out weights!);
    }

    public static void AdjustWeights(ExecutionEnvironment localEnv, OperationModes mode)
    {
        // Initialize a dictionary to accumulate weights
        var combinedWeights = new Dictionary<string, double>();

        foreach (var singleMode in Enum.GetValues<OperationModes>())
            // Check if the mode flag is set
            if (mode.HasFlag(singleMode) && modeWeights.TryGetValue(singleMode, out var weights))
                foreach (var (metric, weight) in weights)
                    if (combinedWeights.ContainsKey(metric))
                        combinedWeights[metric] = Math.Max(combinedWeights[metric], weight);
                    else
                        combinedWeights[metric] = weight;

        // Apply combined weights to the MetricsRegistry
        foreach (var key in localEnv.CryptoAnalysis.MetricsRegistry.Keys)
            if (combinedWeights.TryGetValue(key, out var weight))
                localEnv.CryptoAnalysis.MetricsRegistry[key].Weight = weight;
            else
                Console.WriteLine($"Warning: No default weight specified for metric {key} in mode {mode}.");
    }

    //public static void NormalizeWeights()
    //{
    //    foreach (var key in MetricsRegistry.Keys)
    //    {
    //        MetricsRegistry[key].PushWeight(1.0); // Push the current weight and set to 1.0
    //    }
    //}

    //public static void RestoreWeights()
    //{
    //    foreach (var key in MetricsRegistry.Keys)
    //    {
    //        MetricsRegistry[key].PopWeight(); // Restore the previous weight
    //    }
    //}
}

public static class UtilityHelpers
{
    public static object _debug_lock = new();

    public static bool AreListsEquivalent(List<byte[]> list1, List<byte[]> list2)
    {
        return list1.Count == list2.Count &&
               !list1.Except(list2, new ByteArrayComparer()).Any() &&
               !list2.Except(list1, new ByteArrayComparer()).Any();
    }

    public static (bool success, string errorMessage) SetTransformRounds(
        CryptoLib? cryptoLib,
        List<(string name, int id, int tRounds)> parsedSequence) // 🚀 No GR needed
    {
        if (parsedSequence.Count == 0) return (false, "No valid transforms provided.");

        foreach (var (name, id, tRounds) in parsedSequence) // 🚀 No GR here either
        {
            if (!cryptoLib!.TransformRegistry.TryGetValue(id, out var transform))
                return (false, $"Transform ID {id} not found in registry.");

            transform.Rounds = (byte)tRounds; // 🔹 Set per-transform rounds

            // 🔹 Set the **inverse transform** to the same TR value
            if (cryptoLib!.TransformRegistry.TryGetValue(transform.InverseId, out var inverseTransform))
                inverseTransform.Rounds = (byte)tRounds;
        }

        return (true, ""); // ✅ Success, no errors
    }


    public static List<string> GetMungeBody(ExecutionEnvironment localEnv)
    {
        var failDBColor = localEnv.Globals.CreateMungeFailDB ? "Red" : "Green"; // Red if MungeFailDB is enabled

        return new List<string>
        {
            $"<Green>[Timestamp] {DateTime.Now:MM/dd/yyyy hh:mm:ss tt}</Green>", // Provides a readable timestamp
            $"<Green>DataType: {localEnv.Globals.InputType}</Green>", // Input type (Combined, Random, etc.)
            $"<Green>Rounds: {localEnv.Globals.Rounds}</Green>", // Global rounds for encryption
            $"<Green>Mode: {localEnv.Globals.Mode}</Green>", // Cryptographic or Exploratory mode
            $"<Green>PassCount: {localEnv.Globals.PassCount}</Green>", // Number of passes required for success
            $"<Green>MaxSequenceLen: {localEnv.Globals.MaxSequenceLen}</Green>", // Maximum sequence length allowed
            $"<Green>Munge Level: L{localEnv.Globals.MaxSequenceLen}</Green>", // Same as MaxSequenceLen, expressed as a level
            $"<Green>Metric Scoring: {(localEnv.Globals.UseMetricScoring ? "True" : "False")}</Green>", // Whether metric scoring is enabled
            $"<Green>Database: {GetFailDBFilename(localEnv, "MungeFailDB,")}</Green>", // Name of the MungeFailDB file
            $"<{failDBColor}>Database Creation Mode: {(localEnv.Globals.CreateMungeFailDB ? "Enabled" : "Read-Only")}</{failDBColor}>", // MungeFailDB mode
            $"<Green>Commandline: {localEnv.Globals.Commandline ?? "<not set>"}</Green>" // Logs the command-line arguments
        };
    }

    public static List<string> GetMungeTitle(string headerTitle, string? name = null)
    {
        // Dynamically build the header title, ensuring no extra spaces if `name` is null or empty
        headerTitle = string.IsNullOrWhiteSpace(name) ? headerTitle : $"{name} {headerTitle}";

        // Determine the length of the title for formatting
        var titleLength = headerTitle.Length;
        var borderLine = new string('=', titleLength + 10); // Matches title length with padding

        // Construct title as a list
        return new List<string>
        {
            $"<Yellow>{borderLine}</Yellow>",
            $"<Yellow>     {headerTitle}     </Yellow>",
            $"<Yellow>{borderLine}</Yellow>"
        };
    }

    public static List<string> GetMungeTail(List<string> headerLines)
    {
        if (headerLines == null || headerLines.Count == 0)
            throw new ArgumentException("Header lines cannot be null or empty.", nameof(headerLines));

        // Determine the length of the longest line in the header for proper formatting
        var maxLength = headerLines.Max(line => ColorConsole.RemoveColorTags(line).Length);
        var borderLine = new string('=', maxLength); // Matches longest title length

        // Construct tail as a list
        return new List<string> { $"<Yellow>{borderLine}</Yellow>" };
    }


    /// <summary>
    /// Generates a standardized ContenderLog filename for Mango Munge results.
    /// The format ensures clear identification of the Munge level, pass count, data type,
    /// cryptographic mode, and whether metric scoring was enabled. 
    /// 
    /// 📌 **Explanation of the Format:**
    /// - **YYMM_DDD** → Uses `DateTime.UtcNow` to generate the year, month, and day of the year.
    /// - **L<Munge Level>** → Indicates the Munge level (e.g., L4 for Level 4).
    /// - **P<Pass Count>** → Specifies the required pass count (retrieved from `GlobalEnv.Globals.PassCount`).
    /// - **D<DataType>** → Data classification:
    ///   - `'C'` = Combined  
    ///   - `'N'` = Natural  
    ///   - `'R'` = Random  
    ///   - `'S'` = Sequence  
    /// - **M<Mode>** → Encryption mode:
    ///   - `'C'` = Cryptographic  
    ///   - `'E'` = Exploratory  
    /// - **S<UseMetricScoring>** → Indicates if metric scoring was used:
    ///   - `'T'` = True  
    ///   - `'F'` = False  
    /// 
    /// **Example Filenames:**
    /// ```
    /// 2502_032_L4-P6-DN-MC-ST.txt  (Feb 1, 2025, L4 Munge, Pass Count 6, Natural Data, Cryptographic, Scoring True)
    /// 2501_015_L3-P5-DC-ME-SF.txt  (Jan 15, 2025, L3 Munge, Pass Count 5, Combined Data, Exploratory, Scoring False)
    /// ```
    ///
    /// 🚀 This naming convention prevents accidental overwrites and allows easy sorting.
    /// </summary>
    /// <returns>Formatted contender log filename as a string.</returns>
    public static string GetContenderFilename(ExecutionEnvironment localEnv, int sequenceLength,
        string extension = "txt")
    {
        return GenerateFilename(localEnv, "Contenders,", sequenceLength, extension);
    }

    public static string GetStateFilename(ExecutionEnvironment localEnv, int sequenceLength, string extension = "json")
    {
        return GenerateFilename(localEnv, "State,", sequenceLength, extension);
    }

    public static string GetFailDBFilename(ExecutionEnvironment localEnv, string prefix, string extension = "db")
    {
        return GenerateFilename(localEnv, prefix, null, extension);
    }

    private static string GenerateFilename(ExecutionEnvironment localEnv,
        string prefix = "",
        int? sequenceLength = null,
        string extension = "")
    {
        var passCount = localEnv.Globals.PassCount;
        var dataType = localEnv.Globals.InputType.ToString()[0]; // ✅ 1st Char of InputType
        var mode = localEnv.Globals.Mode.ToString()[0]; // ✅ 1st Char of Mode
        var useMetricScoring = localEnv.Globals.UseMetricScoring ? 'T' : 'F';

        // ✅ Keep the prefix (e.g., "Contenders," or "MungeFailDB,")
        var lengthSegment = sequenceLength.HasValue ? $"-L{sequenceLength}" : "";

        var basename = $"{prefix}{lengthSegment}-P{passCount}-D{dataType}-M{mode}-S{useMetricScoring}";

        return string.IsNullOrEmpty(extension) ? basename : basename + "." + extension.TrimStart('.');
    }

    public static string GetBestContenderFile(string fileMask)
    {
        var files = Directory.GetFiles(".", fileMask)
            .Select(Path.GetFileName)
            .Where(f => f != null)
            .OrderByDescending(f => int.Parse(Regex.Match(f!, @"-L(\d+)").Groups[1].Value))
            .ThenByDescending(f => int.Parse(Regex.Match(f!, @"-P(\d+)").Groups[1].Value))
            .FirstOrDefault();

        if (files == null)
            throw new FileNotFoundException("No matching contender files found.");

        return files;
    }

    public static double GetAggregateScore(string filename, int contender)
    {
        if (!File.Exists(filename))
        {
            Console.WriteLine($"Error: File not found: {filename}");
            return 0.0; // Return 0 for file not found
        }

        try
        {
            var fileContent = File.ReadAllText(filename);

            // Use Regex to find the specified contender and its aggregate score
            var pattern = $@"Contender #{contender}\s+Sequence:\s*(.*?)\s+Aggregate Score:\s*(\d+(\.\d+)?)";
            var match = Regex.Match(fileContent, pattern, RegexOptions.Singleline); // Singleline is important!

            if (match.Success)
            {
                // Group 2 contains the score (with optional decimal part).
                if (double.TryParse(match.Groups[2].Value, out var score))
                {
                    return score;
                }
                else
                {
                    Console.WriteLine(
                        $"Error: Could not parse Aggregate Score for Contender #{contender} in {filename}.");
                    return 0.0; // Return 0 for parsing error
                }
            }
            else
            {
                Console.WriteLine($"Error: Contender #{contender} not found in {filename}.");
                return 0.0; // Return 0 if contender not found
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading or processing file {filename}: {ex.Message}");
            return 0.0; // Return 0 for any exception
        }
    }

    public static string GetSequence(string filename, int contender)
    {
        if (!File.Exists(filename))
        {
            Console.WriteLine($"Error: File not found: {filename}");
            return string.Empty; // Return empty string for file not found
        }

        try
        {
            var fileContent = File.ReadAllText(filename);

            // Regex pattern to extract the sequence for the given contender
            var pattern = $@"Contender #{contender}\s+Sequence:\s*(.*?)\s+Aggregate Score:";

            var match = Regex.Match(fileContent, pattern, RegexOptions.Singleline);

            if (match.Success)
            {
                return match.Groups[1].Value.Trim(); // Extracts the sequence and trims whitespace
            }
            else
            {
                Console.WriteLine($"Error: Contender #{contender} not found in {filename}.");
                return string.Empty; // Return empty string if contender not found
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading or processing file {filename}: {ex.Message}");
            return string.Empty; // Return empty string for any exception
        }
    }

    /// <summary>
    /// Extracts all key environment settings from a filename,
    /// ensuring correctness without relying on unnecessary date tracking.
    /// </summary>
    /// <param name="filename">The filename to extract settings from.</param>
    /// <returns>A dictionary of settings as key-value pairs.</returns>
    public static Dictionary<string, string> GetEnvironmentSettings(string filename)
    {
        // ✅ Extract settings from filename (removing "Contenders," prefix if present)
        var trimmedFilename = Path.GetFileNameWithoutExtension(filename)
            .Replace("Contenders,", "", StringComparison.OrdinalIgnoreCase);

        var settings = new Dictionary<string, string>();

        // ✅ Extract all known settings from filename
        var filenameParts = trimmedFilename.Split('-');

        foreach (var part in filenameParts)
            if (part.StartsWith("L", StringComparison.OrdinalIgnoreCase))
                settings["MaxSequenceLen"] = part.Substring(1); // *-Lx-* (Munge Level)

            else if (part.StartsWith("P", StringComparison.OrdinalIgnoreCase))
                settings["PassCount"] = part.Substring(1); // *-Px-* (Pass Count)

            else if (part.StartsWith("D", StringComparison.OrdinalIgnoreCase))
                settings["InputType"] = part.Substring(1); // *-Dx-* (Data Type: C, N, R, S)

            else if (part.StartsWith("M", StringComparison.OrdinalIgnoreCase))
                settings["Mode"] = part.Substring(1); // *-Mx-* (Mode: C, E)

            else if (part.StartsWith("S", StringComparison.OrdinalIgnoreCase))
                settings["UseMetricScoring"] = part.Substring(1); // *-Sx-* (Scoring: T, F)

        if (settings.Count != 5)
            throw new InvalidOperationException(
                "Missing required settings in filename. Expected 5 settings (MaxSequenceLen, PassCount, InputType, Mode, UseMetricScoring).");

        return settings;
    }

    public static Dictionary<string, string> GenerateEnvironmentSettings(string[] args)
    {
        var settings = new Dictionary<string, string>();
        string? maxSequenceLen = null;
        string? passCount = null;
        string? inputType = null;
        string? mode = null;
        string? useMetricScoring = null;

        for (var i = 0; i < args.Length; i++)
        {
            var arg = args[i];

            if (arg.StartsWith("-L", StringComparison.OrdinalIgnoreCase))
            {
                maxSequenceLen = arg.Substring(2); // Remove "-L"
            }
            else if (arg.StartsWith("-P", StringComparison.OrdinalIgnoreCase))
            {
                passCount = arg.Substring(2); // Remove "-P"
            }
            else if (arg.StartsWith("-D", StringComparison.OrdinalIgnoreCase))
            {
                inputType = arg.Substring(2); // Remove "-D"
            }
            else if (arg.StartsWith("-M", StringComparison.OrdinalIgnoreCase))
            {
                mode = arg.Substring(2); // Remove "-M"
            }
            else if (arg.StartsWith("-S", StringComparison.OrdinalIgnoreCase))
            {
                useMetricScoring = arg.Substring(2); // Remove "-S"
            }
            // Handle key-value pairs (e.g., -Rounds=10)
            else if (arg.Contains("="))
            {
                var parts = arg.Split('=');
                if (parts.Length == 2)
                {
                    var key = parts[0].TrimStart('-'); //Remove leading -
                    var value = parts[1];
                    settings[key] = value;
                }
                else
                {
                    throw new ArgumentException($"Invalid argument format: {arg}. Expected format is -Key=Value.");
                }
            }
            else
            {
                throw new ArgumentException($"Invalid or unsupported argument: {arg}");
            }
        }

        //Prioritize named args.
        if (maxSequenceLen != null)
            settings["MaxSequenceLen"] = maxSequenceLen;
        if (passCount != null)
            settings["PassCount"] = passCount;
        if (inputType != null)
            settings["InputType"] = inputType;
        if (mode != null)
            settings["Mode"] = mode;
        if (useMetricScoring != null)
            settings["UseMetricScoring"] = useMetricScoring;


        // Check for all required settings.  Use settings.ContainsKey, so we can support any setting.
        var requiredKeys = new string[] { "MaxSequenceLen", "PassCount", "InputType", "Mode", "UseMetricScoring" };
        foreach (var key in requiredKeys)
            if (!settings.ContainsKey(key))
                throw new InvalidOperationException(
                    $"Missing required setting: {key}.  Expected in the format -{key}=value.");

        return settings;
    }

    public static Dictionary<string, string> GetEnvironmentSettings(ExecutionEnvironment exeEnv)
    {
        var settings = new Dictionary<string, string>
        {
            { "MaxSequenceLen", exeEnv.Globals.MaxSequenceLen.ToString() },
            { "PassCount", exeEnv.Globals.PassCount.ToString() },
            { "InputType", exeEnv.Globals.InputType.ToString() },
            { "Mode", exeEnv.Globals.Mode.ToString() },
            { "UseMetricScoring", exeEnv.Globals.UseMetricScoring ? "T" : "F" }
        };

        if (settings.Count != 5)
            throw new InvalidOperationException(
                "Missing required settings in ExecutionEnvironment. Expected 5 settings (MaxSequenceLen, PassCount, InputType, Mode, UseMetricScoring).");

        return settings;
    }

    /// <summary>
    /// Retrieves matching Munge result files based on user-specified parameters.
    ///
    /// 🧠 Flexible File Matching:
    /// - Default pattern: `Contenders,-L4-P6-D?-MC-ST.txt`
    /// - Arguments passed in (e.g., `-L5`, `-DN`, `-SF`) will dynamically replace components of the pattern.
    ///
    /// ✅ Examples:
    /// - `-L5` → `Contenders,-L5-P6-D?-MC-ST.txt`
    /// - `-L5 -P0 -DR -ME -SF` → `Contenders,-L5-P0-DR-ME-SF.txt`
    ///
    /// 🚨 The full resolved pattern is shown to the user before continuing.
    /// User must confirm (Y/N) to proceed.
    ///
    /// 📁 Files are matched against the current folder with wildcard support (`?`)
    /// Results are returned as a sorted array.
    /// </summary>
    public static string[] GetMungeFiles(string[] args)
    {
        var defaultPattern = "Contenders,-L4-P6-D?-MC-ST.txt";
        var resolvedPattern = defaultPattern;

        foreach (var arg in args)
            if (arg.StartsWith("-L", StringComparison.OrdinalIgnoreCase))
                resolvedPattern = Regex.Replace(resolvedPattern, @"-L\d+", arg, RegexOptions.IgnoreCase);
            else if (arg.StartsWith("-P", StringComparison.OrdinalIgnoreCase))
                resolvedPattern = Regex.Replace(resolvedPattern, @"-P\d+", arg, RegexOptions.IgnoreCase);
            else if (arg.StartsWith("-D", StringComparison.OrdinalIgnoreCase))
                resolvedPattern = Regex.Replace(resolvedPattern, @"-D\?", arg, RegexOptions.IgnoreCase);
            else if (arg.StartsWith("-M", StringComparison.OrdinalIgnoreCase))
                resolvedPattern = Regex.Replace(resolvedPattern, @"-M[CFE]", arg, RegexOptions.IgnoreCase);
            else if (arg.StartsWith("-S", StringComparison.OrdinalIgnoreCase))
                resolvedPattern = Regex.Replace(resolvedPattern, @"-S[T|F]", arg, RegexOptions.IgnoreCase);

        string[] matchingFiles = GetMungeFiles(args, resolvedPattern);
        if (matchingFiles.Length == 0) return Array.Empty<string>();

        return matchingFiles.OrderBy(f => f).ToArray();
    }

    /// <summary>
    /// Retrieves the top contender sequences from Munge(A) output files and extracts a specified number of transforms.
    /// </summary>
    /// <param name="env">The execution environment containing cryptographic context.</param>
    /// <param name="pattern">The file pattern to match contender files (e.g., "Contenders,-L4-P6-D?-MC-ST.txt").</param>
    /// <param name="contenders">The number of top contender sequences to retrieve.</param>
    /// <param name="transforms">The number of transforms to extract from each sequence (starting from the left).</param>
    /// <returns>A list of byte arrays, where each array represents a sequence of transform IDs.</returns>
    /// <exception cref="FileNotFoundException">Thrown if no contender files are found.</exception>
    /// <exception cref="InvalidOperationException">Thrown if the requested number of contenders or transforms cannot be satisfied.</exception>
    public static List<byte[]> GetTopContendersAsIDs(ExecutionEnvironment env, string pattern, int contenders,
        int transforms)
    {
        if (contenders <= 0 || transforms <= 0)
            throw new ArgumentException("Both 'contenders' and 'transforms' must be greater than zero.");

        // Get all matching files in the directory
        var files = Directory.GetFiles(Directory.GetCurrentDirectory(), pattern);

        if (files.Length == 0) throw new FileNotFoundException("No contender files found. You must munge first.");

        var topContenders = new List<byte[]>();
        var seqHelper = new SequenceHelper(env.Crypto); // ✅ Helper to convert sequences to IDs

        foreach (var file in files)
            try
            {
                using (var reader = new StreamReader(file))
                {
                    string line;
                    while ((line = reader.ReadLine()!) != null)
                        if (line.StartsWith("Sequence:"))
                        {
                            var sequence = line.Substring(9).Trim();
                            var sequenceList = sequence.Split(" -> ").ToList();

                            // ✅ Ensure we have enough transforms in the sequence
                            if (sequenceList.Count < transforms)
                                throw new InvalidOperationException(
                                    $"Sequence in file {file} has only {sequenceList.Count} transforms, but {transforms} were requested.");

                            // ✅ Truncate to the requested number of transforms
                            sequenceList = sequenceList.Take(transforms).ToList();

                            // ✅ Convert sequence to byte[] using existing function
                            var sequenceIds = seqHelper.GetIDs(sequenceList).ToArray();
                            topContenders.Add(sequenceIds);

                            // Stop once we've collected the required count
                            if (topContenders.Count >= contenders)
                                break;
                        }
                }
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to process file: {file}. Error: {ex.Message}");
            }

        if (topContenders.Count < contenders)
            throw new Exception(
                $"Only {topContenders.Count} contender sequences found, but {contenders} were requested.");

        return topContenders;
    }

    private static string[] GetMungeFiles(string[] args, string defaultPattern)
    {
        // ✅ Get all files in the directory that match the new date-free format
        var allFiles = Directory.GetFiles(Directory.GetCurrentDirectory(), "Contenders,-L?-P?-D?-M?-S?.txt");

        // ✅ Define supported parameters & their defaults (only used if NO arguments are passed)
        var validParams = new Dictionary<string, string>
        {
            { "L", "4" }, // Default Level = L4
            { "P", "6" }, // Default Pass Count = P6
            { "D", "[A-Z]" }, // ✅ Match any uppercase letter combo (DC, DR, etc.)
            { "M", "C" }, // Default Mode = Cryptographic
            { "S", "T" } // Default Metric Scoring = True
        };

        var hasArgs = args.Any(arg => arg.StartsWith("-"));

        // ✅ Parse Arguments & Update validParams
        foreach (var arg in args)
            if (arg.StartsWith("-"))
            {
                var key = arg.Substring(1, 1).ToUpper(); // Extract single-character key
                var value = arg.Substring(2).ToUpper(); // Extract value
                if (validParams.ContainsKey(key)) validParams[key] = value;
            }

        // ✅ Expand ranges (L and P support multiple values)
        validParams["L"] = ExpandRange(validParams["L"], 1, 9);
        validParams["P"] = ExpandRange(validParams["P"], 0, 9);

        // ✅ Construct final regex (ensuring explicit range matching)
        var regexPattern =
            $@"^Contenders,-L{validParams["L"]}-P{validParams["P"]}-D{validParams["D"]}-M{validParams["M"]}-S{validParams["S"]}\.txt$";
        var regex = new Regex(regexPattern, RegexOptions.IgnoreCase);

        // ✅ Filter files using regex AFTER retrieving them all
        var matchingFiles = allFiles
            .Where(file => regex.IsMatch(Path.GetFileName(file))) // ✅ Extract filename first
            .ToArray();

        // ✅ If arguments were provided but no files matched, return an empty array
        return matchingFiles.Length > 0
            ? matchingFiles.OrderBy(f => f).ToArray()
            : hasArgs
                ? Array.Empty<string>()
                : Directory.GetFiles(Directory.GetCurrentDirectory(), defaultPattern);
    }

    public static bool VerifyMungeFile(string[] files, out string message, params string[] requiredFlags)
    {
        message = string.Empty;

        if (files.Length == 0)
        {
            message = "🚨 No files provided for verification.";
            return false;
        }

        if (requiredFlags.Length == 0)
        {
            message = "🚨 No flags provided for verification.";
            return false;
        }

        // ✅ Extract initial reference values from the first file
        Dictionary<string, string> seedValues = new();
        foreach (var flag in requiredFlags)
        {
            var seedValue = ExtractFlagValue(files[0], flag);
            if (seedValue == null)
            {
                message = $"🚨 Missing expected flag `{flag}` in file: {files[0]}";
                return false;
            }

            seedValues[flag] = seedValue; // Store reference value
        }

        // ✅ Validate all files against the reference values
        foreach (var file in files)
            foreach (var flag in requiredFlags)
            {
                var detectedValue = ExtractFlagValue(file, flag);
                if (!string.Equals(detectedValue, seedValues[flag], StringComparison.OrdinalIgnoreCase))
                {
                    message =
                        $"❌ Inconsistent `{flag}` values detected! Expected: {seedValues[flag]} but found: {detectedValue} in file: {file}";
                    return false;
                }
            }

        return true; // ✅ All checks passed
    }

    private static string? ExtractFlagValue(string filename, string flag)
    {
        // ✅ Locate the flag in the filename
        var index = filename.IndexOf(flag, StringComparison.OrdinalIgnoreCase);
        if (index == -1) return null; // Flag not found

        // ✅ Extract the flag's value (e.g., "-DC", "-DN", "-ST", etc.)
        var start = index + flag.Length;

        // ✅ Iterate until we find a non-alphanumeric character
        var end = start;
        while (end < filename.Length && char.IsLetterOrDigit(filename[end])) end++;

        return filename.Substring(start, end - start); // ✅ Extract only valid alphanumeric portion
    }

    /// <summary>
    /// Expands level or pass count parameters from single values or comma-separated lists into regex ranges.
    /// </summary>
    private static string ExpandRange(string input, int min, int max)
    {
        if (input.Contains(","))
            // Handle explicit lists like "3,5,7"
            return $"({string.Join("|", input.Split(',').Select(x => x.Trim()))})";
        else if (int.TryParse(input, out var value))
            // ✅ If a single value, return it as-is (NO parentheses)
            return value.ToString();
        else
            // Handle wildcard or invalid values
            return $"[{min}-{max}]";
    }

    /// <summary>
    /// Converts CSV values (e.g., "3,5") into a regex pattern like "(3|5)".
    /// </summary>
    private static string BuildRegexPattern(string input)
    {
        return input.Contains(",") ? $"({string.Join("|", input.Split(','))})" : input;
    }

    public static class MungeStatePersistence
    {
        public static void SaveMungeState(
            List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysis.AnalysisResult> Metrics)> contenders,
            int length,
            byte[] transforms,
            byte[] sequence,
            string saveFileName
        )
        {
            try
            {
                // If file exists and is read-only, remove the read-only attribute
                if (File.Exists(saveFileName))
                {
                    var attributes = File.GetAttributes(saveFileName);
                    if ((attributes & FileAttributes.ReadOnly) == FileAttributes.ReadOnly)
                        File.SetAttributes(saveFileName, attributes & ~FileAttributes.ReadOnly);
                }

                var options = new JsonSerializerOptions { WriteIndented = true };
                var state = new MungeState
                {
                    Contenders = contenders.Select(c => new SerializableContender
                    {
                        Sequence = c.Sequence,
                        AggregateScore = c.AggregateScore,
                        Metrics = c.Metrics
                    }).ToList(),
                    Length = length,
                    Transforms = transforms,
                    Sequence = sequence
                };

                var jsonString = JsonSerializer.Serialize(state, options);
                File.WriteAllText(saveFileName, jsonString);

                // Set the file to read-only after saving
                File.SetAttributes(saveFileName, FileAttributes.ReadOnly);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error saving munge state: {ex.Message}");
            }
        }

        public static MungeState? RestoreMungeState(string saveFileName)
        {
            try
            {
                if (!File.Exists(saveFileName)) return null; // Return null if there's no saved state

                var jsonString = File.ReadAllText(saveFileName);
                var restoredState = JsonSerializer.Deserialize<MungeState>(jsonString);

                return restoredState; // Return the whole object
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error restoring munge state: {ex.Message}");
                return null; // Indicate failure
            }
        }

        public class SerializableContender
        {
            public List<byte>? Sequence { get; set; }
            public double AggregateScore { get; set; }
            public List<CryptoAnalysis.AnalysisResult>? Metrics { get; set; }
        }

        public class MungeState
        {
            public List<SerializableContender>? Contenders { get; set; }
            public int Length { get; set; }
            public byte[] Transforms { get; set; } = null!;
            public byte[] Sequence { get; set; } = null!;
        }
    }


    public static (byte[] MangoAvalanchePayload, byte[] AESAvalanchePayload, byte[] MangoKeyDependencyPayload, byte[]
        ? AESKeyDependencyPayload)
        ProcessAvalancheAndKeyDependency(
            ExecutionEnvironment localEnv,
            string password,
            List<byte> sequence,
            bool processAes = false)
    {
        // Generate reverse sequence
        var reverseSequence = GenerateReverseSequence(localEnv.Crypto, sequence.ToArray());

        // Modify input and password
        var modifiedInput = ModifyInput(reverseSequence, localEnv.Globals.Input);
        var modifiedPassword = Encoding.UTF8.GetString(ModifyInput(reverseSequence, Encoding.UTF8.GetBytes(password))!);

        // Avalanche: Mango encryption with modified input
        var mangoAvalanchePayload = localEnv.Crypto.Encrypt(sequence.ToArray(), modifiedInput);
        mangoAvalanchePayload = localEnv.Crypto.GetPayloadOnly(mangoAvalanchePayload);

        // Avalanche: AES encryption with modified input (conditionally processed)
        byte[] aesAvalanchePayload = null!;
        if (processAes)
        {
            aesAvalanchePayload = AesEncrypt(modifiedInput, password, out var saltLength, out var paddingLength);
            aesAvalanchePayload = ExtractAESPayload(aesAvalanchePayload, saltLength, paddingLength);
        }

        // KeyDependency: Setup local CryptoLib with modified password
        var options = new CryptoLibOptions(
            localEnv.Globals.Rounds, // ✅ Use dynamically set rounds
            new byte[] { 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5 }
        );
        var kDcryptoLib = new CryptoLib(modifiedPassword, options);

        // KeyDependency: Mango encryption with modified password
        var mangoKeyDependencyPayload = kDcryptoLib.Encrypt(sequence.ToArray(), localEnv.Globals.Input);
        mangoKeyDependencyPayload = kDcryptoLib.GetPayloadOnly(mangoKeyDependencyPayload);

        // KeyDependency: AES encryption with modified password (conditionally processed)
        byte[] aesKeyDependencyPayload = null!;
        if (processAes)
        {
            aesKeyDependencyPayload = AesEncrypt(localEnv.Globals.Input, modifiedPassword, out var saltLength,
                out var paddingLength);
            aesKeyDependencyPayload = ExtractAESPayload(aesKeyDependencyPayload, saltLength, paddingLength);
        }

        // Return results as a tuple
        return (mangoAvalanchePayload, aesAvalanchePayload, mangoKeyDependencyPayload, aesKeyDependencyPayload);
    }

    /// <summary>
    /// Modifies the input buffer by flipping a bit determined based on the reverse sequence.
    /// </summary>
    /// <param name="reverseSequence">The reverse sequence used to determine the bit to flip.</param>
    /// <param name="input">The original input buffer to be modified.</param>
    /// <returns>A new byte array with a single bit flipped.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte[] ModifyInput(byte[] reverseSequence, byte[] input)
    {
        // Hash the reverse sequence to determine the bit to flip
        using var sha256 = SHA256.Create();
        var reverseHash = sha256.ComputeHash(reverseSequence);
        var hashValue = BinaryPrimitives.ReadInt64LittleEndian(reverseHash); // Convert first 8 bytes to a long

        var totalBits = input.Length * 8; // Total number of bits in the input
        var bitToFlip = (int)(Math.Abs(hashValue) % totalBits); // Map hash to a valid bit index

        // Create a copy of the input and flip the calculated bit
        var modifiedInput = (byte[])input.Clone();
        var byteIndex = bitToFlip / 8;
        var bitIndex = bitToFlip % 8;
        modifiedInput[byteIndex] ^= (byte)(1 << bitIndex); // Flip the bit

        return modifiedInput;
    }

    public static byte[] AesEncrypt(byte[] input, string password, out int saltLength, out int paddingLength)
    {
        // Generate a random salt
        var salt = GenerateRandomBytes(16);
        saltLength = salt.Length; // Return salt length

        // Derive the key and IV using PBKDF2
        using (var deriveBytes = new Rfc2898DeriveBytes(
                   password,
                   salt,
                   100_000,
                   HashAlgorithmName.SHA256)) // ✅ Explicit and modern
        {
            var key = deriveBytes.GetBytes(32); // AES-256 key
            var iv = deriveBytes.GetBytes(16);  // AES block size (128 bits)

            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var encryptor = aes.CreateEncryptor())
                {
                    var encryptedData = encryptor.TransformFinalBlock(input, 0, input.Length);

                    // ✅ Calculate padding length
                    paddingLength = encryptedData.Length - input.Length;

                    // ✅ Prepend salt to encrypted data
                    var result = new byte[salt.Length + encryptedData.Length];
                    Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
                    Buffer.BlockCopy(encryptedData, 0, result, salt.Length, encryptedData.Length);

                    return result;
                }
            }
        }
    }

    public static byte[] GenerateRandomBytes(int length)
    {
        var bytes = new byte[length];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(bytes);
        }

        return bytes;
    }

    public static byte[] ExtractAESPayload(byte[] encryptedData, int saltLength, int paddingLength)
    {
        // Calculate the core length by excluding salt and padding
        var coreLength = encryptedData.Length - saltLength - paddingLength;

        // Use LINQ to skip the salt and take the core length
        return encryptedData.Skip(saltLength).Take(coreLength).ToArray();
    }

    [Flags]
    public enum HeaderOptions
    {
        None = 0,
        Mode = 1 << 0,
        InputType = 1 << 1,
        MetricScoring = 1 << 2,
        GlobalRounds = 1 << 3,
        PassCount = 1 << 4,
        MaxSequenceLength = 1 << 5,
        Sequence = 1 << 6, // 🆕 Sequence info
        AggregateScore = 1 << 7, // 🆕 Aggregate cryptanalysis score
        Reversibility = 1 << 8, // 🆕 Reversibility check

        // 🆕 All standard execution-related options
        AllExecution = Mode | InputType | MetricScoring | GlobalRounds | PassCount | MaxSequenceLength,

        // 🆕 All cryptanalysis-related options
        AllAnalysis = Sequence | AggregateScore | Reversibility,

        // 🆕 Everything
        All = AllExecution | AllAnalysis
    }

    public static List<string> GenerateHeader(
        ExecutionEnvironment localEnv,
        string? title = null,
        string? name = null,
        HeaderOptions options = HeaderOptions.None,
        string? formattedSequence = null, // 🆕 Optional formatted sequence for cryptanalysis
        List<CryptoAnalysis.AnalysisResult>? analysisResults = null, // 🆕 Optional analysis results
        bool? isReversible = null, // 🆕 Nullable to indicate optional usage
        string? additionalInfo = null) // 🆕 New additional info parameter
    {
        // 🔹 Dynamically build the header title
        var headerTitle = string.IsNullOrWhiteSpace(name) ? $"{title}" : $"{name} {title}";
        // ✅ Remove redundant spaces to avoid empty headers while preserving spacing within words.
        var titleLine = $"===== {headerTitle} =====".Replace("  ", "");
        var separator = new string('=', titleLine.Length);

        // 🔹 Create a list to store formatted output
        var output = new List<string> { $"<Yellow>{titleLine}</Yellow>" };

        // 🆕 Add Sequence first
        if (options.HasFlag(HeaderOptions.Sequence))
            output.Add($"<Green>Sequence:</Green> {formattedSequence ?? "<Red><none specified></Red>"}");

        // ✅ Conditionally add requested elements
        if (options.HasFlag(HeaderOptions.Mode))
            output.Add($"<Gray>Mode:</Gray> <Green>{localEnv.Globals.Mode}</Green>");

        if (options.HasFlag(HeaderOptions.InputType))
            output.Add($"<Gray>InputType:</Gray> <Green>{localEnv.Globals.InputType}</Green>");

        if (options.HasFlag(HeaderOptions.MetricScoring))
            output.Add(
                $"<Gray>Metric Scoring:</Gray> <Green>{(localEnv.Globals.UseMetricScoring ? "Enabled" : "Disabled")}</Green>");

        if (options.HasFlag(HeaderOptions.GlobalRounds))
            output.Add($"<Gray>GR (Global Rounds):</Gray> <Green>{localEnv.Crypto.Options.Rounds}</Green>");

        if (options.HasFlag(HeaderOptions.MaxSequenceLength))
            output.Add($"<Gray>Max Sequence Length:</Gray> <Green>{localEnv.Globals.MaxSequenceLen}</Green>");

        // 🆕 Add CryptAnalysis-specific options
        if (analysisResults != null)
        {
            var aggregateScore =
                localEnv.CryptoAnalysis.CalculateAggregateScore(analysisResults, localEnv.Globals.UseMetricScoring);
            var passCount = analysisResults.Count(result => result.Passed);
            var totalMetrics = analysisResults.Count;
            var color = isReversible == true ? "Green" : "Red";

            if (options.HasFlag(HeaderOptions.AggregateScore))
                output.Add($"<Gray>Aggregate Score:</Gray> <Green>{aggregateScore:F4}</Green>");

            if (options.HasFlag(HeaderOptions.Reversibility))
                output.Add(
                    $"<Gray>Reversibility:</Gray> <{color}>[{(isReversible == true ? "PASS" : "FAIL")}]</{color}>");

            if (options.HasFlag(HeaderOptions.PassCount))
                output.Add(
                    $"<Gray>Pass Count:</Gray> <Green>{passCount} / {totalMetrics}</Green>"); // Pass count is always last
        }

        // 🆕 Append additional info before separator if provided
        if (!string.IsNullOrWhiteSpace(additionalInfo))
            output.Add($"<Cyan>{additionalInfo}</Cyan>");

        // 🔹 Closing separator if options were included
        if (options != HeaderOptions.None)
            output.Add($"<Yellow>{separator}</Yellow>");

        return output;
    }

    public static string Field(string text, int fieldLength)
    {
        if (text.Length < fieldLength)
            // Pad the text to the desired length and append a blank space
            return text.PadRight(fieldLength - 1) + " ";
        else if (text.Length == fieldLength)
            // If text fits exactly, just add a blank space at the end
            return text + " ";
        else
            // Truncate the text and append "..." followed by a blank space
            return text.Substring(0, fieldLength - 4) + "... ";
    }

    #region LogToSQL

    public static void FileToSQL(string logFilePath)
    {
        if (!File.Exists(logFilePath))
        {
            Console.WriteLine($"Error: Log file not found at {logFilePath}");
            return;
        }

        // Ensure a fresh start by deleting the database file if it exists
        const string databasePath = "temp.db";
        if (File.Exists(databasePath)) File.Delete(databasePath);

        using var connection = new SQLiteConnection($"Data Source={databasePath};Version=3;");
        connection.Open();

        // Create tables
        using (var command = new SQLiteCommand(connection))
        {
            command.CommandText = @"
            CREATE TABLE IF NOT EXISTS Contenders (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                Sequence TEXT,
                AggregateScore REAL,
                PassCount INTEGER
            );
            CREATE TABLE IF NOT EXISTS Metrics (
                ContenderId INTEGER,
                Name TEXT,
                Passed INTEGER,
                Value REAL,
                Threshold REAL,
                Notes TEXT,
                FOREIGN KEY (ContenderId) REFERENCES Contenders(Id)
            );";
            command.ExecuteNonQuery();
        }

        // Parse log file and insert data
        using (var transaction = connection.BeginTransaction())
        using (var contenderInsert = new SQLiteCommand(
                   "INSERT INTO Contenders (Sequence, AggregateScore, PassCount) VALUES (@Sequence, @AggregateScore, @PassCount);",
                   connection))
        using (var metricInsert = new SQLiteCommand(
                   "INSERT INTO Metrics (ContenderId, Name, Passed, Value, Threshold, Notes) VALUES (@ContenderId, @Name, @Passed, @Value, @Threshold, @Notes);",
                   connection))
        {
            contenderInsert.Parameters.Add(new SQLiteParameter("@Sequence"));
            contenderInsert.Parameters.Add(new SQLiteParameter("@AggregateScore"));
            contenderInsert.Parameters.Add(new SQLiteParameter("@PassCount"));

            metricInsert.Parameters.Add(new SQLiteParameter("@ContenderId"));
            metricInsert.Parameters.Add(new SQLiteParameter("@Name"));
            metricInsert.Parameters.Add(new SQLiteParameter("@Passed"));
            metricInsert.Parameters.Add(new SQLiteParameter("@Value"));
            metricInsert.Parameters.Add(new SQLiteParameter("@Threshold"));
            metricInsert.Parameters.Add(new SQLiteParameter("@Notes"));

            // Parse log file
            var lines = File.ReadAllLines(logFilePath);
            Contender currentContender = null!;

            foreach (var line in lines)
            {
                if (line.StartsWith("Contender #"))
                {
                    // Insert the previous contender if any
                    if (currentContender != null)
                        InsertContenderAndMetrics(currentContender, contenderInsert, metricInsert);

                    // Create new contender
                    currentContender = new Contender();
                }
                else if (currentContender != null)
                {
                    if (line.StartsWith("Sequence:"))
                    {
                        currentContender.Sequence = line.Substring("Sequence:".Length).Trim();
                    }
                    else if (line.StartsWith("Aggregate Score:"))
                    {
                        currentContender.AggregateScore = double.Parse(line.Split(':')[1].Trim());
                    }
                    else if (line.StartsWith("Pass Count:"))
                    {
                        currentContender.PassCount = int.Parse(line.Split(':')[1].Trim().Split('/')[0]);
                    }
                    else if (line.StartsWith("- "))
                    {
                        // Parse metrics
                        currentContender.Metrics.Add(ParseMetric(line));
                    }
                    else if (line.StartsWith("  Metric:") && currentContender.Metrics.Count > 0)
                    {
                        var metric = currentContender.Metrics.Last(); // Get the last added metric
                        var parts = line.Split(',', StringSplitOptions.RemoveEmptyEntries);
                        metric.Value = double.Parse(parts[0].Split(':')[1].Trim());
                        metric.Threshold = double.Parse(parts[1].Split(':')[1].Trim());
                    }
                    else if (line.StartsWith("  Notes:") && currentContender.Metrics.Count > 0)
                    {
                        var metric = currentContender.Metrics.Last(); // Get the last added metric
                        metric.Notes = line.Split(':', 2)[1].Trim();
                    }
                }
            }

            // Insert the last contender (ensuring all metrics are processed)
            if (currentContender != null && currentContender.Metrics.Count > 0)
            {
                InsertContenderAndMetrics(currentContender, contenderInsert, metricInsert);
            }

            transaction.Commit();
        }
    }

    public static void LogToSQL(ExecutionEnvironment localEnv)
    {
        // Ensure a fresh start by deleting the database file if it exists
        const string databasePath = "temp.db";
        if (File.Exists(databasePath)) File.Delete(databasePath);

        using var connection = new SQLiteConnection($"Data Source={databasePath};Version=3;");
        connection.Open();

        // Create tables
        using (var command = new SQLiteCommand(connection))
        {
            command.CommandText = @"
    CREATE TABLE IF NOT EXISTS Contenders (
        Id INTEGER PRIMARY KEY AUTOINCREMENT,
        Sequence TEXT,
        AggregateScore REAL,
        PassCount INTEGER
    );
    CREATE TABLE IF NOT EXISTS Metrics (
        ContenderId INTEGER,
        Name TEXT,
        Passed INTEGER,
        Value REAL,
        Threshold REAL,
        Notes TEXT,
        FOREIGN KEY (ContenderId) REFERENCES Contenders(Id)
    );";
            command.ExecuteNonQuery();
        }

        // Insert data from the contenders list
        using (var transaction = connection.BeginTransaction())
        using (var contenderInsert = new SQLiteCommand(
                   "INSERT INTO Contenders (Sequence, AggregateScore, PassCount) VALUES (@Sequence, @AggregateScore, @PassCount);",
                   connection))
        using (var metricInsert = new SQLiteCommand(
                   "INSERT INTO Metrics (ContenderId, Name, Passed, Value, Threshold, Notes) VALUES (@ContenderId, @Name, @Passed, @Value, @Threshold, @Notes);",
                   connection))
        {
            contenderInsert.Parameters.Add(new SQLiteParameter("@Sequence"));
            contenderInsert.Parameters.Add(new SQLiteParameter("@AggregateScore"));
            contenderInsert.Parameters.Add(new SQLiteParameter("@PassCount"));

            metricInsert.Parameters.Add(new SQLiteParameter("@ContenderId"));
            metricInsert.Parameters.Add(new SQLiteParameter("@Name"));
            metricInsert.Parameters.Add(new SQLiteParameter("@Passed"));
            metricInsert.Parameters.Add(new SQLiteParameter("@Value"));
            metricInsert.Parameters.Add(new SQLiteParameter("@Threshold"));
            metricInsert.Parameters.Add(new SQLiteParameter("@Notes"));

            var contenderId = 0;

            foreach (var (sequence, aggregateScore, metrics) in localEnv.CryptoAnalysis.Contenders)
            {
                // Insert the contender
                contenderInsert.Parameters["@Sequence"].Value = string.Join(" -> ", sequence);
                contenderInsert.Parameters["@AggregateScore"].Value = aggregateScore;
                contenderInsert.Parameters["@PassCount"].Value = metrics.Count(m => m.Passed);
                contenderInsert.ExecuteNonQuery();

                contenderId = (int)connection.LastInsertRowId;

                // Insert metrics
                foreach (var metric in metrics)
                {
                    // Retrieve the threshold from the MetricsRegistry
                    var threshold = 0.0;
                    if (localEnv.CryptoAnalysis.MetricsRegistry.TryGetValue(metric.Name, out var metricInfo))
                        threshold = metricInfo.Threshold; // Use the centralized threshold logic

                    metricInsert.Parameters["@ContenderId"].Value = contenderId;
                    metricInsert.Parameters["@Name"].Value = metric.Name; // Use TestName for the Name field
                    metricInsert.Parameters["@Passed"].Value = metric.Passed ? 1 : 0; // Use Passed for Passed field
                    metricInsert.Parameters["@Value"].Value = metric.Score; // Use Metric for Value field
                    metricInsert.Parameters["@Threshold"].Value = threshold; // Use the correct threshold
                    metricInsert.Parameters["@Notes"].Value = metric.Notes ?? "None"; // Use Notes, fallback to "None"
                    metricInsert.ExecuteNonQuery();
                }
            }

            transaction.Commit();
        }

        Console.WriteLine($"Data successfully written to {databasePath}");
    }

    private static void InsertContenderAndMetrics(Contender contender, SQLiteCommand contenderInsert,
        SQLiteCommand metricInsert)
    {
        // Insert Contender
        contenderInsert.Parameters["@Sequence"].Value = contender.Sequence;
        contenderInsert.Parameters["@AggregateScore"].Value = contender.AggregateScore;
        contenderInsert.Parameters["@PassCount"].Value = contender.PassCount;
        contenderInsert.ExecuteNonQuery();

        var contenderId = contenderInsert.Connection.LastInsertRowId;

        // Insert Metrics
        foreach (var metric in contender.Metrics)
        {
            metricInsert.Parameters["@ContenderId"].Value = contenderId;
            metricInsert.Parameters["@Name"].Value = metric.Name;
            metricInsert.Parameters["@Passed"].Value = metric.Passed ? 1 : 0;
            metricInsert.Parameters["@Value"].Value = metric.Value;
            metricInsert.Parameters["@Threshold"].Value = metric.Threshold;
            metricInsert.Parameters["@Notes"].Value = metric.Notes ?? string.Empty;
            metricInsert.ExecuteNonQuery();
        }
    }

    private static Metric ParseMetric(string line)
    {
        var metric = new Metric();
        var statusLineMatch = Regex.Match(line, @"-\s*(\w+):\s*(PASS|FAIL)");
        var detailsLineMatch = Regex.Match(line, @"Metric:\s*([\d.-]+),\s*Threshold:\s*([\d.-]+)");
        var notesLineMatch = Regex.Match(line, @"Notes:\s*(.+)");

        if (statusLineMatch.Success)
        {
            metric.Name = statusLineMatch.Groups[1].Value;
            metric.Passed = statusLineMatch.Groups[2].Value == "PASS";
        }

        if (detailsLineMatch.Success)
        {
            metric.Value = double.Parse(detailsLineMatch.Groups[1].Value);
            metric.Threshold = double.Parse(detailsLineMatch.Groups[2].Value);
        }

        if (notesLineMatch.Success) metric.Notes = notesLineMatch.Groups[1].Value;

        return metric;
    }

    #endregion LogToSQL

    // Levenshtein Distance Algorithm (unchanged)
    public static int LevenshteinDistance(string s, string t)
    {
        var dp = new int[s.Length + 1, t.Length + 1];

        for (var i = 0; i <= s.Length; i++) dp[i, 0] = i;
        for (var j = 0; j <= t.Length; j++) dp[0, j] = j;

        for (var i = 1; i <= s.Length; i++)
            for (var j = 1; j <= t.Length; j++)
            {
                var cost = s[i - 1] == t[j - 1] ? 0 : 1;
                dp[i, j] = Math.Min(
                    Math.Min(dp[i - 1, j] + 1, dp[i, j - 1] + 1),
                    dp[i - 1, j - 1] + cost
                );
            }

        return dp[s.Length, t.Length];
    }

    // Multi-Word Distance Algorithm (unchanged)
    public static int MultiWordDistance(string input, string command)
    {
        var inputTokens = input.Split(' ');
        var commandTokens = command.Split(' ');

        var totalDistance = 0;
        var maxLength = Math.Max(inputTokens.Length, commandTokens.Length);

        for (var i = 0; i < maxLength; i++)
        {
            var inputToken = i < inputTokens.Length ? inputTokens[i] : "";
            var commandToken = i < commandTokens.Length ? commandTokens[i] : "";

            totalDistance += LevenshteinDistance(inputToken, commandToken);
        }

        return totalDistance;
    }

    public static DebugFlags DebugLevel { get; set; } = DebugFlags.StatusMessage | DebugFlags.ReversibleSequence;

    public static void LogIfEnabled(ExecutionEnvironment localEnv, DebugFlags flag, string message,
        int sequenceLength = 0)
    {
        if ((DebugLevel & flag) != 0)
        {
            ColorConsole.WriteLine(message);

            if (localEnv.Globals.LogMungeOutput)
            {
                var filename = GetContenderFilename(localEnv, sequenceLength, "log");
                var cleanMessage = ColorConsole.RemoveColorTags(message);
                File.AppendAllText(filename, cleanMessage + Environment.NewLine);
            }
        }
    }

    public static byte[] GenerateReverseSequence(CryptoLib? cryptoLib, byte[] forwardSequence)
    {
        //Console.WriteLine("=== Generating Reverse Sequence ===");

        var reverseSequence = forwardSequence
            .Select(transformByte => GetInverseTransformByte(cryptoLib, transformByte)) // Map to inverse
            .Reverse() // Reverse the order
            .ToArray(); // Convert back to a byte array

        //Console.WriteLine($"Final Reverse Sequence: [{string.Join(", ", reverseSequence)}]");
        //Console.WriteLine("===================================");

        return reverseSequence;
    }

    // Helper: Map a transform byte to its inverse byte
    private static byte GetInverseTransformByte(CryptoLib? cryptoLib, byte transformByte)
    {
        if (!cryptoLib!.TransformRegistry.TryGetValue(transformByte, out var originalTransform))
            throw new InvalidOperationException($"❌ Transformation not found: {transformByte}");

        //Console.WriteLine($"🔍 Mapping Transform {originalTransform.Name} (ID: {originalTransform.Id}) → Inverse ID: {originalTransform.InverseId}");

        if (!cryptoLib!.TransformRegistry.TryGetValue(originalTransform.InverseId, out var inverseTransform))
            throw new InvalidOperationException(
                $"❌ No inverse transformation found for: {originalTransform.Name} (ID: {originalTransform.Id})");

        //Console.WriteLine($"✅ Found Inverse: {inverseTransform.Name} (ID: {inverseTransform.Id})");

        return (byte)inverseTransform.Id;
    }

    #region Permutations

    /// ✅ Lazily generates all possible sequences of the given length
    /// - Uses `yield return` for **on-demand generation** instead of materializing all results upfront.
    /// - Allows duplicate transforms in different positions (important for full search space exploration).
    /// - **Memory-efficient**: Avoids storing all permutations in a list (`O(n!)` space reduction to `O(n)`).
    /// - This is the approach used in Munge(A), ensuring the same permutation logic.
    /// - Generates a large number of sequences, significantly increasing runtime but **maximizing discovery potential**.
    /// - **Optimized**: Eliminates unnecessary `Concat()` allocations for better performance.
    public static IEnumerable<byte[]> GeneratePermutations(List<byte> transformIds, int length)
    {
        IEnumerable<byte[]> Generate(byte[] sequence)
        {
            if (sequence.Length == length)
            {
                yield return sequence; // ✅ Yielding instead of storing
                yield break;
            }

            foreach (var transformId in transformIds)
            {
                var newSequence = new byte[sequence.Length + 1]; // ✅ Avoids repeated allocations via Concat()
                sequence.CopyTo(newSequence, 0);
                newSequence[^1] = transformId; // ✅ More efficient than `Concat()`

                foreach (var result in Generate(newSequence)) yield return result; // ✅ Lazily yields next permutation
            }
        }

        return Generate(Array.Empty<byte>());
    }

    /// <summary>
    /// Generates all unique permutations of the given items, preserving element frequency.
    /// - Ensures that the output includes only valid permutations based on input occurrences.
    /// - If an element appears N times in the input, it will appear exactly N times in each generated permutation.
    /// - Uses recursive backtracking to efficiently generate permutations without duplicate sequences.
    /// </summary>
    /// <typeparam name="T">The type of elements in the input collection.</typeparam>
    /// <param name="items">The collection of items to generate permutations from.</param>
    /// <returns>An IEnumerable of arrays, each representing a unique permutation.</returns>
#if true
    public static IEnumerable<T[]> GenerateUniquePermutations<T>(IEnumerable<T> items)
        where T : notnull
    {
        var itemList = items.ToList();
        var itemCounts = itemList
            .GroupBy(x => x) // Group items by their value
            .ToDictionary(g => g.Key, g => g.Count()); // Create a dictionary of item counts

        return Permute(new List<T>(), itemList.Count, itemCounts);

        static IEnumerable<T[]> Permute(List<T> current, int remaining, Dictionary<T, int> itemCounts)
        {
            if (remaining == 0)
            {
                yield return current.ToArray();
                yield break;
            }

            foreach (var kvp in itemCounts.Where(kvp => kvp.Value > 0))
            {
                current.Add(kvp.Key);
                itemCounts[kvp.Key]--;

                foreach (var perm in Permute(current, remaining - 1, itemCounts))
                    yield return perm;

                current.RemoveAt(current.Count - 1);
                itemCounts[kvp.Key]++;
            }
        }
    }

#else
    public static IEnumerable<T[]> GenerateUniquePermutations<T>(IEnumerable<T> items)
    {
        var itemList = items.ToList();
        var itemCounts = itemList
            .GroupBy(x => x) // Group items by their value
            .ToDictionary(g => g.Key, g => g.Count()); // Create a dictionary of item counts

        return Permute(new List<T>(), itemList.Count, itemCounts);

        static IEnumerable<T[]> Permute<T>(List<T> current, int remaining, Dictionary<T, int> itemCounts)
        {
            if (remaining == 0)
            {
                yield return current.ToArray();
                yield break;
            }

            foreach (var kvp in itemCounts.Where(kvp => kvp.Value > 0))
            {
                current.Add(kvp.Key);
                itemCounts[kvp.Key]--;

                foreach (var perm in Permute(current, remaining - 1, itemCounts))
                    yield return perm;

                current.RemoveAt(current.Count - 1);
                itemCounts[kvp.Key]++;
            }
        }
    }
#endif
    /// <summary>
    /// Provides static methods for generating and counting sequences by combining meta sequences (byte arrays) with transform sequences (lists of bytes).
    /// This class offers functionality to create permutations where transforms are appended or prepended to meta sequences,
    /// with the ability to specify the number of transforms added.
    /// </summary>
    public static class SequenceGenerator
    {
        public static IEnumerable<byte[]> GenerateMetaSequenceTransformPairs(List<byte[]> metaSequences,
            List<byte> transforms, int transformsToAdd)
        {
            foreach (var metaSequence in metaSequences)
                foreach (var transformCombination in GenerateCombinations(transforms, transformsToAdd))
                {
                    // Append transform combination
                    yield return metaSequence.Concat(transformCombination).ToArray();

                    // Prepend transform combination
                    yield return transformCombination.Concat(metaSequence).ToArray();
                }
        }

        private static IEnumerable<List<byte>> GenerateCombinations(List<byte> transforms, int length)
        {
            if (length == 0)
            {
                yield return new List<byte>();
                yield break;
            }

            foreach (var transform in transforms)
                foreach (var combination in GenerateCombinations(transforms, length - 1))
                    yield return new List<byte> { transform }.Concat(combination).ToList();
        }

        public static int CountMetaPermutations(List<byte[]> metaSequences, List<byte> transforms, int transformsToAdd)
        {
            var combinations = (int)Math.Pow(transforms.Count, transformsToAdd);
            return metaSequences.Count * combinations * 2;
        }
    }

    /// <summary>
    /// Generates sequences of items from a given set, with a specified length and a maximum repetition count for each distinct item.
    /// Uses lazy evaluation (yield return) for memory efficiency.
    /// </summary>
    /// <typeparam name="T">The type of items in the input sequence and generated sequences.</typeparam>
    /// <param name="items">The set of distinct items to choose from.  Duplicates in this list are treated as distinct *types*.</param>
    /// <param name="length">The exact length of the sequences to generate.</param>
    /// <param name="repetitions">The maximum number of times any single item can appear in a generated sequence.</param>
    /// <returns>An IEnumerable of T[] representing the generated sequences.  Each sequence is a `T[]`.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown if `repetitions` is less than 1 or `length` is negative.</exception>
    /// <example>
    /// <code>
    /// List<byte> items = new List<byte>() { 1, 2, 3 };
    ///
    /// // Permutations of length 2, with each item appearing at most once.
    /// foreach (var seq in GenerateLimitedRepetitionSequences(items, 2, 1))
    /// {
    ///     Console.WriteLine(string.Join(", ", seq)); // Output: 1, 2 then 1, 3 then 2, 1 ... etc
    /// }
    ///
    /// // Permutations of length 3, with each item appearing at most twice.
    /// foreach (var seq in GenerateLimitedRepetitionSequences(items, 3, 2))
    /// {
    ///  Console.WriteLine(string.Join(", ", seq)); // Output: 1, 1, 2 then 1, 1, 3 then 1, 2, 1 ... etc
    /// }
    ///
    /// // Permutations of length 4 with two items and two repetitions
    /// List<string> items2 = new List<string>() { "A", "B" };
    /// foreach (var seq in GenerateLimitedRepetitionSequences(items2, 4, 2)) {
    /// 	Console.WriteLine(string.Join(", ", seq)); //Output: A, A, B, B then A, B, A, B, then ...
    /// }
    ///
    /// // Permutations of length 3 with two items, and one repetition (no output)
    /// List<string> items2 = new List<string>() { "A", "B" };
    /// foreach (var seq in GenerateLimitedRepetitionSequences(items2, 3, 1)) {
    /// 	Console.WriteLine(string.Join(", ", seq)); //Output: nothing
    /// }
    /// </code>
    /// </example>
#if true
    public static IEnumerable<T[]> GenerateLimitedRepetitionSequences<T>(IEnumerable<T> items, int length, int repetitions = 1)
        where T : notnull
    {
        if (repetitions < 1)
            throw new ArgumentOutOfRangeException(nameof(repetitions), "Repetitions must be at least 1.");
        if (length < 0)
            throw new ArgumentOutOfRangeException(nameof(length), "Length cannot be negative.");

        var distinctItems = items.Distinct().ToList(); // Get distinct items

        // Use a dictionary to track the allowed repetitions per item
        var itemCounts = distinctItems.ToDictionary(item => item, item => repetitions);

        return PermuteInternal(new List<T>(), length, itemCounts);

        IEnumerable<T[]> PermuteInternal(List<T> current, int remaining, Dictionary<T, int> itemCounts)
        {
            if (current.Count == length)
            {
                yield return current.ToArray();
                yield break;
            }

            foreach (var kvp in itemCounts.Where(kvp => kvp.Value > 0))
            {
                current.Add(kvp.Key);
                itemCounts[kvp.Key]--;

                foreach (var perm in PermuteInternal(current, remaining - 1, itemCounts))
                    yield return perm;

                current.RemoveAt(current.Count - 1);
                itemCounts[kvp.Key]++;
            }
        }
    }

#else
    public static IEnumerable<T[]> GenerateLimitedRepetitionSequences<T>(IEnumerable<T> items, int length, int repetitions = 1)
    {
        if (repetitions < 1)
            throw new ArgumentOutOfRangeException(nameof(repetitions), "Repetitions must be at least 1.");
        if (length < 0) throw new ArgumentOutOfRangeException(nameof(length), "Length cannot be negative.");

        var distinctItems = items.Distinct().ToList(); // Get distinct items.

        // Use a dictionary to track the allowed repetitions *per item*.
        var itemCounts = distinctItems.ToDictionary(item => item, item => repetitions);

        return PermuteInternal(new List<T>(), length, itemCounts);

        IEnumerable<T[]> PermuteInternal<T>(List<T> current, int remaining, Dictionary<T, int> itemCounts)
        {
            if (current.Count == length) // Use current.Count for exact length
            {
                yield return current.ToArray();
                yield break;
            }

            foreach (var kvp in itemCounts.Where(kvp => kvp.Value > 0))
            {
                current.Add(kvp.Key);
                itemCounts[kvp.Key]--;

                foreach (var perm in PermuteInternal(current, remaining - 1, itemCounts)) // Decrement remaining
                    yield return perm;

                current.RemoveAt(current.Count - 1);
                itemCounts[kvp.Key]++; // Restore the count for backtracking.
            }
        }
    }
#endif
    public static class PermutationCounter
    {
        public static long CountLimitedRepetitionSequences<T>(IEnumerable<T> items, int length, int repetitions = 1)
        {
            if (repetitions < 1)
                throw new ArgumentOutOfRangeException(nameof(repetitions), "Repetitions must be at least 1.");

            if (length < 0) throw new ArgumentOutOfRangeException(nameof(length), "Length cannot be negative.");

            var distinctItems = items.Distinct().ToList();
            var numDistinctItems = distinctItems.Count;

            // If length is 0, there's always one permutation (the empty sequence).
            if (length == 0) return 1;

            // If the length is greater than the maximum possible (numDistinctItems * repetitions),
            // there are no valid permutations.
            if (length > numDistinctItems * repetitions) return 0;

            // We can't use a simple formula like n^r or n!/(n-r)! because of the
            // repetition limit AND the length constraint. We need a recursive approach
            // similar to the generation, but just counting, not storing the permutations.

            return CountPermutationsRecursive(numDistinctItems, length, repetitions);
        }

        private static long CountPermutationsRecursive(int numDistinctItems, int remainingLength, int repetitions)
        {
            if (remainingLength == 0) return 1; // Base case: Empty sequence.

            long count = 0;
            // Iterate through all possible items we can choose (we have numDistinctItems options).
            for (var i = 0; i < numDistinctItems; i++)
                //Consider adding 1 element of 'i', and recursively call
                //Calculate number of permutations if this item is choosen up to 'repetition' times
                for (var rep = 1; rep <= repetitions; rep++)
                    if (remainingLength - rep >= 0)
                        //If we add 'rep' instances of this element, there will be 'remainingLength - rep'
                        //positions left.
                        // How many ways can we place those elements?
                        // We need to pick 'rep' positions from 'remainingLength', which is a combinations problem.
                        // We also need to multiply by the number of permutations for the remainingLength
                        // and for each *other* item, up to 'repititions'
                        count += Combinations(remainingLength, rep) *
                                 CountPermutationsRecursive(numDistinctItems - 1, remainingLength - rep,
                                     repetitions);

            return count;
        }

        // Helper function to calculate combinations (nCr)
        private static long Combinations(int n, int r)
        {
            if (r < 0 || r > n) return 0;

            if (r == 0 || r == n) return 1;

            if (r == 1 || r == n - 1) return n;

            // Optimize by choosing the smaller of r and n-r
            if (r > n / 2) r = n - r;

            // Calculate nCr iteratively
            long result = 1;
            for (var i = 1; i <= r; i++) result = result * (n - i + 1) / i;

            return result;
        }
    }

    public record SequenceRoundConfig(List<byte> Sequence, List<byte> RoundConfig);

    public static IEnumerable<SequenceRoundConfig> GenerateSequencesAndRoundConfigs(List<byte> userSequence,
        int sequenceLength, int repetitions)
    {
        var permutations = GenerateLimitedRepetitionSequences(userSequence, sequenceLength, repetitions);
        foreach (var permutation in permutations)
            foreach (var roundConfig in GenerateRoundCombinations(permutation.Count()))
                yield return new SequenceRoundConfig(permutation.ToList(), roundConfig);
    }

    private const int MaxRounds = 9; // 🔥 Easily adjustable for future experiments

    public static IEnumerable<List<byte>> GenerateRoundCombinations(int sequenceLength)
    {
        for (var i = 0; i < Math.Pow(MaxRounds, sequenceLength); i++) // Uses MaxRounds
        {
            List<byte> roundConfig = new();
            var value = i;

            for (var j = 0; j < sequenceLength; j++)
            {
                roundConfig.Add((byte)(value % MaxRounds + 1)); // Generates 1–MaxRounds rounds for each transform
                value /= MaxRounds;
            }

            yield return roundConfig;
        }
    }

    #endregion Permutations

    /// <summary>
    /// Tests a sequence by applying forward and reverse transformations, 
    /// verifying reversibility, and performing cryptanalysis.
    /// </summary>
    /// <param name="cryptoLib">The cryptographic library instance.</param>
    /// <param name="input">The original input data.</param>
    /// <param name="sequence">The sequence of transforms to test.</param>
    /// <returns>A list of analysis results if successful; null if reversibility fails.</returns>
    public static List<CryptoAnalysis.AnalysisResult>? TestSequence(ExecutionEnvironment localEnv, byte[] sequence)
    {
        try
        {
            // Apply forward transformations
            var encrypted = localEnv.Crypto.Encrypt(sequence, localEnv.Globals.Input);

            // Generate reverse sequence
            var reverseSequence = GenerateReverseSequence(localEnv.Crypto, sequence);

            // Apply reverse transformations
            var decrypted = localEnv.Crypto.Decrypt(reverseSequence, encrypted);

            // Check reversibility
            if (!decrypted!.SequenceEqual(localEnv.Globals.Input))
            {
                Console.WriteLine("Reversibility check failed for the provided sequence.");
                return null; // Reversibility failed
            }

            // Extract payload for analysis
            var payload = localEnv.Crypto.GetPayloadOnly(encrypted);

            // Modify a copy of input for Avalanche test and Key Dependency test
            var (MangoAvalanchePayload, _, MangoKeyDependencyPayload, _) =
                ProcessAvalancheAndKeyDependency(
                    localEnv,
                    GlobalsInstance.Password,
                    sequence!.ToList());

            // Run cryptanalysis
            return localEnv.CryptoAnalysis.RunCryptAnalysis(
                payload,
                MangoAvalanchePayload,
                MangoKeyDependencyPayload,
                localEnv.Globals.Input);
        }
        catch (Exception ex)
        {
            // Log or handle unexpected errors during the test
            Console.WriteLine(
                $"Error during sequence testing: {ex.Message}\nSequence: {Convert.ToHexString(sequence!)}");
            return null;
        }
    }

    public static void PressAnyKey(string? explanation = null)
    {
        if (!string.IsNullOrEmpty(explanation))
            ColorConsole.WriteLine($"<yellow>\n{explanation}</yellow>");
        else
            ColorConsole.WriteLine();

        ColorConsole.WriteLine("<gray>Press any key to continue...</gray>");
        Console.ReadKey(true);
    }

    public static bool AskYN(string question)
    {
        if (string.IsNullOrEmpty(question))
            question = "Proceed?";

        ColorConsole.Write($"\n<yellow>{question} (Y/N): </yellow>");
        var response = Console.ReadLine()?.Trim().ToUpperInvariant();
        return response == "Y";
    }

    public static string ReadConsoleBlock(int timeoutMilliseconds = 150, bool trimBlankLines = true)
    {
        List<string> lines = new();
        var lastLineTime = DateTime.UtcNow;

        while (true)
        {
            var line = Console.ReadLine();
            if (line == null)
                break;

            lines.Add(line.Trim());
            lastLineTime = DateTime.UtcNow;

            if (!WaitForNextLine(timeoutMilliseconds))
                break;
        }

        if (trimBlankLines)
            lines = lines.Where(line => !string.IsNullOrWhiteSpace(line)).ToList();

        return string.Join(" ", lines); // ✅ Concatenate with spaces
    }

    private static bool WaitForNextLine(int timeoutMs)
    {
        var waited = 0;
        const int interval = 10;

        while (waited < timeoutMs)
        {
            if (Console.KeyAvailable)
                return true;

            Thread.Sleep(interval);
            waited += interval;
        }

        return false;
    }

    public static InputType GetInputTypeFromFilename(string fileName)
    {
        return fileName.Contains("DC") ? InputType.Combined
            : fileName.Contains("DR") ? InputType.Random
            : fileName.Contains("DN") ? InputType.Natural
            : fileName.Contains("DS") ? InputType.Sequence
            : throw new InvalidOperationException($"Unrecognized InputType in filename: {fileName}");
    }

    public static InputType GetInputTypeFromByte(byte @byte)
    {
        var upper = (byte)char.ToUpper((char)@byte);
        return upper == 'C' ? InputType.Combined
            : upper == 'R' ? InputType.Random
            : upper == 'N' ? InputType.Natural
            : upper == 'S' ? InputType.Sequence
            : throw new InvalidOperationException($"Unrecognized InputType: {upper}");
    }

    public static bool AreEqualWithF10Formatting(double a, double b)
    {
        // This method compares two doubles for equality by formatting them as strings with 10 decimal places.
        // It relies on the assumption that both 'a' and 'b' have been, or will be, consistently formatted 
        // using the "F10" format specifier. This ensures that any differences beyond the 10th decimal place 
        // are either rounded or truncated in the same way, allowing for a direct string comparison.
        // This approach is specific to this known formatting scenario and should not be used for general-purpose 
        // floating-point comparisons where consistent formatting is not guaranteed.
        var formattedA = a.ToString("F10");
        var formattedB = b.ToString("F10");
        return formattedA == formattedB;
    }

    public static void BenchmarkAllTransforms(ExecutionEnvironment localEnv)
    {
        var results = new List<string>();
        var jsonResults = new List<object>();
        var totalTime = 0.0;

        using (var localStatEnvironment = new LocalEnvironment(localEnv))
        {
            localEnv.Globals.UpdateSetting("InputType", InputType.Random);
            localEnv.Globals.UpdateSetting("Rounds", byte.MaxValue.ToString());
            var sampleInput = localEnv.Globals.Input;

            foreach (var kvp in localEnv.Crypto.TransformRegistry)
            {
                var transformId = kvp.Key;
                var transform = kvp.Value;

                var singleTransform = new byte[] { (byte)transformId };
                var reverseTransform = new byte[] { (byte)transform.InverseId };

                // Encrypt timing
                var sw = Stopwatch.StartNew();
                var encrypted = localEnv.Crypto.Encrypt(singleTransform, sampleInput);
                sw.Stop();
                var encryptTime = sw.Elapsed.TotalMilliseconds / localEnv.Globals.Rounds;

                // Decrypt timing
                sw.Restart();
                var decrypted = localEnv.Crypto.Decrypt(reverseTransform, encrypted);
                sw.Stop();
                var decryptTime = sw.Elapsed.TotalMilliseconds / localEnv.Globals.Rounds;

                var timePerOp = (encryptTime + decryptTime) / 2;
                totalTime += timePerOp;

                var result =
                    $"Transform: {transform.Name} (ID: {transformId}) | Avg time per op: {timePerOp:F4} ms";
                results.Add(result);
                Console.WriteLine(result);

                jsonResults.Add(new { Name = transform.Name, ID = transformId, TimePerOpMs = timePerOp });
            }
        }

        var totalSummary = $"Total Benchmark Time Across All Transforms: {totalTime:F4} ms";
        results.Add("");
        results.Add(totalSummary);
        Console.WriteLine();
        Console.WriteLine(totalSummary);

        // Write to TXT
        var txtPath = "TransformBenchmarkResults.txt";
        try
        {
            File.WriteAllLines(txtPath, results);
            Console.WriteLine($"Benchmark results have been written to {txtPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred while writing to the file: {ex.Message}");
        }

        // Write to JSON
        var jsonPath = "TransformBenchmarkResults.json";
        try
        {
            var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
            File.WriteAllText(jsonPath, JsonSerializer.Serialize(jsonResults, jsonOptions));
            Console.WriteLine($"Benchmark results have been written to {jsonPath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"An error occurred while writing JSON: {ex.Message}");
        }
    }

    public static void SetBenchmarkBaselineTime(ExecutionEnvironment localEnv)
    {
        if (localEnv.Crypto.TransformRegistry.TryGetValue(35, out var transform))
            localEnv.Globals.BenchmarkBaselineTime = transform.BenchmarkTimeMs;
        else
            throw new InvalidOperationException("Transform ID 35 not found in TransformRegistry.");
    }

    public static void EstablishCurrentBenchmarkTime(ExecutionEnvironment localEnv)
    {
        const int benchmarkTransformId = 35; // MaskedCascadeSubFwdFbTx
        var finalTimePerOp = 0.0;

        using (var localStatEnvironment = new LocalEnvironment(localEnv))
        {
            localEnv.Globals.UpdateSetting("InputType", InputType.Random);
            localEnv.Globals.UpdateSetting("Rounds", byte.MaxValue.ToString());
            var sampleInput = localEnv.Globals.Input;

            var singleTransform = new byte[] { (byte)benchmarkTransformId };
            var transform = localEnv.Crypto.TransformRegistry[benchmarkTransformId];
            var reverseTransform = new byte[] { (byte)transform.InverseId };

            // Encrypt timing
            var sw = Stopwatch.StartNew();
            var encrypted = localEnv.Crypto.Encrypt(singleTransform, sampleInput);
            sw.Stop();
            var encryptTime = sw.Elapsed.TotalMilliseconds / localEnv.Globals.Rounds; // Divide by rounds

            // Decrypt timing
            sw.Restart();
            var decrypted = localEnv.Crypto.Decrypt(reverseTransform, encrypted);
            sw.Stop();
            var decryptTime = sw.Elapsed.TotalMilliseconds / localEnv.Globals.Rounds; // Divide by rounds

            finalTimePerOp = (encryptTime + decryptTime) / 2;

            localEnv.Globals.CurrentBenchmarkTime = finalTimePerOp;

            // Optional validation
            // Debug.Assert(decrypted.SequenceEqual(sampleInput));

            // Console.WriteLine($"[Benchmark] ID: {benchmarkTransformId} | Encrypt: {encryptTime:F4} ms | Decrypt: {decryptTime:F4} ms | Avg: {finalTimePerOp:F4} ms");
        }
    }
}