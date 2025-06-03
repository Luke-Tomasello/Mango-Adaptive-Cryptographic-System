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

using Mango.Adaptive;
using Mango.Analysis;
using Mango.AnalysisCore;
using Mango.Cipher;
using Mango.Reporting;
using Mango.Workbench;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Data.SQLite;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Mango.Common;
using static Mango.AnalysisCore.CryptoAnalysisCore;
using static Mango.Utilities.SequenceHelper;
using static Mango.Utilities.TestInputGenerator;
using Contender = Mango.Analysis.Contender;
using Metric = Mango.AnalysisCore.Metric;
using static Mango.Common.Scoring;

namespace Mango.Utilities;

public partial class CutListHelper
{
    private static Dictionary<string, Dictionary<int, byte[]>> _cutMatrixCache = new();
    private string _key = null!;
    private int _activeDataIndex;
    private const int NumDataTypes = 5; // DC, DN, DR, DS, DU

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
                    _cutMatrixCache[_key][id] = Enumerable.Repeat((byte)1, NumDataTypes).ToArray(); // everything is VALID (uncut)
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

        var searchPattern = "Contenders,-L?-P?-D?-MC-SP.txt";
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
        if (fileNameParts.Length < 4)
            throw new ArgumentException($"Invalid filename format: {fileName}");

        var dataType = fileNameParts[3];
        return GetDataIndex(dataType); // ✅ Reuse centralized mapping logic
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
                    _cutMatrixCache[key][id] = new byte[NumDataTypes];  // default "cut"
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
                var dataIndex = GetDataIndex(dataType);
                var usedInTop10 = transformsInTopSequences.Contains(id);

                // 🧠 Ensure the cut matrix includes every known transform ID.
                // This is important for newly added transforms that didn’t exist
                // when the cutlist JSON was originally created and loaded.
                //
                // If a transform ID is missing from the matrix for this key,
                // we add a default row (cut = true for all data types) so we
                // can update it incrementally without overwriting existing data.
                //
                // ❗ This preserves accumulated results and prevents crashes due to missing keys.
                if (!_cutMatrixCache[key].ContainsKey(id))
                {
                    _cutMatrixCache[key][id] = new byte[NumDataTypes]; // Default: cut from all data types
                }

                // 🧬 Mark whether this transform appeared in the top 10 contenders
                // for this specific data type in this specific cut matrix key.
                _cutMatrixCache[key][id][dataIndex] = usedInTop10 ? (byte)0x01 : (byte)0x00;
            }

            messages.Add($"✅ Processed {transformsInTopSequences.Count} unique transforms.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ Error processing file {file}: {ex.Message}");
        }
    }
    private static int GetDataIndex(string dataType)
    {
        return dataType switch
        {
            "DC" => 0, // Combined
            "DN" => 1, // Natural
            "DR" => 2, // Random
            "DS" => 3, // Sequence
            "DU" => 4, // UserData (formerly Custom)
            _ => throw new Exception($"Unknown DataType: {dataType}")
        };
    }

    private static void SanityCheck()
    {
        messages.Add("\n🔍 Running Sanity Check...");

        var searchPattern = "Contenders,-L?-P?-D?-MC-SP.txt";
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
                var dataIndex = GetDataIndex(dataType);

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
                if (idEntry.Value.Length != NumDataTypes)
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

        var dataIndex = GetDataIndex(dataType);

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
        // the crypto lib no longer knows anything about 'static' global rounds. All global rounds are now passed
        //  to crypto lib via a profile
        //Rsm.PushGlobalRounds(localEnv.Crypto.Options.Rounds); // ✅ Push default global rounds
        Rsm.PushGlobalRounds(localEnv.Globals.Rounds); // ✅ Push default global rounds
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
            // the crypto lib no longer knows anything about 'static' global rounds. All global rounds are now passed
            //  to crypto lib via a profile
            //: localEnv.Crypto.Options.Rounds;
            : localEnv.Globals.Rounds;

        Rsm.PushAllGlobals();
        Rsm.PushAllTransformRounds();
        Rsm.PushGlobalRounds(globalRounds);

        //// ✅ Apply per-transform TR values
        //var (success, errorMessage) = UtilityHelpers.SetTransformRounds(
        //    localEnv.Crypto,
        //    ParsedSequence.Transforms.Select(t => (t.Name, (int)t.ID, t.TR)).ToList()
        //);
        //if (!success) throw new InvalidOperationException($"Failed to set transform rounds: {errorMessage}");

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
                     .Where(p => p.GetCustomAttribute<GlobalSettingAttribute>() != null))
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

        var propInfo = typeof(GlobalsInstance).GetProperty(GlobalRoundsSetting.Split('.')[1]);
        if (propInfo == null)
            throw new InvalidOperationException($"Property '{GlobalRoundsSetting}' not found.");

        var currentRounds = (int)propInfo.GetValue(_localEnv.Globals)!;
        _globalRoundStack.Push(currentRounds); // ✅ Save current value
        propInfo.SetValue(_localEnv.Globals, new_value); // ✅ Update to new value
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

        var propInfo = typeof(GlobalsInstance).GetProperty(GlobalRoundsSetting.Split('.')[1]);
        if (propInfo == null)
            throw new InvalidOperationException($"Property '{GlobalRoundsSetting}' not found.");

        var previousRounds = _globalRoundStack.Pop();
        propInfo.SetValue(_localEnv.Globals, previousRounds); // ✅ Restore previous value
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
        //lock (_stackLock)
        //{
        //    var (caller, fullCallerInfo) = GetCallerInfo(_context, 1);

        //    _transformPushTracking.Add((caller, fullCallerInfo, Environment.StackTrace));

        //    LogStatus($"PUSH - Caller: {fullCallerInfo}, Stack Depth BEFORE: {_transformRoundStack.Count}");

        //    if (_transformRoundStack.Count % _transformCount != 0)
        //        HandleError(
        //            $"Stack imbalance detected BEFORE push. Expected a multiple of {_transformCount}, but found {_transformRoundStack.Count}.");

        //    // ✅ Normal stack push operation
        //    _pushAllTransformRounds();

        //    LogStatus($"PUSH - Stack Depth AFTER: {_transformRoundStack.Count}");
        //}
    }

    private void _pushAllTransformRounds()
    {
        //CheckStackOverflow(_transformRoundStack); // ✅ Prevent overflow
        //foreach (var transform in _cryptoLib.TransformRegistry.Values)
        //    _transformRoundStack.Push(new KeyValuePair<int, int>(transform.Id, transform.Rounds));
    }

    /// <summary>
    /// Restores the round values of all transforms.
    /// </summary>
    public void PopAllTransformRounds()
    {
        //lock (_stackLock)
        //{
        //    var (caller, fullCallerInfo) = GetCallerInfo(_context, 1);

        //    LogStatus($"POP - Caller: {fullCallerInfo}, Stack Depth BEFORE: {_transformRoundStack.Count}");

        //    var available = _transformRoundStack.Count;
        //    var required = _transformCount;

        //    if (available < required)
        //        HandleError($"Pop attempted by {fullCallerInfo}: Required {required}, but only {available} available.");

        //    if (_transformPushTracking.Count == 0)
        //        HandleError($"Pop operation attempted by {fullCallerInfo}, but no pushes exist.");

        //    var index = _transformPushTracking.FindLastIndex(entry => entry.caller == caller);
        //    if (index != -1)
        //        _transformPushTracking.RemoveAt(index); // ✅ Removes the most recent push by this caller
        //    else
        //        HandleError($"Pop operation attempted by {fullCallerInfo}, but no matching push found.");

        //    // ✅ Normal stack pop operation
        //    _popAllTransformRounds();

        //    LogStatus($"POP - Stack Depth AFTER: {_transformRoundStack.Count}");
        //}
    }

    private void _popAllTransformRounds()
    {
        //var stackSize = _transformRoundStack.Count;
        //if (stackSize < _transformCount)
        //    HandleError(
        //        $"Stack is unbalanced: Expected {_transformCount} elements, but only {stackSize} remain. This suggests a mismatch between push and pop operations.");

        //for (var i = 0; i < _transformCount; i++)
        //{
        //    var (savedId, savedRounds) = _transformRoundStack.Pop();
        //    if (!_cryptoLib.TransformRegistry.TryGetValue(savedId, out var transform))
        //        HandleError($"Transform ID {savedId} not found in registry during PopAllTransformRounds().");
        //    transform!.Rounds = (byte)savedRounds;
        //}
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
            .Count(p => p.GetCustomAttribute<GlobalSettingAttribute>() != null);
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
    Natural,
    UserData      // not tracked by InputProfiler.GetInputProfile()
}

[AttributeUsage(AttributeTargets.Property)]
public class GlobalSettingAttribute : Attribute
{
    /// <summary>
    /// If true, this setting is only shown when debugging.
    /// </summary>
    public bool IsDebugOnly { get; set; } = false;

    /// <summary>
    /// If true, this setting is internal and will not appear in user-facing lists.
    /// </summary>
    public bool IsInternal { get; set; } = false; // ✅ Hides setting from UI but allows CLI access

    /// <summary>
    /// If true, this setting should not be persisted when saving configurations.
    /// </summary>
    public bool IsNoSave { get; set; } = false; // ✅ NEW: Excludes setting from being written to disk

    /// <summary>
    /// If this is a compound setting, this array defines its related properties.
    /// </summary>
    public string[]? RelatedProperties { get; }

    /// <summary>
    /// Standard constructor (for regular settings).
    /// </summary>
    public GlobalSettingAttribute()
    {
    }

    /// <summary>
    /// Constructor for compound settings.
    /// </summary>
    public GlobalSettingAttribute(params string[]? relatedProperties)
    {
        RelatedProperties = relatedProperties;
    }

    /// <summary>
    /// Constructor for debug-only settings.
    /// </summary>
    public GlobalSettingAttribute(bool IsDebugOnly)
    {
        this.IsDebugOnly = IsDebugOnly;
    }

    /// <summary>
    /// Constructor for internal settings.
    /// </summary>
    public GlobalSettingAttribute(bool IsDebugOnly, bool IsInternal)
    {
        this.IsDebugOnly = IsDebugOnly;
        this.IsInternal = IsInternal;
    }

    /// <summary>
    /// Constructor for no-save settings.
    /// </summary>
    public GlobalSettingAttribute(bool IsDebugOnly, bool IsInternal, bool IsNoSave)
    {
        this.IsDebugOnly = IsDebugOnly;
        this.IsInternal = IsInternal;
        this.IsNoSave = IsNoSave;
    }
}
[AttributeUsage(AttributeTargets.Property, Inherited = false, AllowMultiple = false)]
public sealed class DoNotCloneAttribute : Attribute
{
}
// Updated Globals class to include the Mode setting
public class GlobalsInstance
{
    //  properties for global access
    [GlobalSetting] public int Rounds { get; set; } = 9;
    [GlobalSetting] public int MaxSequenceLen { get; set; } = 3;
    [GlobalSetting] public InputType InputType { get; set; } = InputType.Random;
    [GlobalSetting] public int PassCount { get; set; } = 0;
    [GlobalSetting] public int DesiredContenders { get; set; } = 1000;
    [GlobalSetting] public bool Quiet { get; set; } = true;

    [GlobalSetting]
    public int FlushThreshold { get; set; } =
        50000; // Number of items before flushing console output and registering contenders

    [GlobalSetting]
    public bool SqlCompact { get; set; } =
        false; // Compact true outputs SQL queries in CSV, otherwise, a line based format is used

    // ✅ ScoringModes.Metric:
    // Traditional metric-based scoring:
    // • Each metric is rescaled relative to its expected value and weighted.
    // • A logarithmic scaling is applied to compress extreme values and balance the score distribution.
    // • Thresholds are enforced to cap overperforming metrics, preventing score inflation from outliers.
    //
    // ✅ ScoringModes.Practical (default):
    // Modern, banded scoring for cryptographic relevance:
    // • Metrics are grouped into bands: Perfect, Pass, NearMiss, Fail — based on cryptographic robustness.
    // • Bands are weighted to prioritize meaningful structural qualities over raw numeric scores.
    // • Produces clearer separation between strong and weak sequences, better reflecting real-world security value.
    [GlobalSetting] public ScoringModes ScoringMode { get; set; } = ScoringModes.Practical;

    [GlobalSetting] public OperationModes Mode { get; set; } = OperationModes.Cryptographic;

    #region Batch Mode Processing

    [GlobalSetting(false, true, true)] // need to be able to set this through the commandline, don't save
    public bool CreateMungeFailDB { get; set; } = false;

    [GlobalSetting(false, true, true)] // need to be able to set this through the commandline, don't save
    public bool CreateBTRFailDB { get; set; } = true; // BTR is always in creation mode

    [GlobalSetting(false, true, true)] // need to be able to set this through the commandline, don't save
    public bool ExitJobComplete { get; set; } = false;

    [GlobalSetting(false, true, true)] // need to be able to set this through the commandline, don't save
    public bool LogMungeOutput { get; set; } = false;

    public bool BatchMode { get; set; } = false; // never saved, never shown
    public string Commandline { get; set; } = null!; // never saved, never shown
    public Dictionary<string, string[]> FunctionParms = new(StringComparer.OrdinalIgnoreCase);

    #endregion Batch Mode Processing

    [GlobalSetting(true)]
    public ReportHelper.ReportFormat ReportFormat { get; set; } = ReportHelper.ReportFormat.SCR;

    [GlobalSetting(true)] public string ReportFilename { get; set; } = null!;

    [GlobalSetting("ReportFormat", "ReportFilename")]
    public string Reporting { get; set; } = null!;

    private const string SettingsFile = "GlobalSettings.json";

    public const string Password = "sample-password";

    // Input is regenerated when InputType is set via UpdateSetting,
    // so cloning it is unnecessary and could cause stale data issues.
    [DoNotClone]
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

    public void Dupe(GlobalsInstance? source)
    {
        if (source == null)
            throw new ArgumentNullException(nameof(source));

        var properties = typeof(GlobalsInstance).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.CanRead && p.CanWrite && !p.IsDefined(typeof(DoNotCloneAttribute)));

        foreach (var property in properties)
        {
            try
            {
                var value = property.GetValue(source);
                UpdateSetting(property.Name, value); // ✅ Preserves trigger actions and consistency
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Warning: Failed to copy setting {property.Name}. Error: {ex.Message}");
            }
        }
    }

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
                .Where(p => p.IsDefined(typeof(GlobalSettingAttribute)))
                .ToDictionary(p => p.Name, p => p, StringComparer.OrdinalIgnoreCase);

            foreach (var (key, jsonElement) in settings)
            {
                if (!properties.TryGetValue(key, out var property))
                {
                    Console.WriteLine($"Warning: Ignoring unknown setting '{key}' from settings file.");
                    continue;
                }

                var attribute = property.GetCustomAttribute<GlobalSettingAttribute>();
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
                     .Where(p => p.IsDefined(typeof(GlobalSettingAttribute))))
        {
            var attribute = property.GetCustomAttribute<GlobalSettingAttribute>();

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
            .Where(p => p.IsDefined(typeof(GlobalSettingAttribute)))
            .ToList();

        var compoundKeys = new HashSet<string>(); // ✅ Prevent duplicate compound settings

        foreach (var property in properties)
        {
            var attribute = property.GetCustomAttribute<GlobalSettingAttribute>();

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
        var properties = typeof(GlobalsInstance).GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Where(p => p.CanWrite)
            .ToDictionary(p => p.Name, p => p, StringComparer.OrdinalIgnoreCase);

        if (!properties.TryGetValue(key, out var property))
            throw new ArgumentException($"Unknown key: {key}");

        // 🚫 Check for [DoNotClone] and reject
        if (property.IsDefined(typeof(DoNotCloneAttribute)))
            throw new InvalidOperationException($"Setting '{key}' is marked [DoNotClone] and cannot be updated dynamically.");

        // 🔄 Convert value into the expected type
        var sequenceHandler = new SequenceAttributesHandler(_localEnv);
        var convertedValue = sequenceHandler.ConvertValue(property.PropertyType, value);

        property.SetValue(this, convertedValue);

        TriggerSpecialActions(key, convertedValue);
    }

    // Handles special triggers when specific global settings are changed
    private void TriggerSpecialActions(string key, object? value)
    {
        switch (key.ToLowerInvariant())
        {
            case "inputtype":
                Input = GenerateTestInput(_localEnv);
                break;

            case "mode":
                if (value is OperationModes parsedMode)
                {
                    _localEnv.Globals.Mode = parsedMode;
                    _localEnv.CryptoAnalysis.ApplyWeights(parsedMode); // Adjust weights if necessary
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
                    // the crypto lib no longer knows anything about 'static' global rounds. All global rounds are now passed
                    //  to crypto lib via a profile
                    //_cryptoLib.Options.Rounds = newRounds;
                }
                else
                {
                    ColorConsole.WriteLine($"<Red>Invalid value for Rounds:</Red> <Green>{value}</Green>");
                }

                break;
        }
    }

    /// <summary>
    /// Returns the recommended GlobalRounds value based on the current InputType.
    ///
    /// While the Workbench allows users to adjust InputType and Rounds independently for flexible experimentation,
    /// tuning and discovery tools like Munge and BTR explicitly assign a GlobalRounds value tied to the specific
    /// InputType being processed. This ensures consistent, deterministic results during automated optimization,
    /// scoring, and comparison runs.
    ///
    /// ⚠️ Note: For InputType.UserData, no override is applied — the round count must be set manually by the user.
    /// </summary>
    public int GlobalRoundsForType()
    {
        switch (_localEnv.Globals.InputType)
        {
            case InputType.Combined:
                return 6; // verified 4/10/2025
            case InputType.Natural:
                return 3; // verified 4/10/2025
            case InputType.Random:
                return 3; // verified 4/10/2025
            case InputType.Sequence:
                return 5; // verified 4/10/2025
            case InputType.UserData:
                // ✅ For user data, do not override the GlobalRounds.
                // The user is responsible for setting the desired round count manually.
                return _localEnv.Globals.Rounds;
            default:
                throw new InvalidOperationException(
                    $"Unknown InputType detected during adaptive rounds assignment: {_localEnv.Globals.InputType}");
        }
    }
    // Fallback logic to get default value from CryptoLib
    private object GetDefaultFromCryptoLib(string key)
    {
        return (key switch
        {
            // the crypto lib no longer knows anything about 'static' global rounds. All global rounds are now passed
            //  to crypto lib via a profile
            //"TRounds" => _cryptoLib!.Options.Rounds,
            "RequiredSalt" => _cryptoLib!.Options.Salt,
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
    public ExecutionEnvironment(string password, CryptoLibOptions options, bool allowSaving = false)
    {
        // 🛑 Clone options FIRST to ensure nothing is shared
        var clonedOptions = options.Dupe();

        Crypto = new CryptoLib(password, clonedOptions!);

        Globals = new GlobalsInstance(this, allowSaving);

        // ✅ Ensure settings are fully initialized (allocates input, loads weight tables, syncs globals & crypto)
        InitDefaults(Globals, Crypto);
    }

    public ExecutionEnvironment(CryptoLibOptions options, bool allowSaving = false)
    : this(GlobalsInstance.Password, options, allowSaving)
    {

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
        Globals.Dupe(existingEnv.Globals);

        // ✅ Apply any provided setting overrides after duplication
        if (settings != null) ApplySettings(settings);
    }

    /// <summary>
    /// ✅ Clone constructor: Creates a sandboxed <see cref="ExecutionEnvironment"/> based on an existing one,
    /// while preserving password isolation.
    /// 
    /// - Uses the provided <paramref name="password"/> instead of relying on any global password.
    /// - Clones all <see cref="GlobalsInstance"/> settings from the original environment.
    /// - Allows optional overrides to apply after duplication (e.g., rounds, mode, input type).
    /// 
    /// This constructor is ideal for spawning evaluation sandboxes or subcontexts without mutating
    /// the original environment or polluting global password state.
    /// </summary>
    /// <param name="existingEnv">The source environment to clone from.</param>
    /// <param name="password">The password to use for the new environment’s CryptoLib instance.</param>
    /// <param name="settings">Optional setting overrides to apply post-clone.</param>
    public ExecutionEnvironment(ExecutionEnvironment existingEnv, string password, Dictionary<string, string>? settings = null)
        : this(password, existingEnv.Crypto.Options, false)
    {
        Globals.Dupe(existingEnv.Globals);

        if (settings != null)
            ApplySettings(settings);
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
        // the crypto lib no longer knows anything about 'static' global rounds. All global rounds are now passed
        //  to crypto lib via a profile
        //instance.UpdateSetting("rounds", cryptoLib!.Options.Rounds); // ✅ Syncs round count
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
            else if (key == "ScoringMode")
            {
                processedValue = Enum.GetNames(typeof(ScoringModes))
                                     .FirstOrDefault(name => name.StartsWith(value, StringComparison.OrdinalIgnoreCase))
                                 ?? throw new FormatException(
                                     $"❌ ERROR: Unrecognized Mode '{value}' in settings file!");
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
public class EnvPool
{
    private readonly ConcurrentBag<ExecutionEnvironment> _pool = new();
    private readonly ExecutionEnvironment _template;

    public EnvPool(ExecutionEnvironment template)
    {
        _template = template;
    }

    public ExecutionEnvironment Rent()
    {
        if (_pool.TryTake(out var env))
        {
            //env.Reset(); // optional: pass _template if needed
            return env;
        }

        return new ExecutionEnvironment(_template);
    }

    public void Return(ExecutionEnvironment env)
    {
        _pool.Add(env);
    }

    public int Count => _pool.Count;
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
    private static byte[] _userData = Array.Empty<byte>();

    public static void InitializeInputData()
    {
        lock (_initLock)
        {
            if (_isInitialized)
                return;

            var randoms_filename = "randoms.bin";
            var natural_filename = "Frankenstein.bin";
            var natural_source = "Frankenstein.txt";
            var userData_filename = "userdata.bin";

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
            else if (_combinedData.Length > 4096)
                _combinedData = _combinedData.Take(4096).ToArray();

            // 🚀 Load user data if available
            if (File.Exists(userData_filename))
            {
                _userData = File.ReadAllBytes(userData_filename);
                ValidateBuffer(_userData, _userData.Length, userData_filename);
            }

            _isInitialized = true;
        }
    }

    public static void InitializeUserData(byte[] buffer)
    {
        File.WriteAllBytes("userdata.bin", buffer);
        _userData = buffer;
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
            InputType.UserData => _userData,
            _ => throw new ArgumentException($"❌ CRITICAL ERROR: Invalid input type specified: {type}")
        };

        ValidateBuffer(sourceData, size, $"Requested {type} Data");
        return sourceData.Take(size).ToArray();
    }

    public static byte[] GenerateTestInput(ExecutionEnvironment localEnv)
    {
        int size = localEnv.Globals.InputType == InputType.UserData ? _userData.Length : 4096;
        return GenerateTestInput(size, localEnv.Globals.InputType);
    }

    private static void ValidateBuffer(byte[] buffer, int expectedSize, string sourceName)
    {
        if (buffer == null || buffer.Length == 0)
            throw new InvalidOperationException($"❌ CRITICAL ERROR: {sourceName} buffer is null or empty.");

        if (buffer.Length < expectedSize)
            throw new ArgumentException($"❌ CRITICAL ERROR: Requested size ({expectedSize}) exceeds available {sourceName} data ({buffer.Length}).");
    }
}

public static class UtilityHelpers
{
    public static readonly byte[] AesSalt =
    {
        0x06, 0x05, 0x77, 0x38,
        0x64, 0x15, 0x5C, 0xD6,
        0x36, 0x0E, 0x06, 0xA3,
        0xE6, 0x24, 0x9E, 0x35
    };

    /// <summary>
    /// Prompts the user to select a number within a given range.
    /// Returns 0 if the user presses Escape or enters an invalid value.
    /// </summary>
    /// <summary>
    /// Prompts the user to select a number between the given bounds.
    /// Returns 0 if the user cancels or enters an invalid option.
    /// </summary>
    public static int SelectMenuOpt(byte from, byte to)
    {
        Console.Write($"\nEnter a number between {from} and {to} to select a profile, or press ESC to cancel: ");

        var inputBuffer = new StringBuilder();

        while (true)
        {
            var key = Console.ReadKey(intercept: true);

            if (key.Key == ConsoleKey.Escape)
            {
                Console.WriteLine("\n❌ Selection cancelled.");
                return 0;
            }

            if (key.Key == ConsoleKey.Enter)
            {
                Console.WriteLine(); // Move to next line
                if (int.TryParse(inputBuffer.ToString(), out int result) && result >= from && result <= to)
                    return result;

                Console.WriteLine($"❌ Invalid selection. Please enter a number between {from} and {to}.");
                return 0;
            }

            if (char.IsDigit(key.KeyChar))
            {
                inputBuffer.Append(key.KeyChar);
                Console.Write(key.KeyChar);
            }
            else if (key.Key == ConsoleKey.Backspace && inputBuffer.Length > 0)
            {
                inputBuffer.Length--;
                Console.Write("\b \b");
            }
            else
            {
                Console.Beep();
            }
        }
    }
    public static void AssertWeightsMatchExpectedMode(ExecutionEnvironment env)
    {
#if DEBUG
        var mode = env.Globals.Mode;

        // ❌ Abort if no mode is set
        if (mode == OperationModes.None)
            throw new InvalidOperationException("Mode is not set. Cannot validate weight table.");

        // ✅ Try to retrieve expected weights for the current mode
        if (!env.CryptoAnalysis.TryGetWeights(mode, out var expectedWeights))
            throw new InvalidOperationException($"No predefined weight table found for mode: {mode}.");

        // ✅ Get actual weights from the MetricsRegistry
        var actualWeights = env.CryptoAnalysis.MetricsRegistry
            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Weight);

        // 🔄 Compare actual vs expected (order-insensitive)
        var matches = actualWeights.OrderBy(kvp => kvp.Key)
            .SequenceEqual(expectedWeights.OrderBy(kvp => kvp.Key));

        if (!matches)
            throw new InvalidOperationException(
                $"Active weight table does not match expected weights for mode: {mode}.");
#endif
    }

    public static List<string> GetMungeBody(ExecutionEnvironment localEnv, int? rounds = null)
    {
        int resolvedRounds = rounds ?? localEnv.Globals.Rounds;
        var failDBColor = localEnv.Globals.CreateMungeFailDB ? "Red" : "Green"; // Red if MungeFailDB is enabled

        return new List<string>
        {
            $"<Green>[Timestamp] {DateTime.Now:MM/dd/yyyy hh:mm:ss tt}</Green>", // Provides a readable timestamp
            $"<Green>DataType: {localEnv.Globals.InputType}</Green>", // Input type (Combined, Random, etc.)
            $"<Green>Rounds: {resolvedRounds}</Green>", // Global rounds for encryption
            $"<Green>Mode: {localEnv.Globals.Mode}</Green>", // Cryptographic or Exploratory mode
            $"<Green>PassCount: {localEnv.Globals.PassCount}</Green>", // Number of passes required for success
            $"<Green>MaxSequenceLen: {localEnv.Globals.MaxSequenceLen}</Green>", // Maximum sequence length allowed
            $"<Green>Munge Level: L{localEnv.Globals.MaxSequenceLen}</Green>", // Same as MaxSequenceLen, expressed as a level
            $"<Green>Scoring Mode: {localEnv.Globals.ScoringMode}</Green>", // Current scoring strategy
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
    /// - **S<ScoringMode>** → Indicates if Practical or Metric scoring was used:
    ///   - `'P'` = Practical
    ///   - `'M'` = Metric
    /// 
    /// **Example Filenames:**
    /// ```
    /// 2502_032_L4-P6-DN-MC-SP.txt  (Feb 1, 2025, L4 Munge, Pass Count 6, Natural Data, Cryptographic, Scoring Practical)
    /// 2501_015_L3-P5-DC-ME-SM.txt  (Jan 15, 2025, L3 Munge, Pass Count 5, Combined Data, Exploratory, Scoring Metric)
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
        var scoringMode = localEnv.Globals.ScoringMode.ToString()[0];

        // ✅ Keep the prefix (e.g., "Contenders," or "MungeFailDB,")
        var lengthSegment = sequenceLength.HasValue ? $"-L{sequenceLength}" : "";

        var basename = $"{prefix}{lengthSegment}-P{passCount}-D{dataType}-M{mode}-S{scoringMode}";

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
                settings["ScoringMode"] = part.Substring(1); // *-Sx-* (Scoring: Practical, Metric)

        if (settings.Count != 5)
            throw new InvalidOperationException(
                "Missing required settings in filename. Expected 5 settings (MaxSequenceLen, PassCount, InputType, Mode, ScoringMode).");

        return settings;
    }

    public static Dictionary<string, string> GenerateEnvironmentSettings(string[] args)
    {
        var settings = new Dictionary<string, string>();
        string? maxSequenceLen = null;
        string? passCount = null;
        string? inputType = null;
        string? mode = null;
        string? scoringMode = null;

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
                scoringMode = arg.Substring(2); // Remove "-S"
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
        if (scoringMode != null)
            settings["ScoringMode"] = scoringMode;


        // Check for all required settings.  Use settings.ContainsKey, so we can support any setting.
        var requiredKeys = new string[] { "MaxSequenceLen", "PassCount", "InputType", "Mode", "scoringMode" };
        foreach (var key in requiredKeys)
            if (!settings.ContainsKey(key))
                throw new InvalidOperationException(
                    $"Missing required setting: {key}.  Expected in the format -{key}=value.");

        return settings;
    }

    /// <summary>
    /// Retrieves matching Munge result files based on user-specified parameters.
    ///
    /// 🧠 Flexible File Matching:
    /// - Default pattern: `Contenders,-L4-P6-D?-MC-SP.txt`
    /// - Arguments passed in (e.g., `-L5`, `-DN`, `-SP`) will dynamically replace components of the pattern.
    ///
    /// ✅ Examples:
    /// - `-L5` → `Contenders,-L5-P6-D?-MC-SP.txt`
    /// - `-L5 -P0 -DR -ME -SP` → `Contenders,-L5-P0-DR-ME-SP.txt`
    ///
    /// 🚨 The full resolved pattern is shown to the user before continuing.
    /// User must confirm (Y/N) to proceed.
    ///
    /// 📁 Files are matched against the current folder with wildcard support (`?`)
    /// Results are returned as a sorted array.
    /// </summary>
    public static string[] GetMungeFiles(string[] args)
    {
        var defaultPattern = "Contenders,-L4-P6-D?-MC-SP.txt";
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
                resolvedPattern = Regex.Replace(resolvedPattern, @"-S[P|M]", arg, RegexOptions.IgnoreCase);

        string[] matchingFiles = GetMungeFiles(args, resolvedPattern);
        if (matchingFiles.Length == 0) return Array.Empty<string>();

        return matchingFiles.OrderBy(f => f).ToArray();
    }

    /// <summary>
    /// Retrieves the top contender sequences from Munge(A) output files and extracts a specified number of transforms.
    /// </summary>
    /// <param name="env">The execution environment containing cryptographic context.</param>
    /// <param name="pattern">The file pattern to match contender files (e.g., "Contenders,-L4-P6-D?-MC-SP.txt").</param>
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

        // ✅ Extract the flag's value (e.g., "-DC", "-DN", "-SP", etc.)
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
            List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysisCore.AnalysisResult> Metrics)> contenders,
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
            public List<CryptoAnalysisCore.AnalysisResult>? Metrics { get; set; }
        }

        public class MungeState
        {
            public List<SerializableContender>? Contenders { get; set; }
            public int Length { get; set; }
            public byte[] Transforms { get; set; } = null!;
            public byte[] Sequence { get; set; } = null!;
        }
    }

    public static (
        byte[] MangoAvalanchePayload,
        byte[]? AESAvalanchePayload,
        byte[] MangoKeyDependencyPayload,
        byte[]? AESKeyDependencyPayload)
        ProcessAvalancheAndKeyDependency(
            CryptoLib cryptoLib,
            byte[] input,
            string password,
            InputProfile profile,
            bool processAes = false)
    {
        // ✂️ Use normalized core logic from Mango.Common
        var (mangoAvalanchePayload, mangoKeyDependencyPayload) =
            Mango.Common.Scoring.ProcessAvalancheAndKeyDependency(cryptoLib, input, password, profile);

        // 🔐 AES Avalanche (optional)
        byte[]? aesAvalanchePayload = null;
        byte[]? aesKeyDependencyPayload = null;

        if (processAes)
        {
            // Re-derive mutated input and password for AES processing
            var mutationSeed = Mango.Common.Scoring.MutationSeed;
            var modifiedInput = Mango.Common.Scoring.ModifyInput(mutationSeed, input);
            var modifiedPasswordBytes = Mango.Common.Scoring.ModifyInput(mutationSeed, Encoding.UTF8.GetBytes(password));
            var modifiedPassword = Encoding.UTF8.GetString(modifiedPasswordBytes!);

            aesAvalanchePayload = AesEncrypt(modifiedInput, password, out var saltLen1, out var padLen1);
            aesAvalanchePayload = ExtractAESPayload(aesAvalanchePayload, saltLen1, padLen1);

            aesKeyDependencyPayload = AesEncrypt(input, modifiedPassword, out var saltLen2, out var padLen2);
            aesKeyDependencyPayload = ExtractAESPayload(aesKeyDependencyPayload, saltLen2, padLen2);
        }

        return (
            MangoAvalanchePayload: mangoAvalanchePayload,
            AESAvalanchePayload: aesAvalanchePayload,
            MangoKeyDependencyPayload: mangoKeyDependencyPayload,
            AESKeyDependencyPayload: aesKeyDependencyPayload
        );
    }

    public static byte[] AesEncrypt(byte[] input, string password, out int saltLength, out int paddingLength)
    {
        // use a fixed salt for tests
        var salt = AesSalt;
        saltLength = salt.Length;

        // Derive the key and IV using PBKDF2
        using var deriveBytes = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
        var key = deriveBytes.GetBytes(32); // AES-256
        var iv = deriveBytes.GetBytes(16);

        var aes = new AesSoftwareCore.AesSoftwareCore(key);
        var encryptedData = aes.EncryptCbc(input, iv);

        paddingLength = encryptedData.Length - input.Length; // Matches TransformFinalBlock behavior

        // Prepend salt to match expected format
        var result = new byte[salt.Length + encryptedData.Length];
        Buffer.BlockCopy(salt, 0, result, 0, salt.Length);
        Buffer.BlockCopy(encryptedData, 0, result, salt.Length, encryptedData.Length);

        return result;
    }
    public static byte[] AesDecrypt(byte[] encryptedInput, string password)
    {
        // Use the known test salt
        var salt = AesSalt;

        if (encryptedInput.Length < salt.Length)
            throw new ArgumentException("Encrypted data is too short to contain salt.");

        var ciphertext = new byte[encryptedInput.Length - salt.Length];
        Buffer.BlockCopy(encryptedInput, salt.Length, ciphertext, 0, ciphertext.Length);

        using var deriveBytes = new Rfc2898DeriveBytes(password, salt, 100_000, HashAlgorithmName.SHA256);
        var key = deriveBytes.GetBytes(32); // AES-256
        var iv = deriveBytes.GetBytes(16);

        var aes = new AesSoftwareCore.AesSoftwareCore(key);
        return aes.DecryptCbc(ciphertext, iv);
    }

    public static byte[] ExtractAESPayload(byte[] encryptedData, int saltLength, int paddingLength)
    {
        var coreLength = encryptedData.Length - saltLength - paddingLength;
        return encryptedData.Skip(saltLength).Take(coreLength).ToArray();
    }


    public static class CsvFormatter
{
    /// <summary>
    /// Displays formatted CSV data from a file path to the console.
    /// </summary>
    /// <param name="csvFilePath">The path to the CSV file.</param>
    public static void DisplayCsvFormatted(string csvFilePath)
    {
        if (!File.Exists(csvFilePath))
        {
            Console.WriteLine($"Error: File not found at {csvFilePath}");
            return;
        }

        var lines = File.ReadAllLines(csvFilePath);
        DisplayCsvFormatted(lines); // Call the new overload
    }

        /// <summary>
        /// Displays formatted CSV data from a collection of strings (lines) to the console.
        /// Assumes the first string(s) are titles, and the actual CSV header is on the third line (index 2).
        /// </summary>
        /// <param name="csvLines">A collection of strings, where each string represents a line from the CSV.</param>
#if true
public static void DisplayCsvFormatted(IEnumerable<string> csvLines)
{
    var linesList = csvLines?.ToList(); // Convert to list to handle multiple enumerations and check for null

    if (linesList == null || linesList.Count < 3)
    {
        Console.WriteLine("CSV data is empty or malformed (expected at least 3 lines: title, empty, header).");
        return;
    }

    // Print title and spacer
    Console.WriteLine(linesList[0]);
    Console.WriteLine(linesList[1]);

    // Parse header and data
    var headers = linesList[2].Split(',').Select(h => h.Trim()).ToArray();
    var dataRows = linesList.Skip(3).Select(line => line.Split(',').Select(c => c.Trim()).ToArray()).ToList();

    // Compute column widths using max of header and data visual length
    int[] columnWidths = new int[headers.Length];

    for (int i = 0; i < headers.Length; i++)
    {
        int maxWidth = GetVisualLength(headers[i]);

        foreach (var row in dataRows)
        {
            if (i < row.Length)
            {
                int cellWidth = GetVisualLength(row[i]);
                if (cellWidth > maxWidth)
                    maxWidth = cellWidth;
            }
        }

        columnWidths[i] = maxWidth + 2; // Add padding
    }

    // Print header and divider
    PrintLine(columnWidths);
    PrintRow(headers, columnWidths);
    PrintLine(columnWidths);

    // Print data rows
    foreach (var row in dataRows)
    {
        string[] currentRowValues = new string[headers.Length];
        Array.Copy(row, currentRowValues, Math.Min(row.Length, headers.Length));
        for (int i = row.Length; i < headers.Length; i++)
            currentRowValues[i] = "";

        PrintRow(currentRowValues, columnWidths);
    }

    PrintLine(columnWidths);
}

private static void PrintLine(int[] columnWidths)
{
    Console.WriteLine(new string('-', columnWidths.Sum() + (columnWidths.Length - 1) * 3 + 2));
}

private static void PrintRow(string[] rowValues, int[] columnWidths)
{
    for (int i = 0; i < rowValues.Length; i++)
    {
        var value = rowValues[i];
        var originalColor = Console.ForegroundColor;

        // Apply color if emoji prefix is present
        bool hasEmoji = value.StartsWith("✅") || value.StartsWith("❌") || value.StartsWith("❓");

        if (hasEmoji)
        {
            if (value.StartsWith("✅"))
                Console.ForegroundColor = ConsoleColor.Green;
            else if (value.StartsWith("❌"))
                Console.ForegroundColor = ConsoleColor.Red;
            else if (value.StartsWith("❓"))
                Console.ForegroundColor = ConsoleColor.Yellow;
        }

        int visualLength = GetVisualLength(value);
        int extraPadding = hasEmoji ? value.Length - visualLength : 0;
        int padLength = columnWidths[i] + extraPadding;

        Console.Write(value.PadRight(padLength));
        Console.ForegroundColor = originalColor;
        Console.Write(" | ");
    }
    Console.WriteLine();
}


        private static int GetVisualLength(string s)
{
    int length = 0;
    for (int i = 0; i < s.Length; i++)
    {
        if (char.IsSurrogatePair(s, i))
        {
            length += 1;
            i++; // Skip the low surrogate
        }
        else
        {
            length += 1;
        }
    }
    return length;
}

#else
        public static void DisplayCsvFormatted(IEnumerable<string> csvLines)
    {
        var linesList = csvLines?.ToList(); // Convert to list to handle multiple enumerations and check for null

        // We expect at least 3 lines: Title, Empty, Header
        if (linesList == null || linesList.Count < 3)
        {
            Console.WriteLine("CSV data is empty or malformed (expected at least 3 lines: title, empty, header).");
            return;
        }

        // Print the initial title and empty line directly
        Console.WriteLine(linesList[0]); // e.g., "🔶 Mango Metric Breakdown"
        Console.WriteLine(linesList[1]); // The empty line

        // The actual header is at index 2
        var headers = linesList[2].Split(',').Select(h => h.Trim()).ToArray();
        // The data rows start from index 3
        var dataRows = linesList.Skip(3).Select(line => line.Split(',').Select(c => c.Trim()).ToArray()).ToList();

        // Determine maximum column widths
        int[] columnWidths = new int[headers.Length];
        for (int i = 0; i < headers.Length; i++)
        {
            columnWidths[i] = headers[i].Length; // Start with header length
        }

        foreach (var row in dataRows)
        {
            // Ensure bounds checking for rows that might have fewer columns than headers
            for (int i = 0; i < row.Length && i < headers.Length; i++)
            {
                //if (row[i].Length > columnWidths[i])
                //{
                //    columnWidths[i] = row[i].Length;
                //}

                int visualLength = GetVisualLength(row[i]);
                if (visualLength > columnWidths[i])
                {
                    columnWidths[i] = visualLength;
                }

                }
            }

        // Add some padding
        for (int i = 0; i < columnWidths.Length; i++)
        {
            columnWidths[i] += 2; // Add 2 spaces for padding
        }

        // Print Header and Data Table
        PrintLine(columnWidths);
        PrintRow(headers, columnWidths);
        PrintLine(columnWidths);

        // Print Data
        foreach (var row in dataRows)
        {
            // Create a temporary array to hold row values, ensuring it matches header length
            string[] currentRowValues = new string[headers.Length];
            Array.Copy(row, currentRowValues, Math.Min(row.Length, headers.Length)); // Copy existing values
            for (int i = row.Length; i < headers.Length; i++)
            {
                currentRowValues[i] = ""; // Fill any missing columns with empty strings
            }
            PrintRow(currentRowValues, columnWidths);
        }
        PrintLine(columnWidths);
    }
    static int GetVisualLength(string s)
    {
        // Treat emoji as 1 visual char
        int length = 0;
        for (int i = 0; i < s.Length; i++)
        {
            if (char.IsSurrogatePair(s, i))
            {
                length += 1; // Count emoji or surrogate as one
                i++;         // Skip the low surrogate
            }
            else
            {
                length += 1;
            }
        }
        return length;
    }

        private static void PrintLine(int[] columnWidths)
    {
        // This calculates the total length of the line including column contents, padding, and separators.
        // For N columns, the pattern is "| Content | Content | ... | Content |"
        // Each column adds its width + 3 characters for the delimiter (' ', '|', ' ') EXCEPT the very last one.
        // Total length = Sum(padded column widths) + (number of columns * 3) + 1 (for the initial '|' and final ' ')
        int totalLineLength = columnWidths.Sum() + (columnWidths.Length * 3) + 1;
        Console.WriteLine(new string('-', totalLineLength));
    }

    // Using the color-aware PrintRow
    private static void PrintRow(string[] rowValues, int[] columnWidths)
    {
        Console.Write("| "); // Start of the row

        for (int i = 0; i < rowValues.Length; i++)
        {
            var value = rowValues[i];
            var originalColor = Console.ForegroundColor; // Save current color

            // Apply color based on emoji prefix
            if (value.StartsWith("✅"))
                Console.ForegroundColor = ConsoleColor.Green;
            else if (value.StartsWith("❌"))
                Console.ForegroundColor = ConsoleColor.Red;
            else if (value.StartsWith("❓"))
                Console.ForegroundColor = ConsoleColor.Yellow;
            else
                Console.ForegroundColor = ConsoleColor.Gray; // Default data color

            // Write the value, padded to its column width
            Console.Write(value.PadRight(columnWidths[i]));

            // Reset color before writing the delimiter for the next column
            Console.ForegroundColor = originalColor;

            // Write the column delimiter
            Console.Write(" | ");
        }
        Console.WriteLine(); // End the row with a newline
    }
#endif
    }

    // Example Usage:
    // Create a dummy CSV file for testing
    // File.WriteAllText("test.csv", "Name,Age,City\nAlice,30,New York\nBob,25,San Francisco\nCharlie,35,Los Angeles");
    // CsvFormatter.DisplayCsvFormatted("test.csv");
    [Flags]
    public enum HeaderOptions
    {
        None = 0,
        Mode = 1 << 0,
        InputType = 1 << 1,
        ScoringMode = 1 << 2,
        GlobalRounds = 1 << 3,
        PassCount = 1 << 4,
        MaxSequenceLength = 1 << 5,
        Sequence = 1 << 6, // 🆕 Sequence info
        AggregateScore = 1 << 7, // 🆕 Aggregate cryptanalysis score
        Reversibility = 1 << 8, // 🆕 Reversibility check

        // 🆕 All standard execution-related options
        AllExecution = Mode | InputType | ScoringMode | GlobalRounds | PassCount | MaxSequenceLength,

        // 🆕 All cryptanalysis-related options
        AllAnalysis = Sequence | AggregateScore | Reversibility,

        // 🆕 Everything
        All = AllExecution | AllAnalysis
    }

    public static string FormatScoreWithPassRatio(double score, List<AnalysisResult> results, double elapsedMs)
    {
        int passCount = results.Count(r => r.Passed);
        int total = results.Count;
        return $"({score:F4}) ({passCount} / {total}) ({elapsedMs:F2}ms)";
    }
    public static List<string> GenerateHeader(
        ExecutionEnvironment localEnv,
        string? title = null,
        string? name = null,
        HeaderOptions options = HeaderOptions.None,
        string? formattedSequence = null, // 🆕 Optional formatted sequence for cryptanalysis
        List<CryptoAnalysisCore.AnalysisResult>? analysisResults = null, // 🆕 Optional analysis results
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

        if (options.HasFlag(HeaderOptions.ScoringMode))
            output.Add(
                $"<Gray>Scoring Mode:</Gray> <Green>{localEnv.Globals.ScoringMode}</Green>");

        if (options.HasFlag(HeaderOptions.GlobalRounds))
            output.Add($"<Gray>GR (Global Rounds):</Gray> <Green>{localEnv.Globals.Rounds}</Green>");

        if (options.HasFlag(HeaderOptions.MaxSequenceLength))
            output.Add($"<Gray>Max Sequence Length:</Gray> <Green>{localEnv.Globals.MaxSequenceLen}</Green>");

        // 🆕 Add CryptAnalysis-specific options
        if (analysisResults != null)
        {
            AssertWeightsMatchExpectedMode(localEnv);

            var aggregateScore =
                localEnv.CryptoAnalysis.CalculateAggregateScore(analysisResults, localEnv.Globals.ScoringMode);
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

    public static class PermutationEngine
    {
        // Entry point — safe for use in all existing and future code
        public static IEnumerable<byte[]> GeneratePermutations(
            List<byte> transformIds,
            int length,
            List<byte>? required = null,
            bool allowWildcardRepeat = true,
            List<byte>? noRepeat = null)

        {
            if (required == null || required.Count == 0)
            {
                foreach (var seq in GenerateBasicPermutations(transformIds, length))
                {
                    if (noRepeat != null && noRepeat.Any(id => seq.Count(t => t == id) > 1))
                        continue;

                    yield return seq;
                }

                yield break; // ← 🔒 Required to avoid continuing into the second branch
            }

            int wildcardCount = length - required.Count;
            if (wildcardCount < 0)
                yield break;

            var wildcardSet = transformIds.Except(required).ToList();
            var wildcardCombos = GenerateWildcardCombinations(wildcardSet, wildcardCount, allowWildcardRepeat);

            foreach (var wildcards in wildcardCombos)
            {
                var seen = new HashSet<string>(); // Use string key to avoid duplicates

                foreach (var fullSequence in InterleaveRequiredWithWildcards(required, wildcards))
                {
                    if (noRepeat != null && noRepeat.Any(id => fullSequence.Count(t => t == id) > 1))
                        continue;

                    var key = string.Join(",", fullSequence);
                    if (seen.Contains(key)) continue;
                    seen.Add(key);

                    yield return fullSequence.ToArray();
                }

            }
        }


        // Original behavior — untouched
        private static IEnumerable<byte[]> GenerateBasicPermutations(List<byte> transformIds, int length)
        {
            IEnumerable<byte[]> Generate(byte[] sequence)
            {
                if (sequence.Length == length)
                {
                    yield return sequence;
                    yield break;
                }

                foreach (var transformId in transformIds)
                {
                    var newSequence = new byte[sequence.Length + 1];
                    sequence.CopyTo(newSequence, 0);
                    newSequence[^1] = transformId;

                    foreach (var result in Generate(newSequence))
                        yield return result;
                }
            }

            return Generate(Array.Empty<byte>());
        }

        // Generates all wildcard-only combinations (length = wildcardCount)
        private static IEnumerable<List<byte>> GenerateWildcardCombinations(List<byte> wildcardSet, int length, bool allowRepeat)
        {
            IEnumerable<List<byte>> Generate(List<byte> sequence)
            {
                if (sequence.Count == length)
                {
                    yield return sequence;
                    yield break;
                }

                foreach (var id in wildcardSet)
                {
                    if (!allowRepeat && sequence.Contains(id)) continue;
                    var next = new List<byte>(sequence) { id };
                    foreach (var combo in Generate(next))
                        yield return combo;
                }
            }

            return Generate(new List<byte>());
        }

        // Interleaves required + wildcard elements in all positional combinations
        private static IEnumerable<List<byte>> InterleaveRequiredWithWildcards(List<byte> required, List<byte> wildcards)
        {
            var pool = new List<byte>(required.Count + wildcards.Count);
            pool.AddRange(required);
            pool.AddRange(wildcards);

            foreach (var permutation in Permute(pool))
            {
                if (ContainsAll(permutation, required))
                    yield return permutation;
            }
        }

        // Simple permutation helper (non-recursive)
        private static IEnumerable<List<byte>> Permute(List<byte> list)
        {
            int n = list.Count;
            var a = list.ToArray();
            var c = new int[n];
            yield return new List<byte>(a);

            for (int i = 0; i < n;)
            {
                if (c[i] < i)
                {
                    if (i % 2 == 0) (a[0], a[i]) = (a[i], a[0]);
                    else (a[c[i]], a[i]) = (a[i], a[c[i]]);
                    yield return new List<byte>(a);
                    c[i] += 1;
                    i = 0;
                }
                else
                {
                    c[i] = 0;
                    i++;
                }
            }
        }

        private static bool ContainsAll(List<byte> sequence, List<byte> required)
        {
            foreach (var id in required)
                if (!sequence.Contains(id)) return false;
            return true;
        }
        public static long CountFilteredPermutations(
            List<byte> transformIds,
            int length,
            List<byte>? required = null,
            bool allowWildcardRepeat = true,
            List<byte>? noRepeat = null)
        {
            if (required == null || required.Count == 0)
            {
                return CountBasicPermutations(transformIds, length, noRepeat);
            }

            int wildcardCount = length - required.Count;
            if (wildcardCount < 0)
                return 0;

            var wildcardSet = transformIds.Except(required).ToList();
            long total = 0;

            // Use generator-aligned wildcard permutations
            IEnumerable<IEnumerable<byte>> GenerateWildcardPermutations(List<byte> source, int count)
            {
                if (count == 0)
                {
                    yield return Enumerable.Empty<byte>();
                    yield break;
                }

                foreach (var item in source)
                {
                    if (!allowWildcardRepeat && count > 1)
                    {
                        var remaining = source.Where(x => x != item).ToList();
                        foreach (var sub in GenerateWildcardPermutations(remaining, count - 1))
                            yield return new[] { item }.Concat(sub);
                    }
                    else
                    {
                        foreach (var sub in GenerateWildcardPermutations(source, count - 1))
                            yield return new[] { item }.Concat(sub);
                    }
                }
            }

            foreach (var wildcardSeq in GenerateWildcardPermutations(wildcardSet, wildcardCount))
            {
                var combined = required.Concat(wildcardSeq).ToList();
                if (noRepeat != null && noRepeat.Any(id => combined.Count(t => t == id) > 1))
                    continue;

                total += CountUniquePermutations(combined, required);
            }

            return total;
        }
        private static long CountUniquePermutations(List<byte> combined, List<byte> required)
        {
            // Count permutations accounting for repeated elements (multiset)
            var counts = new Dictionary<byte, int>();
            foreach (var id in combined)
            {
                if (!counts.ContainsKey(id)) counts[id] = 0;
                counts[id]++;
            }

            long numerator = Factorial(combined.Count);
            long denominator = counts.Values
                .Select(Factorial)
                .Aggregate(1L, (acc, val) => acc * val);

            return numerator / denominator;
        }
        private static long Factorial(int n)
        {
            long result = 1;
            for (int i = 2; i <= n; i++) result *= i;
            return result;
        }

        private static long CountBasicPermutations(List<byte> ids, int length, List<byte>? noRepeat)
        {
            if (noRepeat == null || noRepeat.Count == 0)
            {
                return (long)Math.Pow(ids.Count, length);
            }

            long count = 0;

            void Recurse(List<byte> sequence)
            {
                if (sequence.Count == length)
                {
                    if (noRepeat.Any(id => sequence.Count(t => t == id) > 1))
                        return;
                    count++;
                    return;
                }

                foreach (var id in ids)
                {
                    sequence.Add(id);
                    Recurse(sequence);
                    sequence.RemoveAt(sequence.Count - 1);
                }
            }

            Recurse(new List<byte>());
            return count;
        }

        public static double CalculateTotalMungeTime(
            ExecutionEnvironment localEnv,
            List<byte> transforms,
            int length,
            List<byte>? required = null,
            bool allowWildcardRepeat = true,
            List<byte>? noRepeat = null)
        {
            double totalTime = 0.0;

            // Use the same permutation engine as the actual Munge run
            foreach (var seq in PermutationEngine.GeneratePermutations(
                         transforms,
                         length,
                         required: required,
                         allowWildcardRepeat: allowWildcardRepeat,
                         noRepeat: noRepeat))
            {
                double seqTime = 0.0;

                foreach (var transformId in seq)
                {
                    if (!BenchmarkCache.TryGetValue(transformId, out var rawTime))
                    {
                        ColorConsole.WriteLine($"<red>[Warning]</red> No benchmark entry found for transform ID {transformId}. Defaulting to 0.");
                        rawTime = 0.0;
                    }

                    // Normalize for machine performance
                    double normalizedTime = rawTime *
                                            (localEnv.Globals.BenchmarkBaselineTime / localEnv.Globals.CurrentBenchmarkTime);

                    // Scale based on input size
                    double inputSizeFactor = (double)localEnv.Globals.Input.Length / localEnv.Globals.BenchmarkBaselineSize;

                    // Total cost per transform for all phases (4 ops per round: Encrypt+Decrypt + Avalanche + KeyDependency)
                    seqTime += normalizedTime * inputSizeFactor * localEnv.Globals.Rounds * 4;
                }


                totalTime += seqTime;
            }

            return totalTime;
        }
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
    public static List<CryptoAnalysisCore.AnalysisResult>? TestSequence(ExecutionEnvironment localEnv, byte[] sequence)
    {
        try
        {
            // 🎯 Construct profile using flat TR:1 for all transforms
            var flatTRs = Enumerable.Repeat((byte)1, sequence.Length).ToArray();
            var profile = InputProfiler.CreateInputProfile(name: "Test",
                sequence: sequence,
                tRs: flatTRs, // 👈 TR: 1 for all
                globalRounds: localEnv.Globals.Rounds);

            // 🔐 Encrypt using high-level profile API
            var encrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, localEnv.Globals.Input);
            var decrypted = localEnv.Crypto.Decrypt(encrypted);

            // 🔁 Ensure reversibility
            if (!decrypted.SequenceEqual(localEnv.Globals.Input))
            {
                Console.WriteLine("Reversibility check failed for the provided sequence.");
                return null;
            }

            // 🧪 Extract payload for analysis
            var payload = localEnv.Crypto.GetPayloadOnly(encrypted);

            // 🧬 Perform Avalanche and Key Dependency tests
            var (MangoAvalanchePayload, _, MangoKeyDependencyPayload, _) =
                ProcessAvalancheAndKeyDependency(
                    localEnv.Crypto,
                    localEnv.Globals.Input,
                    GlobalsInstance.Password,
                    profile);

            // 📊 Run cryptanalysis
            return localEnv.CryptoAnalysis.RunCryptAnalysis(
                payload,
                MangoAvalanchePayload,
                MangoKeyDependencyPayload,
                localEnv.Globals.Input);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error during sequence testing: {ex.Message}\nSequence: {Convert.ToHexString(sequence)}");
            return null;
        }
    }
    public sealed class BatchModeScope : IDisposable
    {
        private readonly ExecutionEnvironment _env;
        private readonly bool _original;

        public BatchModeScope(ExecutionEnvironment env, bool mode = true)
        {
            _env = env;
            _original = env.Globals.BatchMode;
            env.Globals.BatchMode = mode;
        }

        public void Dispose() => _env.Globals.BatchMode = _original;
    }

    public static bool IsInteractiveWorkbench(ExecutionEnvironment env)
    {
        return env.Globals is { ExitJobComplete: false, BatchMode: false };
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
    public static int? ParseForInt(string[] args, string keyword)
    {
        int index = Array.IndexOf(args, keyword);
        if (index == -1)
            return null;

        if (index + 1 >= args.Length || !int.TryParse(args[index + 1], out var value))
            throw new ArgumentException($"Bad or missing parameter for command argument {keyword}");

        return value;
    }

    #region Benchmark Stuff
    public static void EstablishCurrentBenchmarkTime(ExecutionEnvironment parentEnv)
    {
        var localEnv = new ExecutionEnvironment(parentEnv);
        const int benchmarkTransformId = 35; // MaskedCascadeSubFwdFbTx
        var finalTimePerOp = 0.0;

        using (var localStatEnvironment = new LocalEnvironment(localEnv))
        {
            var sampleInput = SetupStandardBenchmarkEnv(localEnv);

            // 🔧 Build a minimal InputProfile with TR:1 and GR:parent setting
            var profile = InputProfiler.CreateInputProfile(name: "benchmark",
                sequence: new[] { (byte)benchmarkTransformId },
                tRs: new byte[] { 1 },
                globalRounds: localEnv.Globals.Rounds
            );

            // Encrypt timing
            var sw = Stopwatch.StartNew();
            var encrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, sampleInput);
            sw.Stop();
            var encryptTime = sw.Elapsed.TotalMilliseconds / profile.GlobalRounds;

            // Decrypt timing
            sw.Restart();
            var decrypted = localEnv.Crypto.Decrypt(encrypted);
            sw.Stop();
            var decryptTime = sw.Elapsed.TotalMilliseconds / profile.GlobalRounds;

            finalTimePerOp = (encryptTime + decryptTime) / 2;

            // ☠️ WARNING: This must go to parentEnv, not localEnv!
            parentEnv.Globals.CurrentBenchmarkTime = finalTimePerOp;

            // Optional validation
            // Debug.Assert(decrypted.SequenceEqual(sampleInput));
        }
    }
    public static void BenchmarkAllTransforms(ExecutionEnvironment parentEnv)
    {
        var localEnv = new ExecutionEnvironment(parentEnv);
        var rawResults = new List<(string Text, string Name, byte Id, double TimePerOp)>();
        var totalTime = 0.0;

        using (var localStatEnvironment = new LocalEnvironment(localEnv))
        {
            var sampleInput = SetupStandardBenchmarkEnv(localEnv);
            var globalRounds = localEnv.Globals.Rounds;

            foreach (var kvp in localEnv.Crypto.TransformRegistry)
            {
                var transformId = (byte)kvp.Key;
                var transform = kvp.Value;

                var profile = InputProfiler.CreateInputProfile(name: transform.Name,
                    sequence: new[] { transformId },
                    tRs: new byte[] { 1 },
                    globalRounds: globalRounds
                );

                var sw = Stopwatch.StartNew();
                var encrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, sampleInput);
                sw.Stop();
                var encryptTime = sw.Elapsed.TotalMilliseconds / profile.GlobalRounds;

                sw.Restart();
                var decrypted = localEnv.Crypto.Decrypt(encrypted);
                sw.Stop();
                var decryptTime = sw.Elapsed.TotalMilliseconds / profile.GlobalRounds;

                var timePerOp = (encryptTime + decryptTime) / 2.0;
                totalTime += timePerOp;

                var result = $"Transform: {transform.Name} (Id: {transformId}) | Avg time per op: {timePerOp:F4} ms";
                rawResults.Add((result, transform.Name, transformId, timePerOp));
            }
        }

        // ✅ Sort by timePerOp (ascending)
        var sorted = rawResults.OrderBy(r => r.TimePerOp).ToList();

        // Build sorted output
        var results = sorted.Select(r => r.Text).ToList();
        var jsonResults = sorted.Select(r => new { Name = r.Name, Id = r.Id, TimePerOpMs = r.TimePerOp }).ToList();

        var totalSummary = $"Total Benchmark Time Across All Transforms: {totalTime:F4} ms";
        results.Add("");
        results.Add(totalSummary);
        Console.WriteLine();
        foreach (var line in results) Console.WriteLine(line);

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

    private static byte[] SetupStandardBenchmarkEnv(ExecutionEnvironment env)
    {
        env.Globals.UpdateSetting("InputType", InputType.Random);
        env.Globals.UpdateSetting("Rounds", byte.MaxValue);

        // Force re-profiling of input in case InputType changed
        return env.Globals.Input;
    }

    public static void SetBenchmarkBaselineTime(ExecutionEnvironment localEnv)
    {
        const int AnchorTransform = 35; // MaskedCascadeSubFwdFbTx
        if (BenchmarkCache.TryGetValue(AnchorTransform, out var baselineTime))
            localEnv.Globals.BenchmarkBaselineTime = baselineTime;
        else
            throw new InvalidOperationException($"Benchmark time for Anchor Transform ID {AnchorTransform} not found in BenchmarkCache.");
    }

    public static Dictionary<int, double> BenchmarkCache = new();

    private static readonly object CacheLock = new();

    public static void LoadBenchmarkCache()
    {
        try
        {
            var json = File.ReadAllText("TransformBenchmarkResults.json");
            var parsed = System.Text.Json.JsonSerializer.Deserialize<List<TransformBenchmark>>(json);

            BenchmarkCache = parsed!.ToDictionary(x => x.Id, x => x.TimePerOpMs);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[Error] Failed to load benchmark cache: {ex.Message}");
            throw; // Fail loudly since benchmarks are required!
        }
    }

    public static void FlushAndReloadBenchmarkCache()
    {
        lock (CacheLock)
        {
            // Clear existing cache
            BenchmarkCache!.Clear();

            // Reload benchmark data from disk
            LoadBenchmarkCache();
        }
    }

    private class TransformBenchmark
    {
        //public string Name { get; set; }
        public int Id { get; set; }
        public double TimePerOpMs { get; set; }
    }

    #endregion Benchmark Stuff
}