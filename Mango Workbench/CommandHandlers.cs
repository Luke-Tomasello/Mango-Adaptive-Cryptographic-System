/*
 * CommandHandlers Module
 * =============================================
 * Project: Mango
 * Purpose: Central dispatch for Mango's interactive and batch commands.
 *          Contains handlers for transform profiling, regression tests,
 *          configuration access, visualization, and interactive analysis.
 *
 *          This module supports:
 *            • Command-line handlers for CLI and REPL use
 *            • Settings retrieval and configuration updates
 *            • AES vs Mango comparative analysis
 *            • Regression testing and benchmark execution
 *            • Weight tuning, profiling, and smart reporting utilities
 *
 *          Interfaces directly with MangoConsole and Workbench layers
 *          to interpret user commands and trigger core functionality.
 *
 * Author: [Luke Tomasello, luke@tomasello.com]
 * Created: November 2024
 * License: [MIT]
 * =============================================
 */

using Mango.Adaptive;
using Mango.Analysis;
using Mango.Cipher;
using Mango.Reporting;
using Mango.SQL;
using Mango.Utilities;
using System.Diagnostics;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using static Mango.Utilities.TestInputGenerator;
using static Mango.Utilities.UtilityHelpers;

namespace Mango.Workbench;

public partial class Handlers
{
    public enum LogType
    {
        Informational,
        Error,
        Warning,
        Debug
    }

    public static (string, ConsoleColor) RunRegressionTests(ExecutionEnvironment localEnv)
    {
        try
        {
            RegressionTests.RunRegressionTests(localEnv);
            return ("Run Regression Tests completed successfully.", ConsoleColor.Green);
        }
        catch (Exception ex)
        {
            return ($"❌ Regression Test Failure: {ex.Message}", ConsoleColor.Red);
        }
    }

    public static (string, ConsoleColor) ProfileTransforms(ExecutionEnvironment localEnv, string[] args)
    {
        var results = ProfileTransformsWorker(localEnv, args);

        Console.WriteLine("\nPress any key to return to the main menu...");
        Console.ReadKey();

        return results;
    }

    public static (string, ConsoleColor) ProfileTransformsWorker(ExecutionEnvironment parentEnv, string[] args)
    {
        if (args.Length < 1)
            return ("[Error] Please specify a profile name (e.g., ApplyTransforms[X] + GetCoins[X])",
                ConsoleColor.Red);

        var testName = string.Join(" ", args);
        var rounds = 1000;

        var jsonPath = "TransformProfileResults.json";
        var resultCache = File.Exists(jsonPath)
            ? JsonSerializer.Deserialize<Dictionary<string, double>>(File.ReadAllText(jsonPath))
            : new Dictionary<string, double>();

        Console.WriteLine($"Running profile test: {testName}...");
        var performanceScore = ProfileTransformsCore(parentEnv, rounds);

        resultCache![testName] = performanceScore;

        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
        File.WriteAllText(jsonPath, JsonSerializer.Serialize(resultCache, jsonOptions));

        Console.WriteLine("\n=== Performance Results ===");
        foreach (var kv in resultCache.OrderBy(kv => kv.Value)) Console.WriteLine($"{kv.Key}: {kv.Value:F4} ms");

        return ($"✅ Profile test '{testName}' completed.", ConsoleColor.Green);
    }

    public static double ProfileTransformsCore(ExecutionEnvironment parentEnv, int rounds)
    {
        var localEnv = new ExecutionEnvironment(parentEnv);
        localEnv.Globals.UpdateSetting("InputType", InputType.Random);
        localEnv.Globals.UpdateSetting("Rounds", 1); // We'll loop manually

        // Build the pairs list (deduplicated)
        var transformRegistry = localEnv.Crypto.TransformRegistry;
        var pairedIds = new HashSet<byte>();
        var transformPairs = new List<(byte ForwardId, byte InverseId)>();

        foreach (var kvp in transformRegistry)
        {
            var id = (byte)kvp.Key;
            var transform = kvp.Value;

            if (transform.ExcludeFromPermutations || pairedIds.Contains(id))
                continue;

            var inverseId = (byte)transform.InverseId;
            transformPairs.Add((id, inverseId));

            // Mark both as handled (works for self-inverse too)
            pairedIds.Add(id);
            pairedIds.Add(inverseId);
        }

        // Thread pool setup
        var threadPoolSize = Environment.ProcessorCount;
        using var semaphore = new SemaphoreSlim(threadPoolSize);
        var tasks = new List<Task>(transformPairs.Count);

        var grandTotalTimeMs = 0.0;
        var locker = new object();

        foreach (var (forwardId, inverseId) in transformPairs)
        {
            semaphore.Wait();

            tasks.Add(Task.Run(() =>
            {
                try
                {
                    var forwardTx = transformRegistry[forwardId];
                    var inverseTx = transformRegistry[inverseId];

                    var input = localEnv.Globals.Input;
                    var timings = new double[rounds];

                    for (var i = 0; i < rounds; i++)
                    {
                        var sw = Stopwatch.StartNew();
                        var encrypted = localEnv.Crypto.Encrypt(new[] { forwardId }, input);
                        var decrypted = localEnv.Crypto.Decrypt(new[] { inverseId }, encrypted);
                        sw.Stop();

                        timings[i] = sw.Elapsed.TotalMilliseconds;
                    }

                    var best = timings.Min();
                    lock (locker)
                    {
                        grandTotalTimeMs += best;
                    }
                }
                finally
                {
                    semaphore.Release();
                }
            }));
        }

        Task.WaitAll(tasks.ToArray());

        return grandTotalTimeMs;
    }

    public static (string, ConsoleColor) BenchmarkTransforms(ExecutionEnvironment localEnv, string[] args)
    {
        // ⚠️ Warn user about overwriting existing benchmark data
        ColorConsole.WriteLine(
            "<Yellow>WARNING:</Yellow> This will overwrite all existing benchmark data in <Cyan>TransformBenchmarkResults.txt</Cyan> and <Cyan>TransformBenchmarkResults.json</Cyan>.");
        Console.Write("Are you sure you want to continue? (Y/N): ");

        var key = Console.ReadKey(true);
        Console.WriteLine(); // For clean line break after keypress

        if (key.Key != ConsoleKey.Y) return ("Run benchmark transforms canceled by user.", ConsoleColor.Red);

        // ✅ Execute the full benchmarking suite across all registered transforms.
        // // This will measure and output individual transform timings to benchmark result files.
        BenchmarkAllTransforms(localEnv);

        // ✅ Refresh the benchmark cache to ensure the latest benchmark data is loaded from disk.
        // // This clears any stale in-memory data and reloads updated timing information.
        CryptoLib.FlushAndReloadBenchmarkCache();

        // ✅ Apply the freshly loaded benchmark timings to all transforms in the active registry.
        // // This populates each transform’s BenchmarkTimeMs property for in-memory use.
        localEnv.Crypto.AssignBenchmarkValues();

        // ✅ Set the global baseline benchmark time used for normalization and comparison.
        // // Typically sourced from a designated representative transform (e.g., ID 35).
        SetBenchmarkBaselineTime(localEnv);

        ColorConsole.WriteLine("<Green>Run benchmark transforms complete.</Green>");
        Console.WriteLine("\nPress any key to exit...");
        Console.ReadKey();

        return ("Run benchmark transforms completed successfully.", ConsoleColor.Green);
    }

    public static (string, ConsoleColor) QueryHandler(ExecutionEnvironment localEnv, string[] args)
    {
        // Validate args length
        if (args.Length < 1)
            return ("Query requires at least one argument.", ConsoleColor.Red);

        var key = args[0].ToLower(); // Normalize key to lowercase

        try
        {
            switch (key)
            {
#if true
                case "inputtype":
                {
                    var totalLength = localEnv.Globals.Input.Length;
                    int fullChunks = totalLength / 4096;
                    int remainder = totalLength % 4096;

                    Console.WriteLine($"Input Type: {localEnv.Globals.InputType}");
                    Console.WriteLine($"Input Size: {totalLength:N0} bytes ({fullChunks} full chunks of 4096)");

                    for (int i = 0; i < fullChunks; i++)
                    {
                        var chunk = localEnv.Globals.Input.Skip(i * 4096).Take(4096).ToArray();
                        var first16Bytes = string.Join(" ", chunk.Take(16).Select(b => b.ToString("X2")));
                        Console.WriteLine($"Chunk {i + 1}: {first16Bytes}");
                    }

                    if (remainder > 0)
                    {
                        var lastChunk = localEnv.Globals.Input.Skip(fullChunks * 4096).ToArray();
                        var first16Bytes = string.Join(" ", lastChunk.Take(16).Select(b => b.ToString("X2")));
                        Console.WriteLine($"(Partial) Chunk {fullChunks + 1}: {first16Bytes} ({lastChunk.Length} bytes)");
                    }

                    Console.WriteLine("\nPress any key to return to the main menu...");
                    Console.ReadKey();
                    break;
                }

#else
                case "inputtype":
                    if (localEnv.Globals.Input.Length % 4096 != 0)
                        return ("Input length must be a multiple of 4096 bytes.", ConsoleColor.Red);

                    var chunkCount = localEnv.Globals.Input.Length / 4096;
                    Console.WriteLine($"Input Type: {localEnv.Globals.InputType}");
                    Console.WriteLine(
                        $"Input Size: {localEnv.Globals.Input.Length} bytes ({chunkCount} chunks of 4096 bytes)");

                    for (var i = 0; i < chunkCount; i++)
                    {
                        var chunk = localEnv.Globals.Input.Skip(i * 4096).Take(4096).ToArray();
                        var first16Bytes = string.Join(" ", chunk.Take(16).Select(b => b.ToString("X2")));
                        Console.WriteLine($"Chunk {i + 1}: {first16Bytes}");
                    }

                    Console.WriteLine("\nPress any key to return to the main menu...");
                    Console.ReadKey();
                    break;
#endif
                case "weights":
                    {
                        if (localEnv.Globals.Mode == OperationModes.None)
                            return ("Error: Mode is not set.", ConsoleColor.Red);

                        // Retrieve actual weights from MetricsRegistry
                        var actualWeights =
                            localEnv.CryptoAnalysis.MetricsRegistry.ToDictionary(kvp => kvp.Key,
                                kvp => kvp.Value.Weight);

                        // Retrieve known weight tables dynamically
                        var foundCryptographic = MetricInfoHelper.TryGetWeights(OperationModes.Cryptographic,
                            out var cryptographicWeights);
                        var foundExploratory =
                            MetricInfoHelper.TryGetWeights(OperationModes.Exploratory, out var exploratoryWeights);

                        if (!foundCryptographic || !foundExploratory)
                            return ("Error: Could not retrieve predefined mode weights.", ConsoleColor.Red);

                        // Compare the active weights to the official tables
                        var matchesCryptographic = actualWeights.OrderBy(kvp => kvp.Key)
                            .SequenceEqual(cryptographicWeights.OrderBy(kvp => kvp.Key));
                        var matchesExploratory = actualWeights.OrderBy(kvp => kvp.Key)
                            .SequenceEqual(exploratoryWeights.OrderBy(kvp => kvp.Key));

                        // Determine the mode label
                        string modeLabel;
                        if (matchesCryptographic && !matchesExploratory)
                            modeLabel = "<green>Active Mode: Cryptographic</green>";
                        else if (matchesExploratory && !matchesCryptographic)
                            modeLabel = "<green>Active Mode: Exploratory</green>";
                        else
                            modeLabel = "<yellow>Active Mode: None (No Weighting)</yellow>";
                        ;

                        // Display weights with detected mode label
                        ColorConsole.WriteLine($"{modeLabel}\n");
                        foreach (var kvp in actualWeights)
                            Console.WriteLine(
                                $"{kvp.Key,-22}: {kvp.Value:F4}"); // Left-align metric names, format weight to 4 decimals

                        Console.WriteLine("\nPress any key to return to the main menu...");
                        Console.ReadKey();
                        break;
                    }


                default:
                    return ($"Unknown query: {args[0]}.", ConsoleColor.Red);
            }

            return ("Query processed successfully.", ConsoleColor.Green);
        }
        catch (FormatException)
        {
            return ($"Invalid value for {key}. Please provide valid input.", ConsoleColor.Red);
        }
        catch (ArgumentException)
        {
            return ($"Invalid value for {key}. Allowed values depend on the key.", ConsoleColor.Red);
        }
        catch (Exception ex)
        {
            return ($"Error processing query {key}: {ex.Message}", ConsoleColor.Red);
        }
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

    public static (string, ConsoleColor) GetSettingsHandler(string[] args)
    {
        var properties = typeof(GlobalsInstance).GetProperties(BindingFlags.Public | BindingFlags.Instance)
            .Where(p => p.IsDefined(typeof(GlobalSettingAttribute)) && p.CanRead)
            .ToList();

        if (args.Length == 0)
        {
            // Only show non-debug settings unless debugging is enabled
            var visibleProperties = properties
                .Where(p => !(p.GetCustomAttribute<GlobalSettingAttribute>()?.IsDebugOnly ?? false) ||
                            Debugger.IsAttached)
                .Where(p => p.GetCustomAttribute<GlobalSettingAttribute>()?.RelatedProperties ==
                            null) // Hide related props
                .Select(p => p.Name);

            return ($"Usage: get <key>\nAvailable keys: {string.Join(", ", visibleProperties)}",
                ConsoleColor.Yellow);
        }

        var key = args[0];

        // ✅ Check if it's a compound setting (e.g., "Reporting")
        var compoundProperty = properties
            .FirstOrDefault(p =>
                p.GetCustomAttribute<GlobalSettingAttribute>()?.RelatedProperties?.Length > 0 && p.Name == key);

        if (compoundProperty != null)
        {
            var compoundAttribute = compoundProperty.GetCustomAttribute<GlobalSettingAttribute>();

            // 🎯 Generate the derived value (e.g., "RTF, foo.rtf" for Reporting)
            var relatedValues = (compoundAttribute!.RelatedProperties ?? Array.Empty<string>())
                .Select(propName =>
                {
                    var prop = properties.FirstOrDefault(p => p.Name == propName);
                    return prop?.GetValue(null)?.ToString() ?? "<unset>";
                })
                .Where(val => !string.IsNullOrEmpty(val)) // Remove empty values
                .ToList();

            var derivedValue = relatedValues.Any() ? string.Join(", ", relatedValues) : "<unset>";

            return ($"{key} = {derivedValue}", ConsoleColor.Green);
        }

        // ✅ Handle regular settings
        var property =
            properties.FirstOrDefault(p => string.Equals(p.Name, key, StringComparison.OrdinalIgnoreCase));

        if (property == null) return ($"Unknown or inaccessible key: {key}.", ConsoleColor.Red);

        // 🚨 Hide debug-only settings if not debugging
        var attribute = property.GetCustomAttribute<GlobalSettingAttribute>();
        if (attribute?.IsDebugOnly == true && !Debugger.IsAttached)
            return ($"Unknown or inaccessible key: {key}.", ConsoleColor.Red);

        var value = property.GetValue(null);

        // 🛠 Special formatting for OperationModes
        if (property.PropertyType == typeof(OperationModes)) value = $"{value}";

        return ($"{key} = {value}", ConsoleColor.Green);
    }

    public static (string, ConsoleColor) SetSettingsHandler(ExecutionEnvironment localEnv, string[] args)
    {
        if (args.Length < 2) return ("<Yellow>Usage: set <key> <value></Yellow>", Console.ForegroundColor);

        var key = args[0];
        var value = string.Join(" ", args.Skip(1)); // Combine all args after the key into a single string

        try
        {
            var properties = typeof(GlobalsInstance).GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .Where(p => p.IsDefined(typeof(GlobalSettingAttribute)))
                .ToDictionary(p => p.Name, p => p,
                    StringComparer.OrdinalIgnoreCase); // ✅ Case-insensitive dictionary

            // 🔍 **Check if the key belongs to a compound setting**
            var compoundProperty = properties.Values
                .FirstOrDefault(p => string.Equals(p.Name, key, StringComparison.OrdinalIgnoreCase) &&
                                     p.GetCustomAttribute<GlobalSettingAttribute>()?.RelatedProperties != null);

            if (compoundProperty != null)
            {
                var compoundAttribute = compoundProperty.GetCustomAttribute<GlobalSettingAttribute>();

                // 🛠 **Parse user input into separate values**
                string[] values = Regex.Matches(value, @"[^\s""]+|""([^""]*)""")
                    .Cast<Match>()
                    .Select(m => (m.Groups[1].Success ? m.Groups[1].Value : m.Value).Trim()) // ✅ Trim each result
                    .ToArray();

                var requiredArguments = compoundAttribute!.RelatedProperties!.Length;

                // 🚨 **If SCR is selected, enforce its constraints**
                var isSCR = values.Length > 0 && values[0]!.Equals("SCR", StringComparison.OrdinalIgnoreCase);
                var warningMessage = "";

                if (isSCR)
                {
                    if (values.Length > 1)
                        warningMessage = "<Yellow>[NOTE] SCR output does not take a filename.</Yellow>\n";

                    values = new string[] { "SCR" }; // ✅ Only SCR remains
                }

                // 🔍 **Ensure we only take the required number of arguments**
                if (values.Length > requiredArguments)
                    return (
                        $"<Yellow>Warning:</Yellow> Too many arguments provided for <Green>{key}</Green>. Ignoring extra values.",
                        Console.ForegroundColor);

                // 🚨 **Explicitly clear any extra related properties**
                for (var i = values.Length; i < requiredArguments; i++)
                    if (properties.TryGetValue(compoundAttribute.RelatedProperties[i], out var extraProperty))
                    {
                        var defaultValue = extraProperty.PropertyType.IsValueType
                            ? Activator.CreateInstance(extraProperty
                                .PropertyType) // ✅ Default for value types (0 for int, false for bool, etc.)
                            : null; // ✅ Default for reference types (null)

                        localEnv.Globals.UpdateSetting(extraProperty.Name, defaultValue);
                    }

                // ✅ **Update each related property**
                for (var i = 0; i < values.Length; i++)
                    if (properties.TryGetValue(compoundAttribute.RelatedProperties[i], out var relatedProperty))
                        localEnv.Globals.UpdateSetting(relatedProperty.Name, values[i]);

                // 🔹 **Final return message: If a warning was generated, prepend it**
                return ($"{warningMessage}<Green>{key}</Green> updated to: <Green>{value}</Green>",
                    Console.ForegroundColor);
            }

            // 🔍 Handle **regular settings**
            if (!properties.TryGetValue(key, out var property))
                return ($"<Red>Unknown or inaccessible key:</Red> <Green>{key}</Green>", Console.ForegroundColor);

            // 🚫 **Check if it's a debug-only setting**
            var globalAttribute = property.GetCustomAttribute<GlobalSettingAttribute>();
            if (globalAttribute?.IsDebugOnly == true && !Debugger.IsAttached)
                return ($"<Red>Cannot modify debug-only setting:</Red> <Green>{key}</Green>",
                    Console.ForegroundColor);

            // ✅ **Update the setting**
            var sequenceHandler = new SequenceAttributesHandler(localEnv);
            var convertedValue = sequenceHandler.ConvertValue(property.PropertyType, value);

            // 🛡️ Guard: Prevent setting InputType = UserData unless UserData.bin exists
            if (key.Equals("inputtype", StringComparison.OrdinalIgnoreCase) &&
                value.Equals("userdata", StringComparison.OrdinalIgnoreCase) &&
                !File.Exists("UserData.bin"))
            {
                return ("⚠️ Cannot switch to UserData input: UserData.bin not found. Use 'load user data <file>' to load your data first.", ConsoleColor.Yellow);
            }
            localEnv.Globals.UpdateSetting(key, convertedValue);

            // ✅ immediat save
            localEnv.Globals.Save();

            return ($"<Green>{key}</Green> updated to: <Green>{value}</Green>", Console.ForegroundColor);
        }
        catch (Exception ex)
        {
            return ($"<Red>Error updating {key}:</Red> {ex.Message}", Console.ForegroundColor);
        }
    }

    public static (string, ConsoleColor) ListSettingsHandler(ExecutionEnvironment localEnv, string[] args)
    {
        var properties = typeof(GlobalsInstance).GetProperties(BindingFlags.Instance | BindingFlags.Public)
            .Where(p =>
            {
                var attr = p.GetCustomAttribute<GlobalSettingAttribute>();
                return attr != null && !attr.IsInternal && (!attr.IsDebugOnly || Debugger.IsAttached);
            })
            .ToList();

        if (!properties.Any()) return ("No accessible settings found.", ConsoleColor.Yellow);

        var settingsList = new StringBuilder();
        settingsList.AppendLine("Global Settings:");

        var displayedCompoundSettings = new HashSet<string>(); // ✅ Prevent duplicate listings

        foreach (var property in properties)
        {
            var attr = property.GetCustomAttribute<GlobalSettingAttribute>();

            // 🛑 **If it's a compound setting (like Reporting), show it normally**
            if (attr?.RelatedProperties?.Length > 0)
            {
                if (displayedCompoundSettings.Contains(property.Name))
                    continue; // ✅ Already displayed

                displayedCompoundSettings.Add(property.Name);

                // 🛠 **Build compound setting display from related properties**
                var relatedValues = attr.RelatedProperties
                    .Select(propName =>
                        typeof(GlobalsInstance).GetProperty(propName, BindingFlags.Instance | BindingFlags.Public)
                            ?.GetValue(localEnv.Globals))
                    .Where(val => val != null)
                    .ToList();

                var compoundValue = string.Join(", ", relatedValues); // 🔄 Renamed to avoid shadowing
                settingsList.AppendLine($"- {property.Name}: {compoundValue}");
                continue;
            }

            // 🛠 **If this property is part of a compound setting, only display it when debugging**
            var isPartOfCompound = properties.Any(p =>
                p.GetCustomAttribute<GlobalSettingAttribute>()?.RelatedProperties?.Contains(property.Name) == true);

            if (isPartOfCompound && !Debugger.IsAttached)
                continue; // ✅ Skip in normal mode, but allow in debug mode

            var name = property.Name;
            var settingValue = property.GetValue(localEnv.Globals) ?? "<not set>"; // 🔄 Renamed to avoid shadowing

            // 🛠 **Special formatting for OperationModes**
            if (property.PropertyType == typeof(OperationModes)) settingValue = $"{settingValue}";

            settingsList.AppendLine($"- {name}: {settingValue}");
        }

        return (settingsList.ToString(), ConsoleColor.Green);
    }

    public static (string, ConsoleColor) AnalyzerHandler()
    {
        try
        {
            ContenderAnalyzer.AnalyzeAndReport(".");

            // Pause the output
            Console.WriteLine("\nPress any key to return to the main menu...");
            Console.ReadKey();

            return ($"Contender Analyzer completed.", ConsoleColor.Green);
        }
        catch (Exception ex)
        {
            return ($"Error: {ex.Message}", ConsoleColor.Red);
        }
        finally
        {
        }
    }

    public static (string, ConsoleColor) VisualizationHandler(ExecutionEnvironment localEnv,
        List<byte> userSequence, string[] args)
    {
        // Normalize arguments to uppercase for case-insensitive handling
        var normalizedArgs = args.Select(arg => arg.ToUpperInvariant()).ToArray();

        var mode = normalizedArgs.Contains("BYTES") ? "BYTES" : "BITS";
        var rows = normalizedArgs.Contains("ROWS")
            ? int.Parse(normalizedArgs[Array.IndexOf(normalizedArgs, "ROWS") + 1])
            : 1;
        var columns = normalizedArgs.Contains("COLUMNS")
            ? int.Parse(normalizedArgs[Array.IndexOf(normalizedArgs, "COLUMNS") + 1])
            : 16;
        var offset = normalizedArgs.Contains("OFFSET")
            ? int.Parse(normalizedArgs[Array.IndexOf(normalizedArgs, "OFFSET") + 1])
            : 0;
        var format = normalizedArgs.Contains("ASCII") ? "ASCII" : "HEX";

        // Store results for each transform in the sequence
        List<byte[]> results = new();

        // Ensure input is not modified by making a copy
        var previousEncrypted = localEnv.Globals.Input.ToArray();

        foreach (var transformId in userSequence)
        {
            // Apply the transform and get the encrypted result
            var transformInputCopy = previousEncrypted!.ToArray(); // Ensure transform input is untouched
            var encrypted = localEnv.Crypto.Encrypt(new byte[] { transformId }, transformInputCopy);

            // Extract payload (removes Mango header)
            var payload = localEnv.Crypto.GetPayloadOnly(encrypted);

            // Add the result to the list
            results.Add(payload);

            // Update previousEncrypted for the next iteration
            previousEncrypted = payload;
        }

        if (!results.Any()) return ("No valid sequences found.", ConsoleColor.Yellow);

        // Visualization
        Console.WriteLine("Visualization of Sequence:");
        Console.WriteLine("--------------------------------------------------");

        // Ensure input is untouched when visualizing
        var inputCopy = localEnv.Globals.Input.ToArray();
        var inputRows = Visualizer.Format(inputCopy, inputCopy, mode, rows, columns,
            offset, format);

        foreach (var (row, rowIndex) in inputRows.Select((value, i) => (value, i)))
        {
            var label = rowIndex == 0 ? Field("Input", 20) : new string(' ', 20);
            ColorConsole.WriteLine($"{label}{row}");
        }

        // Iterate over the sequence and display results
        previousEncrypted = localEnv.Globals.Input.ToArray(); // Copy input again to ensure no mutation

        foreach (var (encrypted, index) in results.Select((value, i) => (value, i)))
        {
            var transformName = Field(
                new SequenceHelper(localEnv.Crypto).FormattedSequence(new byte[] { userSequence[index] },
                    SequenceFormat.Bare)!, 20);

            // Ensure previousEncrypted is unmodified by making a copy
            var previousCopy = previousEncrypted!.ToArray();
            var transformRows = Visualizer.Format(previousCopy, encrypted, mode, rows, columns,
                offset, format);

            foreach (var (row, rowIndex) in transformRows.Select((value, i) => (value, i)))
            {
                var label = rowIndex == 0 ? transformName : new string(' ', 20);
                ColorConsole.WriteLine($"{label}{row}");
            }

            // Update previousEncrypted for the next transform
            previousEncrypted = encrypted;
        }

        Console.WriteLine("--------------------------------------------------");

        // Pause the output
        Console.WriteLine("\nPress any key to return to the main menu...");
        Console.ReadKey();

        return ("Visualization completed successfully.", ConsoleColor.Green);
    }

    public static (string, ConsoleColor) LoadUserDataHandler(ExecutionEnvironment localEnv, string[] args)
    {
        // 🔒 Cap to 10 MB
        const int MaxAllowedBytes = 10 * 1024 * 1024;

        if (args.Length == 0)
            return ("❌ Please specify a file name.", ConsoleColor.Red);

        // Parse arguments: filename (may contain spaces), optional -max <bytes>
        string joined = string.Join(' ', args);
        int maxBytes = MaxAllowedBytes;

        // Look for optional "-max NNN" pattern
        var maxMatch = Regex.Match(joined, @"-max\s+(\d+)", RegexOptions.IgnoreCase);
        if (maxMatch.Success && int.TryParse(maxMatch.Groups[1].Value, out int parsedMax))
            maxBytes = Math.Min(parsedMax, MaxAllowedBytes); // Enforce hard cap

        // Remove -max section to isolate the filename
        string cleaned = maxMatch.Success ? joined.Remove(maxMatch.Index).Trim() : joined.Trim();
        string filename = cleaned.Trim('"');

        if (!File.Exists(filename))
            return ($"❌ Could not load \"{filename}\" — file not found.", ConsoleColor.Red);

        try
        {
            byte[] bytesLoaded;
            using (FileStream fs = File.OpenRead(filename))
            {
                int length = (int)Math.Min(fs.Length, maxBytes);
                bytesLoaded = new byte[length];
                int bytesRead = fs.Read(bytesLoaded, 0, length);
                if (bytesRead < length)
                    Array.Resize(ref bytesLoaded, bytesRead);
            }

            InitializeUserData(bytesLoaded);
            localEnv.Globals.UpdateSetting("InputType", InputType.UserData);
            return ($"✅ Loaded {bytesLoaded.Length:N0} bytes from \"{filename}\" as user data.", ConsoleColor.Green);
        }
        catch (Exception ex)
        {
            return ($"❌ Failed to load \"{filename}\": {ex.Message}", ConsoleColor.Red);
        }
    }


    #region ComparativeAnalysis

    public static (string, ConsoleColor) RunComparativeAnalysisHandler(ExecutionEnvironment localEnv, List<string> sequence)
    {
        // ✅ LocalEnvironment parses the sequence and sets the Global Rounds, which are then used throughout localStateEnv
        using (var localStateEnv = new LocalEnvironment(localEnv, sequence))
        {
            // ✅ Run the sequence using **IDs only** (TR is now applied, GR is handled globally)
            return RunComparativeAnalysis(localEnv, localStateEnv.ParsedSequence);
        }
    }

    /// <summary>
    /// Runs a high-volume throughput benchmark comparing Mango vs AES across all supported input types.
    /// 
    /// For each type (Combined, Random, Natural, Sequence), this test:
    /// - Encrypts and decrypts a series of fixed-size blocks using Mango and AES
    /// - Times only the core encryption/decryption paths (excluding setup overhead)
    /// - Reports speeds in MB/s and Gbps
    /// - Produces a final average comparison across all types
    /// 
    /// Returns a formatted string summary and a color code for visual CLI feedback.
    /// </summary>
    /// <param name="localEnv">The active execution environment, containing CryptoLib instance and configuration context.</param>
    /// <returns>A tuple containing the benchmark summary and console display color.</returns>
    public static (string, ConsoleColor) RunComparativeThroughput(ExecutionEnvironment localEnv)
    {
        var blockCount = 128;
        var blockSize = 4096;
        var decrypt = true;
        var resultBuilder = new StringBuilder();
        var color = ConsoleColor.Gray;

        double totalMangoEncryptBytes = 0, totalMangoEncryptTime = 0;
        double totalMangoDecryptBytes = 0, totalMangoDecryptTime = 0;
        double totalAesEncryptBytes = 0, totalAesEncryptTime = 0;
        double totalAesDecryptBytes = 0, totalAesDecryptTime = 0;

        foreach (InputType type in Enum.GetValues(typeof(InputType)))
        {
            if (type == InputType.UserData)
                continue; // ❌ Skip throughput test for UserData

            List<byte[]> inputBlocks = new();
            for (var i = 0; i < blockCount; i++)
                inputBlocks.Add(GenerateTestInput(blockSize, type));

            var profile = InputProfiler.GetInputProfile(inputBlocks[0]);

            List<byte[]> mangoEncryptedBlocks = new();
            var encryptedFirst = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, inputBlocks[0]);
            mangoEncryptedBlocks.Add(encryptedFirst);

            var swEncrypt = Stopwatch.StartNew();
            for (var i = 1; i < inputBlocks.Count; i++)
            {
                var encrypted = localEnv.Crypto.EncryptBlock(inputBlocks[i]);
                mangoEncryptedBlocks.Add(encrypted);
            }

            swEncrypt.Stop();

            double mangoEncryptBytes = (blockCount - 1) * blockSize;
            var mangoEncryptMBps = mangoEncryptBytes / (1024.0 * 1024.0) / swEncrypt.Elapsed.TotalSeconds;
            var mangoEncryptBps = mangoEncryptBytes * 8 / swEncrypt.Elapsed.TotalSeconds;

            totalMangoEncryptBytes += mangoEncryptBytes;
            totalMangoEncryptTime += swEncrypt.Elapsed.TotalSeconds;

            double mangoDecryptMBps = 0;
            double mangoDecryptBps = 0;

            if (decrypt)
            {
                List<byte[]> mangoDecryptedBlocks = new();
                var decryptedFirst = localEnv.Crypto.Decrypt(mangoEncryptedBlocks[0]);
                mangoDecryptedBlocks.Add(decryptedFirst);

                var swDecrypt = Stopwatch.StartNew();
                for (var i = 1; i < mangoEncryptedBlocks.Count; i++)
                {
                    var decrypted = localEnv.Crypto.DecryptBlock(mangoEncryptedBlocks[i]);
                    mangoDecryptedBlocks.Add(decrypted);
                }

                swDecrypt.Stop();

                double mangoDecryptBytes = (blockCount - 1) * blockSize;
                mangoDecryptMBps = mangoDecryptBytes / (1024.0 * 1024.0) / swDecrypt.Elapsed.TotalSeconds;
                mangoDecryptBps = mangoDecryptBytes * 8 / swDecrypt.Elapsed.TotalSeconds;

                totalMangoDecryptBytes += mangoDecryptBytes;
                totalMangoDecryptTime += swDecrypt.Elapsed.TotalSeconds;
            }

            var password = "mango_benchmark";
            var salt = GenerateRandomBytes(16);
            using var deriveBytes = new Rfc2898DeriveBytes(
                password,
                salt,
                250_000, // ⬅️ Strong iteration count
                HashAlgorithmName.SHA256 // ⬅️ Modern secure hash function
            );

            var aesKey = deriveBytes.GetBytes(32);
            var aesIV = deriveBytes.GetBytes(16);

            using var aes = Aes.Create();
            aes.Key = aesKey;
            aes.IV = aesIV;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            using var encryptor = aes.CreateEncryptor();
            using var decryptor = aes.CreateDecryptor();

            List<byte[]> aesEncryptedBlocks = new();

            var swAesEncrypt = Stopwatch.StartNew();
            for (var i = 0; i < inputBlocks.Count; i++)
            {
                var encrypted = encryptor.TransformFinalBlock(inputBlocks[i]!, 0, inputBlocks[i]!.Length);
                aesEncryptedBlocks.Add(encrypted);
            }

            swAesEncrypt.Stop();

            double aesEncryptBytes = blockCount * blockSize;
            var aesEncryptMBps = aesEncryptBytes / (1024.0 * 1024.0) / swAesEncrypt.Elapsed.TotalSeconds;
            var aesEncryptBps = aesEncryptBytes * 8 / swAesEncrypt.Elapsed.TotalSeconds;

            totalAesEncryptBytes += aesEncryptBytes;
            totalAesEncryptTime += swAesEncrypt.Elapsed.TotalSeconds;

            double aesDecryptMBps = 0;
            double aesDecryptBps = 0;

            if (decrypt)
            {
                List<byte[]> aesDecryptedBlocks = new();
                var swAesDecrypt = Stopwatch.StartNew();
                for (var i = 0; i < aesEncryptedBlocks.Count; i++)
                {
                    var decrypted =
                        decryptor.TransformFinalBlock(aesEncryptedBlocks[i], 0, aesEncryptedBlocks[i].Length);
                    aesDecryptedBlocks.Add(decrypted);
                }

                swAesDecrypt.Stop();

                double aesDecryptBytes = blockCount * blockSize;
                aesDecryptMBps = aesDecryptBytes / (1024.0 * 1024.0) / swAesDecrypt.Elapsed.TotalSeconds;
                aesDecryptBps = aesDecryptBytes * 8 / swAesDecrypt.Elapsed.TotalSeconds;

                totalAesDecryptBytes += aesDecryptBytes;
                totalAesDecryptTime += swAesDecrypt.Elapsed.TotalSeconds;
            }

            var speedRatio = mangoEncryptMBps / aesEncryptMBps;
            var assessment = speedRatio >= 1.2
                ? $"⚡ Mango is {speedRatio:F1}× faster than AES"
                : speedRatio < 0.9
                    ? $"🐢 Mango is {1 / speedRatio:F1}× slower than AES"
                    : "⚖️ Speeds are roughly equivalent";

            if (speedRatio >= 1.5)
                color = ConsoleColor.Green;
            else if (speedRatio <= 0.75)
                color = ConsoleColor.Red;
            else
                color = ConsoleColor.Yellow;

            resultBuilder.AppendLine($"Input Type: {type}");
            resultBuilder.AppendLine(
                $"Mango Encrypt: {mangoEncryptMBps:F2} MB/s ({mangoEncryptBps / 1_000_000_000:F2} Gbps)");
            if (decrypt)
                resultBuilder.AppendLine(
                    $"Mango Decrypt: {mangoDecryptMBps:F2} MB/s ({mangoDecryptBps / 1_000_000_000:F2} Gbps)");
            resultBuilder.AppendLine(
                $"AES Encrypt:   {aesEncryptMBps:F2} MB/s ({aesEncryptBps / 1_000_000_000:F2} Gbps)");
            if (decrypt)
                resultBuilder.AppendLine(
                    $"AES Decrypt:   {aesDecryptMBps:F2} MB/s ({aesDecryptBps / 1_000_000_000:F2} Gbps)");
            resultBuilder.AppendLine(assessment);
            resultBuilder.AppendLine(new string('-', 50));
        }

        var mangoAvgEncMBps = totalMangoEncryptBytes / (1024.0 * 1024.0) / totalMangoEncryptTime;
        var aesAvgEncMBps = totalAesEncryptBytes / (1024.0 * 1024.0) / totalAesEncryptTime;
        var mangoAvgEncBps = totalMangoEncryptBytes * 8 / totalMangoEncryptTime;
        var aesAvgEncBps = totalAesEncryptBytes * 8 / totalAesEncryptTime;
        var finalRatio = mangoAvgEncMBps / aesAvgEncMBps;

        resultBuilder.AppendLine("🏁 Overall Average:");
        resultBuilder.AppendLine(
            $"Mango Encrypt Avg: {mangoAvgEncMBps:F2} MB/s ({mangoAvgEncBps / 1_000_000_000:F2} Gbps)");
        resultBuilder.AppendLine(
            $"AES Encrypt Avg:   {aesAvgEncMBps:F2} MB/s ({aesAvgEncBps / 1_000_000_000:F2} Gbps)");
        resultBuilder.AppendLine($"⚡ Mango is {finalRatio:F1}× faster on average");

        return (resultBuilder.ToString(), color);
    }

    public static (string, ConsoleColor) RunComparativeAnalysis(ExecutionEnvironment localEnv,
        SequenceHelper.ParsedSequence parsedSequence)
    {
        SequenceHelper seqHelper = new(localEnv.Crypto);
        var sequence = seqHelper.GetIDs(parsedSequence);
        var formattedSequence = seqHelper.FormattedSequence<string>(parsedSequence,
            SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes,
            2, true);

        if (sequence.Count == 0) return ("No transforms in sequence. Add transforms before running.", ConsoleColor.Red);

        try
        {
            // Reset metrics and contenders before starting
            localEnv.CryptoAnalysis.Initialize();

            Console.WriteLine(
                $"\n--- Executing Comparative Analysis (GRounds: {localEnv.Crypto.Options.Rounds})---\n");

            // Measure Mango Encryption Time
            var stopwatch = Stopwatch.StartNew();
            var MangoEncrypted = localEnv.Crypto.Encrypt(sequence.ToArray(), localEnv.Globals.Input);
            stopwatch.Stop();
            var MangoTime = stopwatch.Elapsed;
            var MangoPayload = localEnv.Crypto.GetPayloadOnly(MangoEncrypted); // Extract payload for Mango encryption

            // Measure AES Encryption Time
            stopwatch = Stopwatch.StartNew();
            var AESPayload = AesEncrypt(localEnv.Globals.Input, GlobalsInstance.Password,
                out var saltLength,
                out var paddingLength);
            stopwatch.Stop();
            var AESTime = stopwatch.Elapsed;
            AESPayload = ExtractAESPayload(AESPayload, saltLength, paddingLength);

            // Modify a copy of input for Avalanche test and Key Dependency test
            var (MangoAvalanchePayload, AESAvalanchePayload, MangoKeyDependencyPayload, AESKeyDependencyPayload) =
                ProcessAvalancheAndKeyDependency(
                    localEnv,
                    GlobalsInstance.Password,
                    sequence,
                    true);

            // Mango Results
            var analysisResults = localEnv.CryptoAnalysis.RunCryptAnalysis(
                MangoPayload,
                MangoAvalanchePayload,
                MangoKeyDependencyPayload,
                localEnv.Globals.Input);

            var aggregateScore =
                localEnv.CryptoAnalysis.CalculateAggregateScore(analysisResults, localEnv.Globals.UseMetricScoring,
                    null);

            // Display cryptanalysis report
            var mangoHeader = GenerateHeader(
                localEnv,
                formattedSequence: formattedSequence,
                analysisResults: analysisResults,
                isReversible: true,
                name: "Mango'",
                options: HeaderOptions.AllAnalysis | HeaderOptions.Mode | HeaderOptions.InputType |
                         HeaderOptions.MetricScoring | HeaderOptions.PassCount
            );

            List<string> mangoAnalysis = localEnv.CryptoAnalysis.CryptAnalysisReport(localEnv.Crypto, analysisResults);
            List<string> mangoTiming = new List<string> { $"Mango Encryption took: {MangoTime.TotalMilliseconds} ms" };

            // AES Results
            analysisResults = localEnv.CryptoAnalysis.RunCryptAnalysis(
                AESPayload,
                AESAvalanchePayload,
                AESKeyDependencyPayload,
                localEnv.Globals.Input);

            aggregateScore =
                localEnv.CryptoAnalysis.CalculateAggregateScore(analysisResults, localEnv.Globals.UseMetricScoring);

            // Display cryptanalysis report: Dummy sequence for AES (it doesn't execute our sequences)
            var aesHeader = GenerateHeader(
                localEnv,
                formattedSequence: new SequenceHelper(localEnv.Crypto).FormattedSequence(new byte[] { },
                    SequenceFormat.None),
                analysisResults: analysisResults,
                isReversible: true,
                name: "AES'",
                options: HeaderOptions.AllAnalysis | HeaderOptions.Mode | HeaderOptions.InputType |
                         HeaderOptions.MetricScoring | HeaderOptions.PassCount
            );

            var aesAnalysis = localEnv.CryptoAnalysis.CryptAnalysisReport(localEnv.Crypto, analysisResults);
            var aesTiming = new List<string> { $"AES Encryption took: {AESTime.TotalMilliseconds} ms" };

            // ✅ Report all sections in **one call** (keeps them in the same output file)
            ReportHelper.Report(localEnv.Globals.ReportFormat,
                new List<string>[]
                {
                    mangoHeader, mangoAnalysis, mangoTiming,
                    ReportHelper.SectionBreak,
                    aesHeader, aesAnalysis, aesTiming
                },
                new string[] { localEnv.Globals.ReportFilename! });

            Console.WriteLine("\nPress any key to return to the menu...");
            Console.ReadKey();

            return ("Comparative Analysis complete.", ConsoleColor.Green);
        }
        catch (Exception ex)
        {
            return ($"Error during comparative analysis: {ex.Message}", ConsoleColor.Red);
        }
    }

    #endregion ComparativeAnalysis

    #region RunAutoTuneWeights

    /// <summary>
    /// Runs an automated weight tuning process to optimize metric weight distributions.
    /// This process iteratively adjusts metric weights, evaluating performance using a restricted set of transforms.
    /// </summary>
    /// <param name="babyMungeFile">The filename containing the top transform sequences extracted from a prior Munge(A) run.</param>
    /// <returns>A tuple containing the final optimization report as a string and the appropriate console color for display.</returns>
    private static readonly Dictionary<string, double> OriginalWeights = new();

    private static readonly List<(string Higher, string Lower)> RankingRules = new();

    public static (string, ConsoleColor) RunAutoWeightTunerHandler(ExecutionEnvironment localEnv)
    {
        if (localEnv.Globals.Mode == OperationModes.None)
            return (
                "⚠️ Weight tuning requires a defined mode. 'None' mode is for unrestricted analysis, not optimization.",
                ConsoleColor.Yellow);

        var result = RunAutoWeightTuner(localEnv, "babymunge.txt");
        OriginalWeights.Clear();
        RankingRules.Clear();
        return result;
    }

    private static (string, ConsoleColor) RunAutoWeightTuner(ExecutionEnvironment localEnv, string babyMungeFile)
    {
        var pl = new PeriodicLogger(120); // Logs every 120 seconds
        HashSet<string> FailedWeightConfigs = new(); // Track known bad configurations

        //// ✅ Step 1: Create a single CryptoLib instance (instead of scattering instances)
        //CryptoLibOptions options = new CryptoLibOptions(
        //    rounds: localEnv.Globals.Rounds, // ✅ Use dynamically set rounds
        //    sessionIV: new byte[] { 0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5 },
        //    mode: localEnv.Globals.Mode // ✅ Use the actual mode from ExecutionEnvironment
        //);
        //CryptoLib cryptoLib = new CryptoLib(GlobalsInstance.Password, options);

        var header = GenerateHeader(localEnv, "Auto Weight Tuner", null,
            HeaderOptions.AllExecution);
        // ✅ Report all sections in **one call** (keeps them in the same output file)
        ReportHelper.Report(localEnv.Globals.ReportFormat,
            new List<string>[]
            {
                header
            },
            new string[] { localEnv.Globals.ReportFilename! });

        if (OriginalWeights.Count == 0) // Ensure it's only stored once
            foreach (var kvp in GetDefaultWeights(localEnv))
                OriginalWeights[kvp.Key] = kvp.Value;

        foreach (var a in OriginalWeights)
            foreach (var b in OriginalWeights)
                if (a.Value > b.Value) // Enforce order
                    RankingRules.Add((a.Key, b.Key));


        // ✅ Step 2: Extract top transforms from BabyMunge results
        var topTransforms = ExtractTopTransforms(babyMungeFile, 10);
        if (topTransforms.Count == 0)
            return ($"No valid transform sequences found in {babyMungeFile}.", ConsoleColor.Red);

        // ✅ Step 3: Initialize with current cryptographic weights
        var currentWeights = GetDefaultWeights(localEnv);
        var currentBestWeights = new Dictionary<string, double>(currentWeights); // ✅ Mutable copy for safe updates

        // ✅ Track best sequence across MiniMunge runs
        List<string> bestSequenceSoFar = new();

        var bestScore = RunBabyMunge(localEnv, topTransforms, currentWeights, ref bestSequenceSoFar);
        var bestWeights = new Dictionary<string, double>(currentWeights);
        var bestMetrics = EvaluateMetrics(localEnv, topTransforms, currentWeights, ref bestSequenceSoFar);

        // ✅ Print baseline weights for transparency
        ColorConsole.WriteLine(
            $"<cyan>🔹 Using Weights for MiniMunge: {string.Join(", ", bestWeights.Select(kvp => $"{kvp.Key}: {kvp.Value:F4}"))}</cyan>");
        ColorConsole.WriteLine($"<cyan>🔹 Best Starting Sequence: {string.Join(" -> ", bestSequenceSoFar)}</cyan>");

        var noImprovementCount = 0;
        const int maxNoImprovement = 5; // 🔹 Stop if no improvement after 5 tries

        foreach (var weightConfig in GenerateWeightVariations(FailedWeightConfigs, currentWeights))
        {
            // ✅ Check if this weight configuration has already failed before
            var weightSignature = string.Join("|",
                weightConfig.OrderBy(kvp => kvp.Key).Select(kvp => $"{kvp.Key}:{kvp.Value:F4}"));
            if (FailedWeightConfigs.Contains(weightSignature))
            {
                ColorConsole.WriteLine($"<red>⚠ Skipping known bad weight config: {weightSignature}</red>");
                continue; // Skip this config
            }

            pl.WriteLine(
                $"🔄 Testing new weight config: {string.Join(", ", weightConfig.Select(kvp => $"{kvp.Key}: {kvp.Value:F3}"))}");

            // ✅ Run MiniMunge with the new weights
            List<string> newBestSequence = new();
            var newScore = RunBabyMunge(localEnv, topTransforms, weightConfig, ref newBestSequence);
            var newMetrics = EvaluateMetrics(localEnv, topTransforms, weightConfig, ref newBestSequence);

            var isOverallBetter = newScore > bestScore;
            var isStable = CheckMetricStability(localEnv, bestMetrics, newMetrics);

            if (isOverallBetter && isStable)
            {
                if (newScore > bestScore) // ✅ Prevent regressions
                {
                    bestScore = newScore;
                    bestWeights = new Dictionary<string, double>(weightConfig); // ✅ Update best weights
                    currentBestWeights = new Dictionary<string, double>(weightConfig); // ✅ Store in mutable copy
                    bestMetrics = newMetrics;
                    bestSequenceSoFar = new List<string>(newBestSequence);
                    noImprovementCount = 0; // ✅ Reset counter on success
                    ColorConsole.WriteLine(
                        $"<yellow>✅ New Best Score: {newScore:F4} (Prev: {bestScore:F4}) → Updating best weights.</yellow>");
                    ColorConsole.WriteLine(
                        $"<yellow>✅ Best Sequence So Far: {string.Join(" -> ", bestSequenceSoFar)}</yellow>");
                }
            }
            else
            {
                noImprovementCount++;
                pl.WriteLine($"❌ No improvement for {noImprovementCount}/{maxNoImprovement} attempts.");
                FailedWeightConfigs.Add(weightSignature); // ✅ Add to fail database
                ColorConsole.WriteLine(
                    $"<red>❌ New weight config dropped the score (Prev: {bestScore:F4}, New: {newScore:F4}).</red>");

                if (noImprovementCount >= maxNoImprovement)
                {
                    // ✅ Restore best weights **only when exiting Auto-Weight Tuning**
                    ColorConsole.WriteLine($"<cyan>🏁 Restoring best-known weights before exiting...</cyan>");
                    currentWeights =
                        new Dictionary<string, double>(bestWeights); // ✅ Ensures we restore the true best
                }
            }

            if (noImprovementCount >= maxNoImprovement)
            {
                ColorConsole.WriteLine(
                    "<cyan>🏁 No further improvements detected. Exiting Auto-Weight Tuning...</cyan>");
                break; // ✅ Exit after too many failed attempts
            }
        }

        // ✅ Print final best score after tuning completes
        ColorConsole.WriteLine($"<cyan>🔹 Final Best Score After Tuning: {bestScore:F4}</cyan>");
        ColorConsole.WriteLine($"<cyan>🔹 Best Final Sequence: {string.Join(" -> ", bestSequenceSoFar)}</cyan>");
        ColorConsole.WriteLine($"<green>🏁 Optimized Weights Found!</green>");

        foreach (var kvp in bestWeights) ColorConsole.WriteLine($"- **{kvp.Key}** → `{kvp.Value:F4}`");

        // ✅ Pause before exiting to let user review results
        ColorConsole.WriteLine("<magenta>🔹 Press any key to continue...</magenta>");
        Console.ReadKey(true); // Wait for key press without displaying the key

        // ✅ Step 3: Output final weight recommendations
        return GenerateFinalWeightReport(bestWeights);
    }

    private static (string, ConsoleColor) GenerateFinalWeightReport(Dictionary<string, double> bestWeights)
    {
        StringBuilder report = new();
        report.AppendLine("🎯 **Optimized Weights Found!** 🔥\n");

        // Print in Mango dictionary format, sorted by rank (highest first)
        report.AppendLine("{");
        foreach (var kvp in bestWeights.OrderByDescending(k => k.Value))
            report.AppendLine($"    {{ \"{kvp.Key}\", {kvp.Value:F4} }},");

        report.AppendLine("}");

        report.AppendLine("\n✅ **Recommended Action:** Copy and paste into Mango’s MetricsRegistry!");

        return (report.ToString(), ConsoleColor.Green);
    }

    private static IEnumerable<Dictionary<string, double>> GenerateWeightVariations(
        HashSet<string> FailedWeightConfigs, Dictionary<string, double> currentWeights)
    {
        const double stepSize = 0.05; // 🔹 5% adjustment per step
        const int maxVariationsPerMetric = 3; // 🔹 Number of variations per metric

        List<Dictionary<string, double>> variations = new();

        foreach (var metric in currentWeights.Keys)
            for (var i = 1; i <= maxVariationsPerMetric; i++)
            {
                var adjustment = stepSize * i;
                string weightSignature;

                // ✅ Increase weight (but normalize)
                var increased = AdjustWeights(currentWeights, metric, adjustment);
                if (increased != null)
                {
                    weightSignature = string.Join("|",
                        increased.OrderBy(kvp => kvp.Key).Select(kvp => $"{kvp.Key}:{kvp.Value:F4}"));
                    if (!FailedWeightConfigs.Contains(weightSignature)) // ✅ Skip known bad configs
                    {
                        variations.Add(increased);
                        ColorConsole.WriteLine($"<cyan>🔹 Testing Weight Increase: {weightSignature}</cyan>");
                    }
                }

                // ✅ Decrease weight (but normalize)
                var decreased = AdjustWeights(currentWeights, metric, -adjustment);
                if (decreased != null)
                {
                    weightSignature = string.Join("|",
                        decreased.OrderBy(kvp => kvp.Key).Select(kvp => $"{kvp.Key}:{kvp.Value:F4}"));
                    if (!FailedWeightConfigs.Contains(weightSignature)) // ✅ Skip known bad configs
                    {
                        variations.Add(decreased);
                        ColorConsole.WriteLine($"<cyan>🔹 Testing Weight Decrease: {weightSignature}</cyan>");
                    }
                }
            }

        // ✅ Log final count of weight variations generated
        ColorConsole.WriteLine($"<magenta>🔹 Generated {variations.Count} valid weight variations.</magenta>");

        return variations;
    }

    private static Dictionary<string, double>? AdjustWeights(Dictionary<string, double> baseWeights,
        string targetMetric, double adjustment)
    {
        const double minWeight = 0.05; // 🔹 Minimum allowable weight per metric
        Dictionary<string, double>? newWeights = new(baseWeights);

        if (!newWeights.ContainsKey(targetMetric))
            return null; // ❌ Should never happen, but safety check

        var newValue = newWeights[targetMetric] + adjustment;
        if (newValue < minWeight) return null; // ❌ Avoid dropping too low

        newWeights[targetMetric] = newValue;

        // ✅ Normalize weights so sum remains ≈ 1.0
        var total = newWeights.Values.Sum();
        foreach (var key in newWeights.Keys.ToList()) newWeights[key] /= total;

        // ✅ NEW: Check ranking rules before returning
        if (ViolatesRankingRules(newWeights))
            return null; // 🚫 Discard changes if rules are broken

        return newWeights;
    }

    private static bool ViolatesRankingRules(Dictionary<string, double>? weights)
    {
        foreach (var (higher, lower) in RankingRules)
        {
            if (!weights!.ContainsKey(higher) || !weights.ContainsKey(lower))
                throw new InvalidOperationException(
                    $"Ranking rule references missing metric(s): {higher} or {lower}. This should NEVER happen!"
                );

            if (weights[higher] <= weights[lower]) // 🔥 Now enforcing strict inequality
            {
                ColorConsole.WriteLine(
                    $"<red>❌ Adjustment blocked: {higher} must be strictly greater than {lower} ({weights[higher]:F4} ≤ {weights[lower]:F4})</red>");
                return true; // 🚫 Block the adjustment
            }
        }

        return false; // ✅ Safe to proceed
    }

    private static Dictionary<string, double> EvaluateMetrics(
        ExecutionEnvironment localEnv,
        HashSet<string> transformSet,
        Dictionary<string, double> weights,
        ref List<string> bestSequenceSoFar)
    {
        // ✅ Log weight configuration being tested
        ColorConsole.WriteLine(
            $"<cyan>🔹 Evaluating Metrics with Weights: {string.Join(", ", weights.Select(kvp => $"{kvp.Key}: {kvp.Value:F4}"))}</cyan>");

        // ✅ Run MiniMunge with the provided transforms and weights, tracking the best sequence
        var results = MiniMunge(localEnv, transformSet, ref bestSequenceSoFar);

        // ✅ Handle cases where MiniMunge produces no results
        if (results.Count == 0)
        {
            ColorConsole.WriteLine(
                "<red>⚠ MiniMunge returned no valid sequences! Metrics evaluation aborted.</red>");
            return new Dictionary<string, double>(); // ❌ No valid results
        }

        // ✅ Aggregate metric values across all sequences
        var metricSums = localEnv.CryptoAnalysis.MetricsRegistry.Keys
            .ToDictionary(metric => metric, _ => 0.0);

        foreach (var result in results)
            foreach (var metric in result.Metrics)
                if (metricSums.ContainsKey(metric.Key))
                    metricSums[metric.Key] += metric.Value;

        // ✅ Compute averages safely (avoid divide-by-zero)
        var sequenceCount = results.Count;
        if (sequenceCount == 0) return new Dictionary<string, double>(); // Prevent division by zero

        var averagedMetrics = metricSums
            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value / sequenceCount);

        // ✅ Log final metrics and best sequence for debugging
        ColorConsole.WriteLine(
            $"<cyan>🔹 Averaged Metrics: {string.Join(", ", averagedMetrics.Select(kvp => $"{kvp.Key}: {kvp.Value:F4}"))}</cyan>");
        ColorConsole.WriteLine($"<cyan>🔹 Best Sequence So Far: {string.Join(" -> ", bestSequenceSoFar)}</cyan>");

        return averagedMetrics;
    }

    private static Dictionary<string, double> GetDefaultWeights(ExecutionEnvironment localEnv)
    {
        return localEnv.CryptoAnalysis.MetricsRegistry.ToDictionary(kvp => kvp.Key, kvp => kvp.Value.Weight);
    }

    private static HashSet<string> ExtractTopTransforms(string babyMungeFile, int maxSequences = 10)
    {
        HashSet<string> uniqueTransforms = new();
        var sequenceCount = 0;

        foreach (var line in File.ReadLines(babyMungeFile))
            if (line.StartsWith("Sequence: "))
            {
                if (sequenceCount >= maxSequences)
                    break; // ✅ Stop after reaching the required number of sequences

                var sequencePart = line.Substring(9).Trim(); // Remove "Sequence: " prefix
                var transforms = sequencePart.Split(" -> ");

                foreach (var transform in transforms)
                    uniqueTransforms.Add(transform); // ✅ Ensure uniqueness across sequences

                sequenceCount++;
            }

        return uniqueTransforms;
    }

    private static bool CheckMetricStability(ExecutionEnvironment localEnv, Dictionary<string, double> previousMetrics,
        Dictionary<string, double> newMetrics)
    {
        foreach (var metric in previousMetrics.Keys)
        {
            var oldValue = previousMetrics[metric];
            var newValue = newMetrics[metric];
            var threshold = GetMetricThreshold(localEnv, metric);

            if (oldValue >= threshold && newValue < threshold)
                return false; // ❌ Drop below threshold → Reject weight change

            if ((oldValue - newValue) / oldValue > 0.05)
                return false; // ❌ More than 5% loss → Reject weight change
        }

        return true;
    }

    private static double GetMetricThreshold(ExecutionEnvironment localEnv, string metric)
    {
        if (localEnv.CryptoAnalysis.MetricsRegistry.TryGetValue(metric, out var metricInfo)) return metricInfo.Baseline;

        throw new ArgumentException($"Unknown metric: {metric}");
    }

    public class SequenceResult
    {
        public List<string> Sequence { get; }
        public double AggregateScore { get; }
        public Dictionary<string, double> Metrics { get; } // ✅ Added per-metric values

        public SequenceResult(List<string> sequence, double aggregateScore, Dictionary<string, double> metrics)
        {
            Sequence = sequence;
            AggregateScore = aggregateScore;
            Metrics = metrics ?? new Dictionary<string, double>(); // ✅ Ensure non-null metrics
        }

        public override string ToString()
        {
            return $"[{string.Join(" -> ", Sequence)}] Score: {AggregateScore:F4}";
        }
    }

    private static double RunBabyMunge(ExecutionEnvironment localEnv, HashSet<string> topTransforms,
        Dictionary<string, double> weightConfig, ref List<string> bestSequenceSoFar)
    {
        // ✅ Apply the weight configuration
        foreach (var metric in weightConfig.Keys)
            localEnv.CryptoAnalysis.MetricsRegistry[metric].Weight = weightConfig[metric];

        // ✅ Print weight configuration for better debugging
        ColorConsole.WriteLine(
            $"<cyan>🔹 Running BabyMunge with Weights: {string.Join(", ", weightConfig.Select(kvp => $"{kvp.Key}: {kvp.Value:F4}"))}</cyan>");

        // ✅ Run MiniMunge process (restricted to only `topTransforms`) with the prior best sequence
        var results = MiniMunge(localEnv, topTransforms, ref bestSequenceSoFar);

        // ✅ Handle empty results case
        if (results.Count == 0)
        {
            ColorConsole.WriteLine("<red>⚠ MiniMunge returned no valid sequences!</red>");
            return 0.0; // No valid results, return lowest possible score
        }

        // ✅ Extract best sequence and aggregate score
        var bestResult = results.OrderByDescending(r => r.AggregateScore).First();
        var newBestScore = bestResult.AggregateScore;

        // ✅ If this run found a better sequence, update the best one
        var currentBestScore = bestSequenceSoFar.Count > 0 ? newBestScore : 0.0;

        if (newBestScore > currentBestScore)
        {
            bestSequenceSoFar = new List<string>(bestResult.Sequence);
            ColorConsole.WriteLine(
                $"<yellow>✅ New Best Sequence: {string.Join(" -> ", bestSequenceSoFar)} (Score: {newBestScore:F4})</yellow>");
        }


        // ✅ Print out for debugging
        ColorConsole.WriteLine($"<cyan>🔹 MiniMunge finished. Best Score: {newBestScore:F4}</cyan>");

        return newBestScore;
    }

    private static List<SequenceResult> MiniMunge(ExecutionEnvironment localEnv, HashSet<string> topTransforms,
        ref List<string> bestSequenceSoFar)
    {
        List<SequenceResult> results = new();
        var transformList = topTransforms.ToList();

        // 🔹 Convert transform names to their corresponding IDs
        var transformIds = transformList
            .Select(name =>
            {
                if (!localEnv.Crypto.TransformRegistry.Any(kvp => kvp.Value.Name == name))
                    throw new KeyNotFoundException($"Transform '{name}' not found in TransformRegistry.");
                return (byte)localEnv.Crypto.TransformRegistry.First(kvp => kvp.Value.Name == name).Key;
            })
            .ToList();

        if (transformIds.Count == 0)
            return results; // ❌ No valid transforms found

        // ✅ Step 1: Generate all possible transform sequences (up to length 4)
        var sequences = GeneratePermutations(transformIds, 4).ToList();

        // ✅ If a best sequence exists, run it first
        if (bestSequenceSoFar != null && bestSequenceSoFar.Count > 0)
        {
            var bestTransformIds = bestSequenceSoFar
                .Select(name => (byte)localEnv.Crypto.TransformRegistry.First(kvp => kvp.Value.Name == name).Key)
                .ToList();

            if (bestTransformIds.Count > 0)
                sequences.Insert(0, bestTransformIds.ToArray()); // Prioritize the best sequence
        }

        // ✅ Step 2: Evaluate each sequence
        var seqHelper = new SequenceHelper(localEnv.Crypto);
        var inputData = GenerateTestInput(localEnv);
        var bestScore = 0.0;
        var pl = new PeriodicLogger(120);
        var sequenceCount = 0;
        foreach (var sequence in sequences)
        {
            sequenceCount++;
            var transformBytes = sequence!.ToList();

            // ✅ Run the sequence through MangoEncryptor
            // ✅ Run CryptAnalysis on the encrypted output
            var analysisResults = EncryptAndAnalyze(localEnv, transformBytes);
            Debug.Assert(false, "Unimplemented: need to extract payload here.");
            // ✅ Compute the aggregate score
            var aggregateScore =
                localEnv.CryptoAnalysis.CalculateAggregateScore(analysisResults, localEnv.Globals.UseMetricScoring,
                    null);

            // ✅ Extract individual metric values
            Dictionary<string, double> metricScores = new();
            foreach (var result in analysisResults)
                if (!string.IsNullOrEmpty(result.Name)) // Ensure valid metric
                    metricScores[result.Name] = result.Score; // Extract metric and its score

            // ✅ Convert byte sequence to string format before storing
            var sequenceStrings = seqHelper.GetNames(sequence.ToList());

            // ✅ Store the result with both **aggregate score** and **per-metric values**
            results.Add(new SequenceResult(sequenceStrings, aggregateScore, metricScores));

            // ✅ If this is the new best sequence, update the tracking variable
            if (aggregateScore > bestScore)
            {
                bestScore = aggregateScore;
                bestSequenceSoFar = new List<string>(sequenceStrings);
                ColorConsole.WriteLine(
                    $"<yellow>✅ New Best Score: {bestScore:F4} → {string.Join(" -> ", bestSequenceSoFar)}</yellow>");
            }

            // ✅ Log every 120s OR every 100 sequences
            if (sequenceCount % 100 == 0 || pl.ShouldLog()) pl.WriteLine($"🔄 Processed {sequenceCount} sequences...");
        }

        // ✅ Step 3: Sort by best score and return results
        var sortedResults = results.OrderByDescending(r => r.AggregateScore).ToList();

        // ✅ Notify that MiniMunge has completed this run
        ColorConsole.WriteLine(
            $"<magenta>🔹 MiniMunge completed. Processed {sortedResults.Count} sequences.</magenta>");
        ColorConsole.WriteLine($"<cyan>🔹 After MiniMunge, best score is: {bestScore:F4}</cyan>");

        return sortedResults;
    }

    public static List<CryptoAnalysis.AnalysisResult>? EncryptAndAnalyze(ExecutionEnvironment localEnv,
        List<byte> sequence)
    {
        // Measure Mango Encryption Time
        var MangoEncrypted = localEnv.Crypto.Encrypt(sequence.ToArray(), localEnv.Globals.Input);
        var MangoPayload = localEnv.Crypto.GetPayloadOnly(MangoEncrypted); // Extract payload for Mango encryption

        // Modify a copy of input for Avalanche test and Key Dependency test
        var (MangoAvalanchePayload, _, MangoKeyDependencyPayload, _) =
            ProcessAvalancheAndKeyDependency(
                localEnv,
                GlobalsInstance.Password,
                sequence,
                false); // ✅ No AES processing needed


        // Mango Results
        var analysisResults = localEnv.CryptoAnalysis.RunCryptAnalysis(
            MangoPayload,
            MangoAvalanchePayload,
            MangoKeyDependencyPayload,
            localEnv.Globals.Input);

        return analysisResults;
    }

    private static Dictionary<string, double> BabyMungeWithWeightTuning(HashSet<string> transforms)
    {
        var currentWeights = GetCurrentWeights();
        Dictionary<string, double> newWeights = new(currentWeights);

        // ✅ Identify problem areas (over/under contribution)
        var metricScores = EvaluateMetricImpact(transforms);
        var targetScore = 50.0; // Ideal balance point

        foreach (var (metric, score) in metricScores)
        {
            var deviation = Math.Abs(score - targetScore);
            if (deviation > 5.0) // ✅ Only adjust weights if deviation is significant
            {
                var adjustment = deviation / 100.0; // Scale adjustment factor
                newWeights[metric] = Math.Max(0.05, Math.Min(0.5, newWeights[metric] - adjustment));
            }
        }

        return newWeights;
    }

    private static Dictionary<string, double> GetCurrentWeights()
    {
        return new Dictionary<string, double>
        {
            { "Entropy", 0.3 },
            { "BitVariance", 0.2 },
            { "SlidingWindow", 0.1 },
            { "FrequencyDistribution", 0.1 },
            { "PeriodicityCheck", 0.1 },
            { "MangosCorrelation", 0.3 },
            { "PositionalMapping", 0.3 },
            { "AvalancheScore", 0.4 },
            { "KeyDependency", 0.3 }
        };
    }

    private static Dictionary<string, double> EvaluateMetricImpact(HashSet<string> transforms)
    {
        Dictionary<string, double> metricImpact = new()
        {
            { "Entropy", 48.0 },
            { "BitVariance", 51.2 },
            { "SlidingWindow", 60.4 },
            { "FrequencyDistribution", 75.0 },
            { "PeriodicityCheck", 49.3 },
            { "MangosCorrelation", 52.1 },
            { "PositionalMapping", 50.9 },
            { "AvalancheScore", 62.0 },
            { "KeyDependency", 47.5 }
        };

        return metricImpact;
    }

    #endregion RunAutoTuneWeights

    public static (string, ConsoleColor) MangoCipherHandler(ExecutionEnvironment localEnv, string[] args)
    {
        // ✅ Allow optional filename input
        byte[] inputData = null!;
        if (args.Length > 1 && File.Exists(args[1]))
        {
            inputData = File.ReadAllBytes(args[1]);
            Console.WriteLine($"Loaded file: {args[1]} ({inputData.Length} bytes)");
        }
        else if (localEnv.Globals.Input?.Length > 0)
        {
            Console.WriteLine("Using currently configured input.");
            inputData = localEnv.Globals.Input;
        }

        // ✅ Final check to ensure inputData is valid before proceeding
        if (inputData == null || inputData.Length == 0)
            return ("Error: No input data found. Provide a file or pre-load data into memory.", ConsoleColor.Red);

        // ✅ Auto-detect data type and select the best sequence
        //var (classification, sequenceString) = DataEvaluator.GetInputProfile(inputData);
        var profile = InputProfiler.GetInputProfile(inputData);
        var classification = profile.Name;
        SequenceHelper seqHelper = new(localEnv.Crypto);
        var sequenceString = seqHelper.FormattedSequence<string>(profile);

        if (string.IsNullOrWhiteSpace(sequenceString))
            return ($"Error: No optimal transform sequence found for detected type: {classification}",
                ConsoleColor.Red);

        Console.WriteLine($"Detected Data Type: {classification}");
        Console.WriteLine($"Using Transform Sequence: {sequenceString}");

        // ✅ Convert sequence string to a list of transform names
        var sequence = sequenceString.Split(" -> ").ToList();

        // ✅ Pass sequence to RunComparativeAnalysisHandler (no need to reinvent the wheel)
        return RunComparativeAnalysisHandler(localEnv, sequence);
    }

    public static void CheckRecordFail(ExecutionEnvironment localEnv,
        List<CryptoAnalysis.AnalysisResult>? analysisResults, List<byte> currentSequence, string failurekey)
    {
        // If analysisResults is null, the sequence already failed reversibility.
        if (analysisResults == null)
        {
            SequenceFailSQL.RecordBadSequence(currentSequence, failurekey);
            return;
        }

        var passCount = analysisResults.Count(r => r.Passed);

        // ✅ Only record if the sequence does NOT meet the required PassCount 
        //    AND isn't already marked as a known failure.
        if (passCount < localEnv.Globals.PassCount && !SequenceFailSQL.IsBadSequence(currentSequence, failurekey))
            SequenceFailSQL.RecordBadSequence(currentSequence, failurekey);
    }

    public static long CountPermutations(List<byte> transformIds, int length)
    {
        return (long)Math.Pow(transformIds.Count, length);
    }

    public static (string, ConsoleColor) LogToScreenHandler(ExecutionEnvironment localEnv)
    {
        // Call LogEvaluationSummary and capture success/failure
        var success = localEnv.CryptoAnalysis.LogToScreen(localEnv, localEnv.Globals.InputType, 5);

        Console.WriteLine("\nPress any key to return to the main menu...");
        Console.ReadKey();

        // Return status message based on success or failure
        if (!success) return ("EvaluationSummary failed due to sanity check errors.", ConsoleColor.Red);

        return ($"EvaluationSummary completed for max length {localEnv.Globals.MaxSequenceLen}.",
            ConsoleColor.Green);
    }

    //public static (string, ConsoleColor) AnalyzeContendersHandler()
    //{
    //    string logFileName = "ContenderLog.txt";
    //    var result = AnalyzeContenders(new string[] { logFileName });
    //    return result;
    //}

    public static (string, ConsoleColor) LogToFileHandler(ExecutionEnvironment localEnv)
    {
        var logFileName = GetContenderFilename(localEnv, 0);
        localEnv.CryptoAnalysis.LogToFile(localEnv, logFileName, 1000);
        return ($"Log summary written to {logFileName}.", ConsoleColor.Green);
    }

    public static (string, ConsoleColor) LogToSQLHandler(ExecutionEnvironment localEnv)
    {
        LogToSQL(localEnv);
        return ($"Contenders converted to SQL database.", ConsoleColor.Green);
    }

    public static (string, ConsoleColor) FileToSQLHandler()
    {
        var filaname = "ContenderLog.txt";
        FileToSQL(filaname);
        return ($"Contenders written to {filaname}.", ConsoleColor.Green);
    }

    public static (string, ConsoleColor) QueryConsoleHandler(ExecutionEnvironment localEnv)
    {
        MangoSQLConsole.RunQueryConsole(localEnv);
        return ($"Query Console completed successfully.", ConsoleColor.Green);
    }

    public static (string, ConsoleColor) AddTransformHandler(CryptoLib? cryptoLib, string[] args, List<byte> sequence)
    {
        if (args.Length == 0)
            return ("No transform specified. Please provide a valid transform name or ID.", ConsoleColor.Red);

        var input = args[0];

        // ✅ Try parsing as menu ordinal (e.g., "10" means the 10th visible transform)
        if (byte.TryParse(input, out var menuOrdinal))
        {
            // Build forward-only, menu-visible transforms
            var forwardTransforms = cryptoLib!.TransformRegistry.Values
                .Where(t => t.Id <= t.InverseId)
                .OrderBy(t => t.Id)
                .ToList();

            if (menuOrdinal >= 1 && menuOrdinal <= forwardTransforms.Count)
            {
                var tform = forwardTransforms[menuOrdinal - 1];

                // ✅ Push the *ordinal*, not the ID
                MangoConsole.CommandStack.Push(menuOrdinal.ToString());

                return ($"{tform.Name} (Menu #{menuOrdinal}, ID:{tform.Id}) added successfully.", ConsoleColor.Green);
            }

            return ($"No transform found at menu position {menuOrdinal}.", ConsoleColor.Red);
        }

        // ✅ Otherwise, treat input as a transform name
        var transform = cryptoLib!.TransformRegistry.Values
            .FirstOrDefault(t => t.Name!.Equals(input, StringComparison.OrdinalIgnoreCase));

        if (transform != null)
        {
            MangoConsole.CommandStack.Push(transform.Id.ToString());
            return ($"{transform.Name} Transform added successfully.", ConsoleColor.Green);
        }
        else
        {
            return ($"Transform '{input}' not found.", ConsoleColor.Red);
        }
    }

    public static (string, ConsoleColor) RunOptimizeGRHandler(ExecutionEnvironment localEnv, List<string> sequence,
        string[] args)
    {
        // 🔍 Step 1: Parse `-max N`
        var roundsMax = args
            .SkipWhile(arg => !arg.Equals("-max", StringComparison.OrdinalIgnoreCase))
            .Skip(1)
            .Select(arg =>
            {
                if (int.TryParse(arg, out var val)) return val;
                return -1;
            })
            .FirstOrDefault();

        if (roundsMax <= 0) return ("❌ Missing or invalid parameter: -max <N> (e.g., -max 9)", ConsoleColor.Red);

        // ✅ LocalEnvironment parses the sequence and sets Global Rounds (minGR)
        using (var localStateEnv = new LocalEnvironment(localEnv, sequence))
        {
            var result = RunOptimizeGRCore(localEnv, localStateEnv.ParsedSequence, roundsMax);

            PressAnyKey();

            return result;
        }
    }

    public static (string, ConsoleColor) RunOptimizeGRCore(ExecutionEnvironment localEnv,
        SequenceHelper.ParsedSequence parsedSequence, int roundsMax)
    {
        SequenceHelper seqHelper = new(localEnv.Crypto);
        var sequence = seqHelper.GetIDs(parsedSequence);

        if (sequence.Count == 0)
            return ("No transforms in sequence. Add transforms before running.", ConsoleColor.Red);

        // Freeze TR settings (the parsed sequence already locked these in)
        localEnv.CryptoAnalysis.Initialize();

        var formatted = seqHelper.FormattedSequence<string>(parsedSequence,
            SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes, 2, true);

        var roundsStart = 1;
        double bestScore = 0;
        var bestGR = roundsStart;
        var bestFormatted = formatted;
        List<CryptoAnalysis.AnalysisResult>? bestMetrics = null;

        ColorConsole.WriteLine(
            $"\n<white>🔧 Optimizing Global Rounds (Start: {roundsStart}, Max: {roundsMax})</white>\n");

        for (var rounds = roundsStart; rounds <= roundsMax; rounds++)
        {
            localEnv.Globals.UpdateSetting("rounds", rounds);
            var encrypted = localEnv.Crypto.Encrypt(sequence.ToArray(), localEnv.Globals.Input);
            var payload = localEnv.Crypto.GetPayloadOnly(encrypted);
            var reverseSequence = GenerateReverseSequence(localEnv.Crypto, sequence.ToArray());
            var decrypted = localEnv.Crypto.Decrypt(reverseSequence, encrypted);

            if (!decrypted!.SequenceEqual(localEnv.Globals.Input))
            {
                ColorConsole.WriteLine($"<red>❌ Reversibility failed at GR: {rounds}</red>");
                continue;
            }

            var (avalanche, _, keydep, _) = ProcessAvalancheAndKeyDependency(
                localEnv,
                GlobalsInstance.Password,
                sequence.ToList());

            var results = localEnv.CryptoAnalysis.RunCryptAnalysis(
                payload,
                avalanche,
                keydep,
                localEnv.Globals.Input,
                null);

            var score = localEnv.CryptoAnalysis.CalculateAggregateScore(results, localEnv.Globals.UseMetricScoring);

            ColorConsole.WriteLine($"<yellow>GR:{rounds,-2}</yellow> → Score: <green>{score:F4}</green>");

            if (score > bestScore)
            {
                bestScore = score;
                bestGR = rounds;
                bestMetrics = results;
            }
        }

        // ✅ Restore best GR for reporting
        localEnv.Crypto.Options.Rounds = bestGR;

        if (bestMetrics != null)
        {
            var finalSeq = seqHelper.FormattedSequence<string>(parsedSequence,
                SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.InferGRounds |
                SequenceFormat.RightSideAttributes,
                2, true);

            var header = GenerateHeader(
                localEnv,
                formattedSequence: finalSeq,
                analysisResults: bestMetrics,
                isReversible: true,
                options: HeaderOptions.AllAnalysis | HeaderOptions.Mode | HeaderOptions.InputType |
                         HeaderOptions.MetricScoring | HeaderOptions.PassCount
            );

            List<string> report = localEnv.CryptoAnalysis.CryptAnalysisReport(localEnv.Crypto, bestMetrics);

            ColorConsole.WriteLine($"\n<cyan>🏁 Best GR Found: {bestGR}</cyan>");
            ReportHelper.Report(localEnv.Globals.ReportFormat, new List<string>[] { header, report },
                new string[] { localEnv.Globals.ReportFilename! });

            return ($"🏆 Optimization complete. Best Score: {bestScore:F4} at GR:{bestGR}", ConsoleColor.Green);
        }

        return ("⚠️ No valid GR setting improved the score.", ConsoleColor.Yellow);
    }

    public static (string, ConsoleColor) RunSequenceHandler(ExecutionEnvironment localEnv, List<string> sequence)
    {
        // ✅ LocalEnvironment parses the sequence and sets the Global Rounds, which are then used throughout localStateEnv
        using (var localStateEnv = new LocalEnvironment(localEnv, sequence))
        {
            return RunSequence(localEnv, localStateEnv.ParsedSequence);
        }
    }

    public static (string, ConsoleColor) RunSequence(ExecutionEnvironment localEnv,
        SequenceHelper.ParsedSequence parsedSequence)
    {
        SequenceHelper seqHelper = new(localEnv.Crypto);
        var sequence = seqHelper.GetIDs(parsedSequence);
        var formattedSequence = seqHelper.FormattedSequence<string>(parsedSequence,
            SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes,
            2, true);
        if (sequence.Count == 0) return ("No transforms in sequence. Add transforms before running.", ConsoleColor.Red);

        try
        {
            // Reset metrics and contenders before starting
            localEnv.CryptoAnalysis.Initialize();

            Console.WriteLine(
                $"\n--- Executing Transformations (GRounds: {localEnv.Crypto.Options.Rounds})---\n");

            const int labelWidth = 16;
            const int rows = 1; // Display one row of bits/bytes for simplicity
            const int columns = 16; // 16 bytes per row
            const string mode = "BITS"; // Default to bit visualization
            const string format = "HEX"; // Default format is HEX

            // Make a copy of inputData for safe visualization
            var inputCopy = localEnv.Globals.Input.ToArray();

            // Display Input Data (ensure Format() never modifies inputData)
            ColorConsole.WriteLine(
                Field("Input Data", labelWidth) +
                Visualizer.Format(inputCopy, inputCopy, mode, rows, columns,
                    format: format)[0]);

            // Encrypt using the sequence
            var stopwatch = Stopwatch.StartNew(); // Start the stopwatch
            var encrypted = localEnv.Crypto.Encrypt(sequence.ToArray(), localEnv.Globals.Input);
            var payload = localEnv.Crypto.GetPayloadOnly(encrypted);

            // Make a copy of inputData before passing it to Format()
            var inputForComparison = localEnv.Globals.Input.ToArray();
            ColorConsole.WriteLine(
                Field("Encrypted Data", labelWidth) +
                Visualizer.Format(inputForComparison, payload, mode, rows, columns,
                    format: format)[0]);

            // Bit Comparison (ensure Format() doesn’t alter inputData)
            var bitComparisonRows = Visualizer.Format(inputForComparison, payload, mode, rows,
                columns, format: format);
            ColorConsole.WriteLine(
                Field("Bit Comparison", labelWidth) +
                string.Join(" ", bitComparisonRows));

            // Decrypt using the reverse sequence
            var reverseSequence = GenerateReverseSequence(localEnv.Crypto, sequence.ToArray());
            var decrypted = localEnv.Crypto.Decrypt(reverseSequence, encrypted);
            stopwatch.Stop(); // Stop the stopwatch after sequence execution

            // Ensure inputData isn't altered by Format()
            var inputForDecryptionComparison = localEnv.Globals.Input.ToArray();
            ColorConsole.WriteLine(
                Field("Decrypted Data", labelWidth) +
                Visualizer.Format(inputForDecryptionComparison, decrypted, mode, rows, columns,
                    format: format)[0]);


            // Reversibility Check
            var isReversible = decrypted!.SequenceEqual(localEnv.Globals.Input);
            var color = isReversible ? "Green" : "Red";

            // Modify a copy of input for Avalanche test
            var (MangoAvalanchePayload, _, MangoKeyDependencyPayload, _) =
                ProcessAvalancheAndKeyDependency(
                    localEnv,
                    GlobalsInstance.Password,
                    sequence.ToList());

            var analysisResults = localEnv.CryptoAnalysis.RunCryptAnalysis(
                payload,
                MangoAvalanchePayload,
                MangoKeyDependencyPayload,
                localEnv.Globals.Input, null);

            localEnv.CryptoAnalysis.CryptAnalysisRecordBest(localEnv, analysisResults, sequence.ToList());

            // Display cryptanalysis report
            var header = GenerateHeader(
                localEnv,
                formattedSequence: formattedSequence,
                analysisResults: analysisResults,
                isReversible: isReversible,
                options: HeaderOptions.AllAnalysis | HeaderOptions.Mode | HeaderOptions.InputType |
                         HeaderOptions.MetricScoring | HeaderOptions.PassCount
            );

            List<string> analysis = localEnv.CryptoAnalysis.CryptAnalysisReport(localEnv.Crypto, analysisResults);
            List<string> timing = new List<string>
                { $"\n--- Sequence Execution Completed in {stopwatch.Elapsed.TotalSeconds:F2} seconds ---" };

            // ✅ Report all sections in **one call** (keeps them in the same output file)
            ReportHelper.Report(localEnv.Globals.ReportFormat, new List<string>[] { header, analysis, timing },
                new string[] { localEnv.Globals.ReportFilename! });

            Console.WriteLine("\nPress any key to return to the menu...");
            Console.ReadKey();

            return ("Sequence executed successfully.", ConsoleColor.Green);
        }
        catch (Exception ex)
        {
            return ($"Error while running sequence: {ex.Message}", ConsoleColor.Red);
        }
    }

    #region Run Best Fit (Munge(A) Interactive

    public static (string, ConsoleColor) RunBestFitHandler(ExecutionEnvironment localEnv, List<string> sequence)
    {
        // ✅ LocalEnvironment parses the sequence and sets the Global Rounds, which are then used throughout localStateEnv
        using (var localStateEnv = new LocalEnvironment(localEnv, sequence))
        {
            return RunBestFit(localEnv, localStateEnv.ParsedSequence);
        }
    }

    public static (string, ConsoleColor) RunBestFit(ExecutionEnvironment localEnv, SequenceHelper.ParsedSequence parsedSequence)
    {
        SequenceHelper seqHelper = new(localEnv.Crypto);
        var _sequence = seqHelper.GetIDs(parsedSequence);
        var format = SequenceFormat.ID | SequenceFormat.InferTRounds | SequenceFormat.InferGRounds |
                     SequenceFormat.RightSideAttributes;
        // Reset metrics and contenders before starting
        localEnv.CryptoAnalysis.Initialize();

        Console.WriteLine("Running Best Fit...");

        // Generate permutations from user-supplied sequence
        var permutations = GenerateUniquePermutations(_sequence).ToList();
        if (!permutations.Any()) return ("No permutations generated. Ensure your sequence is valid.", ConsoleColor.Red);

        // Store results for each permutation
        List<(byte[], double, List<CryptoAnalysis.AnalysisResult>?)> results = new();

        foreach (var permutation in permutations)
        {
            Console.WriteLine(
                $"Testing sequence: {new SequenceHelper(localEnv.Crypto).FormattedSequence(permutation, format, 2, true)}");

            // Test each permutation
            var metrics = TestSequence(localEnv, permutation);
            if (metrics == null)
            {
                Console.WriteLine(
                    $"Failed Reversibility Check for sequence: {new SequenceHelper(localEnv.Crypto).FormattedSequence(permutation, SequenceFormat.ID | SequenceFormat.TRounds)}");
                continue;
            }

            // Calculate aggregate score
            var score = localEnv.CryptoAnalysis.CalculateAggregateScore(metrics, localEnv.Globals.UseMetricScoring);

            // Add to results
            results.Add((permutation, score, metrics));
        }

        if (!results.Any()) return ("No valid sequences found.", ConsoleColor.Yellow);

        // Find the best scoring sequence
        var best = results.OrderByDescending(r => r.Item2).First();

        // Run analysis on the best sequence
        var isReversible = true; // TestSequence() above already ensures reversibility
        var sequence = best.Item1.ToList();
        var analysisResults = best.Item3;

        localEnv.CryptoAnalysis.CryptAnalysisRecordBest(localEnv, best.Item3!, best.Item1.ToList());

        //string formattedSequence = seqHelper.FormattedSequence<string>(parsedSequence,
        //    SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes,
        //    chunks: 2, indent: true);

        // Display cryptanalysis report
        var header = GenerateHeader(
            localEnv,
            formattedSequence: seqHelper.FormattedSequence(
                sequence.ToArray(),
                format,
                2,
                true
            ),
            analysisResults: analysisResults,
            isReversible: isReversible,
            options: HeaderOptions.AllAnalysis | HeaderOptions.Mode | HeaderOptions.InputType |
                     HeaderOptions.MetricScoring | HeaderOptions.PassCount
        );

        List<string> analysis = localEnv.CryptoAnalysis.CryptAnalysisReport(localEnv.Crypto, analysisResults!);

        List<string> commandHeader =
            GenerateHeader(localEnv, "Run Best Fit", null, HeaderOptions.AllExecution);
        // ✅ Report all sections in **one call** (keeps them in the same output file)
        ReportHelper.Report(localEnv.Globals.ReportFormat,
            new List<string>[]
            {
                commandHeader
            },
            new string[] { localEnv.Globals.ReportFilename! });

        // ✅ Report all sections in **one call** (keeps them in the same output file)
        ReportHelper.Report(localEnv.Globals.ReportFormat, new List<string>[] { header, analysis },
            new string[] { localEnv.Globals.ReportFilename! });

        // Pause the output
        Console.WriteLine("\nPress any key to return to the main menu...");
        Console.ReadKey();

        return ("Best Fit sequence found and displayed.", ConsoleColor.Green);
    }

    #endregion Run Best Fit (Munge(A) Interactive

    #region Best Fit Transform Rounds (BTR) Handlers & Implementations

    // 🏆 **Best Fit Transform Rounds (BTR)** is a family of functions designed to optimize 
    // transform rounds (TR) and, in some cases, reordering. The system consists of high-level
    // handlers for user interaction and batch processing, as well as core implementations for 
    // execution logic. 

    // 🔹 **Handlers** (Public) – Manage execution flow and user interaction
    // 🔹 **Core Implementations** (Private) – Perform TR optimization (and reordering, if applicable)

    //
    // ✅ **Handlers (Public):**
    // `RunBTR`        – Primary handler for Best Fit Transform Rounds (BTR).
    // `RunBTRBatch`   – Batch handler for multiple sequences.
    // `RunBTRRBatch`  – Batch handler for both rounds + reordering.
    //
    // ✅ **Core Implementations (Private):**
    // `BestFitTransformRoundsCore`      – Core logic for optimizing TR values.
    // `BestFitTransformRoundsReorderCore` – Core logic for optimizing both TR values and reordering.
    //

    #region Run Best Fit Autotune MT (Munge(B) + Convergence Detection)

    /// <summary>
    /// Runs Best Fit Autotune (Munge(B) + Convergence Detection) to optimize per-transform rounds (TR).
    /// 
    /// **Baseline Comparisons:**
    /// 1. **Munge(A)(9) Baseline** – Evaluates the original sequence at "sequence rounds" = 9.
    ///    - This represents the best result found in the global tuning phase.
    /// 2. **Munge(B) (BTR) Baseline** – Evaluates the sequence at "sequence rounds" = 1.
    ///    - This provides the initial point for per-transform round optimization.
    /// 
    /// **Optimization Process:**
    /// - The function systematically tunes **per-transform rounds (TR)** while keeping **global rounds (GR) fixed**.
    /// - If improvements are found, the best configuration is updated.
    /// - Once no further **per-transform** improvements occur, **global rounds (GR) are incremented**.
    /// - The process repeats until **no further gains** are observed, at which point tuning stops.
    /// 
    /// **BTR MT (Multi-Threaded) vs BTR ST (Single-Threaded):**
    /// - **BTR MT is designed to match BTR ST results exactly, just faster.**
    /// - By running multiple optimizations in parallel, BTR MT **can reach the same conclusions faster**.
    /// - Due to parallelization, threads may reset the **no-progress counter** more often, potentially leading to **deeper TR exploration**.
    /// - **Global Rounds (GR) still increment just as in BTR ST, ensuring consistency.**
    /// - Despite parallel execution, **no sequence is unfairly prioritized due to thread execution order**.
    /// 
    /// **Final Comparison:**
    /// - If **Munge(B) (BTR) finds a sequence that outperforms Munge(A)(9)**, it is selected.
    /// - If **Munge(A)(9) remains superior**, the original high-round configuration is retained.
    /// - If no further tuning produces better results, the best sequence found is confirmed.
    /// 
    /// **Key Takeaways:**
    /// - Ensures that per-transform tuning (Munge(B)) is explored to its **fullest potential**.
    /// - Confirms whether **Munge(A) (global round tuning) alone was sufficient**.
    /// - Guarantees that **no better transform ordering exists**—providing final validation.
    /// - The best sequence is then ready for **deep validation in RunSequence** and comparison against **AES**.
    /// 
    /// </summary>
    /// <param name="cryptoLib">The cryptographic library instance.</param>
    /// <param name="input">The input data to be analyzed.</param>
    /// <param name="userSequence">The initial transform sequence to optimize.</param>
    /// <returns>
    /// A tuple containing a message summarizing the results and a console color for status output.
    /// </returns>

    #endregion Run Best Fit Autotune MT (Munge(B) + Convergence Detection)

    #region Run Best Fit Autotune Extreme (Munge(B) + Convergence Detection)

    #endregion Run Best Fit Autotune Extreme (Munge(B) + Convergence Detection)

    #endregion Best Fit Transform Rounds (BTR) Handlers & Implementations

    #region Tools

    public class FileReadException(string fileName, string message, Exception? innerException = null)
        : Exception($"Error reading {fileName}: {message}", innerException)
    {
        public string FileName { get; } = fileName;
    }

    public class NoSequencesFoundException(string fileName)
        : Exception($"No sequences found in {fileName}")
    {
        public string FileName { get; } = fileName;
    }

    // Data structure to capture relevant state before and after encryption/decryption
    public class UsefulContextInfo
    {
        public int RoundsBefore { get; set; }
        public int RoundsAfter { get; set; }
        public int InputSumBefore { get; set; }
        public int InputSumAfter { get; set; }
        public int CboxSumBefore { get; set; }
        public int CboxSumAfter { get; set; }
        public int CryptoLibInstanceBefore { get; set; }
        public int CryptoLibInstanceAfter { get; set; }
        public int EncryptedBefore { get; set; }
        public int EncryptedAfter { get; set; }

        public override string ToString()
        {
            return $"RoundsBefore: {RoundsBefore}, RoundsAfter: {RoundsAfter}, " +
                   $"InputSumBefore: {InputSumBefore}, InputSumAfter: {InputSumAfter}";
        }
    }


    public static
        Dictionary<string, List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysis.AnalysisResult> Metrics
            )>> CreateCandidateList(
            Dictionary<string, List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysis.AnalysisResult>
                Metrics)>> table)
    {
        Dictionary<string, List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysis.AnalysisResult> Metrics
            )>> refinedTable = new();

        foreach (var entry in table)
        {
            var dataType = entry.Key;
            var contenders =
                entry.Value;

            // Track which transforms have been used
            HashSet<List<byte>> usedSequences = new();

            // Dynamically extract metric names from the first contender (if available)
            var firstContender = contenders.FirstOrDefault();
            if (firstContender.Sequence == null)
            {
                // No valid contenders, just continue
                refinedTable[dataType] =
                    new List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysis.AnalysisResult> Metrics
                        )>();
                continue;
            }

            var metricNames = firstContender.Metrics.Select(m => m.Name).ToList(); // No hardcoded metric names

            List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysis.AnalysisResult> Metrics)>
                bestTransforms = new();

            foreach (var metric in metricNames)
            {
                var bestTransform = contenders
                    .Where(c => !usedSequences.Contains(c.Sequence)) // Ignore already selected transforms
                    .Select(c => (Transform: c,
                        MetricScore: c.Metrics.FirstOrDefault(m => m.Name == metric)?.Score ?? double.MinValue))
                    .OrderByDescending(x => x.MetricScore) // Sort by highest metric score
                    .FirstOrDefault();

                if (bestTransform.Transform.Sequence != null)
                {
                    bestTransforms.Add((bestTransform.Transform.Sequence, bestTransform.Transform.AggregateScore,
                        bestTransform.Transform.Metrics));
                    usedSequences.Add(bestTransform.Transform.Sequence); // Prevent duplicate selection
                }
            }

            refinedTable[dataType] = bestTransforms;
        }

        return refinedTable;
    }

    #endregion Tools
}