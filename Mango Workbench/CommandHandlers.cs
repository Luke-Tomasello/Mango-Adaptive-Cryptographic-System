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
using Mango.AnalysisCore;
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
using static Mango.Adaptive.InputProfiler;
using static Mango.AnalysisCore.CryptoAnalysisCore;
using static Mango.Utilities.TestInputGenerator;
using static Mango.Utilities.UtilityHelpers;
using Mango.Common;
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

    public static (string, ConsoleColor) Say(string[] args)
    {
        return (string.Join(" ", args).Trim(), ConsoleColor.Green);
    }
    public static (string, ConsoleColor) RunClassification(ExecutionEnvironment localEnv, string[] args)
    {
        var input = localEnv.Globals.Input;
        var scoringMode = localEnv.Globals.ScoringMode;
        const string password = GlobalsInstance.Password;
        var cryptoLib = localEnv.Crypto; // 
        var cryptoAnalysis = localEnv.CryptoAnalysis; // 

        var path = Path.Combine(AppContext.BaseDirectory, "InputProfiles.json");
        if (!File.Exists(path))
            return ("⚠️ No profiles found.", ConsoleColor.Yellow);

        var json = File.ReadAllText(path);
        var rawProfiles = JsonSerializer.Deserialize<Dictionary<string, InputProfileDto>>(json);
        if (rawProfiles == null || rawProfiles.Count == 0)
            return ("⚠️ No profiles found.", ConsoleColor.Yellow);

        Console.WriteLine($"\n▶️  Running Classification for data type {localEnv.Globals.InputType}...\n");

        var profileList = new List<(int Index, string Name, double Score, double TimeMs, InputProfile Profile)>();
        int index = 1;

        foreach (var (name, dto) in rawProfiles.OrderBy(kvp => kvp.Key))
        {
            var sequence = dto.Sequence.Select(pair => ((byte)pair[0], (byte)pair[1])).ToArray();
            var profile = new InputProfile(name, sequence, dto.GlobalRounds, dto.AggregateScore);

            try
            {
                var sw = Stopwatch.StartNew();
                var encrypted = cryptoLib.Encrypt(profile.Sequence, profile.GlobalRounds, input);
                sw.Stop();

                var payload = cryptoLib.GetPayloadOnly(encrypted);
                // 🧪 Avalanche and Key Dependency
                var (avalanche, _, keydep, _) = 
                    ProcessAvalancheAndKeyDependency(cryptoLib, input, password, profile);

                var results = cryptoAnalysis.RunCryptAnalysis(
                    encryptedData: payload, 
                    avalanchePayload: avalanche, 
                    keyDependencyPayload: keydep, 
                    inputData: input);

                var score = cryptoAnalysis.CalculateAggregateScore(results, scoringMode);
                
                double elapsedMs = sw.Elapsed.TotalMilliseconds;

                Console.WriteLine($"[{index}] {name,-20} Score: {score:F10}   in {elapsedMs:F2} ms");

                profileList.Add((index, name, score, elapsedMs, profile));
                index++;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Failed to score profile '{name}': {ex.Message}");
            }
        }

        if (profileList.Count == 0)
            return ("❌ No suitable profiles were scored.", ConsoleColor.Red);

        var best = profileList.OrderByDescending(p => p.Score).First();
        Console.WriteLine($"\n🏆 Best Match: {best.Name} (Score: {best.Score:F10})\n");

        Console.WriteLine("Select a profile to use, or press Escape to cancel...");
        int selectedIndex = SelectMenuOpt(1, (byte)profileList.Count);
        if (selectedIndex == 0)
            return ($"⚠️ No selection made.", ConsoleColor.Yellow);

        var selected = profileList.First(p => p.Index == selectedIndex);
        string baselineSequence = new SequenceHelper(localEnv.Crypto).FormattedSequence<string>(selected.Profile);
        MangoConsole.CommandStack.Push("Say " + $"✅ Profile '{selected.Name}' selected.\n\n🔧 Next Steps:\n• Run Sequence             → Encrypt your input and view output\n• Run Comparative Analysis → Compare against AES and view metric scores\n• Run BTR                  → Optimize the sequence for even better results\n• Save Profile             → Store this as a named profile for reuse\n\n📌 Tip: Type 'help' to view all available commands.");
        MangoConsole.CommandStack.Push("$" + baselineSequence);

        return (null, ConsoleColor.Green)!;
    }

    #region Profile Management
    public static (string, ConsoleColor) LoadProfile(ExecutionEnvironment localEnv, string[] args)
    {
        if (args.Length == 0)
            return ("❌ Usage: Load Profile <name>", ConsoleColor.Red);

        string profileName = string.Join(" ", args).Trim();
        if (string.IsNullOrWhiteSpace(profileName))
            return ("❌ Profile name cannot be empty.", ConsoleColor.Red);

        var path = Path.Combine(AppContext.BaseDirectory, "InputProfiles.json");
        if (!File.Exists(path))
            return ("⚠️ No profiles found.", ConsoleColor.Yellow);

        var json = File.ReadAllText(path);
        var rawProfiles = JsonSerializer.Deserialize<Dictionary<string, InputProfileDto>>(json);

        // Re-key with case-insensitive comparison
        var comparer = StringComparer.OrdinalIgnoreCase;
        var profileMap = new Dictionary<string, InputProfileDto>(rawProfiles ?? new(), comparer);

        if (!profileMap.TryGetValue(profileName, out var dto))
            return ($"⚠️ Profile '{profileName}' not found.", ConsoleColor.Yellow);

        var sequence = dto.Sequence.Select(pair => ((byte)pair[0], (byte)pair[1])).ToArray();
        var profile = new InputProfile(profileName, sequence, dto.GlobalRounds, dto.AggregateScore);

        // Format the sequence as a command-line ready string
        string formatted = new SequenceHelper(localEnv.Crypto).FormattedSequence<string>(profile);

        MangoConsole.CommandStack.Push("Say " +
                                       $"✅ Profile '{profileName}' loaded successfully.\n\n🔧 Next Steps:\n" +
                                       "• Run Sequence             → Encrypt your input and view output\n" +
                                       "• Run Comparative Analysis → Compare against AES and view metric scores\n" +
                                       "• Run BTR                  → Optimize the sequence for even better results\n" +
                                       "• Save Profile             → Store this as a named profile for reuse\n\n" +
                                       "📌 Tip: Type 'help' to view all available commands.");
        MangoConsole.CommandStack.Push("$" + formatted);

        return (null, ConsoleColor.Green)!;
    }

    public static (string, ConsoleColor) SaveProfile(ExecutionEnvironment localEnv, List<string> sequence, string[] args)
    {
        if (args.Length == 0)
            return ("❌ Usage: Save Profile <name>", ConsoleColor.Red);

        string profileName = string.Join(" ", args).Trim();
        if (string.IsNullOrWhiteSpace(profileName))
            return ("❌ Profile name cannot be empty.", ConsoleColor.Red);

        var sequenceHelper = new SequenceHelper(localEnv.Crypto);
        SequenceHelper.ParsedSequence parsed;

        try
        {
            parsed = sequenceHelper.ParseSequenceFull(sequence);
        }
        catch (Exception ex)
        {
            return ($"❌ Failed to parse current sequence: {ex.Message}", ConsoleColor.Red);
        }

        if (!parsed.SequenceAttributes.TryGetValue("GR", out string? grStr) || !int.TryParse(grStr, out int globalRounds))
        {
            // Profiles must explicitly define 'GR' (GlobalRounds) to avoid hidden dependencies.
            // Falling back to a default based on InputType can introduce subtle, hard-to-detect bugs,
            // especially when reloading, optimizing, or comparing profiles. Enforcing this requirement
            // ensures profiles are fully self-describing, reproducible, and compatible with strict workflows.
            return ("❌ Profile must explicitly specify 'GR' (GlobalRounds).", ConsoleColor.Red);
        }

        var transformSequence = parsed.Transforms.Select(t => (t.ID, (byte)t.TR)).ToArray();
        var profile = InputProfiler.CreateInputProfile(profileName, transformSequence, globalRounds);

        // Load existing profiles
        var path = Path.Combine(AppContext.BaseDirectory, "InputProfiles.json");
        var existingProfiles = new List<InputProfile>();

        if (File.Exists(path))
        {
            try
            {
                var json = File.ReadAllText(path);
                var rawProfiles = JsonSerializer.Deserialize<Dictionary<string, InputProfileDto>>(json);

                if (rawProfiles != null)
                {
                    existingProfiles = rawProfiles
                        .Select(kvp =>
                        {
                            var sequence = kvp.Value.Sequence
                                .Select(pair => ((byte)pair[0], (byte)pair[1]))
                                .ToArray();

                            return new InputProfile(kvp.Key, sequence, kvp.Value.GlobalRounds, kvp.Value.AggregateScore);
                        })
                        .ToList();
                }
            }
            catch (Exception ex)
            {
                return ($"❌ Failed to load existing profiles: {ex.Message}", ConsoleColor.Red);
            }
        }


        // Check for overwrite
        if (existingProfiles.Any(p => p.Name.Equals(profileName, StringComparison.OrdinalIgnoreCase)))
        {
            if (!AskYN($"⚠️ Profile '{profileName}' already exists. Overwrite?"))
                return ($"⚠️ Save aborted. Profile '{profileName}' was not overwritten.", ConsoleColor.Yellow);

            existingProfiles = existingProfiles.Where(p => !p.Name.Equals(profileName, StringComparison.OrdinalIgnoreCase)).ToList();
        }

        #region Calc Aggrate Score
        // Run encryption to calculate AggregateScore
        var crypto = localEnv.Crypto;
        var input = localEnv.Globals.Input;

        var encrypted = crypto.Encrypt(profile.Sequence, profile.GlobalRounds, input);
        var payload = crypto.GetPayloadOnly(encrypted);

        var (avalanche, _, keydep, _) =
            ProcessAvalancheAndKeyDependency(crypto, input, GlobalsInstance.Password, profile);

        var analysis = localEnv.CryptoAnalysis.RunCryptAnalysis(payload, avalanche, keydep, input);

        var aggregateScore = localEnv.CryptoAnalysis.CalculateAggregateScore(analysis, localEnv.Globals.ScoringMode);

        // Update the profile object
        profile = profile with { AggregateScore = aggregateScore };
        #endregion Calc Aggrate Score

        existingProfiles.Add(profile);

        try
        {
            // Convert InputProfiles to InputProfileDto
            var dtoDict = existingProfiles.ToDictionary(
                kvp => kvp.Name,
                kvp => new InputProfileDto
                {
                    Sequence = kvp.Sequence
                        .Select(pair => new List<byte> { pair.ID, pair.TR })
                        .ToList(),
                    GlobalRounds = kvp.GlobalRounds,
                    AggregateScore = kvp.AggregateScore
                }
            );

            var updatedJson = JsonSerializer.Serialize(dtoDict, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, updatedJson);
        }
        catch (Exception ex)
        {
            return ($"❌ Failed to save profile: {ex.Message}", ConsoleColor.Red);
        }

        RefreshProfiles();
        return ($"✅ Profile '{profileName}' saved successfully.", ConsoleColor.Green);
    }

    public static (string, ConsoleColor) ReplaceProfile(ExecutionEnvironment localEnv, List<string> sequence, string[] args)
    {
        if (args.Length == 0)
            return ("❌ Usage: Replace Profile <name>", ConsoleColor.Red);

        string profileName = string.Join(" ", args).Trim();
        if (string.IsNullOrWhiteSpace(profileName))
            return ("❌ Profile name cannot be empty.", ConsoleColor.Red);

        var sequenceHelper = new SequenceHelper(localEnv.Crypto);
        SequenceHelper.ParsedSequence parsed;

        try
        {
            parsed = sequenceHelper.ParseSequenceFull(sequence);
        }
        catch (Exception ex)
        {
            return ($"❌ Failed to parse current sequence: {ex.Message}", ConsoleColor.Red);
        }

        if (!parsed.SequenceAttributes.TryGetValue("GR", out string? grStr) || !int.TryParse(grStr, out int globalRounds))
            return ("❌ Profile must explicitly specify 'GR' (GlobalRounds).", ConsoleColor.Red);

        var transformSequence = parsed.Transforms.Select(t => (t.ID, (byte)t.TR)).ToArray();
        var profile = InputProfiler.CreateInputProfile(profileName, transformSequence, globalRounds);

        var path = Path.Combine(AppContext.BaseDirectory, "InputProfiles.json");
        var existingProfiles = new List<InputProfile>();

        if (File.Exists(path))
        {
            try
            {
                var json = File.ReadAllText(path);
                var rawProfiles = JsonSerializer.Deserialize<Dictionary<string, InputProfileDto>>(json);

                if (rawProfiles != null)
                {
                    existingProfiles = rawProfiles
                        .Select(kvp =>
                        {
                            var sequence = kvp.Value.Sequence
                                .Select(pair => ((byte)pair[0], (byte)pair[1]))
                                .ToArray();

                            return new InputProfile(kvp.Key, sequence, kvp.Value.GlobalRounds, kvp.Value.AggregateScore);
                        })
                        .Where(p => !p.Name.Equals(profileName, StringComparison.OrdinalIgnoreCase)) // ← always remove old
                        .ToList();
                }
            }
            catch (Exception ex)
            {
                return ($"❌ Failed to load existing profiles: {ex.Message}", ConsoleColor.Red);
            }
        }

        #region Calc Aggregate Score
        var crypto = localEnv.Crypto;
        var input = localEnv.Globals.Input;

        var encrypted = crypto.Encrypt(profile.Sequence, profile.GlobalRounds, input);
        var payload = crypto.GetPayloadOnly(encrypted);

        var (avalanche, _, keydep, _) =
            ProcessAvalancheAndKeyDependency(crypto, input, GlobalsInstance.Password, profile);

        var analysis = localEnv.CryptoAnalysis.RunCryptAnalysis(payload, avalanche, keydep, input);
        var aggregateScore = localEnv.CryptoAnalysis.CalculateAggregateScore(analysis, localEnv.Globals.ScoringMode);
        profile = profile with { AggregateScore = aggregateScore };
        #endregion

        existingProfiles.Add(profile);

        try
        {
            var dtoDict = existingProfiles.ToDictionary(
                kvp => kvp.Name,
                kvp => new InputProfileDto
                {
                    Sequence = kvp.Sequence
                        .Select(pair => new List<byte> { pair.ID, pair.TR })
                        .ToList(),
                    GlobalRounds = kvp.GlobalRounds,
                    AggregateScore = kvp.AggregateScore
                }
            );

            var updatedJson = JsonSerializer.Serialize(dtoDict, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, updatedJson);
        }
        catch (Exception ex)
        {
            return ($"❌ Failed to replace profile: {ex.Message}", ConsoleColor.Red);
        }

        RefreshProfiles();
        return ($"✅ Profile '{profileName}' replaced successfully.", ConsoleColor.Green);
    }

    public static (string, ConsoleColor) DeleteProfile(string[] args)
    {
        if (args.Length == 0)
            return ("❌ Usage: Delete Profile <name>", ConsoleColor.Red);

        string profileName = string.Join(" ", args).Trim();
        if (string.IsNullOrWhiteSpace(profileName))
            return ("❌ Profile name cannot be empty.", ConsoleColor.Red);

        var path = Path.Combine(AppContext.BaseDirectory, "InputProfiles.json");
        if (!File.Exists(path))
            return ($"⚠️ No profiles found.", ConsoleColor.Yellow);

        var json = File.ReadAllText(path);
        var tempProfiles = JsonSerializer.Deserialize<Dictionary<string, InputProfileDto>>(json);

        // Wrap with case-insensitive comparer
        var rawProfiles = tempProfiles != null
            ? new Dictionary<string, InputProfileDto>(tempProfiles, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, InputProfileDto>(StringComparer.OrdinalIgnoreCase);

        if (!rawProfiles.ContainsKey(profileName))
            return ($"⚠️ Profile '{profileName}' does not exist.", ConsoleColor.Yellow);

        rawProfiles.Remove(profileName);

        var updatedJson = JsonSerializer.Serialize(rawProfiles, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, updatedJson);

        RefreshProfiles();
        return ($"✅ Profile '{profileName}' deleted successfully.", ConsoleColor.Green);
    }
    public static (string, ConsoleColor) RenameProfile(string[] args)
    {
        if (args.Length != 2)
            return ("❌ Usage: Rename Profile <\"old name\"> <\"new name\">", ConsoleColor.Red);

        string oldName = args[0].Trim();
        string newName = string.Join(" ", args.Skip(1)).Trim();

        if (string.IsNullOrWhiteSpace(oldName) || string.IsNullOrWhiteSpace(newName))
            return ("❌ Profile names cannot be empty.", ConsoleColor.Red);

        var path = Path.Combine(AppContext.BaseDirectory, "InputProfiles.json");
        if (!File.Exists(path))
            return ($"⚠️ No profiles found.", ConsoleColor.Yellow);

        var json = File.ReadAllText(path);
        var tempProfiles = JsonSerializer.Deserialize<Dictionary<string, InputProfileDto>>(json);

        var rawProfiles = tempProfiles != null
            ? new Dictionary<string, InputProfileDto>(tempProfiles, StringComparer.OrdinalIgnoreCase)
            : new Dictionary<string, InputProfileDto>(StringComparer.OrdinalIgnoreCase);

        if (!rawProfiles.TryGetValue(oldName, out var profile))
            return ($"⚠️ Profile '{oldName}' does not exist.", ConsoleColor.Yellow);

        if (rawProfiles.ContainsKey(newName))
            return ($"⚠️ A profile named '{newName}' already exists.", ConsoleColor.Yellow);

        rawProfiles.Remove(oldName);
        rawProfiles[newName] = profile;

        var updatedJson = JsonSerializer.Serialize(rawProfiles, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, updatedJson);

        RefreshProfiles();
        return ($"✅ Profile renamed from '{oldName}' to '{newName}' successfully.", ConsoleColor.Green);
    }

    public static (string, ConsoleColor) ListProfiles(ExecutionEnvironment localEnv, string[] args)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "InputProfiles.json");
        if (!File.Exists(path))
            return ("⚠️ No profiles found.", ConsoleColor.Yellow);

        var json = File.ReadAllText(path);
        var rawProfiles = JsonSerializer.Deserialize<Dictionary<string, InputProfileDto>>(json);
        if (rawProfiles == null || rawProfiles.Count == 0)
            return ("⚠️ No profiles found.", ConsoleColor.Yellow);

        string wildcard = args.Length == 0 ? "*" : string.Join(" ", args).Trim();
        string pattern = "^" + Regex.Escape(wildcard)
            .Replace(@"\*", ".*")
            .Replace(@"\?", ".") + "$";

        var regex = new Regex(pattern, RegexOptions.IgnoreCase);

        var matchingProfiles = rawProfiles
            .Where(kvp => regex.IsMatch(kvp.Key))
            .OrderBy(kvp => kvp.Key)
            .ToList();

        if (matchingProfiles.Count == 0)
            return ($"⚠️ No profiles matched pattern: \"{pattern}\"", ConsoleColor.Yellow);

        foreach (var kvp in matchingProfiles)
        {
            var name = kvp.Key;
            var dto = kvp.Value;

            var sequence = dto.Sequence.Select(pair => ((byte)pair[0], (byte)pair[1])).ToArray();

            var readable = string.Join(" -> ",
                sequence.Select(p =>
                    localEnv.Crypto.TransformRegistry.TryGetValue(p.Item1, out var info)
                        ? $"{info.Name}(ID:{p.Item1})(TR:{p.Item2})"
                        : $"Unknown(ID:{p.Item1})(TR:{p.Item2})"
                ));

            var structured = $"InputProfile(\"{name}\", new (byte, byte)[]\n    {{\n        {string.Join(",\n        ", sequence.Select(p => $"({p.Item1}, {p.Item2}), // {(localEnv.Crypto.TransformRegistry.TryGetValue(p.Item1, out var info) ? info.Name : "Unknown")}"))}\n    }}, {dto.GlobalRounds}, {dto.AggregateScore:F10})";

            Console.WriteLine($"\n🧩 {name}");
            Console.WriteLine(readable + $" | (GR:{dto.GlobalRounds})");
            Console.WriteLine(structured);
        }

        PressAnyKey();

        return ("✅ Profile list complete.", ConsoleColor.Green);
    }

    public static (string, ConsoleColor) TouchProfiles(ExecutionEnvironment parentEnv)
    {
        var path = Path.Combine(AppContext.BaseDirectory, "InputProfiles.json");
        if (!File.Exists(path))
            return ("⚠️ No profiles found.", ConsoleColor.Yellow);

        var json = File.ReadAllText(path);
        var rawProfiles = JsonSerializer.Deserialize<Dictionary<string, InputProfileDto>>(json);
        if (rawProfiles == null || rawProfiles.Count == 0)
            return ("⚠️ No profiles found.", ConsoleColor.Yellow);

        var updatedProfiles = new Dictionary<string, InputProfileDto>();
        var transformRegistry = parentEnv.Crypto.TransformRegistry;

        foreach (var kvp in rawProfiles.OrderBy(kvp => kvp.Key))
        {
            var fullName = kvp.Key;
            var dto = kvp.Value;
            var sequence = dto.Sequence.Select(pair => ((byte)pair[0], (byte)pair[1])).ToArray();

            string baseName = fullName.Split('.')[0];

            InputType inputType;
            if (!Enum.TryParse<InputType>(baseName, ignoreCase: true, out inputType))
            {
                inputType = InputType.Combined;
                Console.WriteLine($"⚠️ Profile '{fullName}' has unrecognized base name '{baseName}'. Falling back to InputType.Combined.");
            }

            var localEnv = new ExecutionEnvironment(parentEnv);
            localEnv.Globals.UpdateSetting("InputType", inputType);

            var profile = new InputProfile(fullName, sequence, dto.GlobalRounds, dto.AggregateScore);

            try
            {
                var crypto = localEnv.Crypto;
                var input = localEnv.Globals.Input;

                var sw = Stopwatch.StartNew();
                var encrypted = crypto.Encrypt(profile.Sequence, profile.GlobalRounds, input);
                sw.Stop();
                var payload = crypto.GetPayloadOnly(encrypted);

                var (avalanche, _, keydep, _) =
                    ProcessAvalancheAndKeyDependency(crypto, input, GlobalsInstance.Password, profile);

                var analysis = localEnv.CryptoAnalysis.RunCryptAnalysis(payload, avalanche, keydep, input);
                var aggregateScore = localEnv.CryptoAnalysis.CalculateAggregateScore(analysis, localEnv.Globals.ScoringMode);

                profile = profile with { AggregateScore = aggregateScore };

                updatedProfiles[fullName] = new InputProfileDto
                {
                    Sequence = profile.Sequence
                        .Select(pair => new List<byte> { pair.ID, pair.TR })
                        .ToList(),
                    GlobalRounds = profile.GlobalRounds,
                    AggregateScore = profile.AggregateScore
                };

                Console.WriteLine($"✅ Refreshed profile: {fullName} (Score: {aggregateScore:F10}) ({sw.Elapsed.TotalMilliseconds} ms)");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"❌ Failed to refresh '{fullName}': {ex.Message}");
            }
        }

        try
        {
            var updatedJson = JsonSerializer.Serialize(updatedProfiles, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(path, updatedJson);
        }
        catch (Exception ex)
        {
            return ($"❌ Failed to write updated profiles: {ex.Message}", ConsoleColor.Red);
        }

        if (IsInteractiveWorkbench(parentEnv))
            PressAnyKey();

        RefreshProfiles();
        return ("✅ All profiles touched and updated.", ConsoleColor.Green);
    }

    #endregion Profile Management
    public static (string, ConsoleColor) AssessSequence(ExecutionEnvironment localEnv, List<string> sequence, string[] args, List<string>? results)
    {
        var inputTypes = Enum.GetValues(typeof(InputType)).Cast<InputType>();
        var password = GlobalsInstance.Password;
        using var _ = new BatchModeScope(localEnv); // Sets BatchMode = true

        // Allow override from args
        var passwordIndex = Array.IndexOf(args, "--password");
        if (passwordIndex >= 0 && passwordIndex < args.Length - 1)
        {
            password = string.Join(" ", args.Skip(passwordIndex + 1));
        }

        // Build profile from sequence
        var seq = new SequenceHelper(localEnv.Crypto);
        SequenceHelper.ParsedSequence parsed;
        try
        {
            parsed = seq.ParseSequenceFull(sequence);
        }
        catch (Exception ex)
        {
            return ($"❌ Failed to parse current sequence: {ex.Message}", ConsoleColor.Red);
        }
        var profile = InputProfiler.CreateInputProfile("sequence",
            sequence: parsed.Transforms.Select(t => t.ID).ToArray(),
            tRs: parsed.Transforms.Select(t => (byte)t.TR).ToArray(),
            globalRounds: parsed.SequenceAttributes.TryGetValue("GR", out var grStr) && int.TryParse(grStr, out var parsedGR)
                ? parsedGR : localEnv.Globals.Rounds);

        foreach (var inputType in inputTypes)
        {
            var env = new ExecutionEnvironment(localEnv, password);
            env.Globals.UpdateSetting("InputType", inputType);

            try
            {
                var crypto = env.Crypto;
                var input = env.Globals.Input;

                // Time encryption only
                var sw = Stopwatch.StartNew();
                var encrypted = crypto.Encrypt(profile.Sequence, profile.GlobalRounds, input);
                sw.Stop();
                var payload = crypto.GetPayloadOnly(encrypted);

                // Analyze metrics
                var (avalanche, _, keydep, _) =
                    ProcessAvalancheAndKeyDependency(crypto, input, password, profile);

                var analysisResults = env.CryptoAnalysis.RunCryptAnalysis(payload, avalanche, keydep, input);
                var score = env.CryptoAnalysis.CalculateAggregateScore(analysisResults, env.Globals.ScoringMode);
                var fswp = FormatScoreWithPassRatio(score, analysisResults, sw.Elapsed.TotalMilliseconds);

                string output = $"{inputType,-12}: {fswp}";
                Console.WriteLine(output);
                if (results != null)
                    results.Add(output);
            }
            catch (Exception ex)
            {
                return ($"❌ {inputType}: Error - {ex.Message}", ConsoleColor.Red);
            }
        }

        if (IsInteractiveWorkbench(localEnv))
            PressAnyKey();

        return ("Assess Sequence completed successfully.", ConsoleColor.Green);
    }

    public static (string, ConsoleColor) SelectBestFast(ExecutionEnvironment localEnv, string[] args)
    {
        var fileIndex = Array.IndexOf(args, "--file");
        if (fileIndex == -1 || fileIndex >= args.Length - 1)
            return ("❌ Missing or malformed --file <filename> argument.", ConsoleColor.Red);

        var filename = args[fileIndex + 1];
        if (!File.Exists(filename))
            return ($"❌ File not found: {filename}", ConsoleColor.Red);

        // Optional minimum pass count
        int? minPassCount = null;
        var passArg = args.FirstOrDefault(a => a.StartsWith("--min-passCount"));
        if (passArg != null && int.TryParse(passArg.Split(' ').Last(), out int min))
            minPassCount = min;

        // Read and clean candidate sequences
        var candidateLines = File.ReadAllLines(filename)
            .Where(line => line.Contains("New Best:"))
            .Select(line =>
            {
                var start = line.IndexOf("New Best:") + "New Best:".Length;
                var grIndex = line.IndexOf("| (GR:");
                if (start < 0 || grIndex < 0 || grIndex <= start) return null;

                // Extract core sequence and GR attribute
                var core = line[start..grIndex].Trim();
                var grPartEnd = line.IndexOf(')', grIndex);
                if (grPartEnd < 0) return null;
                var grPart = line[grIndex..(grPartEnd + 1)].Trim();

                var fullSequence = $"{core} {grPart}";

                SequenceHelper seqHelper = new(localEnv.Crypto);
                var format = SequenceFormat.ID | seqHelper.DetermineFormat(fullSequence);
                var parsedSequence = seqHelper.ParseSequenceFull(fullSequence, format);

                if (parsedSequence == null || !parsedSequence.Transforms.Any())
                    return null;

                return seqHelper.FormattedSequence<List<string>>(
                    parsedSequence,
                    SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes,
                    2, true);
            })
            .Where(seq => seq != null && seq.Any())
            .Distinct(new SequenceListComparer())
            .ToList();

        if (candidateLines.Count == 0)
            return ("❌ No valid sequences found in the candidate file.", ConsoleColor.Red);

        var scoredCandidates = new List<(List<string> Sequence, double AvgScore, int PassCount, double TimeMs, List<string> Report)>();

        foreach (var candidate in candidateLines)
        {
            var results = new List<string>();
            var (msg, color) = AssessSequence(localEnv, candidate!, args, results);
            if (color != ConsoleColor.Green)
            {
                ColorConsole.WriteLine($"<{color.ToString()}>{msg}</{color.ToString()}>");
                continue;
            }

            try
            {
                List<(double Score, int Passes, double Time)> scores = results
                    .Select(line =>
                    {
                        var match = Regex.Match(line, @"\((?<score>\d+\.\d+)\)\s+\((?<pass>\d) / 9\)\s+\((?<time>\d+\.\d+)ms\)");
                        return match.Success
                            ? (Score: double.Parse(match.Groups["score"].Value),
                                Passes: int.Parse(match.Groups["pass"].Value),
                                Time: double.Parse(match.Groups["time"].Value))
                            : ((double Score, int Passes, double Time)?)null;
                    })
                    .Where(r => r.HasValue)
                    .Select(r => r!.Value)
                    .ToList();


                if (scores.Count == 0) continue;

                double avg = scores.Average(s => s.Item1);
                int passCount = scores.Sum(s => s.Item2);
                double totalTime = scores.Sum(s => s.Item3);

                scoredCandidates.Add((candidate, avg, passCount, totalTime, results)!);
            }
            catch { /* skip malformed */ }
        }

        if (scoredCandidates.Count == 0)
            return ("❌ No valid scoring candidates after assessment.", ConsoleColor.Red);

        var best = scoredCandidates.OrderByDescending(c => c.AvgScore).First();

        var fast = scoredCandidates
            .Where(c => c != best)
            .Where(c => !minPassCount.HasValue || c.PassCount >= minPassCount.Value)
            .OrderByDescending(c => c.PassCount)
            .ThenByDescending(c => c.AvgScore)
            .ThenBy(c => c.TimeMs)
            .FirstOrDefault();

        Console.WriteLine("\n===== 🏆 Selected .Best Sequence =====\n");
        best.Sequence.ForEach(Console.WriteLine);
        best.Report.ForEach(Console.WriteLine);

        if (fast != default)
        {
            Console.WriteLine("\n===== ⚡ Selected .Fast Sequence =====\n");
            fast.Sequence.ForEach(Console.WriteLine);
            fast.Report.ForEach(Console.WriteLine);
        }
        else
        {
            Console.WriteLine("\n⚠️ No suitable .Fast sequence found meeting pass count threshold.");
        }

        PressAnyKey();

        return ("✅ SelectBestFast completed.", ConsoleColor.Green);
    }

    // Helper comparer to prevent duplicate sequence lists
    //class SequenceListComparer : IEqualityComparer<List<string>>
    //{
    //    public bool Equals(List<string>? x, List<string>? y)
    //    {
    //        if (x == null || y == null) return false;
    //        return x.SequenceEqual(y);
    //    }

    //    public int GetHashCode(List<string> obj)
    //    {
    //        return string.Join("|", obj).GetHashCode();
    //    }
    //}
    class SequenceListComparer : IEqualityComparer<List<string>?>
    {
        public bool Equals(List<string>? x, List<string>? y)
        {
            if (ReferenceEquals(x, y)) return true;
            if (x is null || y is null) return false;
            if (x.Count != y.Count) return false;
            return x.SequenceEqual(y);
        }

        public int GetHashCode(List<string>? obj)
        {
            if (obj is null) return 0;
            return obj.Aggregate(17, (hash, str) => hash * 31 + (str?.GetHashCode() ?? 0));
        }
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
                        // 🧱 Build input profile for forward transform
                        var profile = InputProfiler.CreateInputProfile(name: $"Benchmark-{forwardId}",
                            sequence: new[] { forwardId },
                            tRs: new[] { (byte)1 },
                            globalRounds: 1 // or use `localEnv.Globals.Rounds` if dynamic
                        );

                        var sw = Stopwatch.StartNew();

                        // 🔐 Encrypt using profile
                        var encrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, input);

                        // 🔓 New-style decryption (self-contained header)
                        var decrypted = localEnv.Crypto.Decrypt(encrypted);

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
        FlushAndReloadBenchmarkCache();

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


                case "weights":
                    {
                        if (localEnv.Globals.Mode == OperationModes.None)
                            return ("Error: Mode is not set.", ConsoleColor.Red);

                        // Retrieve actual weights from MetricsRegistry
                        var actualWeights =
                            localEnv.CryptoAnalysis.MetricsRegistry.ToDictionary(kvp => kvp.Key,
                                kvp => kvp.Value.Weight);

                        // Retrieve known weight tables dynamically
                        var foundCryptographic = localEnv.CryptoAnalysis.TryGetWeights(OperationModes.Cryptographic,
                            out var cryptographicWeights);
                        var foundExploratory =
                            localEnv.CryptoAnalysis.TryGetWeights(OperationModes.Exploratory, out var exploratoryWeights);

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
                return (
                    "⚠️ Cannot switch to UserData input: UserData.bin not found. Use 'load user data <file>' to load your data first.",
                    ConsoleColor.Yellow);
            }

            localEnv.Globals.UpdateSetting(key, convertedValue);

            // ✅ immediat save
            localEnv.Globals.Save();

            // after a set command, show the list
            MangoConsole.CommandStack.Push("list");
            //return ($"<Green>{key}</Green> updated to: <Green>{value}</Green>", Console.ForegroundColor);
            return (null, Console.ForegroundColor)!;
        }
        catch (Exception ex)
        {
            return ($"<Red>Error updating {key}:</Red> {ex.Message}", Console.ForegroundColor);
        }
        finally
        {
            
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
            // Build single-transform InputProfile (TR = 1)
            var profile = InputProfiler.CreateInputProfile(name: $"Step-{transformId}",
                sequence: new[] { transformId },
                tRs: new byte[] { 1 },
                globalRounds: localEnv.Globals.Rounds
            );

            // Encrypt using high-level API
            var transformInputCopy = previousEncrypted!.ToArray(); // Ensure original input is untouched
            var encrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, transformInputCopy);

            // Extract payload (removes Mango header)
            var payload = localEnv.Crypto.GetPayloadOnly(encrypted);

            // Store the result
            results.Add(payload);

            // Update input for the next transform
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

            ColorConsole.WriteLine($"Processing InputType: <green>{type.ToString()}</green>");

            List<byte[]> inputBlocks = new();
            for (var i = 0; i < blockCount; i++)
                inputBlocks.Add(GenerateTestInput(blockSize, type));

            var profile = InputProfiler.GetInputProfile(
                inputBlocks[0], 
                localEnv.Globals.Mode, 
                localEnv.Globals.ScoringMode, 
                performance: EncryptionPerformanceMode.Fast);

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
            var salt = AesSalt;
            using var deriveBytes = new Rfc2898DeriveBytes(
                password,
                salt,
                250_000, // ⬅️ Strong iteration count
                HashAlgorithmName.SHA256 // ⬅️ Modern secure hash function
            );

            var aesKey = deriveBytes.GetBytes(32);
            var aesIV = deriveBytes.GetBytes(16);

            var aes = new AesSoftwareCore.AesSoftwareCore(aesKey);
            List<byte[]> aesEncryptedBlocks = new();

            var swAesEncrypt = Stopwatch.StartNew();
            for (var i = 0; i < inputBlocks.Count; i++)
            {
                var encrypted = aes.EncryptCbc(inputBlocks[i]!, aesIV);
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
                    var decrypted = aes.DecryptCbc(aesEncryptedBlocks[i], aesIV);
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

            //if (speedRatio >= 1.5)
            //    color = ConsoleColor.Green;
            //else if (speedRatio <= 0.75)
            //    color = ConsoleColor.Red;
            //else
            //    color = ConsoleColor.Yellow;
            color = ConsoleColor.Gray;

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

        if (finalRatio >= 1.0)
        {
            resultBuilder.AppendLine($"⚡ Mango is {finalRatio:F1}× faster on average");
        }
        else
        {
            double slowerFactor = aesAvgEncMBps / mangoAvgEncMBps;
            resultBuilder.AppendLine($"🐢 Mango is {slowerFactor:F1}× slower than AES");
        }

        return (resultBuilder.ToString(), color);
    }
    public static (string, ConsoleColor) RunCryptoShowdown(ExecutionEnvironment parentEnv)
    {
        var inputTypes = Enum.GetValues<InputType>();
        var reportSections = new List<List<string>>();
        var localEnv = new ExecutionEnvironment(parentEnv);

        foreach (var inputType in inputTypes)
        {
            localEnv.Globals.UpdateSetting("InputType", inputType);

            var bestProfile = InputProfiler.GetInputProfile(localEnv.Globals.Input, localEnv.Globals.Mode, localEnv.Globals.ScoringMode);
            if (bestProfile == null)
            {
                Console.WriteLine($"❌ No profile found for input type: {inputType}");
                continue;
            }

            var profile = new InputProfile(bestProfile.Name, bestProfile.Sequence, bestProfile.GlobalRounds, bestProfile.AggregateScore);

            localEnv.CryptoAnalysis.Initialize();

            // 🔒 Mango encryption
            var swMango = Stopwatch.StartNew();
            var encryptedMango = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, localEnv.Globals.Input);
            swMango.Stop();
            var mangoPayload = localEnv.Crypto.GetPayloadOnly(encryptedMango);

            // 🔐 AES encryption
            var swAes = Stopwatch.StartNew();
            var aesEncrypted = AesEncrypt(localEnv.Globals.Input, GlobalsInstance.Password, out var saltLen, out var padLen);
            swAes.Stop();
            var aesPayload = ExtractAESPayload(aesEncrypted, saltLen, padLen);
            var aesDecrypted = AesDecrypt(aesEncrypted, GlobalsInstance.Password);
            var aesReversible = aesDecrypted.SequenceEqual(localEnv.Globals.Input);

            var (mangoAv, aesAv, mangoKd, aesKd) = ProcessAvalancheAndKeyDependency(
                localEnv.Crypto,
                localEnv.Globals.Input,
                GlobalsInstance.Password,
                profile,
                processAes: true);

            // 🧠 Mango analysis
            var mangoAnalysis = localEnv.CryptoAnalysis.RunCryptAnalysis(mangoPayload, mangoAv, mangoKd, localEnv.Globals.Input);
            var mangoScore = localEnv.CryptoAnalysis.CalculateAggregateScore(mangoAnalysis, localEnv.Globals.ScoringMode);
            var mangoPasses = mangoAnalysis.Count(m => m.Passed);

            // 🔍 AES analysis
            var aesAnalysis = localEnv.CryptoAnalysis.RunCryptAnalysis(aesPayload, aesAv, aesKd, localEnv.Globals.Input);
            var aesScore = localEnv.CryptoAnalysis.CalculateAggregateScore(aesAnalysis, localEnv.Globals.ScoringMode);
            var aesPasses = aesAnalysis.Count(m => m.Passed);

            var section = new List<string>
        {
            $"=== InputType: {inputType} ===",
            $"Mango: {profile.Name} (Score: {mangoScore:F4}, Passes: {mangoPasses}/9, Time: {swMango.Elapsed.TotalMilliseconds:F2} ms)",
            $"AES  : Built-in (Score: {aesScore:F4}, Passes: {aesPasses}/9, Time: {swAes.Elapsed.TotalMilliseconds:F2} ms)",
            string.Empty
        };

            reportSections.Add(section);
        }

        foreach (var section in reportSections)
            foreach (var line in section)
                Console.WriteLine(line);

        if (IsInteractiveWorkbench(parentEnv))
            PressAnyKey();

        return ("✅ Crypto Showdown complete.", ConsoleColor.Green);
    }
#if true
    public static (string, ConsoleColor) RunMetricBreakdown(ExecutionEnvironment parentEnv)
    {
        var inputTypes = Enum.GetValues<InputType>();
        var localEnv = new ExecutionEnvironment(parentEnv);

        var metricNames = new[]
        {
        "Entropy",
        "BitVariance",
        "SlidingWindow",
        "FrequencyDistribution",
        "PeriodicityCheck",
        "MangosCorrelation",
        "PositionalMapping",
        "AvalancheScore",
        "KeyDependency"
    };

        // Helper to format metric cell
        string FormatMetric(string status, double score) => $"{status} {score:F7}";
        string FormatStatus(CryptoAnalysisCore.AnalysisResult r) =>
            r == null ? FormatMetric("❓", 0) : FormatMetric(r.Passed ? "✅" : "❌", r.Score);
        //r == null ? FormatMetric("❓", 0) : FormatMetric(r.Passed ? "✅" : "❌", r.Score);

        // Build Mango CSV
        var mangoCsv = new List<string> { "🔶 Mango Metric Breakdown", "" };
        mangoCsv.Add("InputType," + string.Join(",", metricNames));

        // Build AES CSV
        var aesCsv = new List<string> { "🔷 AES Metric Breakdown", "" };
        aesCsv.Add("InputType," + string.Join(",", metricNames));

        foreach (var inputType in inputTypes)
        {
            localEnv.Globals.UpdateSetting("InputType", inputType);

            var bestProfile = InputProfiler.GetInputProfile(localEnv.Globals.Input, localEnv.Globals.Mode, localEnv.Globals.ScoringMode);
            if (bestProfile == null)
            {
                Console.WriteLine($"❌ No profile found for input type: {inputType}");
                continue;
            }

            var profile = new InputProfile(bestProfile.Name, bestProfile.Sequence, bestProfile.GlobalRounds, bestProfile.AggregateScore);
            localEnv.CryptoAnalysis.Initialize();

            var mangoEncrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, localEnv.Globals.Input);
            var mangoPayload = localEnv.Crypto.GetPayloadOnly(mangoEncrypted);

            var aesEncrypted = AesEncrypt(localEnv.Globals.Input, GlobalsInstance.Password, out var saltLen, out var padLen);
            var aesPayload = ExtractAESPayload(aesEncrypted, saltLen, padLen);

            var (mangoAv, aesAv, mangoKd, aesKd) = ProcessAvalancheAndKeyDependency(
                localEnv.Crypto,
                localEnv.Globals.Input,
                GlobalsInstance.Password,
                profile,
                processAes: true);

            var mangoResults = localEnv.CryptoAnalysis.RunCryptAnalysis(mangoPayload, mangoAv, mangoKd, localEnv.Globals.Input);
            var aesResults = localEnv.CryptoAnalysis.RunCryptAnalysis(aesPayload, aesAv, aesKd, localEnv.Globals.Input);

            string mangoRow = inputType + "," +
                              string.Join(",", metricNames.Select(name =>
                                  FormatStatus(mangoResults.FirstOrDefault(r => r.Name == name)!)));

            string aesRow = inputType + "," +
                            string.Join(",", metricNames.Select(name =>
                                FormatStatus(aesResults.FirstOrDefault(r => r.Name == name)!)));

            mangoCsv.Add(mangoRow);
            aesCsv.Add(aesRow);
        }

        // Display both CSVs to console
        CsvFormatter.DisplayCsvFormatted(mangoCsv);
        CsvFormatter.DisplayCsvFormatted(aesCsv);

        if (IsInteractiveWorkbench(parentEnv))
            PressAnyKey();

        return ("✅ Metric breakdown complete.", ConsoleColor.Green);
    }

#else
    public static (string, ConsoleColor) RunMetricBreakdown(ExecutionEnvironment parentEnv)
    {
        var inputTypes = Enum.GetValues<InputType>();
        var localEnv = new ExecutionEnvironment(parentEnv);

        var metricNames = new[]
        {
        "Entropy",
        "BitVariance",
        "SlidingWindow",
        "FrequencyDistribution",
        "PeriodicityCheck",
        "MangosCorrelation",
        "PositionalMapping",
        "AvalancheScore",
        "KeyDependency"
    };

        int colWidth = 17;//metricNames.Max(name => name.Length) + 3; // 3 = buffer
        string FormatCell(string content) => content.PadRight(colWidth);
        string FormatMetric(string status, double score) =>
            $"{status} {score,6:F2}";

        var mangoTable = new List<string> { "\n🔶 Mango Metric Breakdown" };
        var aesTable = new List<string> { "\n🔷 AES Metric Breakdown" };
        string header = FormatCell("InputType") + string.Join(" ", metricNames.Select(name => FormatCell(name)));

        string divider = new string('-', header.Length);

        mangoTable.Add(header);
        mangoTable.Add(divider);
        aesTable.Add(header);
        aesTable.Add(divider);

        foreach (var inputType in inputTypes)
        {
            localEnv.Globals.UpdateSetting("InputType", inputType);

            var bestProfile = InputProfiler.GetInputProfile(localEnv.Globals.Input, localEnv.Globals.Mode, localEnv.Globals.ScoringMode);
            if (bestProfile == null)
            {
                Console.WriteLine($"❌ No profile found for input type: {inputType}");
                continue;
            }

            var profile = new InputProfile(bestProfile.Name, bestProfile.Sequence, bestProfile.GlobalRounds, bestProfile.AggregateScore);
            localEnv.CryptoAnalysis.Initialize();

            var mangoEncrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, localEnv.Globals.Input);
            var mangoPayload = localEnv.Crypto.GetPayloadOnly(mangoEncrypted);

            var aesEncrypted = AesEncrypt(localEnv.Globals.Input, GlobalsInstance.Password, out var saltLen, out var padLen);
            var aesPayload = ExtractAESPayload(aesEncrypted, saltLen, padLen);

            var (mangoAv, aesAv, mangoKd, aesKd) = ProcessAvalancheAndKeyDependency(
                localEnv.Crypto,
                localEnv.Globals.Input,
                GlobalsInstance.Password,
                profile,
                processAes: true);

            var mangoResults = localEnv.CryptoAnalysis.RunCryptAnalysis(mangoPayload, mangoAv, mangoKd, localEnv.Globals.Input);
            var aesResults = localEnv.CryptoAnalysis.RunCryptAnalysis(aesPayload, aesAv, aesKd, localEnv.Globals.Input);

            string FormatStatus(CryptoAnalysisCore.AnalysisResult r) => r == null
                ? FormatMetric("❓", 0)
                : FormatMetric(r.Passed ? "✅" : "❌", r.Score);

            string mangoRow = FormatCell(inputType.ToString()) +
                              string.Join("", metricNames.Select(name =>
                                  FormatCell(FormatStatus(mangoResults.FirstOrDefault(r => r.Name == name)))));
            string aesRow = FormatCell(inputType.ToString()) +
                            string.Join("", metricNames.Select(name =>
                                FormatCell(FormatStatus(aesResults.FirstOrDefault(r => r.Name == name)))));

            mangoTable.Add(mangoRow);
            aesTable.Add(aesRow);
        }

        foreach (var line in mangoTable.Concat(aesTable))
            Console.WriteLine(line);

        if (IsInteractiveWorkbench(parentEnv))
            PressAnyKey();

        return ("✅ Metric breakdown complete.", ConsoleColor.Green);
    }
#endif
    public static (string, ConsoleColor) RunComparativeAnalysis(ExecutionEnvironment localEnv,
        SequenceHelper.ParsedSequence parsedSequence)
    {
        SequenceHelper seqHelper = new(localEnv.Crypto);
        var sequence = parsedSequence.Transforms.Select(t => t.ID).ToArray();
        var trs = parsedSequence.Transforms.Select(t => (byte)t.TR).ToArray();
        var globalRounds = parsedSequence.SequenceAttributes.TryGetValue("GR", out var grStr)
                           && int.TryParse(grStr, out var parsedGR) ? parsedGR : localEnv.Globals.Rounds;
        var formattedSequence = seqHelper.FormattedSequence<string>(parsedSequence,
            SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes,
            2, true);

        if (sequence.Length == 0) return ("No transforms in sequence. Add transforms before running.", ConsoleColor.Red);

        try
        {
            // Reset metrics and contenders before starting
            localEnv.CryptoAnalysis.Initialize();

            Console.WriteLine(
                $"\n--- Executing Comparative Analysis (GRounds: {globalRounds})---\n");

            // 🎯 Construct InputProfile using resolved TRs from registry
            var profile = InputProfiler.CreateInputProfile(name: "comparative",
                sequence: sequence.ToArray(),
                tRs: trs,
                globalRounds: globalRounds
            );

            // Measure Mango Encryption Time
            var stopwatch = Stopwatch.StartNew();

            // 🔑 Include Mango's startup cost in the calculation
            var options = new CryptoLibOptions(Scoring.MangoSalt);
            var cryptoLib = new CryptoLib(GlobalsInstance.Password, options);

            var MangoEncrypted = cryptoLib.Encrypt(profile.Sequence, profile.GlobalRounds, localEnv.Globals.Input);
            stopwatch.Stop();
            var MangoTime = stopwatch.Elapsed;
            var MangoPayload = cryptoLib.GetPayloadOnly(MangoEncrypted); // Extract payload for Mango encryption

            // Measure AES Encryption Time
            stopwatch = Stopwatch.StartNew();
            var AESPayloadRaw = AesEncrypt(localEnv.Globals.Input, GlobalsInstance.Password,
                out var saltLength,
                out var paddingLength);
            stopwatch.Stop();
            var AESTime = stopwatch.Elapsed;
            var AESPayload = ExtractAESPayload(AESPayloadRaw, saltLength, paddingLength);

            // make sure AES is able to decrypt it's input
            var aesDecrypted = AesDecrypt(AESPayloadRaw, GlobalsInstance.Password);
            var aesReversible = aesDecrypted.SequenceEqual(localEnv.Globals.Input);

            // 🔁 Run Avalanche & KeyDependency tests
            var (MangoAvalanchePayload, AESAvalanchePayload, MangoKeyDependencyPayload, AESKeyDependencyPayload) =
                ProcessAvalancheAndKeyDependency(
                    localEnv.Crypto,
                    localEnv.Globals.Input,
                    GlobalsInstance.Password,
                    profile,
                    processAes: true);

            // Mango Results
            var analysisResults = localEnv.CryptoAnalysis.RunCryptAnalysis(
                MangoPayload,
                MangoAvalanchePayload,
                MangoKeyDependencyPayload,
                localEnv.Globals.Input);

            // Display cryptanalysis report
            var mangoHeader = GenerateHeader(
                localEnv,
                formattedSequence: formattedSequence,
                analysisResults: analysisResults,
                isReversible: true,
                name: "Mango",
                options: HeaderOptions.AllAnalysis | HeaderOptions.Mode | HeaderOptions.InputType |
                         HeaderOptions.ScoringMode | HeaderOptions.PassCount
            );

            List<string> mangoAnalysis = localEnv.CryptoAnalysis.CryptAnalysisReport(localEnv.Crypto, analysisResults);
            List<string> mangoTiming = new List<string> { $"Mango Encryption took: {MangoTime.TotalMilliseconds} ms" };

            // AES Results
            analysisResults = localEnv.CryptoAnalysis.RunCryptAnalysis(
                AESPayload,
                AESAvalanchePayload,
                AESKeyDependencyPayload,
                localEnv.Globals.Input);

            // Display cryptanalysis report: Dummy sequence for AES (it doesn't execute our sequences)
            var aesHeader = GenerateHeader(
                localEnv,
                formattedSequence: new SequenceHelper(localEnv.Crypto).FormattedSequence(new byte[] { },
                    SequenceFormat.None),
                analysisResults: analysisResults,
                isReversible: aesReversible,
                name: "AES",
                options: HeaderOptions.AllAnalysis | HeaderOptions.Mode | HeaderOptions.InputType |
                         HeaderOptions.ScoringMode | HeaderOptions.PassCount
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

            AssertWeightsMatchExpectedMode(localEnv);

            // ✅ Compute the aggregate score
            var aggregateScore =
                localEnv.CryptoAnalysis.CalculateAggregateScore(analysisResults, localEnv.Globals.ScoringMode,
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

    public static List<CryptoAnalysisCore.AnalysisResult>? EncryptAndAnalyze(
        ExecutionEnvironment localEnv,
        List<byte> sequence)
    {
        // 🎯 Construct profile using flat TR:1 for all transforms
        var flatTRs = Enumerable.Repeat((byte)1, sequence.Count).ToArray();
        var profile = InputProfiler.CreateInputProfile(name: "EncryptAndAnalyze",
            sequence: sequence.ToArray(),
            tRs: flatTRs, // Auto-resolve from registry
            globalRounds: localEnv.Globals.Rounds
        );

        // 🔐 Encrypt using high-level profile API
        var encrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, localEnv.Globals.Input);
        var payload = localEnv.Crypto.GetPayloadOnly(encrypted);

        // 🧪 Generate Avalanche and Key Dependency outputs (no AES needed)
        var (mangoAvalanche, _, mangoKeyDep, _) =
            ProcessAvalancheAndKeyDependency(
                cryptoLib: localEnv.Crypto,
                input: localEnv.Globals.Input,
                password: GlobalsInstance.Password,
                profile: profile
            );

        // 📊 Analyze cryptographic results
        var results = localEnv.CryptoAnalysis.RunCryptAnalysis(
            payload,
            mangoAvalanche,
            mangoKeyDep,
            localEnv.Globals.Input
        );

        return results;
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
        var profile = InputProfiler.GetInputProfile(inputData, localEnv.Globals.Mode, localEnv.Globals.ScoringMode);
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
        List<CryptoAnalysisCore.AnalysisResult>? analysisResults, List<byte> currentSequence, string failurekey)
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
        //var sequence = seqHelper.GetIDs(parsedSequence);
        var sequence = parsedSequence.Transforms.Select(t => t.ID).ToArray();
        var trs = parsedSequence.Transforms.Select(t => (byte)t.TR).ToArray();

        if (sequence.Length == 0)
            return ("No transforms in sequence. Add transforms before running.", ConsoleColor.Red);

        localEnv.CryptoAnalysis.Initialize();

        var roundsStart = 1;
        double bestScore = 0;
        var bestGR = roundsStart;
        List<CryptoAnalysisCore.AnalysisResult>? bestMetrics = null;

        ColorConsole.WriteLine(
            $"\n<white>🔧 Optimizing Global Rounds (Start: {roundsStart}, Max: {roundsMax})</white>\n");

        for (var rounds = roundsStart; rounds <= roundsMax; rounds++)
        {
            // 🧠 Build profile with current round count and TRs pulled from registry
            var profile = InputProfiler.CreateInputProfile(name: "optGR",
                sequence: sequence.ToArray(),
                tRs: trs,
                globalRounds: rounds
            );

            // 🔐 Encrypt and verify reversibility
            var encrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, localEnv.Globals.Input);
            var payload = localEnv.Crypto.GetPayloadOnly(encrypted);
            var decrypted = localEnv.Crypto.Decrypt(encrypted);

            if (!decrypted.SequenceEqual(localEnv.Globals.Input))
            {
                ColorConsole.WriteLine($"<red>❌ Reversibility failed at GR: {rounds}</red>");
                continue;
            }

            // 📊 Run avalanche and key-dependency analysis
            var (avalanche, _, keydep, _) = ProcessAvalancheAndKeyDependency(
                localEnv.Crypto,
                localEnv.Globals.Input,
                GlobalsInstance.Password,
                profile);

            var results = localEnv.CryptoAnalysis.RunCryptAnalysis(
                payload,
                avalanche,
                keydep,
                localEnv.Globals.Input);

            AssertWeightsMatchExpectedMode(localEnv);

            var score = localEnv.CryptoAnalysis.CalculateAggregateScore(results, localEnv.Globals.ScoringMode);

            ColorConsole.WriteLine($"<yellow>GR:{rounds,-2}</yellow> → Score: <green>{score:F4}</green>");

            if (score > bestScore)
            {
                bestScore = score;
                bestGR = rounds;
                bestMetrics = results;
            }
        }

        // ✅ Restore best GR for continuity
        localEnv.Globals.UpdateSetting("rounds", bestGR);

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
                         HeaderOptions.ScoringMode | HeaderOptions.PassCount
            );

            List<string> report = localEnv.CryptoAnalysis.CryptAnalysisReport(localEnv.Crypto, bestMetrics);

            ColorConsole.WriteLine($"\n<cyan>🏁 Best GR Found: {bestGR}</cyan>");
            ReportHelper.Report(localEnv.Globals.ReportFormat, new List<string>[] { header, report },
                new string[] { localEnv.Globals.ReportFilename! });

            return ($"🏆 Optimization complete. Best Score: {bestScore:F4} at GR:{bestGR}", ConsoleColor.Green);
        }

        return ("⚠️ No valid GR setting improved the score.", ConsoleColor.Yellow);
    }


    public static (string, ConsoleColor) RunSequenceHandler(ExecutionEnvironment parentEnv, string[] args, List<string> sequence)
    {
        // 🔐 Determine password
        string password;
        var passwordIndex = Array.IndexOf(args, "--password");
        if (passwordIndex >= 0 && passwordIndex < args.Length - 1)
        {
            // Join all remaining args after --password into one space-separated string
            password = string.Join(" ", args.Skip(passwordIndex + 1));
        }
        else
        {
            // Fallback to parent environment password
            password = GlobalsInstance.Password;
        }

        // ✅ Create a fresh local execution environment with the selected password
        var localEnv = new ExecutionEnvironment(parentEnv, password);
        //var localEnv = new ExecutionEnvironment(password, parentEnv.Crypto.Options);

        // ✅ Parse the sequence and run it in a scoped environment
        using (var localStateEnv = new LocalEnvironment(localEnv, sequence))
        {
            return RunSequence(localEnv, localStateEnv.ParsedSequence);
        }
    }

    public static (string, ConsoleColor) RunSequence(ExecutionEnvironment localEnv,
    SequenceHelper.ParsedSequence parsedSequence)
    {
        SequenceHelper seqHelper = new(localEnv.Crypto);
        var globalRounds = parsedSequence.SequenceAttributes.TryGetValue("GR", out var grStr)
                   && int.TryParse(grStr, out var parsedGR) ? parsedGR : localEnv.Globals.Rounds;
        var sequence = parsedSequence.Transforms.Select(t => t.ID).ToArray();
        var trs = parsedSequence.Transforms.Select(t => (byte)t.TR).ToArray();

        var formattedSequence = seqHelper.FormattedSequence<string>(parsedSequence,
            SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes,
            2, true);
        if (sequence.Length == 0)
            return ("No transforms in sequence. Add transforms before running.", ConsoleColor.Red);

        try
        {
            // Reset metrics and contenders before starting
            localEnv.CryptoAnalysis.Initialize();

            Console.WriteLine($"\n--- Executing Transformations (GRounds: {globalRounds})---\n");

            const int labelWidth = 16;
            const int rows = 1;
            const int columns = 16;
            const string mode = "BITS";
            const string format = "HEX";

            var inputCopy = localEnv.Globals.Input.ToArray();

            // 🧾 Input Display
            ColorConsole.WriteLine(
                Field("Input Data", labelWidth) +
                Visualizer.Format(inputCopy, inputCopy, mode, rows, columns, format: format)[0]);

            // 🎯 Build InputProfile with auto-resolved TRs
            var profile = InputProfiler.CreateInputProfile(name: "sequence",
                sequence: sequence.ToArray(),
                tRs: trs,
                globalRounds: globalRounds
            );

            // 🔐 Encrypt using profile
            var stopwatch = Stopwatch.StartNew();
            var encrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, localEnv.Globals.Input);
            stopwatch.Stop();

            var payload = localEnv.Crypto.GetPayloadOnly(encrypted);

            var inputForComparison = localEnv.Globals.Input.ToArray();
            ColorConsole.WriteLine(
                Field("Encrypted Data", labelWidth) +
                Visualizer.Format(inputForComparison, payload, mode, rows, columns, format: format)[0]);

            var bitComparisonRows = Visualizer.Format(inputForComparison, payload, mode, rows, columns, format: format);
            ColorConsole.WriteLine(
                Field("Bit Comparison", labelWidth) +
                string.Join(" ", bitComparisonRows));

            // 🔓 Decrypt (reverse handled internally)
            var decrypted = localEnv.Crypto.Decrypt(encrypted);

            var inputForDecryptionComparison = localEnv.Globals.Input.ToArray();
            ColorConsole.WriteLine(
                Field("Decrypted Data", labelWidth) +
                Visualizer.Format(inputForDecryptionComparison, decrypted, mode, rows, columns, format: format)[0]);

            var isReversible = decrypted!.SequenceEqual(localEnv.Globals.Input);
            var color = isReversible ? "Green" : "Red";

            // 🧪 Avalanche and Key Dependency
            var (MangoAvalanchePayload, _, MangoKeyDependencyPayload, _) =
                ProcessAvalancheAndKeyDependency(
                    localEnv.Crypto,
                    localEnv.Globals.Input,
                    GlobalsInstance.Password,
                    profile
                );

            var analysisResults = localEnv.CryptoAnalysis.RunCryptAnalysis(
                encryptedData: payload,
                avalanchePayload: MangoAvalanchePayload,
                keyDependencyPayload: MangoKeyDependencyPayload,
                inputData: localEnv.Globals.Input, null);

            localEnv.CryptoAnalysis.CryptAnalysisRecordBest(localEnv, analysisResults, sequence.ToList());

            var header = GenerateHeader(
                localEnv,
                formattedSequence: formattedSequence,
                analysisResults: analysisResults,
                isReversible: isReversible,
                options: HeaderOptions.AllAnalysis | HeaderOptions.Mode | HeaderOptions.InputType |
                         HeaderOptions.ScoringMode | HeaderOptions.PassCount);

            var analysis = localEnv.CryptoAnalysis.CryptAnalysisReport(localEnv.Crypto, analysisResults);
            var timing = new List<string>
        {
            $"\n--- Sequence Execution Completed in {stopwatch.Elapsed.TotalMilliseconds:F2} ms ---"
        };

            ReportHelper.Report(localEnv.Globals.ReportFormat,
                new List<string>[] { header, analysis, timing },
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

        // 🔍 Extract (ID, TR) tuple array from parsed sequence
        var originalSequence = parsedSequence.Transforms
            .Select(t => (ID: t.ID, TR: (byte)t.TR))
            .ToArray();

        var format = SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.InferGRounds | SequenceFormat.RightSideAttributes;

        // 🔄 Reset metrics before running analysis
        localEnv.CryptoAnalysis.Initialize();
        Console.WriteLine("Running Best Fit...\n");

        // 🔧 Score the original sequence before permutations
        var globalRounds = parsedSequence.SequenceAttributes.TryGetValue("GR", out var grStr)
                           && int.TryParse(grStr, out var parsedGR) ? parsedGR : localEnv.Globals.Rounds;
        var profile = InputProfiler.CreateInputProfile("Original", originalSequence, globalRounds);
        var encrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, localEnv.Globals.Input);
        var decrypted = localEnv.Crypto.Decrypt(encrypted);
        var originalValid = decrypted.SequenceEqual(localEnv.Globals.Input);

        Console.WriteLine($"Original sequence: {seqHelper.FormattedSequence(profile.Sequence, format, 2, true)}");

        if (!originalValid)
            Console.WriteLine("<red>❌ Original sequence failed reversibility.</red>");
        else
        {
            var payload = localEnv.Crypto.GetPayloadOnly(encrypted);
            var (avalanche, _, keydep, _) = ProcessAvalancheAndKeyDependency(
                localEnv.Crypto,
                localEnv.Globals.Input,
                GlobalsInstance.Password,
                profile);

            AssertWeightsMatchExpectedMode(localEnv);
            var originalMetrics = localEnv.CryptoAnalysis.RunCryptAnalysis(payload, avalanche, keydep, localEnv.Globals.Input);
            var originalScore = localEnv.CryptoAnalysis.CalculateAggregateScore(originalMetrics, localEnv.Globals.ScoringMode);

            ColorConsole.WriteLine($"Original Score: <green>{originalScore:F4}</green>\n");
        }

        // 🔁 Generate all unique permutations of the full (ID, TR) tuples
        var permutations = GenerateUniquePermutations(originalSequence).ToList();
        if (!permutations.Any()) return ("No permutations generated. Ensure your sequence is valid.", ConsoleColor.Red);

        List<((byte ID, byte TR)[], double Score, List<CryptoAnalysisCore.AnalysisResult>? Metrics)> results = new();

        foreach (var permutation in permutations)
        {
            var testProfile = InputProfiler.CreateInputProfile("BestFitTest", permutation, globalRounds);

            Console.WriteLine($"\nTesting sequence:\n{seqHelper.FormattedSequence(testProfile.Sequence, format, 2, true)}");

            var (isValid, score, metrics) = TestAndScorePermutation(localEnv, testProfile);

            if (!isValid)
            {
                Console.WriteLine($"<red>❌ Reversibility failed</red>");
                continue;
            }

            ColorConsole.WriteLine($"Score: <green>{score:F4}</green>");
            results.Add((permutation, score, metrics));
        }

        if (!results.Any()) return ("⚠️ No valid sequences found.", ConsoleColor.Yellow);

        // 🏆 Find best scoring sequence
        var best = results.OrderByDescending(r => r.Score).First();
        var bestSequence = best.Item1;
        var bestMetrics = best.Metrics;

        //localEnv.CryptoAnalysis.CryptAnalysisRecordBest(localEnv, bestMetrics!, bestSequence.ToList());

        var header = GenerateHeader(
            localEnv,
            formattedSequence: seqHelper.FormattedSequence(bestSequence, format, 2, true),
            analysisResults: bestMetrics,
            isReversible: true,
            options: HeaderOptions.AllAnalysis | HeaderOptions.Mode | HeaderOptions.InputType |
                     HeaderOptions.ScoringMode | HeaderOptions.PassCount
        );

        var analysis = localEnv.CryptoAnalysis.CryptAnalysisReport(localEnv.Crypto, bestMetrics!);
        var commandHeader = GenerateHeader(localEnv, "Run Best Fit", null, HeaderOptions.AllExecution);

        ReportHelper.Report(localEnv.Globals.ReportFormat,
            new List<string>[] { commandHeader },
            new string[] { localEnv.Globals.ReportFilename! });

        ReportHelper.Report(localEnv.Globals.ReportFormat,
            new List<string>[] { header, analysis },
            new string[] { localEnv.Globals.ReportFilename! });

        Console.WriteLine("\nPress any key to return to the main menu...");
        Console.ReadKey();

        return ($"🏁 Best Fit complete. Top score: {best.Score:F4}", ConsoleColor.Green);
    }
    private static (bool IsValid, double Score, List<CryptoAnalysisCore.AnalysisResult>? Metrics)
        TestAndScorePermutation(ExecutionEnvironment env, InputProfile profile)
    {
        var encrypted = env.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, env.Globals.Input);
        var decrypted = env.Crypto.Decrypt(encrypted);

        if (!decrypted.SequenceEqual(env.Globals.Input))
            return (false, 0.0, null);

        var payload = env.Crypto.GetPayloadOnly(encrypted);

        var (avalanche, _, keydep, _) = ProcessAvalancheAndKeyDependency(
            env.Crypto,
            env.Globals.Input,
            GlobalsInstance.Password,
            profile);

        AssertWeightsMatchExpectedMode(env);
        var metrics = env.CryptoAnalysis.RunCryptAnalysis(payload, avalanche, keydep, env.Globals.Input);
        var score = env.CryptoAnalysis.CalculateAggregateScore(metrics, env.Globals.ScoringMode);

        return (true, score, metrics);
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
        Dictionary<string, List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysisCore.AnalysisResult> Metrics
            )>> CreateCandidateList(
            Dictionary<string, List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysisCore.AnalysisResult>
                Metrics)>> table)
    {
        Dictionary<string, List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysisCore.AnalysisResult> Metrics
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
                    new List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysisCore.AnalysisResult> Metrics
                        )>();
                continue;
            }

            var metricNames = firstContender.Metrics.Select(m => m.Name).ToList(); // No hardcoded metric names

            List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysisCore.AnalysisResult> Metrics)>
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