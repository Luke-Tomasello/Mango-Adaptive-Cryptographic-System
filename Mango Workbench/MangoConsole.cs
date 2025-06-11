/*
 * MangoConsole Module
 * =============================================
 * Project: Mango
 * Purpose: Implements the interactive command-line interface for executing
 *          cryptographic operations, analyzing transform sequences, and
 *          managing automated test runs within the Mango Workbench.
 *
 *          This module supports:
 *            • Full-featured CLI for cryptographic experimentation
 *            • Command stack execution for scripting and automation
 *            • Built-in sequence editor and transform menu
 *            • Natural language command scaffolding
 *            • Persistence of command and sequence history
 *            • Robust command-line parser for batch mode
 *
 *          It serves as the entry point for Mango operations, allowing
 *          both manual control and scripted operation for deep testing.
 *
 * Author: [Luke Tomasello, luke@tomasello.com]
 * Created: November 2024
 * License: [MIT]
 * =============================================
 */

using Mango.Adaptive;
using Mango.AnalysisCore;
using Mango.Cipher;
using Mango.Common;
using Mango.Utilities;
using Newtonsoft.Json;
using System.Text;
using System.Text.RegularExpressions;
using static Mango.Cipher.CryptoLib;
using static Mango.Utilities.SequenceHelper;
using static Mango.Utilities.TestInputGenerator;
using static Mango.Utilities.UtilityHelpers;
using static Mango.Workbench.Handlers;
namespace Mango.Workbench;

public static class MangoConsole
{
    private static void Main(string[] args)
    {
        try
        {
            // Batchmode mode test
            //args = new string[] { "-RunCommand", "run munge", "-ExitJobComplete", "-maxSequenceLen", "4", "-inputType", "Random", "-passCount", "6", "-quiet", "-scoringMode", "Practical", "-mode", "Cryptographic", "-createMungeFailDB", "-logMungeOutput" };
            //args = new string[] { "-RunCommand", "run munge", "-RunCommand", "clear sequence", "-ExitJobComplete", "-maxSequenceLen", "2", "-inputType", "Random", "-passCount", "6", "-quiet", "-scoringMode", "Practical", "-mode", "Cryptographic" };
            //args = new string[] { "-RunCommand", "run best fit batch autotune(-L3 -P0 -DC -MF)", "-logMungeOutput", "-ExitJobComplete" };
            //args = new string[] { "-Rounds", "7" };
            //args = new string[] { "-RunCommand", "run munge(-L5 -restore)", "-ExitJobComplete", "-maxSequenceLen", "5", "-inputType", "Combined", "-passCount", "6", "-quiet", "-scoringMode", "Practical", "-mode", "Cryptographic", "-createMungeFailDB" };
            //args = new string[] { "-RunCommand", "run munge(-restore)", "-ExitJobComplete", "-maxSequenceLen", "4", "-inputType", "Combined", "-passCount", "6", "-quiet", "-mode", "Cryptographic", };
            //args = new string[] { "-RunCommand", "run munge(--no-cutlist --remove-inverse)", "-ExitJobComplete", "-maxSequenceLen", "4", "-inputType", "Combined", "-passCount", "6", "-quiet", "-mode", "Cryptographic", };

            Console.OutputEncoding = System.Text.Encoding.UTF8;
            ColorConsole.WriteLine($"\n<yellow>🚀 Initializing Mango Workbench...</yellow>\n");

            // ✅ Initialize the cryptographic library with predefined options
            var options = new CryptoLibOptions(Scoring.MangoSalt);

            // ✅ One-time initialization: Preloads all test input data into memory to eliminate runtime disk I/O and ensure thread safety.
            InitializeInputData();

            // ✅ Declare LocalEnv in Main
            var localEnv = new ExecutionEnvironment(options, true);

            // ✅ Perform a startup benchmark to gauge the host machine's performance.
            // // This measures a representative transform and records the timing for normalization.
            EstablishCurrentBenchmarkTime(localEnv);

            // ✅ Load the benchmark cache
            LoadBenchmarkCache();

            // ✅ Retrieve the pre-established baseline time from the transform registry.
            // // This serves as a consistent reference point (e.g., ID 35) for future comparisons.
            SetBenchmarkBaselineTime(localEnv);

            // ✅ Load global settings (persists values between runs)
            localEnv.Globals.Load();

            // ✅ Apply command-line arguments (may override previous run settings)
            ParseCommandParameters(localEnv, args);

            // ✅ Before running the console, run regression tests of core components
            if (args.Any(a => a.Equals("--run-regression-tests", StringComparison.OrdinalIgnoreCase)))
                RegressionTests.RunRegressionTests(localEnv);

            // ✅ Run the interactive console
            RunConsole(localEnv);

            // ✅ Save updated global settings after execution
            MangoShutdown(localEnv);
        }
        catch (ArgumentException ex)
        {
            // 🔴 Print helpful error message instead of crashing
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[ERROR] Invalid command-line argument: {ex.Message}");
            Console.ResetColor();
            Environment.Exit(1); // Exit with an error code
        }
        catch (Exception ex)
        {
            // 🔴 Handle unexpected exceptions
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine($"[FATAL ERROR] {ex.Message}");
            Console.WriteLine($"🪵 Stack Trace:\n{ex.StackTrace}");
            Console.ResetColor();
            Environment.Exit(1);
        }
    }

    private static void MangoShutdown(ExecutionEnvironment localEnv)
    {
        localEnv.Globals.Save();
    }


    #region Commandline argument parsing

    /// <summary>
    /// Parses command-line arguments, configuring global application settings based on user input.
    /// Handles integer, boolean, and enum parameters, with case-insensitive matching.
    /// Validates commands using a command registry and throws exceptions for unknown parameters or invalid values.
    /// </summary>
    public static void ParseCommandParameters(ExecutionEnvironment localEnv, string[] args)
    {
        // ✅ Early exit if the first argument starts with '#' (commented-out command)
        if (args.Length > 0 && args[0].StartsWith("#"))
        {
            localEnv.Globals.Commandline = "<none specified>";
            return;
        }

        // ✅ Store the full command-line for sanity checks
        localEnv.Globals.Commandline = args.Length > 0 ? string.Join(" ", args) : "<none specified>";

        // ✅ Keep track of processed parameters to detect unknown ones
        HashSet<string> processedArgs = new(StringComparer.OrdinalIgnoreCase);
        localEnv.Globals.FunctionParms.Clear(); // ✅ Reset function parameter storage

        // ✅ Assign parsed values explicitly to Globals using UpdateSetting
        ProcessIntParam(localEnv.Crypto, "-rounds");
        ProcessIntParam(localEnv.Crypto, "-maxSequenceLen");
        ProcessEnumParam<InputType>(localEnv.Crypto, "-inputType");
        ProcessIntParam(localEnv.Crypto, "-passCount");
        ProcessIntParam(localEnv.Crypto, "-desiredContenders");
        ProcessBoolParam(localEnv.Crypto, "-quiet");
        ProcessIntParam(localEnv.Crypto, "-flushThreshold");
        ProcessBoolParam(localEnv.Crypto, "-sqlCompact");
        ProcessEnumParam<ScoringModes>(localEnv.Crypto, "-scoringMode");
        ProcessEnumParam<OperationModes>(localEnv.Crypto, "-mode");
        ProcessBoolParam(localEnv.Crypto, "-createMungeFailDB");
        ProcessBoolParam(localEnv.Crypto, "-exitJobComplete");
        ProcessBoolParam(localEnv.Crypto, "-logMungeOutput");

        // ✅ Collect `-RunCommand` entries **in user order**
        List<string> runCommands = new();
        var exitRequested = false;

        for (var i = 0; i < args.Length - 1; i++)
            if (args[i].Equals("-RunCommand", StringComparison.OrdinalIgnoreCase))
            {
                var runCommand = ParseFunctionParms(localEnv, args, i);
                processedArgs.Add("-RunCommand");
                processedArgs.Add(runCommand);

                // ✅ Validate command before adding
                if (!ValidateRunCommand(localEnv, runCommand))
                    throw new ArgumentException($"Invalid command for -RunCommand: {runCommand}");

                if (runCommand.Equals("exit", StringComparison.OrdinalIgnoreCase))
                    exitRequested = true; // ✅ Track if exit is explicitly requested
                else
                    runCommands.Add(runCommand); // ✅ Collect valid commands in user order
            }

        // ✅ Ensure "exit" is **always last** (by pushing it first) if requested or `-ExitJobComplete` is enabled
        if (exitRequested || localEnv.Globals.ExitJobComplete) CommandStack.Push("exit");

        // ✅ **Reverse-push commands** so they execute **in the expected order**
        for (var i = runCommands.Count - 1; i >= 0; i--) CommandStack.Push(runCommands[i]);

        // ✅ Check for leftover (unprocessed) parameters
        // Some command-line arguments contain function-specific parameters inside parentheses 
        // (e.g., "run best fit transform rounds(-L3 -P0 -DC -MF)"). 
        // ✅ To prevent false unprocessed argument errors, we apply ClipParms(args) here, 
        // ensuring that only the base command names are considered when checking for unknown parameters.
        var clippedArgs = ClipParms(args);
        var unprocessedArgs = clippedArgs.Except(processedArgs, StringComparer.OrdinalIgnoreCase).ToArray();
        if (unprocessedArgs.Length > 0)
            throw new ArgumentException($"Unknown or invalid parameters detected: {string.Join(" ", unprocessedArgs)}");

        // ✅ Auto-enable Batch Mode if running in automation
        if (processedArgs.Contains("-RunCommand") || localEnv.Globals.ExitJobComplete)
            localEnv.Globals.BatchMode = true;

        void ProcessIntParam(CryptoLib? cryptoLib, string paramName)
        {
            if (args.Contains(paramName, StringComparer.OrdinalIgnoreCase))
            {
                var value = GetIntParameter(args, paramName);
                processedArgs.Add(paramName);
                processedArgs.Add(value.ToString());
                localEnv.Globals.UpdateSetting(paramName.TrimStart('-'), value);
            }
        }

        void ProcessBoolParam(CryptoLib? cryptoLib, string paramName)
        {
            var index = Array.FindIndex(args, arg => string.Equals(arg, paramName, StringComparison.OrdinalIgnoreCase));

            if (index >= 0)
            {
                var parsedValue = index + 1 < args.Length && bool.TryParse(args[index + 1], out var tempValue)
                    ? tempValue
                    : true;
                processedArgs.Add(paramName);
                if (index + 1 < args.Length) processedArgs.Add(args[index + 1]);

                localEnv.Globals.UpdateSetting(paramName.TrimStart('-'), parsedValue);
            }
        }

        void ProcessEnumParam<T>(CryptoLib? cryptoLib, string paramName) where T : struct
        {
            if (args.Contains(paramName, StringComparer.OrdinalIgnoreCase))
            {
                var value = GetEnumParameter<T>(args, paramName);
                processedArgs.Add(paramName); // ✅ Keep paramName for tracking
                processedArgs.Add(value.ToString()!); // ✅ Store for reference/debugging

                localEnv.Globals.UpdateSetting(paramName.TrimStart('-'), value); // ✅ Pass the enum directly
            }
        }
    }

    private static string[] ClipParms(string[] rawCommands)
    {
        return rawCommands.Select(cmd => cmd.Contains('(')
                ? cmd.Substring(0, cmd.IndexOf('(')).Trim()
                : cmd)
            .ToArray();
    }

    private static string ParseFunctionParms(ExecutionEnvironment localEnv, string[] args, int currentIndex)
    {
        // ✅ Ensure there is a next argument
        if (currentIndex + 1 >= args.Length)
            throw new ArgumentException($"Malformed -RunCommand: Missing command name after {args[currentIndex]}");

        var rawCommand = args[currentIndex + 1].Trim(); // ✅ Extract command name (with potential parameters)

        // ✅ Check if there are function parameters (wrapped in parentheses)
        var paramStart = rawCommand.IndexOf('(');
        if (paramStart == -1) return rawCommand; // ✅ No parameters found, return raw command

        var paramEnd = rawCommand.LastIndexOf(')');
        if (paramEnd == -1 || paramEnd < paramStart)
            throw new ArgumentException($"Malformed -RunCommand: Unmatched parentheses in {rawCommand}");

        // ✅ Extract function name and parameters
        var functionName = rawCommand.Substring(0, paramStart).Trim();
        var paramSection = rawCommand.Substring(paramStart + 1, paramEnd - paramStart - 1).Trim();

        if (string.IsNullOrWhiteSpace(functionName))
            throw new ArgumentException($"Malformed -RunCommand: Missing function name in {rawCommand}");

        // ✅ Parse parameters into an array
        var functionArgs = paramSection.Split(' ', StringSplitOptions.RemoveEmptyEntries);

        // ✅ Ensure no duplicate entries
        if (localEnv.Globals.FunctionParms.ContainsKey(functionName))
            throw new InvalidOperationException($"Duplicate -RunCommand found: {functionName}");

        // ✅ Store parameters in FunctionParms
        localEnv.Globals.FunctionParms[functionName] = functionArgs;

        // ✅ Return the cleaned command **without** parameters
        return functionName;
    }

    // 🔹 **Extracts function name and inline arguments**
    private static (string functionName, string[] args) ExtractCommandAndArgs(string rawCommand)
    {
        string functionName;
        string[] functionArgs = Array.Empty<string>();

        if (rawCommand.Contains("(") && rawCommand.EndsWith(")"))
        {
            var parenStart = rawCommand.IndexOf('(');
            functionName = rawCommand.Substring(0, parenStart).Trim();
            var argContent = rawCommand.Substring(parenStart + 1, rawCommand.Length - parenStart - 2);

            functionArgs = argContent.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        }
        else
        {
            functionName = rawCommand.Trim();
        }

        return (functionName, functionArgs);
    }

    private static bool ValidateRunCommand(ExecutionEnvironment localEnv, string command)
    {
        // ✅ Use static registry function
        var commandRegistry = CommandRegistry.Registry(localEnv, new List<string>());
        if (!commandRegistry.ContainsKey(command))
            throw new ArgumentException($"Invalid command for -RunCommand: {command}");
        return true;
    }

    // ✅ GetIntParameter now assumes the caller already checked for existence
    private static int GetIntParameter(string[] args, string paramName)
    {
        var index = Array.FindIndex(args, arg => arg.Equals(paramName, StringComparison.OrdinalIgnoreCase));
        if (index >= 0 && index + 1 < args.Length && int.TryParse(args[index + 1], out var result)) return result;
        throw new ArgumentException($"Invalid or missing value for {paramName}");
    }

    // ✅ GetEnumParameter now assumes the caller already checked for existence
    private static T GetEnumParameter<T>(string[] args, string paramName) where T : struct
    {
        var index = Array.FindIndex(args, arg => arg.Equals(paramName, StringComparison.OrdinalIgnoreCase));
        if (index >= 0 && index + 1 < args.Length && Enum.TryParse(args[index + 1], true, out T result)) return result;
        throw new ArgumentException($"Invalid or missing value for {paramName}");
    }

    #endregion Commandline argument parsing

    public static class CommandRegistry
    {
        public static Dictionary<string, (
            Func<string[], (string, ConsoleColor)> handler,
            int tokenCount,
            string description,
            string example,
            bool experimental)> Registry(ExecutionEnvironment localEnv, List<string> sequence)
        {
            SequenceHelper seq = new(localEnv.Crypto);

            return new Dictionary<string, (
                Func<string[], (string, ConsoleColor)> handler,
                int tokenCount,
                string description,
                string example,
                bool experimental)>(StringComparer.OrdinalIgnoreCase)
            {
                {
                    "add transform",
                    (args => AddTransformHandler(localEnv.Crypto, args, seq.GetIDs(sequence).ToList()), 2,
                        "Add a transform to the sequence.", "add transform XORTransform", experimental: false)
                },
                {
                    "run sequence",
                    (args => RunSequenceHandler(localEnv, args, sequence), 2, "Execute the current sequence of transforms.",
                        "run sequence", experimental: false)
                },
                {
                    "clear sequence", (args =>
                    {
                        sequence.Clear();
                        return ("Sequence cleared.", ConsoleColor.Green);
                    }, 2, "Clear all transforms from the current sequence.", "clear sequence", experimental: false)
                },
                {
                    "find best sequence",
                    (args => RunBestFitHandler(localEnv, sequence), 3,
                        "Finds the best-performing sequence by testing all possible orderings of the given transforms.",
                        "find best sequence", experimental: false)
                },
                {
                    "optimize sequence",
                    (args => RunBTRHandler(localEnv, args, seq.GetIDs(sequence)), 2,
                        "Optimizes the sequence by adjusting transform rounds (TR) and global rounds (GR) to maximize performance.",
                        "optimize sequence", experimental: false)
                },
                {
                    "optimize sequence gr",
                    (args => RunOptimizeGRHandler(localEnv, sequence, args), 3,
                        "Optimizes the sequence by adjusting global rounds (GR) to maximize performance.",
                        "optimize sequence gr -max 9", experimental: false)
                },
                {
                    "batch optimize sequences",
                    (args => RunBTGRBatchHandler(localEnv, args), 3,
                        "Performs sequence optimization (TR/GR tuning) in batch mode across multiple input sequences.",
                        "batch optimize sequences [-L5]", experimental: true)
                },
                {
                    "batch optimize + reorder sequences",
                    (args => RunBTGRRBatchHandler(localEnv, args), 5,
                        "Optimizes and reorders sequences in batch mode, testing different transform orders alongside TR/GR tuning.",
                        "batch optimize + reorder sequences", experimental: true)
                },
                {
                    "run munge",
                    (args => RunMungeHandler(localEnv, args), 2, "Run the Munge process to evaluate sequences.",
                        "run munge", experimental: false)
                },
                {
                    "run smart munge",
                    (args => RunSmartMungeHandler(localEnv, args), 3,
                        "Run the Smart Munge process to evaluate sequences.", "run smart munge", experimental: true)
                },
                {
                    "run munge e",
                    (args => RunMungeEHandler(localEnv, args), 3, "Run exploratory Munge (mode E).", "run munge e",
                        experimental: true)
                },
                {
                    "run munge k",
                    (args => RunMungeKHandler(localEnv, args), 3, "Run keyspace-focused Munge.", "run munge k",
                        experimental: true)
                },
                {
                    "get",
                    (args => GetSettingsHandler(args), 1, "Retrieve the value of a setting.", "get Rounds",
                        experimental: false)
                },
                {
                    "set",
                    (args => SetSettingsHandler(localEnv, args), 1, "Update the value of a setting.", "set Rounds 10",
                        experimental: false)
                },
                {
                    "list",
                    (args => ListSettingsHandler(localEnv, args), 1,
                        "List all global settings and their current values.", "list", experimental: false)
                },
                {
                    "query",
                    (args => QueryHandler(localEnv, args), 1, "Query system values.", "query", experimental: true)
                },
                {
                    "log to screen",
                    (args => LogToScreenHandler(localEnv), 3, "After a Munge, list top sequences.", "log to screen",
                        experimental: true)
                },
                {
                    "log to file",
                    (args => LogToFileHandler(localEnv), 3, "After a Munge, log all Contenders to a file.",
                        "log to file", experimental: true)
                },
                {
                    "log to sql",
                    (args => LogToSQLHandler(localEnv), 3, "Convert the Contenders to an SQL database.", "log to sql",
                        experimental: true)
                },
                {
                    "convert file to sql",
                    (args => FileToSQLHandler(), 4, "Convert the logfile to an SQL database.", "file to sql",
                        experimental: true)
                },
                {
                    "run query console",
                    (args => QueryConsoleHandler(localEnv), 3, "Run the SQL Query Console.", "query console",
                        experimental: true)
                },
                {
                    "run visualization",
                    (args => VisualizationHandler(localEnv, seq.GetIDs(sequence).ToList(), args), 2,
                        "Run the Visualization functionality.",
                        "run visualization [BITS|BYTES] [ROWS N] [COLUMNS N] [OFFSET N]", experimental: true)
                },
                {
                    "run analyzer",
                    (args => AnalyzerHandler(), 2, "Run the Analyzer functionality.", "run analyzer",
                        experimental: true)
                },
                {
                    "run comparative analysis",
                    (args => RunComparativeAnalysisHandler(localEnv, sequence), 3,
                        "Compare analysis results between Mango and AES.", "run comparative analysis",
                        experimental: false)
                },
                {
                    "run comparative throughput",
                    (args => RunComparativeThroughput(localEnv), 3, "Compare throughput between Mango and AES.",
                        "run comparative throughput", experimental: false)
                },
                {
                    "run crypto showdown",
                    (args => RunCryptoShowdown(localEnv), 3, "Compare Mango and AES across all input types, showing score, pass count, and performance.",
                        "run crypto showdown", experimental: false)
                },
                {
                    "run metric breakdown",
                    (args => RunMetricBreakdown(localEnv), 3, "Display Mango and AES metric scores across all input types.",
                        "run metric breakdown", experimental: true)
                },
                {
                    "load user data",
                    (args => LoadUserDataHandler(localEnv, args), 3, "Load a custom input file (up to 10MB) for encryption and analysis.",
                        "load user data <file name> [-max bytes]", experimental: false)
                },
                {
                    "run MangoCipher",
                    (args => MangoCipherHandler(localEnv, args), 2, "Run the Mango cipher engine directly.",
                        "run MangoCipher", experimental: true)
                },
                {
                    "run auto weight tuner",
                    (args => RunAutoWeightTunerHandler(localEnv), 4, "Automatically tune weights.",
                        "run auto weight tuner", experimental: true)
                },
                {
                    "say",
                    (args => Say(args), 1, "Output this text to the status line",
                        "say my dog has fleas!", experimental: true)
                },
                {
                    "run classification",
                    (args => RunClassification(localEnv, args), 2, "Automatically selects the best profile for the current data.",
                        "run classification", experimental: false)
                },
                {
                    "load profile",
                    (args => LoadProfile(localEnv, args), 2, "Loads the named profile and sets it as the current sequence.",
                        "load profile <name>", experimental: false)
                },
                {
                    "save profile",
                    (args => SaveProfile(localEnv, sequence, args), 2, "Save the current sequence as a named profile.",
                        "save profile <name>", experimental: false)
                },
                {
                    "replace profile",
                    (args => ReplaceProfile(localEnv, sequence, args), 2, "Replace the named profile with the current sequence.",
                        "replace profile <name>", experimental: false)
                },
                {
                    "delete profile",
                    (args => DeleteProfile(args), 2, "Delete the named profile.",
                        "delete profile <name>", experimental: false)
                },
                {
                    "rename profile",
                    (args => RenameProfile(args), 2, "Rename the profile.",
                        "rename profile <\"old name\"> <\"new name\">", experimental: false)
                },
                {
                    "list profiles",
                    (args => ListProfiles(localEnv, args), 2, "List all profiles matching pattern.",
                        "list profiles [pattern]", experimental: false)
                },
                {
                    "touch profiles",
                    (args => TouchProfiles(localEnv), 2, "Update full fidelity aggregate score for each profile.",
                        "touch profiles", experimental: true)
                },
                {
                    "seed profiles",
                    (args => SeedProfiles(localEnv), 2, "Seed the InputProfiles.json with unoptimized defaults.",
                        "seed profiles", experimental: true)
                },
                {
                    "assess sequence",
                    (args => AssessSequence(localEnv, sequence, args, results: null), 2, "Assesses how the current sequence performs across all data types.",
                        "assess sequence", experimental: false)
                },
                {
                    "select best fast",
                    (args => SelectBestFast(localEnv, args), 3, "Selects the .Best and .Fast sequences to be used for the Default profiles.",
                        "select best fast <\"file name\">", experimental: true)
                },
                // 🔧 Developer / Admin commands
                {
                    "run benchmark transforms",
                    (args => BenchmarkTransforms(localEnv, args), 3,
                        "Benchmark all transforms and regenerate performance baselines.", "run benchmark transforms",
                        experimental: false)
                },
                {
                    "run profile transforms",
                    (args => ProfileTransforms(localEnv, args), 3,
                        "Profile transforms and output baseline characteristics.", "run profile transforms inline test",
                        experimental: true)
                },
                {
                    "run regression tests",
                    (args => RunRegressionTests(localEnv), 3, "Run the full regression test suite.",
                        "run regression tests", experimental: false)
                }
            };
        }
    }

    // Updated RunConsole with Natural Language Commands (NLC) Scaffolding

    #region Console

    public class PersistenceStateManager
    {
        private readonly string stateFilePath = "ConsoleState.json";
        private bool commandHistoryDirty = false;
        private bool sequenceDataDirty = false;

        private ConsoleMangoState state = new();

        public void AddCommand(string command)
        {
            if (!state.CommandHistory.Contains(command))
            {
                if (state.CommandHistory.Count >= 256) state.CommandHistory.RemoveAt(0);

                state.CommandHistory.Add(command);
                commandHistoryDirty = true;
            }
        }

        public void AddSequence(List<byte> sequence, Dictionary<string, double> metricScores)
        {
            state.Sequences.Add(new SequenceData
            {
                Sequence = sequence,
                MetricScores = metricScores,
                Timestamp = DateTime.Now
            });
            sequenceDataDirty = true;
        }

        public void SaveState()
        {
            if (commandHistoryDirty || sequenceDataDirty)
            {
                File.WriteAllText(stateFilePath, JsonConvert.SerializeObject(state, Formatting.Indented));
                commandHistoryDirty = false;
                sequenceDataDirty = false;
            }
        }

        public void LoadState()
        {
            if (File.Exists(stateFilePath))
                state = JsonConvert.DeserializeObject<ConsoleMangoState>(File.ReadAllText(stateFilePath)) ??
                        new ConsoleMangoState();
        }

        public IEnumerable<string> GetCommandHistory()
        {
            return state.CommandHistory;
        }

        public IEnumerable<SequenceData> GetSequences()
        {
            return state.Sequences;
        }
    }

    public class ConsoleMangoState
    {
        public List<string> CommandHistory { get; set; } = new();
        public List<SequenceData> Sequences { get; set; } = new();
    }

    public class SequenceData
    {
        public List<byte> Sequence { get; set; } = new();
        public Dictionary<string, double> MetricScores { get; set; } = new(); // Scores for each metric
        public DateTime Timestamp { get; set; } = DateTime.Now;
    }

    public static Stack<string> CommandStack = new();

    public static void RunConsole(ExecutionEnvironment localEnv)
    {
        PersistenceStateManager stateManager = new();
        stateManager.LoadState();

        List<string> sequence = new();
        string? statusMessage = null;
        var statusColor = ConsoleColor.Gray;

        var running = true;

        var commandHistory = stateManager.GetCommandHistory().ToList();

        while (running)
        {
#if DEBUG
            if (!localEnv.Globals.Input.SequenceEqual(GenerateTestInput(localEnv)))
                throw new InvalidOperationException(
                    "🚨 FATAL: LocalEnv.Globals.Input has been unexpectedly modified! Debugging required. 🚨");
#endif

            // Clear the console and display the menu once per iteration
            Console.Clear();
            DisplayMenu(localEnv, sequence); // Display the menu

            // ✅ Display the current sequence with full formatting
            if (sequence.Any())
            {
                Console.WriteLine("\nCurrent Sequence:");
                //Console.WriteLine(string.Join("\n", sequence.Select((t, index) => index == 0 ? t : $"\t{t}"))); // Tab indent all but the first
                var rawChunked = ChunkedSequence(sequence, 2, true); // Use neutral spacing
                var formatted = FormatChunks(rawChunked); // Replace with -> and handle right-side
                Console.WriteLine(formatted);
            }
            else
            {
                Console.WriteLine("\nCurrent Sequence: No transforms added.");
            }

            // Display the status message (if any), after the sequence
            if (!string.IsNullOrEmpty(statusMessage)) ColorConsole.WriteLine($"Status: {statusMessage}", statusColor);

            // Prompt for input
            Console.WriteLine();
            Console.WriteLine(
                "Select an option, enter a transform name/ID, type $ for a sequence, or enter a command:");
            Console.Write("Enter your choice or command: ");

            // ✅ Process the next command:
            // - If `CommandStack` has pending commands, execute the next one (e.g., automated exits, queued inputs).
            // - Otherwise, wait for user input from the console.
            var userInput = ""; // Current user input
            if (CommandStack.Count > 0)
            {
                userInput = CommandStack.Pop();
                Console.WriteLine(); // emulate user has hit return after the command
            }
            else
            //userInput = Console.ReadLine()?.Trim();
            {
                userInput = ReadConsoleBlock()?.Trim();
            }

            if (string.IsNullOrEmpty(userInput))
            {
                statusMessage = "Input cannot be empty.";
                statusColor = ConsoleColor.Red;
                continue;
            }

            // Match: "!" or any command ending with " !"
            var match = Regex.Match(userInput, @"^(?<cmd>.*?)(?:\s*!){1}$");

            if (match.Success)
            {
                // Load god-sequence based on current input
                var godProfile = InputProfiler.GetInputProfile(localEnv.Globals.Input, localEnv.Globals.Mode, localEnv.Globals.ScoringMode);
                // all subsystems use the global rounds from the profile, but we set it here for display purposes
                localEnv.Globals.UpdateSetting("Rounds", godProfile.GlobalRounds);
                
                // set the sequence to the god-sequence just loaded
                sequence.Clear();
                SequenceHelper seqHelper = new(localEnv.Crypto);
                sequence.AddRange(seqHelper.FormattedSequence<List<string>>(godProfile));

                var cmd = match.Groups["cmd"].Value.Trim();

                if (!string.IsNullOrWhiteSpace(cmd))
                    // Push the command (e.g., "run sequence") to execute after replacing sequence
                    CommandStack.Push(cmd);

                statusMessage = $"God-sequence loaded for input type: {godProfile.Name}";
                statusColor = ConsoleColor.Green;
                continue;
            }

            if (userInput.Equals("exit", StringComparison.OrdinalIgnoreCase))
            {
                stateManager.SaveState(); // Save state on exit
                running = false;
                break;
            }

            // Process input
            if (int.TryParse(userInput, out var selectedOption))
            {
                if (MenuOptionMap.TryGetValue(selectedOption, out var transform))
                {
                    var formattedTransform = $"{transform.Name}(ID:{transform.Id})";

                    var grIndex = sequence.FindIndex(s => s.StartsWith("(GR:"));
                    if (grIndex >= 0)
                        sequence.Insert(grIndex, formattedTransform);
                    else
                        sequence.Add(formattedTransform);

                    statusMessage = $"{transform.Name} Transform added to sequence.";
                    statusColor = ConsoleColor.Green;
                }
                else
                {
                    Console.Beep();
                    statusMessage = "Invalid menu option.";
                    statusColor = ConsoleColor.Red;
                }
            }

            else if (userInput.StartsWith("$"))
            {
                // ✅ Handle sequence paste operator
                var sequenceInput = userInput.Substring(1).Trim();

                try
                {
                    // ✅ Use official sequence parser
                    SequenceHelper seqHelper = new(localEnv.Crypto);
                    var format = SequenceFormat.ID | seqHelper.DetermineFormat(sequenceInput);
                    var parsedSequence = seqHelper.ParseSequenceFull(sequenceInput, format);

                    if (parsedSequence == null || !parsedSequence.Transforms.Any())
                    {
                        statusMessage = "No valid transforms found.";
                        statusColor = ConsoleColor.Red;
                        return;
                    }

                    // all subsystems use the global rounds from the profile, but we set it here for display purposes
                    localEnv.Globals.UpdateSetting("Rounds", seqHelper.GetGlobalRounds(parsedSequence));

                    // ✅ Store in the command interpreter's sequence list (Proper structure, no more single-string issues)
                    sequence.Clear();
                    sequence.AddRange(seqHelper.FormattedSequence<List<string>>(
                        parsedSequence,
                        SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes,
                        2, true));

                    statusMessage = "Pasted sequence added.";
                    statusColor = ConsoleColor.Green;
                }
                catch (Exception ex)
                {
                    statusMessage = $"Error parsing sequence: {ex.Message}";
                    statusColor = ConsoleColor.Red;
                }
            }
            else
            {
                // Pass all other input to command handler
                (statusMessage, statusColor, sequence) = ConsoleInterpreter(localEnv, userInput, sequence);
            }

            // Save command to history
            stateManager.AddCommand(userInput);
            commandHistory.Add(userInput);
        }
    }

    public static (string, ConsoleColor, List<string>) ConsoleInterpreter(
        ExecutionEnvironment localEnv, string userInput, List<string> sequence)
    {
        // ✅ Use static registry function
        var commandRegistry = CommandRegistry.Registry(localEnv, sequence);

        // Handle "help" as a special case
        if (userInput.Equals("help", StringComparison.OrdinalIgnoreCase))
        {
            DisplayHelp(commandRegistry);
            return ("Displayed help information.", ConsoleColor.Green, sequence);
        }

        // Split the input into tokens
        string[] tokens = userInput.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
        if (tokens.Length == 0) return ("No input provided.", ConsoleColor.Red, sequence);

        // Attempt to match commands by token count, prioritizing longer matches
        foreach (var command in commandRegistry.OrderByDescending(c => c.Value.tokenCount))
        {
            var key = command.Key;
            var (handler, tokenCount, description, example, experimental) = command.Value;

            if (tokens.Length >= tokenCount &&
                key.Equals(string.Join(" ", tokens.Take(tokenCount)), StringComparison.OrdinalIgnoreCase))
            {
                string[] args = tokens.Skip(tokenCount).ToArray();
                args = ParseArgsRespectingQuotes(args);
                try
                {
                    var result = handler.Invoke(args);
                    return (result.Item1, result.Item2, sequence);
                }
                catch (ArgumentException ex) when (ex.ParamName == "sequenceParts")
                {
                    return ("❌ Error: This command requires a sequence, but none was provided.", ConsoleColor.Red,
                        sequence);
                }
                catch (Exception ex)
                {
                    return ($"❌ Unexpected error: {ex.Message}", ConsoleColor.Red, sequence);
                }
            }
        }

        return ("Unrecognized command. Type 'help' for a list of commands.", ConsoleColor.Red, sequence);
    }
    public static string[] ParseArgsRespectingQuotes(string[] tokens)
    {
        string input = string.Join(" ", tokens);
        var args = new List<string>();
        var current = new StringBuilder();
        bool inQuotes = false;

        for (int i = 0; i < input.Length; i++)
        {
            char c = input[i];

            if (c == '"')
            {
                inQuotes = !inQuotes;
                continue;
            }

            if (char.IsWhiteSpace(c) && !inQuotes)
            {
                if (current.Length > 0)
                {
                    args.Add(current.ToString());
                    current.Clear();
                }
            }
            else
            {
                current.Append(c);
            }
        }

        if (current.Length > 0)
            args.Add(current.ToString());

        return args.ToArray();
    }
    // Dynamically builds and displays the menu of transforms.
    private static readonly Dictionary<int, TransformInfo> MenuOptionMap = new();
    public static void DisplayMenu(ExecutionEnvironment localEnv, List<string> sequence)
    {
        ColorConsole.WriteLine($"\n===== Mango Console <green>[{localEnv.Globals.InputType}/{localEnv.Globals.Rounds}]</green> =====\n");

        var transforms = localEnv.Crypto.TransformRegistry.Values
            .OrderBy(t => t.Id)
            .ToList();

        // Clear existing map
        MenuOptionMap.Clear();

        int maxNameLength = transforms.Max(t => t.Name.Length);
        string leftColor = "<cyan>";
        string rightColor = "<yellow>";
        string colorEnd = "</>";

        int menuIndex = 1;
        var printedIds = new HashSet<int>();

        foreach (var forward in transforms)
        {
            if (printedIds.Contains(forward.Id) || forward.Id > forward.InverseId)
                continue;

            int leftPadding = maxNameLength + 4;
            string paddedLeft = $"{menuIndex,2}. Add {leftColor}{forward.Name.PadRight(leftPadding)}{colorEnd}";

            // 🟩 Add forward to map
            MenuOptionMap[menuIndex] = forward;
            printedIds.Add(forward.Id);
            int leftIndex = menuIndex++;

            // Try to find the inverse
            string rightText = string.Empty;
            var inverse = transforms.FirstOrDefault(t => t.Id == forward.InverseId && t.Id != forward.Id);

            if (inverse != null && !printedIds.Contains(inverse.Id))
            {
                rightText = $"{menuIndex,2}. Add {rightColor}{inverse.Name.PadRight(leftPadding)}{colorEnd}";
                MenuOptionMap[menuIndex] = inverse; // 🟨 Add inverse to map
                printedIds.Add(inverse.Id);
                menuIndex++;
            }

            ColorConsole.WriteLine($"{paddedLeft} {rightText}");
        }
    }





    public static int GetMenuOrdinal(CryptoLib cryptoLib, byte transformId)
    {
        var ordinal = 1;
        foreach (var transform in cryptoLib!.TransformRegistry.Values.OrderBy(t => t.Id))
            if (transform.Id <= transform.InverseId)
            {
                if (transform.Id == transformId)
                    return ordinal;
                ordinal++;
            }

        return -1; // Not found (likely an inverse-only transform)
    }

    private static void DisplayHelp(Dictionary<string, (
        Func<string[], (string, ConsoleColor)> handler,
        int tokenCount,
        string description,
        string example,
        bool experimental)> commandRegistry)
    {
        Console.Clear();
        Console.WriteLine("\n===== Console Mango - Help =====\n");

        Console.WriteLine("Available Commands:\n");

        var grouped = commandRegistry
            .Where(cmd =>
#if DEBUG
                    true // show all commands
#else
                        !cmd.Value.experimental // only show non-experimental
#endif
            )
            .OrderBy(cmd => cmd.Value.experimental) // false before true
            .ThenBy(cmd => cmd.Key, StringComparer.OrdinalIgnoreCase);

        foreach (var command in grouped)
        {
            var color =
#if DEBUG
                command.Value.experimental ? "yellow" : "green";
#else
                    "green";
#endif
            ColorConsole.WriteLine($"- <{color}>{command.Key}</{color}>: {command.Value.description}");

            if (!string.IsNullOrWhiteSpace(command.Value.example))
                Console.WriteLine($"  Example: {command.Value.example}");
        }

        Console.WriteLine("\nPress any key to return to the main menu...");
        Console.ReadKey();
    }

    #endregion Console
}