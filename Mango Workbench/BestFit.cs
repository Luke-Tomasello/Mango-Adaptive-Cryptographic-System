/*
 * BestFit Module
 * =============================================
 * Project: Mango
 * Purpose: Implements sequence optimization logic for Mango’s adaptive engine,
 *          including Best Fit Transform Rounds (BTR), Reordering (BTRR),
 *          and Munge batch operations.
 *
 *          This module supports:
 *            • Full BTR/BTRR processing pipelines for sequence optimization
 *            • Smart Munge routines for multi-type contender discovery
 *            • Fail database integration to track rejected sequences
 *            • Header generation and report output for scoring evaluation
 *            • Worker infrastructure for adaptive, multi-core autotuning
 *
 *          Acts as the backend engine for all intelligent sequence exploration
 *          based on scoring feedback and prior performance.
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
using System.Collections.Concurrent;
using System.Diagnostics;
using static Mango.SQL.SequenceFailSQL.Tools;
using static Mango.Utilities.UtilityHelpers;
using static Mango.Utilities.UtilityHelpers.MungeStatePersistence;

namespace Mango.Workbench;

public partial class Handlers
{
    #region Handlers

    public static (string, ConsoleColor) RunBTRHandler(ExecutionEnvironment localEnv, List<byte> userSequence)
    {
        // ✅ Detect core count and compute adaptive exit threshold
        var coreCount = Environment.ProcessorCount;
        // ✅ Use the same Global Rounds (GR) setting from Munge(A) as the BTR exit threshold.
        // This ensures each transform permutation is evaluated up to the same GR depth used
        // during original sequence discovery. Prevents premature exits while avoiding over-exploration.
        // Example: For Combined data, GR = 6 → exitCount = 6 (1 attempt per GR level).
        var exitCount = localEnv.Globals.Rounds;
        var coreThreshold = (int)Math.Ceiling(9.0 / 5.0 * 4); // 7 cores should give you max accuracy

        // ✅ Display configuration
        var additionalInfo = coreCount < coreThreshold
            ? $"🔹 Optimized for {coreCount} CPU cores.\nPerformance will scale up to {coreThreshold} cores for better results."
            : $"🔹 Optimized for {coreCount} CPU cores.\nYou are running at full optimization potential.";

        var header = GenerateHeader(
            localEnv,
            "** Best Fit Autotune Configuration **",
            options: HeaderOptions.All,
            additionalInfo: additionalInfo
        );

        foreach (var line in header) ColorConsole.WriteLine(line);

        // ✅ Prompt user for confirmation
        ColorConsole.Write("<Yellow>Proceed with this configuration? (Y/N): </Yellow>");
        var feedback = Console.ReadLine()?.Trim().ToUpper();

        if (feedback != "Y") return ("Autotune aborted by user.", ConsoleColor.Red);

        // ✅ Detect actual data type from input
        var detectedType = InputProfiler.GetInputProfile(localEnv.Globals.Input).Name;
        var expectedType = localEnv.Globals.InputType.ToString();

        // ✅ Ensure detected type matches configured InputType
        if (!string.Equals(detectedType, expectedType, StringComparison.OrdinalIgnoreCase))
        {
            ColorConsole.WriteLine(
                $"<yellow>\n⚠️ Warning: Selected InputType is '{expectedType}', but Mango detected '{detectedType}'.</yellow>");
            ColorConsole.Write("<yellow>Proceed with tuning anyway? (Y/N): </yellow>");

            var response = Console.ReadLine()?.Trim().ToUpper();
            if (response != "Y") return ("Autotune aborted due to InputType mismatch.", ConsoleColor.Red);
        }

        // ✅ Initialize the failure database  
        SequenceFailSQL.OpenDatabase(GetFailDBFilename(localEnv, "BTRFailDB,"), true);

        // ✅ Pass control to RunBestFitAutotuneMT
        var result = BestFitTransformRoundsCore(localEnv, userSequence, null, exitCount: exitCount);

        // ✅ close the failure database  
        SequenceFailSQL.CloseDatabase();

        // ✅ Construct the final output message, ensuring the winning sequence is displayed
        var finalMessage = $"{result.Message}\n🏆 Best Sequence: {result.BestSequence}";

        // ✅ Return the formatted message along with the status color
        return (finalMessage, result.StatusColor);
    }

    public static (string, ConsoleColor) RunMungeHandler(ExecutionEnvironment localEnv, string[] args)
    {
        try
        {
            // ✅ Extract a list of valid transform IDs from the Transform Registry
            // - Filters out transforms explicitly marked as "ExcludeFromPermutations"
            // - Converts the remaining transform keys to a List<byte> for sequence generation
            var validTransformIds = localEnv.Crypto.TransformRegistry
                .Where(kvp => !kvp.Value.ExcludeFromPermutations)
                .Select(kvp => (byte)kvp.Key)
                .ToList();

            MungeWorker(localEnv, "Munge", validTransformIds, args);

            // 🚀 Refresh CutList before Munge begins
            // - Loads existing cutlist.json (if present), then augments with any new contender files (L3+, P2+)
            // - No need to pre-check IsEligibleContenderFile(): Compile() filters internally
            // - CutList *will* apply to this run — affects which transforms are excluded
            CutListHelper.Compile(localEnv.Crypto);

            // Open failure database
            SequenceFailSQL.OpenDatabase(GetFailDBFilename(localEnv, "MungeFailDB,"),
                localEnv.Globals.CreateMungeFailDB);
            var result = MungeCore(localEnv, "run munge", validTransformIds.AsReadOnly(), args);
            SequenceFailSQL.CloseDatabase();
            return result;
        }
        catch (Exception ex)
        {
            return ($"Error: {ex.Message}", ConsoleColor.Red);
        }
        finally
        {
            // ✅ Future-proof: Place cleanup logic here if needed
        }
    }

    public static (string, ConsoleColor) RunMungeKHandler(ExecutionEnvironment localEnv, string[] args)
    {
        try
        {
            // ✅ Extract a list of valid transform IDs from the Transform Registry
            // - Filters out transforms explicitly marked as "ExcludeFromPermutations"
            // - Converts the remaining transform keys to a List<byte> for sequence generation
            var validTransformIds = localEnv.Crypto.TransformRegistry
                .Where(kvp => !kvp.Value.ExcludeFromPermutations)
                .Select(kvp => (byte)kvp.Key)
                .ToList();

            // ✅ Retrieve the top L4 contender sequences as Meta Packages (Packet(4)) 
            // - Reads the best sequences from L4 Munge results
            // - Extracts the first 4 transforms (ensuring full sequences are taken)
            // - Throws an error if the requested number of contenders or transforms cannot be satisfied
            var metaPackages = GetTopContendersAsIDs(localEnv, "Contenders,-L4-P6-D?-MC-ST.txt", 1, 2);
            using (var localStatEnvironment = new LocalEnvironment(localEnv))
            {
                localEnv.Globals.MaxSequenceLen = 5;
                args = new string[] { "-L5" };
                MungeWorker(localEnv, "Munge K", validTransformIds, args);
                // Open failure database
                SequenceFailSQL.OpenDatabase(GetFailDBFilename(localEnv, "MungeFailDB,"),
                    localEnv.Globals.CreateMungeFailDB);
                var result = MungeKCore(localEnv, "run munge k", metaPackages, validTransformIds, args);
                SequenceFailSQL.CloseDatabase();
                return result;
            }
        }
        catch (Exception ex)
        {
            return ($"Error: {ex.Message}", ConsoleColor.Red);
        }
        finally
        {
            // ✅ Future-proof: Place cleanup logic here if needed
        }
    }

    public static (string, ConsoleColor) RunSmartMungeHandler(ExecutionEnvironment parentEnv, string[] args)
    {
        try
        {
            var stopwatch = Stopwatch.StartNew();

            // ✅ Extract a list of valid transform IDs from the Transform Registry
            // - Filters out transforms explicitly marked as "ExcludeFromPermutations"
            // - Converts the remaining transform keys to a List<byte> for sequence generation
            var validTransformIds = parentEnv.Crypto.TransformRegistry
                .Where(kvp => !kvp.Value.ExcludeFromPermutations)
                .Select(kvp => (byte)kvp.Key)
                .ToList();

            // Base arguments (excluding -D).  We'll add -D in the loop.
            string[] baseArgs = { "-L1", "-P0", "-MC", "-ST" };

            // The different -D values we want to try.
            string[] inputTypes = { "S", "N", "C", "R" };

            // private List<(List<byte> Sequence, double AggregateScore, List<AnalysisResult> Metrics)> contenders = new();
            var
                table =
                    new Dictionary<string, List<(List<byte> Sequence, double AggregateScore,
                        List<CryptoAnalysis.AnalysisResult>
                        Metrics)>>();
            ExecutionEnvironment localEnv = null!;

            foreach (var inputType in inputTypes)
            {
                // Create a new list to hold the combined arguments.
                var currentArgs = new List<string>(baseArgs);

                // Add the -D argument with the current input type.
                currentArgs.Add($"-D{inputType}");

                var settings = GenerateEnvironmentSettings(currentArgs.ToArray());

                // this first localEnv is only used by Munge only.
                localEnv = new ExecutionEnvironment(parentEnv, settings);
                localEnv.Globals.UpdateSetting("Quiet", true);
                localEnv.Globals.UpdateSetting("Mode", OperationModes.None);
                localEnv.Globals.BatchMode = true; // not a user setting and cannot be set with UpdateSetting()
                localEnv.Globals.UpdateSetting("Rounds", 9);
                localEnv.Globals.UpdateSetting("InputType", GetInputTypeFromByte((byte)inputType[0]));

                Console.WriteLine($"Running MungeWorker with -D{inputType}");

                // not sure what to do with the return here. Maybe check for color Red and report the error?
                MungeWorker(localEnv, "Smart Munge", validTransformIds, args);

                //✅ Step 1: After each Munge, store contenders in Dictionary<string, List<Contender>>.
                table[settings["InputType"]] = localEnv.CryptoAnalysis.Contenders.ToList();
            }

            //✅ Step 2: After all Munges complete, pass contenders to CreateCandidateList() to get a trimmed version.
            table = CreateCandidateList(table);

            //✅ Step 3: Loop through the trimmed contenders and pass them to BTRR for processing & .gsd generation.
            foreach (var inputType in inputTypes)
            {
                var transformIds = table[inputType]
                    .SelectMany(entry => entry.Sequence) // Extracts transform IDs from each sequence
                    .Distinct() // Ensures each ID is unique
                    .ToList();

                // now create the context in which BTRBatchWorker will run
                localEnv = new ExecutionEnvironment(parentEnv);
                localEnv.Globals.UpdateSetting("Quiet", true);
                localEnv.Globals.UpdateSetting("Mode", parentEnv.Globals.Mode);
                localEnv.Globals.BatchMode = true; // not a user setting and cannot be set with UpdateSetting()
                localEnv.Globals.UpdateSetting("Rounds", 9); // BestFitTransformRoundsReorderCore will adjust as needed
                localEnv.Globals.UpdateSetting("InputType", GetInputTypeFromByte((byte)inputType[0]));

                // ✅ Step 2: Construct a dynamic file mask to locate contender files
                // - Calls GetContenderFilename() to generate a filename template
                // - Replaces "-L0" and "-P0" with "-L?" and "-P?" to allow wildcard searching
                // - This lets us search for contenders regardless of Munge Level (L?) or Pass Count (P?).
                var fileMask =
                    GetContenderFilename(localEnv, 0, ".txt").Replace("-L0", "-L?").Replace("-P0", "-P?");

                // ✅ Step 3: Find the best available contender file for comparison
                // - Searches for files matching the mask
                // - Selects the one with the highest Munge Level (-L?) and, if tied, the highest Pass Count (-P?)
                // - Ensures we always compare against the strongest existing contender file.
                var bestContenderFile = GetBestContenderFile(fileMask);

                var sequence = GetSequence(bestContenderFile, 1);
                SequenceHelper seq = new(localEnv.Crypto);

                var paramPack = new ParamPack(".gs4", "Smart Munge", 4, 5,
                    referenceSequence: seq.GetIDs(sequence).ToArray());

                // not sure what to do with the return here. Maybe check for color Red and report the error?
                // we need to run BTRBatchWorker with the parentEnv and not the localEnv. localEnv was created for Munge only
                BTRBatchWorker(localEnv, transformIds, paramPack, BestFitTransformRoundsReorderCore);
                ;
            }

            //✅ Final return statement ensures a clean success message(✅ All processes completed successfully!).

            // all done
            stopwatch.Stop();
            var elapsed = stopwatch.Elapsed;
            return (
                $"Smart Munge Completed Successfully in {elapsed.Hours:D2}:{elapsed.Minutes:D2}:{elapsed.Seconds:D2}",
                ConsoleColor.Green);
        }
        catch (Exception ex)
        {
            return ($"Error: {ex.Message}", ConsoleColor.Red);
        }
        finally
        {
            // ✅ Future-proof: Place cleanup logic here if needed
        }
    }

    public static (string, ConsoleColor) RunBTGRBatchHandler(ExecutionEnvironment parentEnv, string[] args)
    {
        // ✅ Use the same Global Rounds (GR) setting from Munge(A) as the BTR exit threshold.
        // This ensures each transform permutation is evaluated up to the same GR depth used
        // during original sequence discovery. Prevents premature exits while avoiding over-exploration.
        // Example: For Combined data, GR = 6 → exitCount = 6 (1 attempt per GR level).
        var exitCount = parentEnv.Globals.Rounds;
        var paramPack = new ParamPack(".gs1", "batch optimize sequences", exitCount: exitCount, reorder: false,
            useCuratedTransforms: false, topContenders: 5);
        // ✅ Initialize the failure database  
        SequenceFailSQL.OpenDatabase(GetFailDBFilename(parentEnv, "BTRFailDB,"), true);
        var result = BTRBatchWorker(parentEnv, args, paramPack, BestFitTransformRoundsCore);
        // ✅ close the failure database  
        SequenceFailSQL.CloseDatabase();
        return result;
    }

    public static (string, ConsoleColor) RunBTGRRBatchHandler(ExecutionEnvironment parentEnv, string[] args)
    {
        var paramPack = new ParamPack(".gs2", "batch optimize + reorder sequences", 5, 5, true, false, 5);
        // ✅ Initialize the failure database  
        SequenceFailSQL.OpenDatabase(GetFailDBFilename(parentEnv, "BTRFailDB,"), true);
        var result = BTRBatchWorker(parentEnv, args, paramPack, BestFitTransformRoundsReorderCore);
        // ✅ close the failure database  
        SequenceFailSQL.CloseDatabase();
        return result;
    }

    public static (string, ConsoleColor) RunMungeEHandler(ExecutionEnvironment parentEnv, string[] args)
    {
        var paramPack = new ParamPack(".gs3", "run munge e", 5, 5, true, true, 20);
        // ✅ Initialize the failure database  
        SequenceFailSQL.OpenDatabase(GetFailDBFilename(parentEnv, "BTRFailDB,"), true);
        var result = BTRBatchWorker(parentEnv, args, paramPack, BestFitTransformRoundsReorderCore);
        // ✅ close the failure database  
        SequenceFailSQL.CloseDatabase();
        return result;
    }

    #endregion Handlers

    #region Workers

    private static (string, ConsoleColor) BTRBatchWorker(ExecutionEnvironment parentEnv, string[] args,
        ParamPack paramPack,
        Func<ExecutionEnvironment, List<byte>, ParamPack, bool, int, BestFitResult>
            BTRCoreFunction) // 🔹 Delegate for core function
    {
        // ✅ Detect core count and compute adaptive exit threshold
        var coreCount = Environment.ProcessorCount;
        // coreCount == 4: exitCount will be 5.
        // coreCount == 20: exitCount will be 9.
        var exitCount = paramPack.ExitCount ?? Math.Max(5, (int)Math.Floor(coreCount * 0.45));
        var coreThreshold = (int)Math.Ceiling(9.0 / 5.0 * 4); // 7 cores should give you max accuracy

        // ✅ Display configuration
        var additionalInfo = coreCount < coreThreshold
            ? $"🔹 Optimized for {coreCount} CPU cores.\nPerformance will scale up to {coreThreshold} cores for better results."
            : $"🔹 Optimized for {coreCount} CPU cores.\nYou are running at full optimization potential.";

        var stopwatch = Stopwatch.StartNew(); // ✅ Start timing execution
        var topContenders = paramPack.TopContenders; // Number of contenders per file

        // ✅ Extract function-specific arguments from FunctionParms if available
        var functionName = paramPack.FunctionName;
        args = parentEnv.Globals.FunctionParms.ContainsKey(functionName)
            ? parentEnv.Globals.FunctionParms[functionName] // ✅ Use FunctionParms if defined
            : args; // ✅ Fallback to default args

        // ✅ Retrieve matching Munge files based on resolved arguments
        var files = GetMungeFiles(args);

        if (files.Length == 0)
            return ("❌ No Munge files found matching criteria.", ConsoleColor.Red);
        else if (VerifyMungeFile(files, out var errorMessage, "-S") == false) return (errorMessage, ConsoleColor.Red);

        if (!parentEnv.Globals.ExitJobComplete && !parentEnv.Globals.BatchMode)
        {
            // 📂 Display files selected for batch optimization
            var toProcess = "\n\n🔍 The following files will be processed:\n" +
                            string.Join("\n", files.Select(f => $"  • {Path.GetFileName(f)}"));
            ColorConsole.WriteLine(toProcess);

            // ✅ Prompt for user confirmation
            ColorConsole.Write(
                "\n<yellow>⚠️  Confirm you want to proceed with these files and settings [Y/N]:</yellow> ");
            var response = Console.ReadKey().Key;
            Console.WriteLine();

            if (response != ConsoleKey.Y) return ($"❌ {functionName} canceled by user.", ConsoleColor.Red);
        }

        // ✅ Log whether FunctionParms was used
        var argsSource = parentEnv.Globals.FunctionParms.ContainsKey(functionName)
            ? "Batch command line"
            : "Interactive command line";
        ColorConsole.WriteLine($"<Yellow>🔍 Searching for Munge files using {argsSource} parameters.</Yellow>");

        additionalInfo += "\n\n🔍 Files to Process:\n" + string.Join("\n", files.Select(Path.GetFileName));
        List<string> header = GenerateHeader(
            parentEnv,
            "** Best Fit Autotune Configuration **",
            options: HeaderOptions.None,
            additionalInfo: additionalInfo
        );

        foreach (var line in header) ColorConsole.WriteLine(line);

        List<PreprocessedFileData> fileData = null!;
        try
        {
            // ✅ Preprocess input files to extract sequences, settings, and baseline scores.
            // - Reads the top `topContenders` sequences from each file.
            // - Captures the first sequence as the "original formatted sequence" (for comparison).
            // - Extracts Munge(A)(9) baseline scores for performance comparison.
            // - Throws exceptions if files cannot be read or contain no valid sequences.
            fileData = PreprocessFiles(parentEnv, files, topContenders, paramPack);
        }
        catch (FileReadException ex)
        {
            return (ex.Message, ConsoleColor.Red); // Handles file read errors
        }
        catch (NoSequencesFoundException ex)
        {
            return (ex.Message, ConsoleColor.Red); // Handles missing sequence errors
        }

        // ✅ Now process using pre-stored data
        foreach (var fileDataEntry in fileData)
        {
            var outputFile = Path.ChangeExtension(fileDataEntry.FileName, paramPack.FileExtension); // God Sequence file
            var localEnv = new ExecutionEnvironment(parentEnv, fileDataEntry.Settings);

            List<(string originalSequence, string sequence, double? score)> bestSequences = new();
            List<(string originalSequence, string sequence, double? score)> unchangedSequences = new();

            foreach (var (seq, seqScore) in fileDataEntry.SequencesWithScores)
            {
                var seqList = seq.Split(" -> ").ToList();
                var contenderNumber = fileDataEntry.SequencesWithScores.FindIndex(x => x.Sequence == seq) + 1;

                var seqHelper = new SequenceHelper(localEnv.Crypto);
                var sequenceBytes = seqHelper.GetIDs(seqList).ToArray();

                // ✅ Store the **original formatted sequence** for this contender
                var originalFormattedSequence = seqHelper.FormattedSequence(sequenceBytes, SequenceFormat.ID);

                var formattedSequence = seqHelper.FormattedSequence(sequenceBytes,
                    SequenceFormat.ID | SequenceFormat.InferTRounds | SequenceFormat.InferGRounds);

                using (var localStateEnv = new LocalEnvironment(localEnv, seqList))
                {
                    var runHeader = GenerateHeader(
                        localEnv,
                        formattedSequence: formattedSequence,
                        analysisResults: null,
                        isReversible: true,
                        name: $"{fileDataEntry.FileName} (Contender #{contenderNumber})",
                        options: HeaderOptions.Mode | HeaderOptions.InputType | HeaderOptions.MetricScoring |
                                 HeaderOptions.PassCount
                    );

                    foreach (var line in runHeader) ColorConsole.WriteLine(line);

                    var result = BTRCoreFunction(localEnv, sequenceBytes.ToList(), paramPack, true, exitCount);

                    if (result.IsError)
                    {
                        return (result.Message, result.StatusColor);
                    }
                    else
                    {
                        Debug.Assert(AreEqualWithF10Formatting(result.BaselineScore ?? 0.0,
                            seqScore)); // ✅ Now compares per-sequence score

                        Debug.Assert((result.BestScore ?? 0.0) != 0);
                    }

                    var finalScore = result.NormalizeF10(result.BestScore);

                    if (result.Improved)
                        bestSequences.Add((originalFormattedSequence, result.BestSequence, finalScore)!);
                    else
                        unchangedSequences.Add((originalFormattedSequence, result.BestSequence, finalScore)!);
                }
            }


            bestSequences = bestSequences.OrderByDescending(x => x.score).ToList();
            unchangedSequences = unchangedSequences.OrderByDescending(x => x.score).ToList();
            //paramPack.FileExtension
            var fileName = Path.ChangeExtension(fileDataEntry.FileName, ".txt");
            var fileTimestamp = File.Exists(fileName)
                ? File.GetLastWriteTime(fileName).ToString("M/d/yyyy h:mm tt")
                : "Unknown Timestamp";

            using (var writer = new StreamWriter(outputFile))
            {
                writer.WriteLine($"===== Best Fit Autotune Results =====");
                writer.WriteLine($"🔹 Mode: {localEnv.Globals.Mode}");
                writer.WriteLine(
                    $"📂 Input Type: {GetInputTypeFromFilename(fileDataEntry.FileName)}"); // ✅ Input Type explicitly stated
                writer.WriteLine($"📄 Source File: {Path.GetFileName(outputFile)} ({fileTimestamp})");
                writer.WriteLine($"⚙️ Source Algo: {paramPack.FunctionName}");
                writer.WriteLine($"🔥 Baseline Comparison:");
                writer.WriteLine($"\tSequence: {fileData.First().SequencesWithScores.FirstOrDefault().Sequence}");
                writer.WriteLine(
                    $"\tAggregate Score: {fileData.First().SequencesWithScores.FirstOrDefault().Score:F10}");
                writer.WriteLine("====================================");
                writer.WriteLine();
                //;
                for (var i = 0; i < bestSequences.Count; i++)
                {
                    var placement = i == 0 ? "1st Place" : $"{i + 1}th Place";
                    writer.WriteLine($"🏆 {placement}");

                    // ✅ Correctly show **original sequence** for this contender
                    if (paramPack.Reorder) writer.WriteLine($"Original Sequence: {bestSequences[i].originalSequence}");

                    writer.WriteLine($"Sequence: {bestSequences[i].sequence}");
                    writer.WriteLine($"Aggregate Score: {bestSequences[i].score:F10}");
                    writer.WriteLine();
                }

                if (unchangedSequences.Any())
                {
                    writer.WriteLine("===== Sequences Without Improvement =====");
                    foreach (var seq in unchangedSequences)
                    {
                        // ✅ Correctly show **original sequence** for this contender
                        if (paramPack.Reorder) writer.WriteLine($"Original Sequence: {seq.originalSequence}");

                        writer.WriteLine($"Sequence: {seq.sequence}");

                        // 🛑 **Check for skipped sequences**
                        writer.WriteLine(seq.score == null
                            ? $"Aggregate Score: (skipped) → ⚠️ Skipped due to prior failures."
                            : $"Aggregate Score: {seq.score:F10} → ❌ No improvement");

                        writer.WriteLine();
                    }
                }
            }
        }

        stopwatch.Stop(); // ✅ Stop timing execution
        var elapsed = stopwatch.Elapsed;

        var formattedTime = elapsed.TotalMinutes >= 1
            ? $"{(int)elapsed.TotalMinutes}m {elapsed.Seconds}s" // ✅ Show minutes if >= 1 min
            : $"{elapsed.TotalSeconds:F2} seconds"; // ✅ Show seconds if < 1 min

        return ($"✅ Best Fit Autotune Batch completed successfully in {formattedTime}.", ConsoleColor.Green);
    }

    public static (string, ConsoleColor) MungeWorker(ExecutionEnvironment localEnv, string headerTitle,
        List<byte> transforms, string[] args)
    {
        try
        {
            // ✅ Initialize the failure database  
            // - If `CreateMungeFailDB = true`, failures will be **tracked and recorded**  
            // - If `CreateMungeFailDB = false`, failures are **only referenced**, preventing unnecessary memory growth  

            var dbMessage = $"<Green>{GetFailDBFilename(localEnv, "MungeFailDB,")} Active</Green>";

            // ✅ Prepare log messages
            var title = GetMungeTitle(headerTitle);
            List<string> block = GetMungeBody(localEnv);
            List<string> tail = GetMungeTail(title);

            block.Add(dbMessage);

            // ✅ Log settings to MangoConfig.txt  
            // Ensures multiple Mango instances can be checked without console clutter  
            ReportHelper.Report(ReportHelper.ReportFormat.TXT | ReportHelper.ReportFormat.SCR,
                new List<string>[] { title, block, tail },
                new string[] { "MangoConfig.txt" });

            return (null, ConsoleColor.Red)!;
            //return MungeCore(localEnv, "run munge", transforms, args);
        }
        catch (Exception ex)
        {
            return ($"Error: {ex.Message}", ConsoleColor.Red);
        }
        finally
        {
            // ✅ Future-proof: Place cleanup logic here if needed
        }
    }

    public static (string, ConsoleColor) BTRBatchWorker(ExecutionEnvironment parentEnv, List<byte> transformIds,
        ParamPack paramPack,
        Func<ExecutionEnvironment, List<byte>, ParamPack, bool, int, BestFitResult>
            BTRCoreFunction) // 🔹 Delegate for core function
    {
        // ✅ Detect core count and compute adaptive exit threshold
        var coreCount = Environment.ProcessorCount;
        // coreCount == 4: exitCount will be 5.
        // coreCount == 20: exitCount will be 9.
        var exitCount = paramPack.ExitCount ?? Math.Max(5, (int)Math.Floor(coreCount * 0.45));
        var coreThreshold = (int)Math.Ceiling(9.0 / 5.0 * 4); // 7 cores should give you max accuracy

        // ✅ Display configuration
        var additionalInfo = coreCount < coreThreshold
            ? $"🔹 Optimized for {coreCount} CPU cores.\nPerformance will scale up to {coreThreshold} cores for better results."
            : $"🔹 Optimized for {coreCount} CPU cores.\nYou are running at full optimization potential.";

        var stopwatch = Stopwatch.StartNew(); // ✅ Start timing execution
        //int topContenders = paramPack.TopContenders; // Number of contenders per file

        additionalInfo += $"🔍 Transforms to Process:{transformIds.Count}"; //Just show count

        var header = GenerateHeader(
            parentEnv,
            "** Best Fit Autotune Configuration **",
            options: HeaderOptions.None,
            additionalInfo: additionalInfo
        );

        foreach (var line in header) ColorConsole.WriteLine(line);

        // --- CHANGE: No fileData, process inputSequences directly ---
        List<(string originalSequence, string sequence, double score)> bestSequences = new();
        List<(string originalSequence, string sequence, double score)> unchangedSequences = new();


        //string outputFile = Path.ChangeExtension(fileDataEntry.FileName, paramPack.FileExtension); // No filename
        //Create a local environment (important of the sequence data has now been set.)
        var localEnv = new ExecutionEnvironment(parentEnv);

        // ✅ Initialize the failure database  -- STILL NEEDED (failure DB is per-environment)
        SequenceFailSQL.OpenDatabase(GetFailDBFilename(localEnv, "BTRFailDB,"), true);

        // --- CHANGE: Formatting the sequence string ---
        var seqHelper = new SequenceHelper(localEnv.Crypto);
        //string originalFormattedSequence = seqHelper.FormattedSequence(sequenceBytes, SequenceFormat.ID);
        var originalFormattedSequence = seqHelper.FormattedSequence(
            paramPack.ReferenceSequence ?? transformIds.ToArray(),
            SequenceFormat.ID | SequenceFormat.InferTRounds | SequenceFormat.InferGRounds);
        BestFitResult result = null!;
        using (var localStateEnv = new LocalEnvironment(localEnv)) //localStateEnv no longer used
        {
            var runHeader = GenerateHeader(
                localEnv,
                formattedSequence: originalFormattedSequence,
                analysisResults: null,
                isReversible: true,
                name: localEnv.Globals.InputType.ToString(),
                options: HeaderOptions.Mode | HeaderOptions.InputType | HeaderOptions.MetricScoring |
                         HeaderOptions.PassCount
            );

            foreach (var line in runHeader) ColorConsole.WriteLine(line);

            // ✅ Call BTRCoreFunction with the byte array (converted to List<byte>)
            result = BTRCoreFunction(localEnv, transformIds, paramPack, true, exitCount);

            if (result.IsError)
                return (result.Message, result.StatusColor);

            var finalScore = result.BestScore ?? result.BaselineScore ?? 0.0;


            if (result.Improved)
                //bestSequences.Add((originalFormattedSequence, result.BestSequence, finalScore));
                bestSequences.Add(("unknown", result.BestSequence, finalScore)!);
            else
                //unchangedSequences.Add((originalFormattedSequence, formattedSequence, finalScore));
                unchangedSequences.Add(("unknown", result.BestSequence, finalScore)!);
        }

        // ✅ Step 1: Sort the best sequences in descending order by score
        // - Ensures the highest-scoring sequences are considered first.
        bestSequences = bestSequences.OrderByDescending(x => x.score).ToList();

        // ✅ Step 2: Construct a dynamic file mask to locate contender files
        // - Calls GetContenderFilename() to generate a filename template
        // - Replaces "-L0" and "-P0" with "-L?" and "-P?" to allow wildcard searching
        // - This lets us search for contenders regardless of Munge Level (L?) or Pass Count (P?).
        var fileMask =
            GetContenderFilename(localEnv, 0, ".txt").Replace("-L0", "-L?").Replace("-P0", "-P?");

        // ✅ Step 3: Find the best available contender file for comparison
        // - Searches for files matching the mask
        // - Selects the one with the highest Munge Level (-L?) and, if tied, the highest Pass Count (-P?)
        // - Ensures we always compare against the strongest existing contender file.
        var bestContenderFile = GetBestContenderFile(fileMask);

        // our .gs4 file
        var outputFile = Path.ChangeExtension(bestContenderFile, paramPack.FileExtension);

        // get the timestamp
        var fileName = bestContenderFile;
        var fileTimestamp = File.Exists(fileName)
            ? File.GetLastWriteTime(fileName).ToString("M/d/yyyy h:mm tt")
            : "Unknown Timestamp";

        using (var writer = new StreamWriter(outputFile))
        {
            writer.WriteLine($"===== Best Fit Autotune Results =====");
            writer.WriteLine($"🔹 Mode: {localEnv.Globals.Mode}");
            writer.WriteLine($"📂 Input Type: {localEnv.Globals.InputType}"); // Input Type
            writer.WriteLine($"📄 Source File: {Path.GetFileName(fileName)} ({fileTimestamp})");
            writer.WriteLine($"🔥 Baseline Comparison: Munge(A)(9) Score: {result.BaselineScore:F10}");
            writer.WriteLine($"🔥 Original Sequence: {result.BaselineSequence}");
            writer.WriteLine("====================================");
            writer.WriteLine();

            for (var i = 0; i < bestSequences.Count; i++)
            {
                var placement = i == 0 ? "1st Place" : $"{i + 1}th Place";
                writer.WriteLine($"🏆 {placement}");
                writer.WriteLine($"Sequence: {bestSequences[i].sequence}");
                writer.WriteLine($"Aggregate Score: {bestSequences[i].score:F10}");
                writer.WriteLine();
            }

            if (unchangedSequences.Any())
            {
                writer.WriteLine("===== Sequences Without Improvement =====");
                foreach (var seq in unchangedSequences)
                {
                    writer.WriteLine($"Sequence: {result.BestSequence}");
                    writer.WriteLine($"Final Score: {result.BestScore:F10} → ❌ No improvement");
                    writer.WriteLine();
                }
            }
        }

        stopwatch.Stop(); // ✅ Stop timing execution
        var elapsed = stopwatch.Elapsed;

        var formattedTime = elapsed.TotalMinutes >= 1
            ? $"{(int)elapsed.TotalMinutes}m {elapsed.Seconds}s" // ✅ Show minutes if >= 1 min
            : $"{elapsed.TotalSeconds:F2} seconds"; // ✅ Show seconds if < 1 min

        return ($"✅ Best Fit Autotune Batch completed successfully in {formattedTime}.", ConsoleColor.Green);
    }

    #endregion Workers

    #region Best Fit Cores

    /// ✂️ CutLists (Transform-Level, Persistent Across Munge Classes)
    /// ───────────────────────────────────────────────────────────────
    /// CutLists operate as a coarse filter that trims down the transform pool based on 
    /// **historical performance across top sequences** for a given DataType.
    /// 
    /// Each CutList matrix encodes whether a transform appeared in the top 10 sequences 
    /// across prior Munge runs for a specific combination of:
    ///   - DataType (DC, DN, DR, DS)
    ///   - PassCount
    ///   - Munge Level
    /// 
    /// ✅ Pros:
    /// - Eliminates weak performers early, dramatically reducing search space.
    /// - Applies immediately on new Munges—no warmup needed.
    /// - Efficient for **broad pruning**.
    ///
    /// ⚠️ Caveat:
    /// - CutList is based solely on **presence in top contenders**, not absolute score.
    /// - A transform may be “valuable” in theory, but if it failed to appear in any of 
    ///   the top 10 sequences across relevant prior Munges, it will be cut.
    /// - This means that *no historically successful combination* utilized the transform 
    ///   for the given config — not a random exclusion.
    private static (string, ConsoleColor) MungeCore(ExecutionEnvironment localEnv, string functionName,
        IReadOnlyList<byte> validTransformIds, string[] args)
    {
        var loopCounter = 0;
        var startTime = DateTime.UtcNow;
#if DEBUG
        var nextSnapshotTime = DateTime.UtcNow.AddMinutes(10);
#else
            DateTime nextSnapshotTime = DateTime.UtcNow.AddHours(1);
#endif
        localEnv.CryptoAnalysis.Initialize();

        var threadPoolSize = Environment.ProcessorCount; // Number of available cores
        var analysisQueue =
            new ConcurrentQueue<(List<CryptoAnalysis.AnalysisResult> AnalysisResults, List<byte> Sequence, LogType
                LogType, string
                LogText)>();

        // ✅ Extract function-specific arguments from FunctionParms if available
        args = localEnv.Globals.FunctionParms.ContainsKey(functionName)
            ? localEnv.Globals.FunctionParms[functionName] // ✅ Use FunctionParms if defined
            : args; // ✅ Fallback to default args

        // 🎯 Check if the user specified "-LN" (e.g., "-L5") to skip directly to a given Munge level.
        // If found, extract the number and store it in 'skipTo'; otherwise, leave it as null.
        var skipTo = args.FirstOrDefault(a => a.StartsWith("-L")) is string match
                     && int.TryParse(match.Substring(2), out var level)
            ? level
            : (int?)null;

        // 💾 Check if the user specified "-restore" to resume from a saved state.
        var restore = args.Contains("-restore");
        var startLength = 1;
        MungeStatePersistence.MungeState? restoredState = null;
        if (restore)
        {
            // 🧠 We use `MaxSequenceLen` to determine which Munge state file to restore.
            // This file acts as an umbrella for all Munge passes up to that length.
            // ➤ For example, an L5 run executes L1–L5 and stores progress in `State,-L5-...json`.
            // ➤ This prevents interference with shorter runs like L4, which use `State,-L4-...json`.
            // ✅ Ensures safe and isolated resume behavior across different Munge configurations.
            restoredState =
                MungeStatePersistence.RestoreMungeState(GetStateFilename(localEnv, localEnv.Globals.MaxSequenceLen));
            if (restoredState != null)
            {
                // 🧼 Normalize: If Contenders was null, assign empty list for safe processing
                restoredState.Contenders ??= new List<SerializableContender>();

                // ✅ Clear current contenders and import restored ones
                localEnv.CryptoAnalysis.Contenders.Clear();
                localEnv.CryptoAnalysis.Contenders.AddRange(
                    restoredState.Contenders.Select(c => (c.Sequence, c.AggregateScore, c.Metrics))!
                );

                startLength = restoredState.Length;

                Console.WriteLine(
                    $"Restored Munge state: Length = {restoredState.Length}, Sequence Count = {restoredState.Contenders.Count}");
            }

            else
            {
                Console.WriteLine("No saved state found, starting fresh...");
                restore = false;
            }
        }

        // 🔄 ========================= MAIN LENGTH LOOP =========================
        // Outer loop: iterates through Munge levels (L1-Ln), corresponding to increasing sequence lengths.
        // Each "length" represents the number of transforms chained in a single permutation.
        // Example: L3 = all permutations of 3-transform sequences.
        // ======================================================================
        for (var length = startLength; length <= localEnv.Globals.MaxSequenceLen; length++)
        {
            // Check if we are skipping this length entirely
            if (skipTo.HasValue && length < skipTo.Value)
            {
                LogIfEnabled(localEnv, DebugFlags.StatusMessage,
                    $"<Yellow>Skipping sequence length</Yellow> {length}... (Starting at {skipTo.Value})");
                continue; // 🚀 Skip processing this sequence length
            }

            var failureKey =
                GenerateFailureKey(localEnv, "standard", 0, length, new StateManager(localEnv).GlobalRounds);
            var badSeqCount = SequenceFailSQL.TotalBadSequences(failureKey);
            ColorConsole.WriteLine(
                $"<Green>Bad Sequences Loaded: " +
                $"<{(badSeqCount > 0 ? "Red" : "Green")}>{badSeqCount}</{(badSeqCount > 0 ? "Red" : "Green")}></Green>");

            // full list of transforms to process
            var transforms = validTransformIds.ToList();

            // 🟢 Apply CutList: Reduce transform set based on prior Munge results.
            // Filters out low-performing transforms early, minimizing wasteful permutations.
            transforms = ApplyCutListFiltering(localEnv, transforms, length);

            // 📊 Preprocess: Estimate total time required for this Munge pass (based on sequence count, machine benchmark, input size, and rounds)
            ColorConsole.WriteLine(
                $"<Yellow>Calculating time to completion for</Yellow> <Cyan>{transforms.Count}</Cyan> <Yellow>transforms of length</Yellow> <Cyan>{length}</Cyan>...");
            var totalTime = CalculateTotalMungeTime(localEnv, transforms, length);

            // Pre-cache this since CountPermutations is cheap and doesn't generate sequences
            var totalSequencesForLength = CountPermutations(transforms, length);

            // 🧮 Compute the average estimated time per sequence (in ms):
            // Total time is divided by the number of sequences of this length.
            // This provides a baseline for per-sequence time reporting during status updates.
            var averageTimePerSequence = totalTime / totalSequencesForLength;

            // ✅ Generate all possible sequences of the given length using the provided list of transform IDs
            // - Supports both full registry and curated lists, depending on the caller's context
            var sequences = GeneratePermutations(transforms, length);

            loopCounter = 0;
            var skippedCount = 0;

            var estimated = TimeSpan.FromMilliseconds(totalTime);
            LogIfEnabled(localEnv, DebugFlags.StatusMessage,
                $"<Green>RunMunge evaluating transformations of length</Green> {length}... " +
                $"<Yellow>(Estimated time: {estimated:d\\.hh\\:mm\\:ss})</Yellow>");

            using (var semaphore = new SemaphoreSlim(threadPoolSize))
            {
                var tasks = new List<Task>();

                var resuming = restore && restoredState != null && restoredState.Length == length;
                var resumePointFound = !resuming;

                // 🔄 ======================= MAIN SEQUENCE LOOP ======================= 
                // Inner loop: iterates through every unique transform sequence of the current length.
                // - Applies encryption/decryption + crypto analysis
                // - Respects resume points (for restore mode)
                // - Skips flagged "bad" sequences via SequenceFailSQL
                // =====================================================================
                foreach (var sequence in sequences)
                {
                    // 🔄 Resumption Logic:
                    // If resuming from a saved state, we skip all permutations until we match the stored "resume point" sequence.
                    // Once found, we resume processing from that exact sequence onward.
                    // This ensures seamless continuation without reprocessing prior permutations.
                    if (resuming && !resumePointFound)
                    {
                        if (sequence.SequenceEqual(restoredState!.Sequence))
                        {
                            resumePointFound = true;
                            Console.WriteLine();
                            ColorConsole.WriteLine($"<Yellow>✅ Resume point detected!</Yellow>");
                            ColorConsole.WriteLine(
                                $"Resuming from sequence: <Cyan>[{string.Join(", ", sequence)}]</Cyan>");
                            ColorConsole.WriteLine(
                                $"Skipped <Magenta>{loopCounter}</Magenta> sequences prior to resume point.");
                            Console.WriteLine();
                        }
                        else
                        {
                            loopCounter++; // 🔴 Track skipped sequences here!
                            continue; // Skip until we find resume point
                        }
                    }

                    // 🚨 Check if sequence is in the "naughty list" BEFORE spawning a thread.
                    // If it is, we skip execution entirely.
                    if (SequenceFailSQL.IsBadSequence(sequence.ToList(), failureKey))
                    {
                        skippedCount++;
                        continue;
                    }

                    semaphore.Wait(); // Wait for an available thread

                    var task = Task.Run(() =>
                    {
                        try
                        {
                            // Generate reverse sequence
                            var reverseSequence = GenerateReverseSequence(localEnv.Crypto, sequence);

                            // Apply forward and reverse transformations
                            var encrypted = localEnv.Crypto.Encrypt(sequence, localEnv.Globals.Input);
                            var payload = localEnv.Crypto.GetPayloadOnly(encrypted);

                            var decrypted = localEnv.Crypto.Decrypt(reverseSequence, encrypted);

                            // Modify a copy of input for Avalanche test and Key Dependency test
                            var (MangoAvalanchePayload, _, MangoKeyDependencyPayload, _) =
                                ProcessAvalancheAndKeyDependency(
                                    localEnv,
                                    GlobalsInstance.Password,
                                    sequence.ToList());

                            // Check reversibility
                            var isReversible = decrypted.SequenceEqual(localEnv.Globals.Input);

                            if (isReversible)
                            {
                                var analysisResults = localEnv.CryptoAnalysis.RunCryptAnalysis(
                                    payload,
                                    MangoAvalanchePayload,
                                    MangoKeyDependencyPayload,
                                    localEnv.Globals.Input);

                                // Always enqueue results, sequence, and log text
                                analysisQueue.Enqueue((analysisResults, sequence.ToList(), LogType.Informational,
                                    $"Reversible sequence found: {new SequenceHelper(localEnv.Crypto).FormattedSequence(sequence, SequenceFormat.ID | SequenceFormat.TRounds)}"));
                            }
                            else
                            {
                                // Queue failure messages with sequence and type
                                analysisQueue.Enqueue((null, sequence.ToList(), LogType.Error,
                                    $"Sequence failed: {new SequenceHelper(localEnv.Crypto).FormattedSequence(sequence, SequenceFormat.ID | SequenceFormat.TRounds)}")!);
                            }
                        }
                        finally
                        {
                            semaphore.Release(); // Release the thread
                        }
                    });

                    tasks.Add(task);

                    // not sure FlushThreshold is the right measure here
                    if (analysisQueue.Count > localEnv.Globals.FlushThreshold)
                        FlushAnalysisQueue(localEnv, analysisQueue, failureKey);

                    // Periodically report progress
                    if (++loopCounter % 20000 == 0)
                    {
                        var adjustedTotalSequences = totalSequencesForLength - skippedCount;

                        var elapsedTime = DateTime.UtcNow - startTime;

                        // Calculate sequences remaining
                        var sequencesRemaining = adjustedTotalSequences - loopCounter;
                        sequencesRemaining = Math.Max(0, sequencesRemaining); // Ensure it's not negative

                        // Calculate estimated time remaining
                        // 🟢 NOTE: averageTimePerSequence is in MILLISECONDS
                        // so we stay in ms and convert directly into TimeSpan
                        var totalRemainingMs = averageTimePerSequence * sequencesRemaining;
                        var estimatedTimeRemaining = TimeSpan.FromMilliseconds(totalRemainingMs);

                        // 🔴 If in database creation mode, print a warning in RED
                        if (localEnv.Globals.CreateMungeFailDB && false)
                            ColorConsole.WriteLine(
                                "<Red>[NOTE] Running in Database Creation Mode - All failures will be recorded!</Red>");

                        // ✅ Enhanced output with CC
                        ColorConsole.WriteLine(
                            $"Processed <Green>{loopCounter}</Green> of <Green>{adjustedTotalSequences}</Green> sequences...");
                        ColorConsole.WriteLine($"Skipped <Yellow>{skippedCount}</Yellow> sequences...");
                        ColorConsole.WriteLine(
                            $"Elapsed time: <Cyan>{elapsedTime:g}</Cyan>, Estimated time remaining: <Cyan>{estimatedTimeRemaining:g}</Cyan>");
                    }

                    // Periodically save state
                    if (DateTime.UtcNow >= nextSnapshotTime)
                    {
                        nextSnapshotTime = DateTime.UtcNow.AddHours(1);

                        // Lightweight trim-only-for-save
                        var snapshotContenders = localEnv.CryptoAnalysis.Contenders
                            .OrderByDescending(x => x.AggregateScore)
                            .Take(localEnv.Globals.DesiredContenders)
                            .ToList();

                        // 💾 Save progress periodically using the MaxSequenceLen-specific resume file.
                        // This snapshot represents cumulative progress for L1–L<MaxSequenceLen> within a single Munge run.
                        // ➤ Example: An L5 Munge saves all intermediate and current progress to `State,-L5-...json`.
                        // ➤ Allows seamless resume across sessions, without clobbering L4 or other configurations.
                        // ✅ Keeps save/restore behavior consistent and isolated by Munge level umbrella.
                        MungeStatePersistence.SaveMungeState(snapshotContenders, length, transforms.ToArray(), sequence,
                            GetStateFilename(localEnv, localEnv.Globals.MaxSequenceLen));

                        ColorConsole.WriteLine($"<Yellow>[Snapshot]</Yellow> Munge state saved at {DateTime.Now:t}");
                    }
                }

                Task.WaitAll(tasks.ToArray()); // Wait for all tasks to complete
                FlushAnalysisQueue(localEnv, analysisQueue, failureKey); // Final flush for the current length
            }

            // Process and flush the analysis queue
            FlushAnalysisQueue(localEnv, analysisQueue, failureKey); // Final flush after all lengths

            var logFileName = GetContenderFilename(localEnv, length);

            localEnv.CryptoAnalysis.LogToFile(localEnv, logFileName, localEnv.Globals.DesiredContenders);

            LogIfEnabled(localEnv, DebugFlags.StatusMessage,
                $"<Green>Completed length</Green> {length} <Green>in</Green> {DateTime.UtcNow - startTime:g}",
                length);
        }

        if (!localEnv.Globals.ExitJobComplete && !localEnv.Globals.BatchMode)
        {
            Console.WriteLine("\nPress any key to return to the main menu...");
            Console.ReadKey();
        }

        return ($"RunMunge completed for max length {localEnv.Globals.MaxSequenceLen}.", ConsoleColor.Green);
    }

    private static (string, ConsoleColor) MungeKCore(ExecutionEnvironment localEnv, string functionName,
        List<byte[]> metaSequences, List<byte> transforms, string[] args)
    {
        var loopCounter = 0;
        var startTime = DateTime.UtcNow;
        localEnv.CryptoAnalysis.Initialize();

        var threadPoolSize = Environment.ProcessorCount; // Number of available cores
        var analysisQueue =
            new ConcurrentQueue<(List<CryptoAnalysis.AnalysisResult> AnalysisResults, List<byte> Sequence, LogType
                LogType, string
                LogText)>();

        //DisplayHeader("Munge", name: null, string.Format($"Bad Sequences Loaded: {MangoSQL.TotalBadSequences()}"));

        // ✅ Extract function-specific arguments from FunctionParms if available
        args = localEnv.Globals.FunctionParms.ContainsKey(functionName)
            ? localEnv.Globals.FunctionParms[functionName] // ✅ Use FunctionParms if defined
            : args; // ✅ Fallback to default args

        // 🎯 Check if the user specified "-LN" (e.g., "-L5") to skip directly to a given Munge level.
        // If found, extract the number and store it in 'skipTo'; otherwise, leave it as null.
        var skipTo = args.FirstOrDefault(a => a.StartsWith("-L")) is string match
                     && int.TryParse(match.Substring(2), out var level)
            ? level
            : (int?)null;

        for (var length = 1; length <= localEnv.Globals.MaxSequenceLen; length++)
        {
            // only length 5 currently supported
            //Debug.Assert(length == 5);

            // Check if we are skipping this length entirely
            if (skipTo.HasValue && length < skipTo.Value)
            {
                LogIfEnabled(localEnv, DebugFlags.StatusMessage,
                    $"<Yellow>Skipping sequence length</Yellow> {length}... (Starting at {skipTo.Value})");
                continue; // 🚀 Skip processing this sequence length
            }

            // 🟢 Munge(k) Context: Track failures across sequence lengths (L1-Ln) under fixed GlobalRounds (GR).
            var failureKey =
                GenerateFailureKey(localEnv, "munge(k)", 0, length, new StateManager(localEnv).GlobalRounds);

            // Generate all possible sequences by combining each meta sequence with all combinations of 3 transforms
            // from the 'transforms' list. For each combination, both the appended and prepended versions are created.
            // The resulting 'sequences' variable will contain an IEnumerable<byte[]> representing all these generated sequences.
            var sequences = SequenceGenerator.GenerateMetaSequenceTransformPairs(metaSequences, transforms, 3);
            var totalSequencesForLength = SequenceGenerator.CountMetaPermutations(metaSequences, transforms, 3);

            loopCounter = 0;
            var skippedCount = 0;

            LogIfEnabled(localEnv, DebugFlags.StatusMessage,
                $"<Green>RunMunge evaluating transformations of length</Green> {length}...", length);
            //LogIfEnabled(localEnv, DebugFlags.StatusMessage, $"<Green>RunMunge evaluating {totalSequencesForLength} Permutations</Green>...");

            using (var semaphore = new SemaphoreSlim(threadPoolSize))
            {
                var tasks = new List<Task>();

                foreach (var sequence in sequences)
                {
                    // currently the only supported length
                    Debug.Assert(sequence.Length == 5);

                    // 🚨 Check if sequence is in the "naughty list" BEFORE spawning a thread.
                    // If it is, we skip execution entirely.
                    if (SequenceFailSQL.IsBadSequence(sequence.ToList(), failureKey))
                    {
                        skippedCount++;
                        continue;
                    }

                    semaphore.Wait(); // Wait for an available thread

                    var task = Task.Run(() =>
                    {
                        try
                        {
                            // Generate reverse sequence
                            var reverseSequence = GenerateReverseSequence(localEnv.Crypto, sequence);

                            // Apply forward and reverse transformations
                            var encrypted = localEnv.Crypto.Encrypt(sequence, localEnv.Globals.Input);
                            var payload = localEnv.Crypto.GetPayloadOnly(encrypted);

                            var decrypted = localEnv.Crypto.Decrypt(reverseSequence, encrypted);

                            // Modify a copy of input for Avalanche test and Key Dependency test
                            var (MangoAvalanchePayload, _, MangoKeyDependencyPayload, _) =
                                ProcessAvalancheAndKeyDependency(
                                    localEnv,
                                    GlobalsInstance.Password,
                                    sequence.ToList());

                            // Check reversibility
                            var isReversible = decrypted!.SequenceEqual(localEnv.Globals.Input);

                            if (isReversible)
                            {
                                var analysisResults = localEnv.CryptoAnalysis.RunCryptAnalysis(
                                    payload,
                                    MangoAvalanchePayload,
                                    MangoKeyDependencyPayload,
                                    localEnv.Globals.Input);

                                // Always enqueue results, sequence, and log text
                                analysisQueue.Enqueue((analysisResults, sequence.ToList(), LogType.Informational,
                                    $"Reversible sequence found: {new SequenceHelper(localEnv.Crypto).FormattedSequence(sequence, SequenceFormat.ID | SequenceFormat.TRounds)}"));
                            }
                            else
                            {
                                // Queue failure messages with sequence and type
                                analysisQueue.Enqueue((null, sequence.ToList(), LogType.Error,
                                    $"Sequence failed: {new SequenceHelper(localEnv.Crypto).FormattedSequence(sequence, SequenceFormat.ID | SequenceFormat.TRounds)}")!);
                            }
                        }
                        finally
                        {
                            semaphore.Release(); // Release the thread
                        }
                    });

                    tasks.Add(task);

                    if (analysisQueue.Count > localEnv.Globals.FlushThreshold)
                        FlushAnalysisQueue(localEnv, analysisQueue, failureKey);

                    // Periodically report progress
                    if (++loopCounter % 20000 == 0)
                    {
                        var adjustedTotalSequences =
                            totalSequencesForLength - skippedCount; // ✅ Only calculate when needed

                        var elapsedTime = DateTime.UtcNow - startTime;
                        var sequencesPerSecond = loopCounter / elapsedTime.TotalSeconds;

                        var estimatedTotalTime = adjustedTotalSequences / sequencesPerSecond;
                        var timeRemaining = TimeSpan.FromSeconds(estimatedTotalTime - elapsedTime.TotalSeconds);

                        // 🔴 If in database creation mode, print a warning in RED
                        // turned off for now... just a tad ugly
                        if (localEnv.Globals.CreateMungeFailDB && false)
                            ColorConsole.WriteLine(
                                "<Red>[NOTE] Running in Database Creation Mode - All failures will be recorded!</Red>");

                        // ✅ Enhanced output with CC
                        ColorConsole.WriteLine(
                            $"Processed <Green>{loopCounter}</Green> of <Green>{adjustedTotalSequences}</Green> sequences...");
                        ColorConsole.WriteLine($"Skipped <Yellow>{skippedCount}</Yellow> sequences...");
                        ColorConsole.WriteLine(
                            $"Elapsed time: <Cyan>{elapsedTime:g}</Cyan>, Estimated time remaining: <Cyan>{timeRemaining:g}</Cyan>");
                    }
                }

                Task.WaitAll(tasks.ToArray()); // Wait for all tasks to complete
                FlushAnalysisQueue(localEnv, analysisQueue, failureKey); // Final flush for the current length
            }

            // Process and flush the analysis queue
            FlushAnalysisQueue(localEnv, analysisQueue, failureKey); // Final flush after all lengths

            var logFileName = GetContenderFilename(localEnv, length);

            localEnv.CryptoAnalysis.LogToFile(localEnv, logFileName, localEnv.Globals.DesiredContenders);

            LogIfEnabled(localEnv, DebugFlags.StatusMessage,
                $"<Green>Completed length</Green> {length} <Green>in</Green> {DateTime.UtcNow - startTime:g}",
                length);
        }

        if (!localEnv.Globals.ExitJobComplete && !localEnv.Globals.BatchMode)
        {
            Console.WriteLine("\nPress any key to return to the main menu...");
            Console.ReadKey();
        }

        return ($"RunMunge completed for max length {localEnv.Globals.MaxSequenceLen}.", ConsoleColor.Green);
    }

    private static BestFitResult BestFitTransformRoundsCore(ExecutionEnvironment parentEnv, List<byte> userSequence,
        ParamPack? paramPack, bool batchMode = false, int exitCount = 5)
    {
        var threadPoolSize = Environment.ProcessorCount;
        var analysisQueue =
            new ConcurrentQueue<(List<CryptoAnalysis.AnalysisResult> AnalysisResults, List<byte> Sequence, LogType
                LogType, string LogText)>();
        var bestQueue = new ConcurrentQueue<(int ThreadID, string Sequence, double Score)>();

        var analysisLog = new ConcurrentDictionary<int, List<string>>();
        var lastFlushTime = DateTime.UtcNow;
        const int flushIntervalSeconds = 120;
        var btrStartTime = DateTime.UtcNow;

        parentEnv.CryptoAnalysis.Initialize();

        Console.WriteLine(
            $"🚀 Running Best Fit Transform + Convergence Autotune (Multi-Threaded) [ExitCount = {exitCount}]...");

        if (userSequence.Count == 0)
            return new BestFitResult(
                "❌ No valid sequences found. Ensure the input sequence is correctly formatted and non-empty.");

        var originalMetrics = TestBestFitSequence(parentEnv, userSequence.ToArray(), "Original (Munge(A)(9))");
        if (originalMetrics == null)
            return new BestFitResult("<Red>Original sequence failed reversibility check.</Red>");
        var baselineScore =
            parentEnv.CryptoAnalysis.CalculateAggregateScore(originalMetrics, parentEnv.Globals.UseMetricScoring);
        var baselineSequence = new SequenceHelper(parentEnv.Crypto).FormattedSequence(
            paramPack?.ReferenceSequence ?? userSequence.ToArray(),
            SequenceFormat.ID | SequenceFormat.InferTRounds | SequenceFormat.InferGRounds);
        double bestScore = 0;
        string? bestSequence = null!;
        ColorConsole.WriteLine($"<Cyan>Baseline Sequence: {baselineSequence}</Cyan>");
        ColorConsole.WriteLine($"<Cyan>Baseline Score: {baselineScore:F4}</Cyan>");
        var processedSequences = 0; // 🔹 Track total sequences tested
        var highWaterMark = 0.0; // 🔹 highWaterMark tracks the best score across all threads.

        // ✅ Define `currentSequence` here to mirror BTRR’s model, ensuring consistency.
        var currentSequence = userSequence;

        //// ✅ EARLY EXIT: Skip bad sequences BEFORE allocating `SemaphoreSlim`
        //if (HasFailedAtAnyGlobalRound(parentEnv, currentSequence, exitCount, MaxGlobalRounds))
        //{
        //    return new BestFitResult(bestSequence, "(skipped)");
        //}

        using (var semaphore = new SemaphoreSlim(threadPoolSize))
        {
            var tasks = new List<Task>();

            foreach (var roundConfig in GenerateRoundCombinations(userSequence.Count))
            {
                semaphore.Wait();
                var task = Task.Run(() =>
                {
                    try
                    {
                        var threadID = Thread.CurrentThread.ManagedThreadId;
                        var threadEnv = new ExecutionEnvironment(parentEnv);
                        var threadSeq = new SequenceHelper(threadEnv.Crypto);
                        var threadRsm = new StateManager(threadEnv);
                        var MaxGlobalRounds = threadRsm.GlobalRounds;
                        double threadBestScore = 0; // 🔹 Each thread tracks its own best score
                        var noProgressCounter = 0; // 🔹 Each thread manages its own progress counter

                        // ✅ Move rounds management inside the thread
                        threadRsm.PushAllTransformRounds();
                        var failureKey = GenerateFailureKey(threadEnv, "standard", exitCount, MaxGlobalRounds);
                        try
                        {
                            for (threadRsm.GlobalRounds = 1;
                                 threadRsm.GlobalRounds <= MaxGlobalRounds;
                                 threadRsm.IncGlobalRound())
                            {
                                SetTransformRounds(threadEnv.Crypto, userSequence, roundConfig);

                                // ✅ Execute the sequence once per global round
                                Interlocked.Increment(ref processedSequences);
                                var metrics = TestBestFitSequence(threadEnv, currentSequence.ToArray(),
                                    $"Test (GR: {threadRsm.GlobalRounds})", roundConfig);
                                if (metrics != null)
                                {
                                    var score = parentEnv.CryptoAnalysis.CalculateAggregateScore(metrics,
                                        parentEnv.Globals.UseMetricScoring);

                                    if (processedSequences % 1000 == 0)
                                    {
                                        var compactConfig =
                                            $"[{string.Concat(roundConfig.Select(b => b.ToString("X2")))}]";
                                        var logEntry =
                                            $"[TID: {threadID:D2}] [RC: {compactConfig}] Evaluating {threadSeq.FormattedSequence(currentSequence.ToArray(), SequenceFormat.ID | SequenceFormat.InferTRounds | SequenceFormat.InferGRounds)} (GlobalRounds: {threadRsm.GlobalRounds})...";
                                        analysisLog.AddOrUpdate(threadID, _ => new List<string> { logEntry },
                                            (_, logList) =>
                                            {
                                                if (logList.Count >= 10) logList.RemoveAt(0);
                                                logList.Add(logEntry);
                                                return logList;
                                            });
                                    }

                                    /*
                                     * ================================================
                                     * 🔹 **Threaded Best-Fit Scoring & Synchronization**
                                     * ================================================
                                     *
                                     * 🚀 **Core Purpose:**
                                     * - Each thread independently evaluates transform sequences.
                                     * - Tracks both **thread-local** and **global** best scores.
                                     * - Ensures **only meaningful improvements** are processed.
                                     * - Uses **fine-grained locking** to minimize contention.
                                     *
                                     * 🏗 **How It Works:**
                                     * -----------------------------------------------
                                     * 1️⃣ **Thread-Local Tracking**
                                     *    - If the new `score` exceeds `threadBestScore`, update:
                                     *      ✅ `threadBestScore = score` → Keeps track of thread's progress.
                                     *      ✅ `noProgressCounter = 0`  → Prevents premature termination.
                                     *      ✅ `improved = true`        → Ensures work continues.
                                     *
                                     * 2️⃣ **Global Synchronization (High-Water Mark)**
                                     *    - If the new `score` is greater than **any** previous thread's:
                                     *      ✅ Update **highWaterMark** (best score seen across all threads).
                                     *      ✅ Store the formatted sequence.
                                     *      ✅ Add it to `bestQueue` and flush results.
                                     *
                                     * 3️⃣ **Final Best-Score Update**
                                     *    - If the new `score` **also beats** the overall `bestScore`:
                                     *      ✅ Acquire `_bestUpdateLock` (ensures safe updates).
                                     *      ✅ Update `bestScore` and `bestMetrics`.
                                     *
                                     * 🔥 **Key Benefits:**
                                     * -----------------------------------------------
                                     * ✅ **Avoids redundant updates** → Only logs sequences that truly improve.
                                     * ✅ **Minimizes lock contention** → Only locks when strictly necessary.
                                     * ✅ **Prevents race conditions** → Ensures consistent global state.
                                     * ✅ **Adaptive work balancing** → Threads continue running until real stagnation.
                                     * ✅ **Scalability** → Works efficiently from 4-core to 20-core machines.
                                     *
                                     */
                                    if (score > threadBestScore)
                                    {
                                        threadBestScore = score; // ✅ Update only this thread's best score
                                        noProgressCounter = 0; // ✅ Reset early exit counter for this thread

                                        lock (_bestUpdateLock)
                                        {
                                            if (score > highWaterMark)
                                            {
                                                highWaterMark = score;
                                                bestSequence = threadSeq.FormattedSequence(
                                                    currentSequence.ToArray(),
                                                    SequenceFormat.ID | SequenceFormat.InferTRounds |
                                                    SequenceFormat.InferGRounds);
                                                bestQueue.Enqueue((threadID, bestSequence, score)!);
                                                FlushBestList(bestQueue);

                                                if (score > bestScore) bestScore = score;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        noProgressCounter++;
                                        if (noProgressCounter >= exitCount)
                                        {
                                            //// Early exit within this permutation if no progress
                                            //if (threadEnv.Globals.CreateBTRFailDB)
                                            //    CheckRecordFail(threadEnv, null, currentSequence, failureKey);
                                            //goto permutation_done; // 7. Adjust goto target
                                        }
                                    }
                                }

                                /// ✅ Status updates must be handled inside worker threads
                                /// -------------------------------------------------------
                                /// Unlike BestFitTransformRoundsCore, the main thread in this function
                                /// reaches `Task.WaitAll()` immediately after launching tasks and does not
                                /// execute further until all threads complete. This means the log update
                                /// condition would never be reached outside the threads.
                                ///
                                /// To ensure periodic updates still happen, we move the log check inside
                                /// the worker thread, allowing each thread to handle its own logging
                                /// while processing sequences.
                                if ((DateTime.UtcNow - lastFlushTime).TotalSeconds >= flushIntervalSeconds)
                                    lock (_consoleLock)
                                    {
                                        lastFlushTime = DateTime.UtcNow;

                                        if (analysisLog.IsEmpty) // ✅ Only log status if no updates were made
                                            analysisLog.AddOrUpdate(0,
                                                _ => new List<string>
                                                {
                                                    $"[INFO] Processed {processedSequences:N0} sequences... Best Score So Far: {bestScore:F4}"
                                                },
                                                (_, logList) =>
                                                {
                                                    if (logList.Count >= 10) // ✅ Keep last 10 logs
                                                        logList.RemoveAt(0);
                                                    logList.Add(
                                                        $"[INFO] Processed {processedSequences:N0} sequences... Best Score So Far: {bestScore:F4}");
                                                    return logList;
                                                }
                                            );

                                        FlushAnalysisLog(analysisLog);
                                    }

                                ResetTransformRounds(threadEnv.Crypto, userSequence.ToArray());

                                //if (threadEnv.Globals.CreateBTRFailDB)
                                //    CheckRecordFail(threadEnv, metrics, userSequence, failureKey); // ✅ Use PassCount to validate failure

                                //if (!currentRoundImproved)
                                //{
                                //    return; // ✅ Now safely exits only after handling bad sequences
                                //}
                            }
                        }
                        catch (Exception ex)
                        {
                            lock (_consoleLock) // 🔹 Prevent garbled multi-threaded output
                            {
                                ColorConsole.WriteLine(
                                    $"<Red>[Thread {threadID}] ERROR: {ex.GetType().Name} - {ex.Message}</Red>");
                                ColorConsole.WriteLine($"<Red>Stack Trace:</Red> {ex.StackTrace}");
                                ColorConsole.WriteLine("\n<Yellow>Press any key to continue...</Yellow>");
                                Console.ReadKey();
                            }
                        }
                        finally
                        {
                            threadRsm.PopAllTransformRounds();
                            semaphore.Release(); // ✅ Release the semaphore here!
                        }
                        /// ✅ **Final safeguard: Ensure bad sequences are recorded if no improvements occurred**
                        /// ----------------------------------------------------------------------------------
                        /// **How we get here:**
                        /// - This block executes **only if** `anyRoundImproved` remains `false`, meaning:
                        ///   1️⃣ The sequence **never improved at any round**
                        ///   2️⃣ It either **exited early due to stagnation** (`exitCount` reached) or 
                        ///   3️⃣ It **ran through all `MaxGlobalRounds` without improvement**.
                        ///
                        /// **What we are doing:**
                        /// - This ensures that sequences **which never passed the threshold** get recorded 
                        ///   in the failure database.
                        /// - Since `ExitCount` is part of `failureKey`, recording the sequence **does not**
                        ///   prevent other configurations (with different `exitCount` values) from evaluating it.
                        ///
                        /// **Why this is safe:**
                        /// - If a sequence showed **any improvement** during testing, `anyRoundImproved`
                        ///   would have been set to `true`, preventing it from being marked as a failure.
                        /// - This ensures we are **only failing sequences that truly never had potential**.
                        //if (!anyRoundImproved)
                        //{
                        //    if (threadEnv.Globals.CreateBTRFailDB)
                        //        CheckRecordFail(threadEnv, null, userSequence, failureKey);
                        //}
                    }
                    catch (Exception ex)
                    {
                        lock (_consoleLock) // 🔹 Prevent garbled multi-threaded output
                        {
                            ColorConsole.WriteLine($"<Red> ERROR: {ex.GetType().Name} - {ex.Message}</Red>");
                            ColorConsole.WriteLine($"<Red>Stack Trace:</Red> {ex.StackTrace}");
                            ColorConsole.WriteLine("\n<Yellow>Press any key to continue...</Yellow>");
                            Console.ReadKey();
                        }
                    }
                    finally
                    {
                    }
                });

                tasks.Add(task);

                /// ✅ Status updates are checked by the main thread
                /// -------------------------------------------------
                /// In this implementation, the main thread remains active
                /// between launching new worker tasks, allowing it to periodically
                /// check if it's time to flush logs. This works because the main thread
                /// does not immediately reach `Task.WaitAll()`, so it continues processing
                /// and naturally hits the log update condition at intervals.
                if ((DateTime.UtcNow - lastFlushTime).TotalSeconds >= flushIntervalSeconds)
                {
                    lastFlushTime = DateTime.UtcNow;
                    FlushAnalysisLog(analysisLog);
                }
            }

            Task.WaitAll(tasks.ToArray());
            FlushAnalysisLog(analysisLog);
        }

        var btrElapsed = DateTime.UtcNow - btrStartTime;
        ColorConsole.WriteLine($"\n<green>🏁 Best Fit Autotune completed in: {btrElapsed:c}</green>\n");

        // 🎯 Final Evaluation:
        // - If BTR MT finds a better sequence, it returns the optimized result.
        // - If no improvement was found, the original Munge(A)(9) sequence remains dominant.
        // - This ensures only **validated improvements** make it through.
        return new BestFitResult(bestSequence, bestScore, baselineScore, baselineSequence);
    }

    private static BestFitResult BestFitTransformRoundsReorderCore(ExecutionEnvironment parentEnv,
        List<byte> userSequence, ParamPack paramPack, bool batchMode = false, int exitCount = 5)
    {
        var threadPoolSize = Environment.ProcessorCount;
        var analysisQueue =
            new ConcurrentQueue<(List<CryptoAnalysis.AnalysisResult> AnalysisResults, List<byte> Sequence, LogType
                LogType, string LogText)>();
        var bestQueue = new ConcurrentQueue<(int ThreadID, string Sequence, double Score)>();
        var analysisLog = new ConcurrentDictionary<int, List<string>>();
        var lastFlushTime = DateTime.UtcNow;
        const int flushIntervalSeconds = 120;
        parentEnv.CryptoAnalysis.Initialize();

        Console.WriteLine("Running Best Fit Transform + Convergence Autotune (Multi-Threaded)...");

        // Calculate the *total* number of permutations that will be generated (without generating them).
        var totalPermutations = PermutationCounter.CountLimitedRepetitionSequences(
            userSequence,
            paramPack.SequenceLength ?? throw new ArgumentException("SequenceLength cannot be null."),
            2);
        Console.WriteLine($"🔍 Total Sequences to Evaluate: {totalPermutations}");


        var originalMetrics = TestBestFitSequence(parentEnv, paramPack.ReferenceSequence ?? userSequence.ToArray(),
            "Original (Munge(A)(9))");
        if (originalMetrics == null)
            return new BestFitResult("<Red>Original sequence failed reversibility check.</Red>");

        var baselineScore =
            parentEnv.CryptoAnalysis.CalculateAggregateScore(originalMetrics, parentEnv.Globals.UseMetricScoring);
        var baselineSequence = new SequenceHelper(parentEnv.Crypto).FormattedSequence(
            paramPack.ReferenceSequence ?? userSequence.ToArray(),
            SequenceFormat.ID | SequenceFormat.InferTRounds | SequenceFormat.InferGRounds);
        double bestScore = 0;
        string? bestSequence = null!;
        ColorConsole.WriteLine($"<Cyan>Original Performance Score (Munge(A)(9)): {baselineScore:F4}</Cyan>");
        var processedSequences = 0;
        var highWaterMark = 0.0;

        // 3. Get the combined sequence and round configurations
        var sequenceRoundConfigs = GenerateSequencesAndRoundConfigs(userSequence, paramPack.SequenceLength ?? 0, 2);

        if (!sequenceRoundConfigs.Any()) //Check if empty here, now it's a single collection
            return new BestFitResult(
                "No valid sequence/round configurations generated. Ensure your sequence and parameters are valid.");

        using (var semaphore = new SemaphoreSlim(threadPoolSize))
        {
            var tasks = new List<Task>();

            // 4. Modify the main loop to iterate over SequenceRoundConfig instances
            foreach (var sequenceRoundConfig in sequenceRoundConfigs)
            {
                semaphore.Wait();
                var task = Task.Run(() =>
                {
                    try
                    {
                        var threadID = Thread.CurrentThread.ManagedThreadId;
                        var threadEnv = new ExecutionEnvironment(parentEnv);
                        var threadSeq = new SequenceHelper(threadEnv.Crypto);
                        var threadRsm = new StateManager(threadEnv);
                        var MaxGlobalRounds = threadRsm.GlobalRounds;
                        double threadBestScore = 0;
                        var noProgressCounter = 0;
                        var anyRoundImproved = false;

                        // 5. Use the Sequence and RoundConfig properties
                        var currentSequence = sequenceRoundConfig.Sequence;
                        var currentRoundConfig = sequenceRoundConfig.RoundConfig;

                        if (currentSequence.Count > 5)
                            throw new InvalidOperationException(
                                $"🚨 ERROR: Generated sequence has {currentSequence.Count} transforms (limit is 5)! This should NEVER happen!");

                        threadRsm.PushAllTransformRounds();
                        var failureKey = GenerateFailureKey(threadEnv, "standard", exitCount, MaxGlobalRounds);
                        try
                        {
                            // 6. Only one inner loop now (GlobalRounds)
                            for (threadRsm.GlobalRounds = 1;
                                 threadRsm.GlobalRounds <= MaxGlobalRounds;
                                 threadRsm.IncGlobalRound())
                            {
                                SetTransformRounds(threadEnv.Crypto, currentSequence, currentRoundConfig);
                                Interlocked.Increment(ref processedSequences);
                                var metrics = TestBestFitSequence(threadEnv, currentSequence.ToArray(),
                                    $"Test (GR: {threadRsm.GlobalRounds})", currentRoundConfig);

                                if (metrics != null)
                                {
                                    var score = parentEnv.CryptoAnalysis.CalculateAggregateScore(metrics,
                                        parentEnv.Globals.UseMetricScoring);

                                    if (processedSequences % 1000 == 0)
                                    {
                                        var compactConfig =
                                            $"[{string.Concat(currentRoundConfig.Select(b => b.ToString("X2")))}]";
                                        var logEntry =
                                            $"[TID: {threadID:D2}] [RC: {compactConfig}] Evaluating {threadSeq.FormattedSequence(currentSequence.ToArray(), SequenceFormat.ID | SequenceFormat.InferTRounds | SequenceFormat.InferGRounds)} (GlobalRounds: {threadRsm.GlobalRounds})...";
                                        analysisLog.AddOrUpdate(threadID, _ => new List<string> { logEntry },
                                            (_, logList) =>
                                            {
                                                if (logList.Count >= 10) logList.RemoveAt(0);
                                                logList.Add(logEntry);
                                                return logList;
                                            });
                                    }

                                    if (score > threadBestScore)
                                    {
                                        threadBestScore = score;
                                        noProgressCounter = 0;
                                        anyRoundImproved = true;

                                        lock (_bestUpdateLock)
                                        {
                                            if (score > highWaterMark)
                                            {
                                                highWaterMark = score;
                                                bestSequence = threadSeq.FormattedSequence(currentSequence.ToArray(),
                                                    SequenceFormat.ID | SequenceFormat.InferTRounds |
                                                    SequenceFormat.InferGRounds);
                                                bestQueue.Enqueue((threadID, bestSequence, score)!);
                                                FlushBestList(bestQueue);

                                                if (score > bestScore) bestScore = score;
                                            }
                                        }
                                    }
                                }
                                else
                                {
                                    noProgressCounter++;
                                    if (noProgressCounter >= exitCount)
                                    {
                                        // Early exit within this permutation if no progress
                                        if (threadEnv.Globals.CreateBTRFailDB)
                                            CheckRecordFail(threadEnv, null, currentSequence, failureKey);
                                        goto permutation_done; // 7. Adjust goto target
                                    }
                                }

                                if ((DateTime.UtcNow - lastFlushTime).TotalSeconds >= flushIntervalSeconds)
                                    lock (_consoleLock)
                                    {
                                        lastFlushTime = DateTime.UtcNow;
                                        if (analysisLog.IsEmpty) // ✅ Only log status if no updates were made
                                            analysisLog.AddOrUpdate(0,
                                                _ => new List<string>
                                                {
                                                    $"[INFO] Processed {processedSequences:N0} sequences... Best Score So Far: {bestScore:F4}"
                                                },
                                                (_, logList) =>
                                                {
                                                    if (logList.Count >= 10) // ✅ Keep last 10 logs
                                                        logList.RemoveAt(0);
                                                    logList.Add(
                                                        $"[INFO] Processed {processedSequences:N0} sequences... Best Score So Far: {bestScore:F4}");
                                                    return logList;
                                                }
                                            );
                                        FlushAnalysisLog(analysisLog);
                                    }

                                ResetTransformRounds(threadEnv.Crypto, currentSequence.ToArray());
                            } // End GlobalRounds loop

                            permutation_done: ; // 7. Corrected goto label
                        }
                        catch (Exception ex)
                        {
                            lock (_consoleLock)
                            {
                                ColorConsole.WriteLine(
                                    $"<Red>[Thread {threadID}] ERROR: {ex.GetType().Name} - {ex.Message}</Red>");
                                ColorConsole.WriteLine($"<Red>Stack Trace:</Red> {ex.StackTrace}");
                                ColorConsole.WriteLine("\n<Yellow>Press any key to continue...</Yellow>");
                                Console.ReadKey();
                            }
                        }
                        finally
                        {
                            threadRsm.PopAllTransformRounds();
                            semaphore.Release(); // ✅ Release the semaphore here!
                        }

                        if (!anyRoundImproved)
                            if (threadEnv.Globals.CreateBTRFailDB)
                                CheckRecordFail(threadEnv, null, currentSequence, failureKey);
                    }
                    catch (Exception ex)
                    {
                        lock (_consoleLock) // 🔹 Prevent garbled multi-threaded output
                        {
                            ColorConsole.WriteLine($"<Red> ERROR: {ex.GetType().Name} - {ex.Message}</Red>");
                            ColorConsole.WriteLine($"<Red>Stack Trace:</Red> {ex.StackTrace}");
                            ColorConsole.WriteLine("\n<Yellow>Press any key to continue...</Yellow>");
                            Console.ReadKey();
                        }
                    }
                    finally
                    {
                    }
                }); // Task ends here
                tasks.Add(task);
            } // End combined sequence/roundConfig loop

            Task.WaitAll(tasks.ToArray());
            FlushAnalysisLog(analysisLog);
        }

        return new BestFitResult(bestSequence, bestScore, baselineScore, baselineSequence);
    }

    #endregion Best Fit Cores

    #region TOOLS

    private static void FlushAnalysisQueue(ExecutionEnvironment localEnv,
        ConcurrentQueue<(List<CryptoAnalysis.AnalysisResult>, List<byte>, LogType, string)> queue, string failurekey)
    {
        while (queue.TryDequeue(out var item))
        {
            var (analysisResults, sequence, logType, logText) = item;

            // Case 1: Normal processing (Reversible sequence, valid analysis results)
            if (analysisResults != null)
            {
                localEnv.CryptoAnalysis.CryptAnalysisRecordBest(localEnv, analysisResults, sequence);

                if (!localEnv.Globals.Quiet && logType == LogType.Informational)
                {
                    Console.WriteLine(logText);
                    ReportHelper.Report(ReportHelper.ReportFormat.SCR,
                        localEnv.CryptoAnalysis.CryptAnalysisReport(localEnv.Crypto, analysisResults));
                }

                // Record sequence failure if it does not meet the minimum pass threshold
                if (localEnv.Globals.CreateMungeFailDB)
                    CheckRecordFail(localEnv, analysisResults, sequence, failurekey);
            }
            // Case 2: Sequence failed reversibility (analysisResults is null)
            else
            {
                // This means the sequence was NOT reversible.
                // Log the error and permanently mark it as a bad sequence if not already recorded.
                Console.WriteLine(logText);
                if (!SequenceFailSQL.IsBadSequence(sequence, failurekey))
                    SequenceFailSQL.RecordBadSequence(sequence, failurekey);
            }
        }
    }

    private static void FlushAnalysisLog(ConcurrentDictionary<int, List<string>> analysisLog)
    {
        lock (_consoleLock)
        {
            if (analysisLog.IsEmpty)
                return; // ✅ Don't print an empty status update

            ColorConsole.WriteLine("\n<Cyan>Periodic Status Update:</Cyan>");

            foreach (var threadLogs in
                     analysisLog.ToArray()) // ✅ Snapshot to avoid modifying collection while iterating
            {
                foreach (var entry in threadLogs.Value.Take(3)) // ✅ Limit output per thread
                    Console.WriteLine(entry);

                // ✅ After flushing, remove the thread's log to free memory
                analysisLog.TryRemove(threadLogs.Key, out _);
            }
        }
    }

    // ✅ Main function: Accepts byte[] sequence + roundConfig
    private static List<CryptoAnalysis.AnalysisResult>? TestBestFitSequence(ExecutionEnvironment localEnv,
        byte[] sequence, string label, List<byte> restoreRounds)
    {
        try
        {
            // Apply forward transformations
            byte[] encrypted = null!;
            encrypted = localEnv.Crypto.Encrypt(sequence, localEnv.Globals.Input);

            // Generate reverse sequence
            byte[] reverseSequence = null!;
            reverseSequence = GenerateReverseSequence(localEnv.Crypto, sequence);

            // ✅ Reverse the transform rounds before decryption
            ReverseTransformRounds(localEnv.Crypto, sequence!.ToList(), reverseSequence!.ToList());

            // Apply reverse transformations
            byte[] decrypted = null!;
            decrypted = localEnv.Crypto.Decrypt(reverseSequence, encrypted);

            // ✅ Check reversibility
            if (!decrypted!.SequenceEqual(localEnv.Globals.Input))
            {
                lock (_consoleLock)
                {
                    ColorConsole.WriteLine($"<Red>{label} Failed Reversibility</Red>");
                }

                return null;
            }

            // Extract payload for analysis
            byte[] payload = null!;
            payload = localEnv.Crypto.GetPayloadOnly(encrypted);

            // Modify a copy of input for Avalanche test and Key Dependency test
            var (MangoAvalanchePayload, _, MangoKeyDependencyPayload, _) =
                ProcessAvalancheAndKeyDependency(
                    localEnv,
                    GlobalsInstance.Password,
                    sequence.ToList(),
                    false); // ✅ No AES processing needed

            // Run cryptanalysis with correct Avalanche and Key Dependency inputs
            return localEnv.CryptoAnalysis.RunCryptAnalysis(
                payload,
                MangoAvalanchePayload,
                MangoKeyDependencyPayload,
                localEnv.Globals.Input);
        }
        catch (Exception ex)
        {
            Console.WriteLine(
                $"Error during {label} testing: {ex.Message}\nSequence: {Convert.ToHexString(sequence!)}");
            return null;
        }
        finally
        {
            // ✅ Restore the original state using roundConfig directly
            SetTransformRounds(localEnv.Crypto, sequence!.ToList(), restoreRounds);
        }
    }

    // ✅ Overload 2: Accepts byte[] sequence but needs explicit roundConfig
    private static List<CryptoAnalysis.AnalysisResult>? TestBestFitSequence(ExecutionEnvironment localEnv,
        byte[] sequence, string label)
    {
        // ✅ Default roundConfig to all 1s, matching the sequence length
        var roundConfig = Enumerable.Repeat((byte)1, sequence!.Length).ToList();

        // ✅ Call the main overload with the default rounds
        return TestBestFitSequence(localEnv, sequence, label, roundConfig);
    }

    private static void ReverseTransformRounds(CryptoLib? cryptoLib, List<byte> sequence, List<byte> reverseSequence)
    {
        // ✅ Step 1: Store forward round mappings BEFORE modifying anything
        var forwardRoundMap = new Dictionary<byte, List<byte>>();

        foreach (var transformId in sequence)
        {
            if (!forwardRoundMap.ContainsKey(transformId))
                forwardRoundMap[transformId] = new List<byte>();

            forwardRoundMap[transformId].Add(cryptoLib!.TransformRegistry[transformId].Rounds);
        }

        // ✅ Step 2: Apply the correct round mappings to the reverse sequence
        for (var i = 0; i < reverseSequence.Count; i++)
        {
            var reverseId = reverseSequence[i]; // Get the reverse transform ID
            var forwardId = sequence[sequence.Count - 1 - i]; // Get the corresponding forward transform ID

            if (cryptoLib!.TransformRegistry.TryGetValue(forwardId, out var forwardTransform) &&
                cryptoLib!.TransformRegistry.TryGetValue(reverseId, out var reverseTransform))
                if (forwardRoundMap.TryGetValue(forwardId, out var roundList) && roundList.Count > 0)
                {
                    reverseTransform.Rounds = roundList.First(); // ✅ Apply the first stored round value
                    roundList.RemoveAt(0); // Remove used round to maintain order consistency
                }
        }
    }

    private static void SetTransformRounds(CryptoLib? cryptoLib, List<byte> sequence, List<byte> roundConfig)
    {
        for (var i = 0; i < sequence.Count; i++)
            if (cryptoLib!.TransformRegistry.TryGetValue(sequence[i], out var transformInfo))
                transformInfo.Rounds = roundConfig[i]; // Assign dynamic rounds
            else
                throw new KeyNotFoundException($"Transform ID {sequence[i]} not found in registry.");
    }

    private static void ResetTransformRounds(CryptoLib? cryptoLib, byte[] sequence)
    {
        foreach (var transformId in sequence)
            if (cryptoLib!.TransformRegistry.TryGetValue(transformId, out var transformInfo))
                transformInfo.Rounds = 1; // 🔹 Reset to default rounds
    }
    //private static bool HasFailedAtAnyGlobalRound(ExecutionEnvironment localEnv, List<byte> sequence, int exitCount, int maxGlobalRounds)
    //{
    //    for (int round = 1; round <= maxGlobalRounds; round++)
    //    {
    //        // 🔵 BTR Context: Optimize per-transform rounds (TR) up to MaxGlobalRounds ceiling.
    //        string failureKey = GenerateFailureKey(localEnv, "standard", exitCount, MaxGlobalRounds, round);

    //        if (SequenceFailSQL.IsBadSequence(sequence, failureKey))
    //            return true; // ✅ Found a failure, no need to check further
    //    }
    //    return false; // ✅ Sequence is clean, proceed with processing
    //}
    // ✅ **Streaming-Friendly Function for Pre-checking Valid Rounds**
    //private static bool HasAnyValidRound(ExecutionEnvironment localEnv, IEnumerable<byte[]> permutations, int exitCount, int maxGlobalRounds)
    //{
    //    foreach (var permutation in permutations) // ✅ Iterates lazily (does not materialize full list)
    //    {
    //        foreach (var roundConfig in GenerateRoundCombinations(permutation.Length)) // ✅ Use permutation.Length
    //        {
    //            if (!HasFailedAtAnyGlobalRound(localEnv, permutation.ToList(), exitCount, maxGlobalRounds)) // ✅ Pass permutation as byte[]
    //            {
    //                return true; // ✅ Early exit if a valid round is found
    //            }
    //        }
    //    }
    //    return false; // ❌ No valid rounds found
    //}
    private static void FlushBestList(ConcurrentQueue<(int ThreadID, string Sequence, double Score)> bestQueue)
    {
        lock (_consoleLock)
        {
            while (bestQueue.TryDequeue(out var best))
                ColorConsole.WriteLine(
                    $"<Green>[Thread {best.ThreadID}] 🏆 New Best:</Green> {best.Sequence} <Cyan>({best.Score:F4})</Cyan>");
        }
    }

    private static List<PreprocessedFileData> PreprocessFiles(ExecutionEnvironment parentEnv, string[] files,
        int topContenders, ParamPack paramPack)
    {
        List<PreprocessedFileData> fileData = new();

        foreach (var file in files)
        {
            var fileName = Path.GetFileNameWithoutExtension(file);
            var settings = GetEnvironmentSettings(fileName);
            List<(string Sequence, double Score)> sequencesWithScores = new(); // 🔹 Store sequence + score pairs

            // ✅ Check if we're in Munge(E) mode (curated transform set)
            if (paramPack.UseCuratedTransforms)
            {
                var curatedTransformSet = GetCuratedTransformSet(parentEnv, file, paramPack.TopContenders);
                var curatedSequence = string.Join(" -> ", curatedTransformSet);

                var preprocessedData = new PreprocessedFileData(
                    fileName,
                    settings,
                    new List<(string, double)> { (curatedSequence, 0.0) } // 🔹 Store curated sequence with 0.0 score
                );

                return new List<PreprocessedFileData> { preprocessedData };
            }

            try
            {
                string currentSequence = null!;
                var currentScore = 0.0;

                foreach (var line in File.ReadLines(file))
                    if (line.StartsWith("Sequence:"))
                    {
                        // If we already captured a previous sequence, save it before moving on
                        if (currentSequence != null)
                        {
                            sequencesWithScores.Add((currentSequence, currentScore));
                            if (sequencesWithScores.Count >= topContenders) break;
                        }

                        // Start new sequence capture
                        currentSequence = line.Substring(9).Trim();
                        currentScore = 0.0; // Reset score, will be updated once we find it
                    }
                    else if (line.StartsWith("Aggregate Score:"))
                    {
                        if (currentSequence != null && double.TryParse(line.Substring(16).Trim(), out var parsedScore))
                            currentScore = parsedScore; // Assign score to the current sequence
                    }

                // Capture last sequence if we didn’t hit topContenders limit
                if (currentSequence != null && sequencesWithScores.Count < topContenders)
                    sequencesWithScores.Add((currentSequence, currentScore));
            }
            catch (Exception ex)
            {
                throw new FileReadException(file, "Failed to process file.", ex);
            }

            if (sequencesWithScores.Count == 0)
                throw new NoSequencesFoundException(file);

            fileData.Add(new PreprocessedFileData(fileName, settings, sequencesWithScores));
        }

        return fileData;
    }

    private static List<string> GetCuratedTransformSet(ExecutionEnvironment parentEnv, string fileName,
        int topContenders)
    {
        HashSet<string> uniqueTransforms = new();
        List<string> curatedTransformSet = new();

        try
        {
            foreach (var line in File.ReadLines(fileName))
                if (line.StartsWith("Sequence:"))
                {
                    var sequence = line.Substring(9).Trim();
                    var transformNames = sequence.Split(" -> ").ToList();

                    foreach (var transform in transformNames)
                        if (uniqueTransforms.Count < topContenders) // Stop at topContenders unique transforms
                        {
                            if (!uniqueTransforms.Contains(transform))
                            {
                                uniqueTransforms.Add(transform);
                                curatedTransformSet.Add(transform);
                            }
                        }
                        else
                        {
                            break;
                        }

                    if (uniqueTransforms.Count >= topContenders)
                        break;
                }
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException(
                $"Error processing curated transform set from {fileName}: {ex.Message}");
        }

        // ✅ Run Cryptanalysis-Based Filtering on Selected Transforms
        curatedTransformSet = FilterCuratedTransforms(parentEnv, fileName, uniqueTransforms.ToList());

        return curatedTransformSet;
    }

    private static List<string> FilterCuratedTransforms(ExecutionEnvironment parentEnv, string fileName,
        List<string> transforms)
    {
        // ✅ Set up the execution environment
        var baseFileName = Path.GetFileNameWithoutExtension(fileName);
        var settings = GetEnvironmentSettings(baseFileName);
        var localEnv = new ExecutionEnvironment(parentEnv, settings!);

        // ✅ Extract the correct input type from the filename
        var inputTypeToSet = GetInputTypeFromFilename(fileName);

        Dictionary<string, Dictionary<string, double>> transformScores = new();

        using (new LocalEnvironment(localEnv))
        {
            // ✅ Set the mode to flat (no weighting) and update input type
            localEnv.Globals.UpdateSetting("Mode", OperationModes.None);
            localEnv.Globals.UpdateSetting("InputType", inputTypeToSet);

            var seq = new SequenceHelper(localEnv.Crypto);

            foreach (var transform in transforms)
            {
                var sequence = seq.GetIDs(new List<string> { transform });

                var encrypted = localEnv.Crypto.Encrypt(sequence.ToArray(), localEnv.Globals.Input);
                var payload = localEnv.Crypto.GetPayloadOnly(encrypted);
                var reverseSequence = GenerateReverseSequence(localEnv.Crypto, sequence.ToArray());
                var decrypted = localEnv.Crypto.Decrypt(reverseSequence, encrypted);
                var isReversible = decrypted!.SequenceEqual(localEnv.Globals.Input);
                Debug.Assert(isReversible);
                var (MangoAvalanchePayload, _, MangoKeyDependencyPayload, _) =
                    ProcessAvalancheAndKeyDependency(
                        localEnv,
                        GlobalsInstance.Password,
                        sequence.ToList());

                // ✅ Run cryptanalysis and retrieve the list of AnalysisResult objects
                var analysisResults = localEnv.CryptoAnalysis.RunCryptAnalysis(
                    payload,
                    MangoAvalanchePayload,
                    MangoKeyDependencyPayload,
                    localEnv.Globals.Input,
                    null);

                // ✅ Convert the results into a Dictionary of metric scores
                Dictionary<string, double> scores = analysisResults!
                    .ToDictionary(result => result.Name, result => result.Score);

                // ✅ Store the transform's scores
                transformScores[transform] = scores;
            }
        }

        // ✅ Select the Best 2 Per Category
        return SelectTopTransforms(transformScores);
    }

    private static List<string> SelectTopTransforms(Dictionary<string, Dictionary<string, double>> metricScores)
    {
        List<string> selectedTransforms = new();
        HashSet<string> usedTransforms = new(); // ✅ Track selected transforms

        foreach (var metric in new[]
                     { "Entropy", "AvalancheScore", "MangosCorrelation", "PositionalMapping", "KeyDependency" })
        {
            var topTwo = metricScores
                .Where(kv => kv.Value.ContainsKey(metric)) // Ensure transform has this metric
                .OrderByDescending(kv => kv.Value[metric]) // Sort by metric value
                .Select(kv => kv.Key) // Get transform names
                .Where(transform => !usedTransforms.Contains(transform)) // ✅ Remove already picked
                .Take(2)
                .ToList();

            selectedTransforms.AddRange(topTwo);
            usedTransforms.UnionWith(topTwo); // ✅ Mark transforms as used
        }

        return selectedTransforms;
    }

    private static double CalculateTotalMungeTime(ExecutionEnvironment localEnv, List<byte> transforms, int length)
    {
        /*
            Calculates the total estimated time to process all possible sequences of transforms.
            This is used to provide accurate time-to-completion estimates during the Munge process.

            The formula accounts for:
            - Machine performance (via benchmark ratio)
            - Input size scaling
            - Encrypt + Decrypt paths for Primary phase
            - Encrypt-only paths for Avalanche and KeyDependency phases
            - Global rounds setting

            Steps:
            1️⃣ For each sequence of transforms (permutation):
                a. Sum the normalized, scaled time of each transform.
                b. Adjust for rounds and scoring phases.
            2️⃣ Sum each sequence time into the total estimated time.

            ✅ Returns: total estimated time in milliseconds.
        */

        var totalTime = 0.0;

        foreach (var seq in GeneratePermutations(transforms, length))
        {
            var seqTime = 0.0;

            foreach (var transformId in seq!)
            {
                var transform = localEnv.Crypto.TransformRegistry[transformId];

                // Normalize time relative to benchmarked baseline machine
                var normalizedTime = transform.BenchmarkTimeMs *
                                     (localEnv.Globals.BenchmarkBaselineTime / localEnv.Globals.CurrentBenchmarkTime);

                // Scale based on input size vs. benchmarked size
                var inputSizeFactor = localEnv.Globals.Input.Length / localEnv.Globals.BenchmarkBaselineSize;

                // 🧮 Calculate total cost per transform for this sequence:
                // Breakdown:
                // 1️⃣ normalizedTime = Benchmark-adjusted time per transform (ms)
                // 2️⃣ inputSizeFactor = Scaling for input size vs. benchmark (linear scaling)
                // 3️⃣ Primary = Encrypt + Decrypt (x2)
                // 4️⃣ Avalanche = Encrypt only (x1)
                // 5️⃣ KeyDependency = Encrypt only (x1)
                // 6️⃣ Total = x4 ops per round
                seqTime += normalizedTime * inputSizeFactor * localEnv.Globals.Rounds * 4;
            }

            totalTime += seqTime;
        }

        return totalTime;
    }

    /// <summary>
    /// Applies the CutList filtering to the current list of transforms.
    /// Removes low-performing transforms as indicated by the CutListHelper.
    /// Optionally verifies cut consistency in DEBUG mode.
    /// </summary>
    /// <param name="localEnv">The execution environment containing config and globals.</param>
    /// <param name="validTransformIds">The full list of valid transform IDs.</param>
    /// <param name="length">The current sequence length (e.g., L3, L4, etc.).</param>
    /// <returns>A filtered list of transform IDs with low-performers removed.</returns>
    private static List<byte> ApplyCutListFiltering(ExecutionEnvironment localEnv, List<byte> validTransformIds,
        int length)
    {
        if (!CutListHelper.AnyWork())
            return validTransformIds; // No filtering needed

        var contenderFile = GetContenderFilename(localEnv, length);
        if (!CutListHelper.IsEligibleContenderFile(contenderFile))
        {
            LogIfEnabled(localEnv, DebugFlags.StatusMessage,
                $"⚠️ Skipped CutList verification for {contenderFile}: Level or PassCount excluded from cutlist generation (L1/L2 or P0/P1).");
            return validTransformIds; // Skip cutlist filtering for low-pass or short-length runs
        }

        var clh = new CutListHelper(contenderFile);
        var willCut = clh.WillCut(validTransformIds);
        var beforeCut = validTransformIds.Count;

        var filtered = validTransformIds
            .Where(id => !clh.IsCut(id))
            .ToList();

        Debug.Assert(filtered.Count == beforeCut - willCut);

        ColorConsole.WriteLine(
            $"<Green>Low Performing transforms Cut: " +
            $"<{(willCut > 0 ? "Red" : "Green")}>{willCut}</{(willCut > 0 ? "Red" : "Green")}></Green>");

#if DEBUG
        List<byte> diff_cutlist_vs_file;
        List<byte> diff_cutlist_vs_table;

        var isVerified = CutListHelper.VerifyCutList(
            contenderFile,
            filtered,
            out diff_cutlist_vs_file,
            out diff_cutlist_vs_table
        );

        if (!isVerified)
        {
            LogIfEnabled(localEnv, DebugFlags.StatusMessage, $"❌ Verification failed for {contenderFile}");
            LogIfEnabled(localEnv, DebugFlags.StatusMessage,
                $"Diff (cutlist vs file): {string.Join(", ", diff_cutlist_vs_file)}");
            LogIfEnabled(localEnv, DebugFlags.StatusMessage,
                $"Diff (cutlist vs table): {string.Join(", ", diff_cutlist_vs_table)}");
        }
        else if (!File.Exists(contenderFile))
        {
            LogIfEnabled(localEnv, DebugFlags.StatusMessage,
                $"⚠️ Skipped CutList verification: No contender file found for {contenderFile}. Likely first run or new level.");
        }
#endif

        return filtered;
    }

    #endregion TOOLS

    #region DATA

    public static readonly object _consoleLock = new(); // 🔹 Shared console lock for all threads

    public static readonly object _bestUpdateLock = new(); // 🔹 Shared high-water mark lock for all threads

    //private const int MaxTransformRounds = 9;                           // 🔥 Transform-level rounds cap (adjustable)
    //private const int MaxGlobalRounds = 9;                              // 🔥 Sequence-level rounds cap (adjustable)
    public class BestFitResult
    {
        public string? BestSequence { get; } // 🔹 Formatted sequence (or null on error)
        public double? BestScore { get; } // 🔹 Final aggregate score (null on error)
        public string? BaselineSequence { get; } // 🔹 Baseline Munge(A)(9) sequence (null on error)
        public double? BaselineScore { get; } // 🔹 Baseline Munge(A)(9) score (null on error)
        public bool Improved { get; } // 🔹 Indicates if an improvement was found
        public bool IsError { get; } // 🔹 Explicitly marks errors!
        public bool IsSkipped { get; } // 🔹 Explicitly marks skipped sequences!
        public string Message { get; } // 🔹 Summary message
        public ConsoleColor StatusColor { get; } // 🔹 Color for display

        // ✅ **Success Constructor**
        public BestFitResult(string? bestSequence, double bestScore, double baselineScore, string? baselineSequence)
        {
            BestSequence = bestSequence;
            BestScore = bestScore;
            BaselineSequence = baselineSequence;
            BaselineScore = baselineScore;
            Improved = NormalizeF10(bestScore) > NormalizeF10(baselineScore);
            IsError = false; // ✅ Not an error
            IsSkipped = false; // ✅ Not skipped

            Message = Improved
                ? $"✅ Best Fit found with Aggregate Score: {BestScore:F4}"
                : $"⚠️ No better sequence found. Aggregate Score: {BestScore:F4}.";

            StatusColor = Improved ? ConsoleColor.Green : ConsoleColor.Yellow;
        }

        public double NormalizeF10(double value)
        {
            var formattedValue = value.ToString("F10");
            return double.Parse(formattedValue);
        }

        public double NormalizeF10(double? value)
        {
            if (value.HasValue)
                return NormalizeF10(value.Value); // Call the other overload
            else
                // Handle the case where value is null (e.g., return a default value, throw an exception)
                return 0.0; // Example: return 0.0 if null
        }

        // ❌ **Error Constructor**
        public BestFitResult(string errorMessage)
        {
            BestSequence = null;
            BestScore = null;
            BaselineScore = null;
            Improved = false;
            IsError = true; // ✅ Explicit error flag
            IsSkipped = false; // ✅ Not skipped

            Message = $"❌ Error: {errorMessage} (File: {"Unknown"}, Time: {DateTime.Now:G})";
            StatusColor = ConsoleColor.Red;
        }

        // ⚠️ **Skipped Constructor**
        public BestFitResult(string skippedSequence, string reason)
        {
            BestSequence = skippedSequence;
            BestScore = null;
            BaselineScore = null;
            Improved = false;
            IsError = false; // ✅ Not an error
            IsSkipped = true; // ✅ Marks the sequence as skipped

            Message = $"⚠️ Skipped: {reason}";
            StatusColor = ConsoleColor.Yellow;
        }
    }

    public class ParamPack
    {
        public string FileExtension { get; } // 🔹 ".gs" (BTR) or ".gse" (BTRR)
        public string FunctionName { get; } // 🔹 "something 1" or "something 2"
        public bool Reorder { get; } // 🔹 helps the report writer format report correctly
        public bool UseCuratedTransforms { get; } // 🔹 do we use a curated list of transforms?
        public int TopContenders { get; } // 🔹 how many contenders will we process?
        public int? SequenceLength { get; } // 🔹 how many contenders will we process?
        public int? ExitCount { get; } // 🔹 how many contenders will we process?

        public byte[]?
            ReferenceSequence { get; } // 🔹 when using munge output directly, we need to infer the reference sequence

        public ParamPack(string extension, string functionName, int? sequenceLength = null, int? exitCount = null,
            bool reorder = false, bool useCuratedTransforms = false, int topContenders = 0,
            byte[]? referenceSequence = null)
        {
            FileExtension = extension ?? throw new ArgumentNullException(nameof(extension));
            FunctionName = functionName ?? throw new ArgumentNullException(nameof(functionName));
            SequenceLength = sequenceLength;
            ExitCount = exitCount;
            Reorder = reorder;
            UseCuratedTransforms = useCuratedTransforms;
            TopContenders = topContenders;
            ReferenceSequence = referenceSequence;
        }
    }

    public class PreprocessedFileData
    {
        public string FileName { get; }
        public Dictionary<string, string> Settings { get; }
        public List<(string Sequence, double Score)> SequencesWithScores { get; } // 🔹 Now stores sequence-score pairs

        public PreprocessedFileData(string fileName, Dictionary<string, string> settings,
            List<(string, double)> sequencesWithScores)
        {
            FileName = fileName;
            Settings = settings;
            SequencesWithScores = sequencesWithScores ?? new List<(string, double)>(); // ✅ Ensure it's initialized
        }
    }

    #endregion DATA
}