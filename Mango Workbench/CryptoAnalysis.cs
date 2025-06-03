/*
 * CryptoAnalysis Module
 * =============================================
 * Project: Mango
 * Purpose: Serves as the analytical engine of Mango, evaluating transform sequences
 *          using a suite of cryptographic metrics. Scores are used to assess diffusion,
 *          entropy, input sensitivity, and structural independence.
 *
 *          Key Responsibilities:
 *            • RunCryptAnalysis: Executes all metrics on encrypted data.
 *            • Metric Registry: Centralized definitions, weights, and baselines.
 *            • Score Calculation: Supports both traditional and practical scoring models.
 *            • Contender Management: Stores top-scoring sequences for further evaluation.
 *            • Consistency Verification: Ensures scoring reproducibility across runs.
 *            • Logging: Generates colorized and log-file-safe reports with full precision.
 *
 *          Supports:
 *            → Avalanche & key-dependency analysis
 *            → Full metric tracing and debug output
 *            → Lightweight contender trimming and sorting
 *            → Band-based practical scoring to reflect cryptographic robustness
 *
 * Author: [Luke Tomasello, luke@tomasello.com]
 * Created: November 2024
 * License: [MIT]
 * =============================================
 */

using Mango.Adaptive;
using Mango.AnalysisCore;
using Mango.Cipher;
using Mango.Utilities;
using System.Text;

namespace Mango.Analysis;

public class CryptoAnalysis
{
    /// <summary>
    /// MetricsRegistry defines the cryptographic metrics used to evaluate the quality of transforms.
    /// Each metric includes its implementation, baseline, leniency, weight, and other attributes.
    /// </summary>
    public Dictionary<string, CryptoAnalysisCore.MetricInfo> MetricsRegistry { get; private set; }

    private readonly CryptoAnalysisCore _analysisCore;
    public CryptoAnalysis()
    {
        _analysisCore = new CryptoAnalysisCore();
        MetricsRegistry = _analysisCore.MetricsRegistry;
    }

    public List<CryptoAnalysisCore.AnalysisResult> RunCryptAnalysis(
        byte[] encryptedData,
        byte[]? avalanchePayload = null,
        byte[]? keyDependencyPayload = null,
        byte[]? inputData = null,
        string? logFilePath = null)
    {

        return _analysisCore.RunCryptAnalysis(
            encryptedData,
            avalanchePayload,
            keyDependencyPayload,
            inputData,
            logFilePath);
    }

    public void ApplyWeights(OperationModes mode)
    {
        _analysisCore.ApplyWeights(mode);
    }
    public bool TryGetWeights(OperationModes mode, out Dictionary<string, double> weights)
    {
        return _analysisCore.TryGetWeights(mode, out weights!);
    }
    #region Reporting and Logging

    public void Initialize()
    {
        // Clear all state related to contenders and other temporary analysis data
        contenders.Clear();
    }

    public List<string> CryptAnalysisReport(
        CryptoLib cryptoLib,
        List<CryptoAnalysisCore.AnalysisResult> results,
        string? context = null,
        IEnumerable<byte>? sequence = null,
        InputType? inputType = null)
    {
        var output = new List<string>();

        // Context information (optional)
        if (!string.IsNullOrEmpty(context))
            output.Add($"<Cyan>Context:</Cyan> {context}");

        // InputType information (optional)
        if (inputType.HasValue)
            output.Add($"<Gray>Input Type:</Gray> {inputType}");

        // Sequence information (optional)
        if (sequence != null)
        {
            var sequenceNames = string.Join(" -> ", sequence.Select(id =>
                cryptoLib.TransformRegistry.TryGetValue(id, out var transform) ? transform.Name : $"Unknown ({id})"));
            output.Add($"<Green>Sequence:</Green> {sequenceNames}");
        }

        // Display detailed metrics
        foreach (var result in results)
        {
            // Determine weight-based color for the metric name
            var metricInfo = MetricsRegistry[result.Name];
            var weightColor = metricInfo.Weight >= 0.3 ? "Red" :
                metricInfo.Weight >= 0.2 ? "White" :
                "Yellow";

            // Metric name with weight-based color
            output.Add($"- <{weightColor}>{result.Name}</{weightColor}>: " +
                       $"<{(result.Passed ? "Green" : "Red")}>{(result.Passed ? "PASS" : "FAIL")}</{(result.Passed ? "Green" : "Red")}>");

            // Metric and threshold with full precision
            output.Add($"  <Gray>Metric: {result.Score:F10}, Threshold: {metricInfo.Baseline:F10}</Gray>");

            // Notes, if any
            if (!string.IsNullOrEmpty(result.Notes))
                output.Add($"  <Gray>Notes: {result.Notes}</Gray>");
        }

        return output;
    }


    private List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysisCore.AnalysisResult> Metrics)> contenders = new();
    public List<(List<byte> Sequence, double AggregateScore, List<CryptoAnalysisCore.AnalysisResult> Metrics)> Contenders => contenders;

    public void CryptAnalysisRecordBest(ExecutionEnvironment localEnv, List<CryptoAnalysisCore.AnalysisResult> analysisResults, List<byte> currentSequence)
    {
        var passCount = analysisResults.Count(r => r.Passed);

        UtilityHelpers.AssertWeightsMatchExpectedMode(localEnv);

        // Calculate aggregate score
        var aggregateScore = CalculateAggregateScore(analysisResults, localEnv.Globals.ScoringMode);

        // Add sequence to contenders if pass count exceeds threshold
        if (passCount >= localEnv.Globals.PassCount) // Example threshold
            contenders.Add((new List<byte>(currentSequence), aggregateScore, analysisResults));

        // Perform trim+sort. Eg, every 1000*4 additions
        if (contenders.Count > localEnv.Globals.DesiredContenders * 4)
            contenders = contenders
                .OrderByDescending(c => c.AggregateScore)
                .Take(localEnv.Globals.DesiredContenders) // Trim to desired count
                .ToList();
    }

    public void TrimContenders(int count = 1000)
    {
        contenders = contenders
            .OrderByDescending(c => c.AggregateScore)
            .Take(count)
            .ToList();
    }

    #region CalculateAggregateScore

    public double CalculateAggregateScore(List<CryptoAnalysisCore.AnalysisResult>? results, ScoringModes scoringMode,
        string? logFilePath = null)
    {
        return _analysisCore.CalculateAggregateScore(results, scoringMode, logFilePath);
    }
    #endregion CalculateAggregateScore

    /*
        Logging Format Update: Introduction of LongForm

        Mango now supports a LongForm logging mode, which provides extended precision
        in metric and aggregate score reporting. Traditionally, scores were logged
        with four decimal places (e.g., 0.9876), but LongForm extends this to ten
        decimal places (e.g., 0.9876543210).

        This change is particularly useful for high-precision debugging and ScoreChecker
        validation, where subtle differences in scoring can impact result interpretation.

        While screen output continues to use the shorter format for readability,
        LongForm logging ensures that fine-grained details are preserved in logs
        for deeper analysis.
    */
    private const bool LongForm = true;

    public List<string> BuildLog(ExecutionEnvironment localEnv, int maxContenders = 10)
    {
        TrimContenders(localEnv.Globals.DesiredContenders);
        var seq = new SequenceHelper(localEnv.Crypto);
        List<string> logOutput = new();

        // 🔹 Generate standardized header
        logOutput.AddRange(UtilityHelpers.GenerateHeader(localEnv, "** Analysis Summary **",
            options: UtilityHelpers.HeaderOptions.AllExecution));

        var contenderNumber = 1;

        foreach (var (sequence, aggregateScore, metrics) in contenders
                     .OrderByDescending(c => c.AggregateScore)
                     .Take(maxContenders)) // ✅ Limit to top N contenders
        {
            var passCount = metrics.Count(result => result.Passed);

            logOutput.Add($"<Yellow>Contender #{contenderNumber++}</Yellow>");

            var tRs = Enumerable.Repeat((byte)1, sequence.Count).ToArray();
            var profile = InputProfiler.CreateInputProfile(
                name: "munge",
                sequence: sequence.ToArray(),
                tRs: tRs,
                globalRounds: localEnv.Globals.Rounds);

            string currentSequence = seq.FormattedSequence<string>(profile);

            logOutput.Add(
                $"<Gray>Sequence:</Gray> <Green>{currentSequence}</Green>");

            logOutput.Add(LongForm
                ? $"<Gray>Aggregate Score:</Gray> <Green>{aggregateScore:F10}</Green>"
                : $"<Gray>Aggregate Score:</Gray> <Green>{aggregateScore:F4}</Green>");

            logOutput.Add($"<Gray>Pass Count:</Gray> <Green>{passCount} / {metrics.Count}</Green>");
            logOutput.Add($"<Cyan>Scores:</Cyan>");

            foreach (var result in metrics)
            {
                var thresholdInfo = MetricsRegistry.TryGetValue(result.Name, out var metricInfo)
                    ? $"Threshold: {metricInfo.Threshold:F4}"
                    : "Threshold info unavailable";

                var passFailColor = result.Passed ? "Green" : "Red";
                logOutput.Add(
                    $"- <{passFailColor}>{result.Name}: {(result.Passed ? "PASS" : "FAIL")}</{passFailColor}>");

                logOutput.Add(LongForm
                    ? $"  Metric: <Yellow>{result.Score:F10}</Yellow>, {thresholdInfo}"
                    : $"  Metric: <Yellow>{result.Score:F4}</Yellow>, {thresholdInfo}");

                if (!string.IsNullOrEmpty(result.Notes)) logOutput.Add($"  <Gray>Notes:</Gray> {result.Notes}");
            }

            logOutput.Add(""); // Blank line between contenders
        }

        return logOutput;
    }
#if DEBUG
    private static readonly bool _fileLocking = false;
#else
    private static bool _fileLocking = true;
#endif

    public void LogToFile(ExecutionEnvironment localEnv, string logFileName, int maxContenders = 0)
    {
        if (File.Exists(logFileName)) File.SetAttributes(logFileName, FileAttributes.Normal); // 🔓 Force unlock

        try
        {
            using (var writer = new StreamWriter(logFileName))
            {
                foreach (var line in BuildLog(localEnv, maxContenders))
                    writer.WriteLine(ColorConsole.RemoveColorTags(line)); // ✅ Strips color tags for file output
            }
        }
        finally
        {
            if (_fileLocking && File.Exists(logFileName))
                File.SetAttributes(logFileName, FileAttributes.ReadOnly); // 🔒 Re-lock after write
        }
    }
    public bool LogToScreen(ExecutionEnvironment localEnv, InputType inputType, int maxContenders = 10)
    {
        Console.Clear();

        // Print the log to the screen with color
        foreach (var line in
                 BuildLog(localEnv, maxContenders)) ColorConsole.WriteLine(line); // ✅ Keeps colors for screen output

        return true;
    }

    #endregion Reporting and Logging
}

public class Contender
{
    public string Sequence { get; set; } = null!;
    public double AggregateScore { get; set; }
    public int PassCount { get; set; }
    public List<Metric> Metrics { get; set; } = new();

    public double GetFieldValue(string field)
    {
        return field.ToLower() switch
        {
            "aggregatescore" => AggregateScore,
            "passcount" => PassCount,
            _ => throw new ArgumentException($"Unknown field: {field}")
        };
    }

    // Generates a summary of metrics for verbose output
    public string MetricsSummary()
    {
        if (Metrics == null || Metrics.Count == 0) return "No metrics available.";

        var summary = new StringBuilder();
        foreach (var metric in Metrics)
            summary.AppendLine(
                $"{metric.Name}: Value={metric.Value:F4}, Threshold={metric.Threshold:F4}, Passed={metric.Passed}, Notes={metric.Notes ?? "None"}");

        return summary.ToString();
    }
}