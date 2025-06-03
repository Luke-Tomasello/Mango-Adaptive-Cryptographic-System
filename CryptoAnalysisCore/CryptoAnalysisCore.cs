using System.Security.Cryptography;
using System.Text;

namespace Mango.AnalysisCore;
public enum OperationModes
{
    None = 0x01,

    /// <summary>
    /// Focuses on cryptographic accuracy and performance.
    /// </summary>
    Cryptographic = 0x02,

    /// <summary>
    /// Enables exploratory mode for experimenting with sequences.
    /// </summary>
    Exploratory = 0x08,

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
    Flattening = 0x20,

    Zero = 0x40
}

public enum ScoringModes
{
    Practical,
    Metric
}

public partial class CryptoAnalysisCore
{

    public class AnalysisResult
    {
        public string Name { get; set; } = null!;
        public bool Passed { get; set; }
        public double Score { get; set; }
        public string Notes { get; set; } = null!;
    }

    public class MetricInfo
    {
        public Func<byte[], byte[], AnalysisResult> Implementation { get; }
        public double Baseline { get; }
        public double Leniency { get; }
        public double Weight { get; set; }
        public bool NeedsInput { get; }
        public bool NeedsAvalanchePayload { get; }
        public bool NeedsKeyDependencyPayload { get; }
        public string? Identifier { get; } // Unique identifier for each metric
        public bool UseTwoSidedLeniency { get; set; } = false; // Default: disabled
        public double? MaxValue { get; } // Optional max value for normalization

        public double Threshold => CalculateThreshold();

        public MetricInfo(
            Func<byte[], byte[], AnalysisResult> implementation,
            double baseline,
            double leniency,
            double weight,
            bool needsInput = false,
            bool needsAvalanchePayload = false,
            bool needsKeyDependencyPayload = false,
            string? identifier = null,
            double? maxValue = null)
        {
            Implementation = implementation;
            Baseline = baseline;
            Leniency = leniency;
            Weight = weight;
            NeedsInput = needsInput;
            Identifier = identifier;
            NeedsAvalanchePayload = needsAvalanchePayload;
            NeedsKeyDependencyPayload = needsKeyDependencyPayload;
            MaxValue = maxValue ?? baseline + leniency; // Default max value

            ValidateLeniency();
        }

        private double CalculateThreshold()
        {
            // Special case: Entropy requires a fixed minimum value
            if (Identifier == "Entropy")
                return Baseline;

            // Default behavior: Baseline ± Leniency
            return Baseline + Leniency;
        }

        public double ComputeRescaledScore(double metricValue)
        {
            var threshold = Threshold; // 👈 Use instance property
            var maxValue = MaxValue ?? threshold; // 👈 Prevents null issues

            if (maxValue > threshold)
            {
                var difference = metricValue - threshold;
                var range = maxValue - threshold;
                var ratio = difference / range;
                var scaledScore = ratio * 100;

                return Math.Max(0, Math.Min(scaledScore, 100));
            }
            else
            {
                // 🚨 ScoreChecker Deviation: Properly penalize deviations instead of simple pass/fail.
                var deviation = Math.Abs(metricValue - threshold);
                var scaledScore = Math.Max(0, 100 * (1 - deviation / threshold)); // Penalize deviations
                return scaledScore;
            }
        }

        public bool IsMetricPassing(double metricValue)
        {
            return UseTwoSidedLeniency
                ? Math.Abs(metricValue - Baseline) <= Leniency
                : metricValue >= Threshold;
        }

        private void ValidateLeniency()
        {
            if (Leniency > 0.0 && Identifier == "Entropy")
                throw new ArgumentException("Entropy does not support leniency. Set Leniency to 0.0.");
        }
    }

    /// <summary>
    /// MetricsRegistry defines the cryptographic metrics used to evaluate the quality of transforms.
    /// Each metric includes its implementation, baseline, leniency, weight, and other attributes.
    /// </summary>
    public Dictionary<string, MetricInfo> MetricsRegistry { get; private set; }

    public CryptoAnalysisCore()
    :this(OperationModes.Zero)
    {

    }
    public CryptoAnalysisCore(OperationModes mode)
    {
        MetricsRegistry = new Dictionary<string, MetricInfo>
        {
            {
                "Entropy", new MetricInfo(
                    (input, encrypted) => RunEntropyTest(encrypted),
                    7.9523,
                    0.0, // Entropy does not use leniency
                    0.0,    // must be explicitly set
                    false,
                    identifier: "Entropy",
                    maxValue: 8.0000)
            },
            {
                "BitVariance", new MetricInfo(
                    (input, encrypted) => RunBitVarianceTest(encrypted),
                    0.5003,
                    0.002,
                    0.0,    // must be explicitly set
                    false,
                    identifier: "BitVariance",
                    maxValue: 0.5023) { UseTwoSidedLeniency = true }
            },
            {
                "SlidingWindow", new MetricInfo(
                    (input, encrypted) => RunSlidingWindowTest(encrypted),
                    0.9027,
                    0.005,
                    0.0,    // must be explicitly set
                    false,
                    identifier: "SlidingWindow",
                    maxValue: 1.0000) { UseTwoSidedLeniency = true }
            },
            {
                "FrequencyDistribution", new MetricInfo(
                    (input, encrypted) => RunFrequencyDistributionTest(encrypted),
                    0.7426,
                    0.010,
                    0.0,    // must be explicitly set
                    false,
                    identifier: "FrequencyDistribution",
                    maxValue: 1.0000) { UseTwoSidedLeniency = true }
            },
            {
                "PeriodicityCheck", new MetricInfo(
                    (input, encrypted) => RunPeriodicityCheck(encrypted),
                    1.0000,
                    0.000,
                    0.0,    // must be explicitly set
                    false,
                    identifier: "PeriodicityCheck",
                    maxValue: 1.0000)
            },
            {
                "MangosCorrelation", new MetricInfo(
                    RunMangosCorrelation,
                    0.0,
                    0.0500,
                    0.0,    // must be explicitly set
                    true,
                    identifier: "MangosCorrelation",
                    maxValue: 0.0500) { UseTwoSidedLeniency = true }
            },
            {
                "PositionalMapping", new MetricInfo(
                    RunPositionalMapping,
                    0.0,
                    0.0500,
                    0.0,    // must be explicitly set
                    true,
                    identifier: "PositionalMapping",
                    maxValue: 0.0500) { UseTwoSidedLeniency = true }
            },
            {
                "AvalancheScore", new MetricInfo(
                    RunAvalancheScore,
                    50.0,
                    5.0,
                    0.0,    // must be explicitly set
                    false,
                    identifier: "AvalancheScore",
                    needsAvalanchePayload: true,
                    maxValue: 60.0000) { UseTwoSidedLeniency = true }
            },
            {
                "KeyDependency", new MetricInfo(
                    RunKeyDependency,
                    50.0,
                    5.0,
                    0.0,    // must be explicitly set
                    false,
                    identifier: "KeyDependency",
                    needsKeyDependencyPayload: true,
                    maxValue: 60.0000) { UseTwoSidedLeniency = true }
            }
        };
        ApplyWeights(mode);
    }
    public List<AnalysisResult> RunCryptAnalysis(
        byte[] encryptedData,
        byte[]? avalanchePayload = null,
        byte[]? keyDependencyPayload = null,
        byte[]? inputData = null,
        string? logFilePath = null)
    {
        List<AnalysisResult> results = new();
        var loggingEnabled = !string.IsNullOrEmpty(logFilePath);

        // ✅ Open the log file only if logging is enabled
        using StreamWriter? logWriter = loggingEnabled ? new StreamWriter(logFilePath!, append: true) : null;

        if (loggingEnabled)
        {
            logWriter!.WriteLine("=== CryptAnalysis Detailed Output ===");
            logWriter.WriteLine(
                $"Input Data Hash: {Convert.ToHexString(SHA256.Create().ComputeHash(inputData ?? Array.Empty<byte>()))}");
            logWriter.WriteLine(
                $"Encrypted Data Hash: {Convert.ToHexString(SHA256.Create().ComputeHash(encryptedData))}");
            logWriter.WriteLine();
        }

        foreach (var metric in MetricsRegistry.Values)
        {
            AnalysisResult result;

            if (metric.NeedsKeyDependencyPayload && keyDependencyPayload == null)
                throw new ArgumentException($"Metric '{metric.Identifier}' requires modified encrypted data, but none was provided.");
            else if (metric.NeedsKeyDependencyPayload)
                result = metric.Implementation(encryptedData, keyDependencyPayload!);
            else if (metric.NeedsAvalanchePayload && avalanchePayload == null)
                throw new ArgumentException($"Metric '{metric.Identifier}' requires modified encrypted data, but none was provided.");
            else if (metric.NeedsAvalanchePayload)
                result = metric.Implementation(encryptedData, avalanchePayload!);
            else if (metric.NeedsInput && inputData == null)
                throw new ArgumentException($"Metric '{metric.Identifier}' requires input data, but none was provided.");
            else if (metric.NeedsInput)
                result = metric.Implementation(inputData!, encryptedData);
            else
                result = metric.Implementation(null!, encryptedData);

            var deviation = Math.Abs(result.Score - metric.Baseline);
            result.Passed = metric.IsMetricPassing(result.Score);
            result.Notes = result.Passed
                ? "Metric is within acceptable range."
                : $"Deviation: {deviation:F4}, Acceptable Range: ±{metric.Leniency:F4}.";

            results.Add(result);

            if (loggingEnabled)
            {
                logWriter!.WriteLine($"Metric: {result.Name}");
                logWriter.WriteLine($"  Computed Metric: {result.Score:F4}");
                logWriter.WriteLine($"  Baseline: {metric.Baseline:F4}");
                logWriter.WriteLine($"  Leniency: ±{metric.Leniency:F4}");
                logWriter.WriteLine($"  Status: {(result.Passed ? "PASS" : "FAIL")}");
                logWriter.WriteLine();
            }
        }

        if (loggingEnabled)
            logWriter!.WriteLine("=== End of Output ===");

        return results;
    }

    #region metric implementations

    public AnalysisResult RunKeyDependency(byte[] encrypted, byte[] modifiedEncrypted)
    {
        var KeyDependency = CalculateAvalancheScore(encrypted, modifiedEncrypted);

        // Define expected behavior for Key Dependency Score
        var baseline = MetricsRegistry["KeyDependency"].Baseline; // Set appropriately, e.g., 50.0
        var leniency = MetricsRegistry["KeyDependency"].Leniency; // Set appropriately, e.g., ±5.0
        var useTwoSidedLeniency = MetricsRegistry["KeyDependency"].UseTwoSidedLeniency;

        // Evaluate result
        var deviation = Math.Abs(KeyDependency - baseline);
        var passed = useTwoSidedLeniency
            ? deviation <= leniency
            : KeyDependency >= baseline - leniency;

        return new AnalysisResult
        {
            Score = KeyDependency,
            Passed = passed,
            Notes = passed
                ? "Key Dependency Score is within the acceptable range."
                : $"Deviation: {deviation:F4}, Acceptable Range: ±{leniency:F4}.",
            Name = "KeyDependency"
        };
    }

    /// <summary>
    /// Evaluates the Avalanche Score for two encrypted byte arrays,
    /// ensuring the diffusion property by measuring the percentage of differing bits.
    /// </summary>
    /// <param name="encrypted">The encrypted output for the original input.</param>
    /// <param name="modifiedEncrypted">The encrypted output after a single-bit change in the input.</param>
    /// <returns>An AnalysisResult containing the Avalanche Score and pass/fail status.</returns>
    public AnalysisResult RunAvalancheScore(byte[] encrypted, byte[] modifiedEncrypted)
    {
        var avalancheScore = CalculateAvalancheScore(encrypted, modifiedEncrypted);

        // Define expected behavior for Avalanche Score
        var baseline = MetricsRegistry["AvalancheScore"].Baseline; // Should be 50.0
        var leniency = MetricsRegistry["AvalancheScore"].Leniency; // Should be ±5.0
        var useTwoSidedLeniency = MetricsRegistry["AvalancheScore"].UseTwoSidedLeniency;

        // Evaluate result
        var deviation = Math.Abs(avalancheScore - baseline);
        var passed = useTwoSidedLeniency
            ? deviation <= leniency
            : avalancheScore >= baseline - leniency;

        return new AnalysisResult
        {
            Score = avalancheScore,
            Passed = passed,
            Notes = passed
                ? "Avalanche Score is within the acceptable range."
                : $"Deviation: {deviation:F4}, Acceptable Range: ±{leniency:F4}.",
            Name = "AvalancheScore"
        };
    }

    public AnalysisResult RunMangosCorrelation(byte[] inputData, byte[] encryptedData)
    {
        var correlation = CalculateMangosCorrelation(inputData, encryptedData);

        // Expected behavior based on correlation
        var expectedThreshold = 0.0; // Default: no correlation expected
        var acceptableRange = 0.05;

        if (correlation == 1.0)
            // Perfect match detected
            expectedThreshold = 1.0;

        // Evaluate result
        var deviation = Math.Abs(correlation - expectedThreshold);
        var passed = deviation <= acceptableRange;

        return new AnalysisResult
        {
            Score = correlation,
            Passed = passed,
            Notes = passed
                ? "Metric is within acceptable range."
                : $"Deviation: {correlation:0.0000}, Acceptable Range: ±{acceptableRange}.",
            Name = "MangosCorrelation" // Set the test name here
        };
    }

    public AnalysisResult RunPositionalMapping(byte[] inputData, byte[] encryptedData)
    {
        // Calculate the positional mapping score
        var mappingScore = CalculatePositionalMapping(inputData, encryptedData);

        // Define expected threshold and acceptable range (static for now)
        var expectedThreshold = 0.0; // Ideal: no positional similarity
        var acceptableRange = 0.05; // Example tolerance

        // Evaluate result
        var deviation = Math.Abs(mappingScore - expectedThreshold);
        var passed = deviation <= acceptableRange;

        return new AnalysisResult
        {
            Score = mappingScore,
            Passed = passed,
            Notes = passed
                ? "Positional mapping is within acceptable range."
                : $"Positional dependencies detected. Score: {mappingScore:0.0000}",
            Name = "PositionalMapping"
        };
    }

    public AnalysisResult RunEntropyTest(byte[] data)
    {
        return new AnalysisResult
        {
            Name = "Entropy",
            Score = CalculateEntropy(data),
            Notes = ""
        };
    }

    public AnalysisResult RunBitVarianceTest(byte[] data)
    {
        return new AnalysisResult
        {
            Name = "BitVariance",
            Score = CalculateBitVariance(data),
            Notes = ""
        };
    }

    public AnalysisResult RunSlidingWindowTest(byte[] data)
    {
        return new AnalysisResult
        {
            Name = "SlidingWindow",
            Score = CalculateSlidingWindow(data),
            Notes = ""
        };
    }

    public AnalysisResult RunFrequencyDistributionTest(byte[] data)
    {
        return new AnalysisResult
        {
            Name = "FrequencyDistribution",
            Score = CalculateFrequencyDistribution(data),
            Notes = ""
        };
    }

    public AnalysisResult RunPeriodicityCheck(byte[] data)
    {
        return new AnalysisResult
        {
            Name = "PeriodicityCheck",
            Score = CalculatePeriodicity(data),
            Notes = ""
        };
    }

    #endregion metric implementations

    #region calculation methods

    /// <summary>
    /// Computes the PositionalMapping score, a custom metric designed to evaluate positional dependencies
    /// between input and output byte arrays. Unlike traditional metrics, it:
    /// - Directly penalizes perfect matches between corresponding input and output bytes.
    /// - Assesses bit-level dependencies by counting ON bits and calculating the number of bit moves needed
    ///   to align them when ON bit counts are identical.
    /// - Provides a normalized score reflecting the degree of positional disruption introduced by the transform.
    /// </summary>
    /// <param name="input">The input byte array before transformation.</param>
    /// <param name="output">The output byte array after transformation.</param>
    /// <returns>A normalized PositionalMapping score (0.0 = no dependencies, higher values indicate stronger dependencies).</returns>
    /// <exception cref="ArgumentException">Thrown when input and output arrays differ in length.</exception>
    public double CalculatePositionalMapping(byte[] input, byte[] output)
    {
        if (input.Length != output.Length)
            throw new ArgumentException("Input and output arrays must have the same length.");

        var n = input.Length;
        double totalScore = 0;

        // Iterate through each byte in input and output
        for (var i = 0; i < n; i++) totalScore += CalculateScore(input[i], output[i]);

        // Normalize the total score by the number of bytes
        return totalScore / n;
    }

    /// <summary>
    /// Calculates Mango's Correlation, measuring the structural relationship between input and output
    /// to detect residual patterns or dependencies in cryptographic transformations.
    /// </summary>
    /// <param name="input">The original input data.</param>
    /// <param name="output">The transformed output data.</param>
    /// <returns>A double representing the correlation metric (0.0 indicates no correlation).</returns>
    public double CalculateMangosCorrelation(byte[] input, byte[] encrypted)
    {
        if (input.Length != encrypted.Length)
            throw new ArgumentException("Input and encrypted arrays must have the same length.");

        var n = input.Length;

        // Check for identical datasets
        var areIdentical = true;
        var areConstantInput = true;
        var areConstantEncrypted = true;

        double firstInput = input[0];
        double firstEncrypted = encrypted[0];

        // Loop through datasets once
        for (var i = 0; i < n; i++)
        {
            if (input[i] != encrypted[i])
                areIdentical = false;

            if (input[i] != firstInput)
                areConstantInput = false;

            if (encrypted[i] != firstEncrypted)
                areConstantEncrypted = false;

            // Early exit if neither constant nor identical
            if (!areIdentical && !areConstantInput && !areConstantEncrypted)
                break;
        }

        // Handle special cases
        if (areIdentical)
            return 1.0; // Perfect match

        if (areConstantInput || areConstantEncrypted)
            return 0.0; // Different constant datasets have no correlation

        // Generalized correlation logic for non-trivial datasets
        double sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0, sumY2 = 0;

        for (var i = 0; i < n; i++)
        {
            double x = input[i];
            double y = encrypted[i];

            sumX += x;
            sumY += y;
            sumXY += x * y;
            sumX2 += x * x;
            sumY2 += y * y;
        }

        var numerator = n * sumXY - sumX * sumY;
        var denominator = Math.Sqrt((n * sumX2 - sumX * sumX) * (n * sumY2 - sumY * sumY));

        return denominator == 0 ? 0 : numerator / denominator;
    }

    public double CalculateEntropy(byte[] data)
    {
        var frequency = new Dictionary<byte, int>();
        foreach (var b in data)
        {
            if (!frequency.ContainsKey(b))
                frequency[b] = 0;
            frequency[b]++;
        }

        var entropy = 0.0;
        var dataLength = data.Length;

        foreach (var count in frequency.Values)
        {
            var probability = (double)count / dataLength;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    public double CalculateBitVariance(byte[] data)
    {
        var totalBits = data.Length * 8;
        var bitCount = 0;

        foreach (var b in data)
            for (var i = 0; i < 8; i++)
                if ((b & (1 << i)) != 0)
                    bitCount++;

        var bitProbability = (double)bitCount / totalBits;
        return bitProbability;
    }

    public double CalculateSlidingWindow(byte[] data)
    {
        const int windowSize = 8;
        var patternCounts = new int[1 << windowSize];

        for (var i = 0; i <= data.Length * 8 - windowSize; i++)
        {
            var pattern = 0;
            for (var j = 0; j < windowSize; j++)
            {
                var byteIndex = (i + j) / 8;
                var bitIndex = (i + j) % 8;

                if ((data[byteIndex] & (1 << bitIndex)) != 0)
                    pattern |= 1 << j;
            }

            patternCounts[pattern]++;
        }

        var average = patternCounts.Average();
        var standardDeviation = Math.Sqrt(patternCounts.Average(v => Math.Pow(v - average, 2)));

        return 1.0 - standardDeviation / average;
    }

    public double CalculateFrequencyDistribution(byte[] data)
    {
        var frequencies = new int[256];
        foreach (var b in data) frequencies[b]++;

        var average = frequencies.Average();
        var standardDeviation = Math.Sqrt(frequencies.Average(v => Math.Pow(v - average, 2)));

        return 1.0 - standardDeviation / average;
    }

    public double CalculatePeriodicity(byte[] data)
    {
        var maxPeriod = Math.Min(256, data.Length / 2);
        var periodicCount = 0;

        for (var period = 1; period <= maxPeriod; period++)
        {
            var periodic = true;
            for (var i = 0; i < data.Length - period; i++)
                if (data[i] != data[i + period])
                {
                    periodic = false;
                    break;
                }

            if (periodic)
                periodicCount++;
        }

        return 1.0 - (double)periodicCount / maxPeriod;
    }

    /// <summary>
    /// Calculates the Avalanche Score, a critical metric for evaluating the diffusion 
    /// property of cryptographic transforms. The Avalanche Effect ensures that a single 
    /// bit change in the input results in approximately 50% of the output bits flipping, 
    /// demonstrating strong sensitivity and randomness.
    /// 
    /// Key Points:
    /// - Measures the percentage of differing bits between two encrypted byte arrays 
    ///   (e.g., before and after a single-bit change in the input).
    /// - Validates the diffusion property, which is distinct from other metrics like 
    ///   correlation or entropy.
    /// - Complements existing cryptographic metrics by directly testing input sensitivity.
    /// 
    /// Expected Output:
    /// - A perfect Avalanche Score is close to 50%, indicating optimal diffusion.
    /// - Scores significantly below 50% suggest weak diffusion (insufficient sensitivity).
    /// - Scores significantly above 50% may indicate bias or structural anomalies.
    ///
    /// Parameters:
    /// <param name="encrypt1">The first encrypted byte array.</param>
    /// <param name="encrypt2">The second encrypted byte array, resulting from a single-bit change in the input.</param>
    /// <returns>
    /// A double representing the Avalanche Score (percentage of differing bits between the arrays).
    /// </returns>
    /// <exception cref="ArgumentNullException">Thrown if either input array is null.</exception>
    /// <exception cref="ArgumentException">
    /// Thrown if the input arrays differ in length, as they must represent comparable data.
    /// </exception>
    public double CalculateAvalancheScore(byte[] encrypt1, byte[] encrypt2)
    {
        if (encrypt1 == null || encrypt2 == null)
            throw new ArgumentNullException("Encrypted data cannot be null.");

        if (encrypt1.Length != encrypt2.Length)
            throw new ArgumentException("Encrypted arrays must be of the same length.");

        var totalBits = encrypt1.Length * 8; // Total number of bits to compare
        var differingBits = 0;

        for (var i = 0; i < encrypt1.Length; i++)
        {
            var xorResult = (byte)(encrypt1[i] ^ encrypt2[i]); // XOR to find differing bits
            differingBits += CountSetBits(xorResult); // Count the set bits in the XOR result
        }

        return (double)differingBits / totalBits * 100; // Percentage of differing bits
    }

    #endregion calculation methods

    #region utilities

    /// <summary>
    /// Counts the number of set bits (1s) in a byte.
    /// </summary>
    /// <param name="value">The byte value to evaluate.</param>
    /// <returns>The number of set bits in the byte.</returns>
    private int CountSetBits(byte value)
    {
        var count = 0;
        while (value != 0)
        {
            count += value & 1; // Increment count if the least significant bit is 1
            value >>= 1; // Shift right to check the next bit
        }

        return count;
    }

    private double CalculateScore(byte inputByte, byte outputByte)
    {
        // Direct penalty for perfect matches
        if (inputByte == outputByte) return 1.0; // Maximum penalty for perfect matches

        // Count ON bits in both bytes
        var inputOnBits = CountOnBits(inputByte);
        var outputOnBits = CountOnBits(outputByte);

        // If ON bit counts differ, assign minimal penalty (or pass entirely)
        if (inputOnBits != outputOnBits) return 0; // Pass directly for ON bit count mismatch

        // Calculate the number of moves required to match ON bits
        return CalculateBitMoveCost(inputByte, outputByte);
    }

    private int CountOnBits(byte b)
    {
        var count = 0;
        while (b > 0)
        {
            count += b & 1;
            b >>= 1;
        }

        return count;
    }

    private double CalculateBitMoveCost(byte inputByte, byte outputByte)
    {
        var inputBitPositions = GetBitPositions(inputByte);
        var outputBitPositions = GetBitPositions(outputByte);

        // Calculate the "move cost" between input and output bit positions
        var moveCost = 0;
        for (var i = 0; i < inputBitPositions.Length; i++)
            moveCost += Math.Abs(inputBitPositions[i] - outputBitPositions[i]);

        // Normalize move cost by maximum possible moves for 8 bits
        return moveCost / 28.0; // Maximum moves for 8 bits: (0+1+2+...+7) = 28
    }

    private int[] GetBitPositions(byte b)
    {
        var positions = new List<int>();
        for (var i = 0; i < 8; i++)
            if ((b & (1 << i)) != 0)
                positions.Add(i);

        return positions.ToArray();
    }

    #endregion utilities

    #region GetPracticalScore

    // Enum representing scoring bands
    public enum PracticalScoreBand
    {
        Perfect = 100,
        HighMarginPass = 90,
        BarelyPass = 70,
        NearMiss = 50,
        Fail = 20,
        Catastrophic = 0
    }

    /// <summary>
    /// Computes the aggregate practical score for a set of metric results by applying band-based scoring
    /// and optional overperformance bonuses. Each metric is weighted according to its defined importance.
    ///
    /// Scoring consists of two stages per metric:
    /// 1. <see cref="GetPracticalScore"/> assigns a base score using discrete threshold bands that reflect
    ///    how closely the metric aligns with expected values.
    /// 2. <see cref="GetBonus"/> applies a scaled bonus for metrics that significantly exceed expectations,
    ///    extending score granularity within high-performing regions.
    ///
    /// The final result is a weighted average normalized to a 0–100 scale. Most strong candidates will fall
    /// within a scoring "mesa" — a plateau of high but stable scores — indicating resilience to small variations
    /// in input, password, or environment.
    ///
    /// Returns 0 if no valid metric weights are found (e.g., all results skipped).
    /// </summary>
    /// <param name="results">The list of metric results to evaluate.</param>
    /// <param name="verbose">Enables console output for detailed per-metric scoring diagnostics.</param>
    /// <returns>The final normalized practical score (0–100).</returns>
    public double ComputePracticalScore(List<AnalysisResult>? results, bool verbose = false)
    {
        double totalWeightedScore = 0;
        double totalWeight = 0;

        foreach (var result in results!)
        {
            if (!MetricsRegistry.TryGetValue(result.Name, out var metricInfo))
                continue;

            var weight = metricInfo.Weight;

            // Step 1: Compute band-based score
            var bandScore = GetPracticalScore(result, metricInfo, verbose);

            // Step 2: Apply overperformance bonus
            var finalScore = GetBonus(result, metricInfo, bandScore);

            // Compute bonus and delta (for logging only)
            var bonus = finalScore - bandScore;
            var reference = metricInfo.UseTwoSidedLeniency
                ? metricInfo.Baseline
                : metricInfo.Threshold;
            var delta = Math.Abs(result.Score - reference);

            totalWeightedScore += finalScore * weight / 100.0;
            totalWeight += weight;

            if (verbose)
            {
                if (bonus > 0)
                    Console.WriteLine($"   ↳ Bonus Applied: +{bonus:F4} (Δ: {delta:F4}, Weight: {metricInfo.Weight:F2})");

                Console.WriteLine(
                    $"🔍 {result.Name,-22} | Band Score: {bandScore,5:0.0} | Final Score: {finalScore,5:0.0} | Weight: {weight,4:0.00} | Weighted: {finalScore * weight / 100.0,5:0.00}");
            }
        }

        if (totalWeight == 0)
            return 0;

        var final = totalWeightedScore / totalWeight * 100.0;

        if (verbose)
            Console.WriteLine($"📊 Final Weighted Practical Score: {final:F4}");

        return final;
    }


    // Scoring per metric, based on proximity to threshold
    private double GetPracticalScore(AnalysisResult result, MetricInfo metricInfo, bool verbose = false)
    {
        var actual = result.Score;

        // ✅ Fix: Correct reference point based on leniency mode
        var reference = metricInfo.UseTwoSidedLeniency ? metricInfo.Baseline : metricInfo.Threshold;
        var delta = Math.Abs(actual - reference);

        double score;

        if (result.Passed)
        {
            if (delta < 0.01 * reference) score = (double)PracticalScoreBand.Perfect;
            else if (delta < 0.03 * reference) score = (double)PracticalScoreBand.HighMarginPass;
            else score = (double)PracticalScoreBand.BarelyPass;
        }
        else
        {
            if (delta < 0.03 * reference) score = (double)PracticalScoreBand.NearMiss;
            else if (delta < 0.20 * reference) score = (double)PracticalScoreBand.Fail;
            else score = (double)PracticalScoreBand.Catastrophic;
        }

        if (verbose)
            Console.WriteLine(
                $"   ↳ Metric: {actual:0.000000}, Reference: {reference:0.000000}, Δ: {delta:0.000000}, Pass: {result.Passed}, Assigned Band: {score}");

        return score;
    }
    /// <summary>
    /// Computes a smooth, weight-scaled bonus for overperformance based on full-fidelity metric deviation.
    /// This function enhances the band-based score by applying a sigmoid-shaped ramp that rewards meaningful
    /// deviation from the ideal reference (threshold or baseline), while capping total impact.
    /// 
    /// Unlike banding, which provides coarse classification, this function ensures fine-grained differentiation
    /// among high-performing sequences by leveraging the raw delta value directly.
    /// 
    /// The resulting bonus is small (e.g., +0.1 to +2.0) and accumulates across metrics to help separate
    /// top-tier contenders without distorting the score ceiling or inflating weak passes.
    /// </summary>
    /// <param name="result">The analysis result containing the actual metric score.</param>
    /// <param name="metricInfo">Metadata for the metric, including weight and leniency mode.</param>
    /// <param name="currentBandScore">The score already assigned by banding (typically 70–100).</param>
    /// <returns>The final score after applying any overperformance bonus, capped at 100.0.</returns>
    private double GetBonus(AnalysisResult result, MetricInfo metricInfo, double currentBandScore)
    {
        if (!result.Passed)
            return currentBandScore;

        var reference = metricInfo.UseTwoSidedLeniency
            ? metricInfo.Baseline
            : metricInfo.Threshold;

        var delta = Math.Abs(result.Score - reference);
        var weightFactor = Math.Min(metricInfo.Weight / 0.20, 1.0); // normalize to [0,1]

        // Smooth sigmoid-based micro-bonus scaling
        const double maxBonus = 2.0; // total possible bonus points per metric
        const double pivot = 0.05;   // center of ramp (5% delta)
        const double k = 20.0;       // curve steepness

        var normalizedDelta = delta / reference;
        var sigmoid = 1.0 / (1.0 + Math.Exp(-k * (normalizedDelta - pivot)));
        var bonus = maxBonus * sigmoid * weightFactor;

        return currentBandScore + bonus;
    }


    #endregion GetPracticalScore

    #region CalculateAggregateScore

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
    public double CalculateAggregateScore(List<AnalysisResult>? results, ScoringModes scoringMode,
        string? logFilePath = null)
    {
        if (scoringMode == ScoringModes.Metric)
        {
            var rawScore = ComputeMetricScore(results, logFilePath);
            return ApplyLogScaling(rawScore, 100); // Apply logarithmic scaling for better score distribution
        }

        return ComputePracticalScore(results, false);
    }

    private double ComputeMetricScore(List<AnalysisResult>? results, string? logFilePath)
    {
        double totalWeightedScore = 0;
        double maxPossibleScore = 0;
        var loggingEnabled = !string.IsNullOrEmpty(logFilePath);

        using (var logWriter = loggingEnabled ? new StreamWriter(logFilePath!, true) : null)
        {
            if (loggingEnabled)
            {
                logWriter?.WriteLine("=== AggregateScore Debugging ===");
                logWriter?.WriteLine();
            }

            foreach (var result in results!)
            {
                if (!MetricsRegistry.TryGetValue(result.Name, out var metricInfo))
                    throw new KeyNotFoundException($"Metric '{result.Name}' is not found in MetricsRegistry.");

                var weight = metricInfo.Weight;

                // 🔥 Compute Rescaled Score INLINE (No need to store it!)
                var rescaledScore = metricInfo.ComputeRescaledScore(result.Score); // 👈 Now calling from MetricInfo

                // Apply weight
                var weightedScore = rescaledScore * weight;
                totalWeightedScore += weightedScore;
                maxPossibleScore += 100.0 * weight;

                // Debug Logging
                if (loggingEnabled)
                {
                    logWriter!.WriteLine($"Metric: {result.Name}");
                    logWriter.WriteLine($"  Raw Value: {result.Score:F10}");
                    logWriter.WriteLine($"  Rescaled Score: {rescaledScore:F4}");
                    logWriter.WriteLine($"  Weight: {weight:F4}");
                    logWriter.WriteLine($"  Weighted Contribution: {weightedScore:F4}");
                    logWriter.WriteLine($"  Accumulated Aggregate Score: {totalWeightedScore:F4}");
                    logWriter.WriteLine($"  Accumulated Max Score: {maxPossibleScore:F4}");
                    logWriter.WriteLine();
                }
            }

            var rawAggregate = maxPossibleScore > 0 ? totalWeightedScore / maxPossibleScore * 100.0 : 0.0;

            if (loggingEnabled)
            {
                logWriter!.WriteLine("--- Final Computation ---");
                logWriter.WriteLine($"Raw Aggregate Score: {rawAggregate:F10}");
                logWriter.WriteLine();
            }

            return rawAggregate;
        }
    }

    // 🔥 ScoreChecker: This needs an update to match Mango's behavior
    private double ApplyLogScaling(double rawScore, double maxPossibleScore)
    {
        if (rawScore <= 1) return 0; // Ensure near-zero raw scores stay near zero
        var scaled = Math.Log(rawScore) / Math.Log(maxPossibleScore) * 100;
        return Math.Max(0, Math.Min(scaled, 100)); // Clamp to [0,100]
    }

    #endregion CalculateAggregateScore

}

public class Metric
{
    public string Name { get; set; } = null!;
    public bool Passed { get; set; }
    public double Value { get; set; }
    public double Threshold { get; set; }
    public string Notes { get; set; } = null!;
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