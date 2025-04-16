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

using Mango.Cipher;
using Mango.Utilities;
using System.Security.Cryptography;
using System.Text;

namespace Mango.Analysis
{
    public class CryptoAnalysis
    {
        public class AnalysisResult
        {
            public string Name { get; set; }
            public bool Passed { get; set; }
            public double Score { get; set; }
            public string Notes { get; set; }
        }

        public class MetricInfo
        {
            private Stack<double> _weightStack = new Stack<double>();

            public Func<byte[], byte[], AnalysisResult> Implementation { get; }
            public double Baseline { get; }
            public double Leniency { get; }
            public double Weight { get; set; }
            public bool NeedsInput { get; }
            public bool NeedsAvalanchePayload { get; }
            public bool NeedsKeyDependencyPayload { get; }
            public string Identifier { get; } // Unique identifier for each metric
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
                string identifier = null,
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
                MaxValue = maxValue ?? (baseline + leniency); // Default max value

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
                double threshold = Threshold; // 👈 Use instance property
                double maxValue = MaxValue ?? threshold; // 👈 Prevents null issues

                if (maxValue > threshold)
                {
                    double difference = metricValue - threshold;
                    double range = maxValue - threshold;
                    double ratio = difference / range;
                    double scaledScore = ratio * 100;

                    return Math.Max(0, Math.Min(scaledScore, 100));
                }
                else
                {
                    // 🚨 ScoreChecker Deviation: Properly penalize deviations instead of simple pass/fail.
                    double deviation = Math.Abs(metricValue - threshold);
                    double scaledScore = Math.Max(0, 100 * (1 - (deviation / threshold))); // Penalize deviations
                    return scaledScore;
                }
            }

            public double CalculateNormalizedScore(double metricValue)
            {
                double deviation = Math.Abs(metricValue - Baseline);
                if (UseTwoSidedLeniency)
                {
                    return deviation <= Leniency
                        ? 1.0
                        : 1.0 - (deviation / (MaxValue ?? Baseline));
                }
                else
                {
                    return metricValue >= Threshold
                        ? 1.0
                        : 1.0 - ((Threshold - metricValue) / (MaxValue ?? Baseline));
                }
            }

            public double CalculateStrictScore(double metricValue)
            {
                double deviation = Math.Abs(metricValue - Baseline);
                double score;

                if (UseTwoSidedLeniency)
                {
                    double scalingFactor = MaxValue ?? Baseline;
                    score = Math.Max(0.0, 100.0 * (1.0 - (deviation / scalingFactor)));
                }
                else
                {
                    if (metricValue >= Threshold)
                    {
                        score = 100.0;
                    }
                    else
                    {
                        double scalingFactor = MaxValue ?? Baseline;
                        score = Math.Max(0.0, 100.0 * (1.0 - ((Threshold - metricValue) / scalingFactor)));
                    }
                }

                return score;
            }

#if true
            public double CalculateMetricScore(double metricValue)
            {
                // Log raw metric value
                Console.WriteLine($"[DEBUG] Calculating Score for {Identifier ?? "Unknown Metric"}");
                Console.WriteLine($"  - Raw Metric Value: {metricValue:F10}");
                Console.WriteLine($"  - Baseline: {Baseline:F10}");
                Console.WriteLine($"  - Threshold: {Threshold:F10}");
                Console.WriteLine($"  - MaxValue: {(MaxValue.HasValue ? MaxValue.Value.ToString("F10") : "N/A")}");
                Console.WriteLine($"  - Leniency: {Leniency:F10}");
                Console.WriteLine($"  - UseTwoSidedLeniency: {UseTwoSidedLeniency}");

                double deviation = Math.Abs(metricValue - Baseline);
                double score;

                if (UseTwoSidedLeniency)
                {
                    if (deviation <= Leniency)
                    {
                        score = 100.0;
                    }
                    else
                    {
                        double scalingFactor = MaxValue ?? Baseline;
                        score = Math.Max(0.0, 100.0 * (1.0 - (deviation / scalingFactor)));
                    }
                }
                else
                {
                    if (metricValue >= Threshold)
                    {
                        score = 100.0;
                    }
                    else
                    {
                        double scalingFactor = MaxValue ?? Baseline;
                        score = Math.Max(0.0, 100.0 * (1.0 - ((Threshold - metricValue) / scalingFactor)));
                    }
                }

                // Log computed score
                Console.WriteLine($"  - Computed Score: {score:F4}");
                Console.WriteLine();

                return score;
            }

#else
            public double CalculateMetricScore(double metricValue)
            {
                double deviation = Math.Abs(metricValue - Baseline);
                if (UseTwoSidedLeniency)
                {
                    return deviation <= Leniency
                        ? 100.0
                        : Math.Max(0.0, 100.0 * (1.0 - (deviation / (MaxValue ?? Baseline))));
                }
                else
                {
                    return metricValue >= Threshold
                        ? 100.0
                        : Math.Max(0.0, 100.0 * (1.0 - ((Threshold - metricValue) / (MaxValue ?? Baseline))));
                }
            }
#endif
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

            // Pushes a temporary weight override onto the stack
            public void PushWeight(double newWeight)
            {
                _weightStack.Push(Weight);
                Weight = newWeight;
            }

            // Restores the previous weight value
            public void PopWeight()
            {
                if (_weightStack.Count > 0)
                    Weight = _weightStack.Pop();
                else
                    throw new InvalidOperationException("No weight to pop from the stack.");
            }

            // Resets weight to its original value
            public void ResetWeight()
            {
                if (_weightStack.Count > 0)
                    Weight = _weightStack.First();
            }
        }

        /// <summary>
        /// MetricsRegistry defines the cryptographic metrics used to evaluate the quality of transforms.
        /// Each metric includes its implementation, baseline, leniency, weight, and other attributes.
        /// </summary>
        public Dictionary<string, MetricInfo> MetricsRegistry { get; private set; }

        public CryptoAnalysis()
        {
            MetricsRegistry = new Dictionary<string, MetricInfo>
        {
            {
                "Entropy", new MetricInfo(
                    (input, encrypted) => RunEntropyTest(encrypted),
                    baseline: 7.9523,
                    leniency: 0.0, // Entropy does not use leniency
                    weight: 0.4,
                    needsInput: false,
                    identifier: "Entropy",
                    maxValue: 8.0000)
            },
            {
                "BitVariance", new MetricInfo(
                    (input, encrypted) => RunBitVarianceTest(encrypted),
                    baseline: 0.5003,
                    leniency: 0.002,
                    weight: 0.3,
                    needsInput: false,
                    identifier: "BitVariance",
                    maxValue: 0.5023) { UseTwoSidedLeniency = true }
            },
            {
                "SlidingWindow", new MetricInfo(
                    (input, encrypted) => RunSlidingWindowTest(encrypted),
                    baseline: 0.9027,
                    leniency: 0.005,
                    weight: 0.15,
                    needsInput: false,
                    identifier: "SlidingWindow",
                    maxValue: 1.0000) { UseTwoSidedLeniency = true }
            },
            {
                "FrequencyDistribution", new MetricInfo(
                    (input, encrypted) => RunFrequencyDistributionTest(encrypted),
                    baseline: 0.7426,
                    leniency: 0.010,
                    weight: 0.15,
                    needsInput: false,
                    identifier: "FrequencyDistribution",
                    maxValue: 1.0000) { UseTwoSidedLeniency = true }
            },
            {
                "PeriodicityCheck", new MetricInfo(
                    (input, encrypted) => RunPeriodicityCheck(encrypted),
                    baseline: 1.0000,
                    leniency: 0.000,
                    weight: 0.1,
                    needsInput: false,
                    identifier: "PeriodicityCheck",
                    maxValue: 1.0000)
            },
            {
                "MangosCorrelation", new MetricInfo(
                    RunMangosCorrelation,
                    baseline: 0.0,
                    leniency: 0.0500,
                    weight: 0.25,
                    needsInput: true,
                    identifier: "MangosCorrelation",
                    maxValue: 0.0500) { UseTwoSidedLeniency = true }
            },
            {
                "PositionalMapping", new MetricInfo(
                    RunPositionalMapping,
                    baseline: 0.0,
                    leniency: 0.0500,
                    weight: 0.25,
                    needsInput: true,
                    identifier: "PositionalMapping",
                    maxValue: 0.0500) { UseTwoSidedLeniency = true }
            },
            {
                "AvalancheScore", new MetricInfo(
                    RunAvalancheScore,
                    baseline: 50.0,
                    leniency: 5.0,
                    weight: 0.3,
                    needsInput: false,
                    identifier: "AvalancheScore",
                    needsAvalanchePayload: true,
                    maxValue: 60.0000) { UseTwoSidedLeniency = true }
            },
            {
                "KeyDependency", new MetricInfo(
                    RunKeyDependency,
                    baseline: 50.0,
                    leniency: 5.0,
                    weight: 0.3,
                    needsInput: false,
                    identifier: "KeyDependency",
                    needsKeyDependencyPayload: true,
                    maxValue: 60.0000) { UseTwoSidedLeniency = true }
            }
        };
        }
#if false
#region This version of RunCryptAnalysis logs the full 10 places of a metric's result
        public  List<AnalysisResult> RunCryptAnalysis(byte[] encryptedData, byte[]? avalanchePayload = null, byte[]? keyDependencyPayload = null, byte[]? inputData = null, string logFilePath = null)
        {
            List<AnalysisResult> results = new();
            bool loggingEnabled = !string.IsNullOrEmpty(logFilePath);

            using (StreamWriter logWriter = loggingEnabled ? new StreamWriter(logFilePath, true) : null)
            {
                if (loggingEnabled)
                {
                    logWriter.WriteLine("=== CryptAnalysis Detailed Output ===");
                    logWriter.WriteLine($"Input Data Hash: {Convert.ToHexString(SHA256.Create().ComputeHash(inputData ?? Array.Empty<byte>()))}");
                    logWriter.WriteLine($"Encrypted Data Hash: {Convert.ToHexString(SHA256.Create().ComputeHash(encryptedData))}");

                    if (keyDependencyPayload != null)
                        logWriter.WriteLine($"Key Dependency Payload Hash: {Convert.ToHexString(SHA256.Create().ComputeHash(keyDependencyPayload))}");

                    if (avalanchePayload != null)
                        logWriter.WriteLine($"Avalanche Payload Hash: {Convert.ToHexString(SHA256.Create().ComputeHash(avalanchePayload))}");

                    logWriter.WriteLine();
                }

                foreach (var metric in MetricsRegistry.Values)
                {
                    AnalysisResult result;

                    if (metric.NeedsKeyDependencyPayload && keyDependencyPayload == null)
                    {
                        throw new ArgumentException($"Metric '{metric.Identifier}' requires modified encrypted data, but none was provided.");
                    }
                    else if (metric.NeedsKeyDependencyPayload && keyDependencyPayload != null)
                    {
                        result = metric.Implementation(encryptedData, keyDependencyPayload);
                    }
                    else if (metric.NeedsAvalanchePayload && avalanchePayload == null)
                    {
                        throw new ArgumentException($"Metric '{metric.Identifier}' requires modified encrypted data, but none was provided.");
                    }
                    else if (metric.NeedsAvalanchePayload && avalanchePayload != null)
                    {
                        result = metric.Implementation(encryptedData, avalanchePayload);
                    }
                    else if (metric.NeedsInput && inputData == null)
                    {
                        throw new ArgumentException($"Metric '{metric.Identifier}' requires input data, but none was provided.");
                    }
                    else if (metric.NeedsInput && inputData != null)
                    {
                        result = metric.Implementation(inputData, encryptedData);
                    }
                    else
                    {
                        result = metric.Implementation(null, encryptedData);
                    }

                    // Compute deviation from baseline
                    double deviation = Math.Abs(result.Metric - metric.Baseline);
                    result.Passed = metric.IsMetricPassing(result.Metric);

                    // Define failure criteria in the log
                    double lowerBound = metric.Baseline - metric.Leniency;
                    double upperBound = metric.Baseline + metric.Leniency;

                    result.Notes = result.Passed
                        ? "Metric is within acceptable range."
                        : $"Deviation: {deviation:F10}, Acceptable Range: [{lowerBound:F10}, {upperBound:F10}].";

                    results.Add(result);

                    if (loggingEnabled)
                    {
                        logWriter.WriteLine("----------------------------------------------------");
                        logWriter.WriteLine($"Metric: {result.TestName}");
                        logWriter.WriteLine($"  Computed Metric: {result.Metric:F10}");
                        logWriter.WriteLine($"  Baseline: {metric.Baseline:F10}");
                        logWriter.WriteLine($"  Leniency: ±{metric.Leniency:F10}");
                        logWriter.WriteLine($"  Acceptable Range: [{lowerBound:F10}, {upperBound:F10}]");
                        logWriter.WriteLine($"  Deviation: {deviation:F10}");
                        logWriter.WriteLine($"  Status: {(result.Passed ? "PASS" : "FAIL")}");
                        logWriter.WriteLine();
                    }
                }

                if (loggingEnabled)
                {
                    logWriter.WriteLine("=== End of CryptAnalysis Output ===");
                }
            }

            return results;
        }
        #endregion This version of RunCryptAnalysis logs the full 10 places of a metric's result
#else
        public List<AnalysisResult> RunCryptAnalysis(byte[] encryptedData, byte[]? avalanchePayload = null, byte[]? keyDependencyPayload = null, byte[]? inputData = null, string logFilePath = null)
        {
            List<AnalysisResult> results = new();
            bool loggingEnabled = !string.IsNullOrEmpty(logFilePath);

            using (StreamWriter logWriter = loggingEnabled ? new StreamWriter(logFilePath, true) : null)
            {
                if (loggingEnabled)
                {
                    logWriter.WriteLine("=== CryptAnalysis Detailed Output ===");
                    logWriter.WriteLine($"Input Data Hash: {Convert.ToHexString(SHA256.Create().ComputeHash(inputData ?? Array.Empty<byte>()))}");
                    logWriter.WriteLine($"Encrypted Data Hash: {Convert.ToHexString(SHA256.Create().ComputeHash(encryptedData))}");
                    logWriter.WriteLine();
                }

                foreach (var metric in MetricsRegistry.Values)
                {
                    AnalysisResult result;

                    if (metric.NeedsKeyDependencyPayload && keyDependencyPayload == null)
                    {
                        // Error message for missing modified encrypted data
                        throw new ArgumentException($"Metric '{metric.Identifier}' requires modified encrypted data, but none was provided.");
                    }
                    else if (metric.NeedsKeyDependencyPayload && keyDependencyPayload != null)
                    {
                        // Call implementation with modified encrypted data
                        result = metric.Implementation(encryptedData, keyDependencyPayload);
                    }
                    else if (metric.NeedsAvalanchePayload && avalanchePayload == null)
                    {
                        // Error message for missing modified encrypted data
                        throw new ArgumentException($"Metric '{metric.Identifier}' requires modified encrypted data, but none was provided.");
                    }
                    else if (metric.NeedsAvalanchePayload && avalanchePayload != null)
                    {
                        // Call implementation with modified encrypted data
                        result = metric.Implementation(encryptedData, avalanchePayload);
                    }
                    else if (metric.NeedsInput && inputData == null)
                    {
                        // Error message for missing input data
                        throw new ArgumentException($"Metric '{metric.Identifier}' requires input data, but none was provided.");
                    }
                    else if (metric.NeedsInput && inputData != null)
                    {
                        // Call implementation with input data and encrypted data
                        result = metric.Implementation(inputData, encryptedData);
                    }
                    else
                    {
                        // Fallback to standard implementation with only encrypted data
                        result = metric.Implementation(null, encryptedData);
                    }

                    double deviation = Math.Abs(result.Score - metric.Baseline);
                    result.Passed = metric.IsMetricPassing(result.Score);

                    result.Notes = result.Passed
                        ? "Metric is within acceptable range."
                        : $"Deviation: {deviation:F4}, Acceptable Range: ±{metric.Leniency:F4}.";

                    results.Add(result);

                    if (loggingEnabled)
                    {
                        logWriter.WriteLine($"Metric: {result.Name}");
                        logWriter.WriteLine($"  Computed Metric: {result.Score:F4}");
                        logWriter.WriteLine($"  Baseline: {metric.Baseline:F4}");
                        logWriter.WriteLine($"  Leniency: ±{metric.Leniency:F4}");
                        logWriter.WriteLine($"  Status: {(result.Passed ? "PASS" : "FAIL")}");
                        logWriter.WriteLine();
                    }
                }

                if (loggingEnabled)
                {
                    logWriter.WriteLine("=== End of Output ===");
                }
            }

            return results;
        }
#endif
        #region metric implementations
        public AnalysisResult RunKeyDependency(byte[] encrypted, byte[] modifiedEncrypted)
        {
            double KeyDependency = CalculateAvalancheScore(encrypted, modifiedEncrypted);

            // Define expected behavior for Key Dependency Score
            double baseline = MetricsRegistry["KeyDependency"].Baseline; // Set appropriately, e.g., 50.0
            double leniency = MetricsRegistry["KeyDependency"].Leniency; // Set appropriately, e.g., ±5.0
            bool useTwoSidedLeniency = MetricsRegistry["KeyDependency"].UseTwoSidedLeniency;

            // Evaluate result
            double deviation = Math.Abs(KeyDependency - baseline);
            bool passed = useTwoSidedLeniency
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
            double avalancheScore = CalculateAvalancheScore(encrypted, modifiedEncrypted);

            // Define expected behavior for Avalanche Score
            double baseline = MetricsRegistry["AvalancheScore"].Baseline; // Should be 50.0
            double leniency = MetricsRegistry["AvalancheScore"].Leniency; // Should be ±5.0
            bool useTwoSidedLeniency = MetricsRegistry["AvalancheScore"].UseTwoSidedLeniency;

            // Evaluate result
            double deviation = Math.Abs(avalancheScore - baseline);
            bool passed = useTwoSidedLeniency
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
            double correlation = CalculateMangosCorrelation(inputData, encryptedData);

            // Expected behavior based on correlation
            double expectedThreshold = 0.0; // Default: no correlation expected
            double acceptableRange = 0.05;

            if (correlation == 1.0)
            {
                // Perfect match detected
                expectedThreshold = 1.0;
            }

            // Evaluate result
            double deviation = Math.Abs(correlation - expectedThreshold);
            bool passed = deviation <= acceptableRange;

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
            double mappingScore = CalculatePositionalMapping(inputData, encryptedData);

            // Define expected threshold and acceptable range (static for now)
            double expectedThreshold = 0.0; // Ideal: no positional similarity
            double acceptableRange = 0.05;  // Example tolerance

            // Evaluate result
            double deviation = Math.Abs(mappingScore - expectedThreshold);
            bool passed = deviation <= acceptableRange;

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

            int n = input.Length;
            double totalScore = 0;

            // Iterate through each byte in input and output
            for (int i = 0; i < n; i++)
            {
                totalScore += CalculateScore(input[i], output[i]);
            }

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

            int n = input.Length;

            // Check for identical datasets
            bool areIdentical = true;
            bool areConstantInput = true;
            bool areConstantEncrypted = true;

            double firstInput = input[0];
            double firstEncrypted = encrypted[0];

            // Loop through datasets once
            for (int i = 0; i < n; i++)
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

            for (int i = 0; i < n; i++)
            {
                double x = input[i];
                double y = encrypted[i];

                sumX += x;
                sumY += y;
                sumXY += x * y;
                sumX2 += x * x;
                sumY2 += y * y;
            }

            double numerator = n * sumXY - sumX * sumY;
            double denominator = Math.Sqrt((n * sumX2 - sumX * sumX) * (n * sumY2 - sumY * sumY));

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

            double entropy = 0.0;
            int dataLength = data.Length;

            foreach (var count in frequency.Values)
            {
                double probability = (double)count / dataLength;
                entropy -= probability * Math.Log2(probability);
            }

            return entropy;
        }
        public double CalculateBitVariance(byte[] data)
        {
            int totalBits = data.Length * 8;
            int bitCount = 0;

            foreach (var b in data)
            {
                for (int i = 0; i < 8; i++)
                {
                    if ((b & (1 << i)) != 0)
                        bitCount++;
                }
            }

            double bitProbability = (double)bitCount / totalBits;
            return bitProbability;
        }

        public double CalculateSlidingWindow(byte[] data)
        {
            const int windowSize = 8;
            int[] patternCounts = new int[1 << windowSize];

            for (int i = 0; i <= data.Length * 8 - windowSize; i++)
            {
                int pattern = 0;
                for (int j = 0; j < windowSize; j++)
                {
                    int byteIndex = (i + j) / 8;
                    int bitIndex = (i + j) % 8;

                    if ((data[byteIndex] & (1 << bitIndex)) != 0)
                        pattern |= (1 << j);
                }

                patternCounts[pattern]++;
            }

            double average = patternCounts.Average();
            double standardDeviation = Math.Sqrt(patternCounts.Average(v => Math.Pow(v - average, 2)));

            return 1.0 - (standardDeviation / average);
        }

        public double CalculateFrequencyDistribution(byte[] data)
        {
            int[] frequencies = new int[256];
            foreach (var b in data)
            {
                frequencies[b]++;
            }

            double average = frequencies.Average();
            double standardDeviation = Math.Sqrt(frequencies.Average(v => Math.Pow(v - average, 2)));

            return 1.0 - (standardDeviation / average);
        }

        public double CalculatePeriodicity(byte[] data)
        {
            int maxPeriod = Math.Min(256, data.Length / 2);
            int periodicCount = 0;

            for (int period = 1; period <= maxPeriod; period++)
            {
                bool periodic = true;
                for (int i = 0; i < data.Length - period; i++)
                {
                    if (data[i] != data[i + period])
                    {
                        periodic = false;
                        break;
                    }
                }

                if (periodic)
                    periodicCount++;
            }

            return 1.0 - ((double)periodicCount / maxPeriod);
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

            int totalBits = encrypt1.Length * 8; // Total number of bits to compare
            int differingBits = 0;

            for (int i = 0; i < encrypt1.Length; i++)
            {
                byte xorResult = (byte)(encrypt1[i] ^ encrypt2[i]); // XOR to find differing bits
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
            int count = 0;
            while (value != 0)
            {
                count += value & 1; // Increment count if the least significant bit is 1
                value >>= 1;        // Shift right to check the next bit
            }
            return count;
        }
        private double CalculateScore(byte inputByte, byte outputByte)
        {
            // Direct penalty for perfect matches
            if (inputByte == outputByte)
            {
                return 1.0; // Maximum penalty for perfect matches
            }

            // Count ON bits in both bytes
            int inputOnBits = CountOnBits(inputByte);
            int outputOnBits = CountOnBits(outputByte);

            // If ON bit counts differ, assign minimal penalty (or pass entirely)
            if (inputOnBits != outputOnBits)
            {
                return 0; // Pass directly for ON bit count mismatch
            }

            // Calculate the number of moves required to match ON bits
            return CalculateBitMoveCost(inputByte, outputByte);
        }
        private int CountOnBits(byte b)
        {
            int count = 0;
            while (b > 0)
            {
                count += b & 1;
                b >>= 1;
            }
            return count;
        }
        private double CalculateBitMoveCost(byte inputByte, byte outputByte)
        {
            int[] inputBitPositions = GetBitPositions(inputByte);
            int[] outputBitPositions = GetBitPositions(outputByte);

            // Calculate the "move cost" between input and output bit positions
            int moveCost = 0;
            for (int i = 0; i < inputBitPositions.Length; i++)
            {
                moveCost += Math.Abs(inputBitPositions[i] - outputBitPositions[i]);
            }

            // Normalize move cost by maximum possible moves for 8 bits
            return moveCost / 28.0; // Maximum moves for 8 bits: (0+1+2+...+7) = 28
        }
        private int[] GetBitPositions(byte b)
        {
            var positions = new List<int>();
            for (int i = 0; i < 8; i++)
            {
                if ((b & (1 << i)) != 0)
                {
                    positions.Add(i);
                }
            }
            return positions.ToArray();
        }
        #endregion utilities

        #region Reporting and Logging
        public void Initialize()
        {
            // Clear all state related to contenders and other temporary analysis data
            contenders.Clear();
        }

        public List<string> CryptAnalysisReport(
            CryptoLib cryptoLib,
            List<AnalysisResult> results,
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
                string sequenceNames = string.Join(" -> ", sequence.Select(id =>
                    cryptoLib.TransformRegistry.TryGetValue(id, out var transform) ? transform.Name : $"Unknown ({id})"));
                output.Add($"<Green>Sequence:</Green> {sequenceNames}");
            }

            // Display detailed metrics
            foreach (var result in results)
            {
                // Determine weight-based color for the metric name
                var metricInfo = MetricsRegistry[result.Name];
                string weightColor = metricInfo.Weight >= 0.3 ? "Red" :
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


        private List<(List<byte> Sequence, double AggregateScore, List<AnalysisResult> Metrics)> contenders = new();
        public List<(List<byte> Sequence, double AggregateScore, List<AnalysisResult> Metrics)> Contenders
        {
            get => contenders;
        }
        public void CryptAnalysisRecordBest(ExecutionEnvironment localEnv, List<AnalysisResult> analysisResults, List<byte> currentSequence)
        {
            int passCount = analysisResults.Count(r => r.Passed);

            // Calculate aggregate score
            double aggregateScore = CalculateAggregateScore(analysisResults, localEnv.Globals.UseMetricScoring);

            // Add sequence to contenders if pass count exceeds threshold
            if (passCount >= localEnv.Globals.PassCount) // Example threshold
            {
                contenders.Add((new List<byte>(currentSequence), aggregateScore, analysisResults));
            }

            // Perform trim+sort. Eg, every 1000*4 additions
            if (contenders.Count > localEnv.Globals.DesiredContenders * 4)
            {
                contenders = contenders
                    .OrderByDescending(c => c.AggregateScore)
                    .Take(localEnv.Globals.DesiredContenders) // Trim to desired count
                    .ToList();
            }
        }

        public void TrimContenders(int count = 1000)
        {
            contenders = contenders
                .OrderByDescending(c => c.AggregateScore)
                .Take(count)
                .ToList();
        }

        /// <summary>
        /// Verifies the consistency of analysis results for the top 'count' contenders.
        /// Ensures that recalculated metrics and aggregate scores match the stored values.
        /// </summary>
        /// <param name="cryptoLib">The cryptographic library instance.</param>
        /// <param name="input">The original input data.</param>
        /// <param name="count">The number of top contenders to verify.</param>
        /// <returns>True if all results are consistent; false otherwise.</returns>
        public bool VerifyAnalysisResults(ExecutionEnvironment localEnv, int count)
        {
            // Sort and take the top 'count' contenders
            var sortedContenders = contenders
                .OrderByDescending(c => c.AggregateScore)
                .Take(count)
                .ToList();

            // Iterate through the selected contenders
            foreach (var (sequence, originalAggregateScore, originalMetrics) in sortedContenders)
            {
                // Re-encrypt the input data
                var encrypted = localEnv.Crypto.Encrypt(sequence.ToArray(), localEnv.Globals.Input);
                var encryptedPayload = localEnv.Crypto.GetPayloadOnly(encrypted);

                // Modify a copy of input for Avalanche test and Key Dependency test
                var (MangoAvalanchePayload, _, MangoKeyDependencyPayload, _) =
                    UtilityHelpers.ProcessAvalancheAndKeyDependency(
                localEnv: localEnv,
                password: GlobalsInstance.Password,
                sequence: sequence.ToList());

                // Recalculate metrics
                var recalculatedMetrics = localEnv.CryptoAnalysis.RunCryptAnalysis(
                    encryptedData: encryptedPayload,
                    avalanchePayload: MangoAvalanchePayload,
                    keyDependencyPayload: MangoKeyDependencyPayload,
                    inputData: localEnv.Globals.Input);

                // Recalculate aggregate score
                var recalculatedAggregateScore = localEnv.CryptoAnalysis.CalculateAggregateScore(recalculatedMetrics, localEnv.Globals.UseMetricScoring);

                // Compare aggregate scores
                if (Math.Abs(originalAggregateScore - recalculatedAggregateScore) > 0.0001)
                {
                    Console.WriteLine($"Aggregate score mismatch for sequence: {new SequenceHelper(localEnv.Crypto).FormattedSequence(sequence.ToArray(), SequenceFormat.ID | SequenceFormat.TRounds)}");
                    Console.WriteLine($"Original: {originalAggregateScore:F4}, Recalculated: {recalculatedAggregateScore:F4}");
                    return false; // Aggregate score mismatch
                }

                // Compare individual metrics
                bool metricsMismatch = originalMetrics.Zip(recalculatedMetrics, (orig, recalc) =>
                    orig.Name != recalc.Name || // Ensure the test names match
                    orig.Passed != recalc.Passed ||    // Check if pass/fail status matches
                    Math.Abs(orig.Score - recalc.Score) > 0.0001 // Compare metric values
                ).Any(mismatch => mismatch);

                if (metricsMismatch)
                {
                    Console.WriteLine($"Metric mismatch detected for sequence: {new SequenceHelper(localEnv.Crypto).FormattedSequence(sequence.ToArray(), SequenceFormat.ID | SequenceFormat.TRounds)}");
                    return false; // Metrics mismatch detected
                }
            }

            return true; // All checks passed
        }

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

        // Core scoring method
        public double ComputePracticalScore(List<AnalysisResult> results, bool verbose = false)
        {
            double totalWeightedScore = 0;
            double totalWeight = 0;

            foreach (var result in results)
            {
                if (!MetricsRegistry.TryGetValue(result.Name, out var metricInfo))
                    continue;

                double weight = metricInfo.Weight;
                double practicalScore = GetPracticalScore(result, metricInfo, verbose);

                totalWeightedScore += practicalScore * weight / 100.0;
                totalWeight += weight;

                if (verbose)
                {
                    Console.WriteLine($"🔍 {result.Name,-22} | Band Score: {practicalScore,5:0.0} | Weight: {weight,4:0.00} | Weighted: {(practicalScore * weight / 100.0),5:0.00}");
                }
            }

            if (totalWeight == 0)
                return 0;

            double final = totalWeightedScore / totalWeight * 100.0;

            if (verbose)
            {
                Console.WriteLine($"📊 Final Weighted Practical Score: {final:F4}");
            }

            return final;
        }
        // Scoring per metric, based on proximity to threshold
        private double GetPracticalScore(AnalysisResult result, MetricInfo metricInfo, bool verbose = false)
        {
            double actual = result.Score;
            double threshold = metricInfo.Threshold;
            double delta = Math.Abs(actual - threshold);
            double score;

            if (result.Passed)
            {
                if (delta < 0.01 * threshold) score = (double)PracticalScoreBand.Perfect;
                else if (delta < 0.03 * threshold) score = (double)PracticalScoreBand.HighMarginPass;
                else score = (double)PracticalScoreBand.BarelyPass;
            }
            else
            {
                if (delta < 0.03 * threshold) score = (double)PracticalScoreBand.NearMiss;
                else if (delta < 0.20 * threshold) score = (double)PracticalScoreBand.Fail;
                else score = (double)PracticalScoreBand.Catastrophic;
            }

            if (verbose)
            {
                Console.WriteLine($"   ↳ Metric: {actual:0.000000}, Threshold: {threshold:0.000000}, Δ: {delta:0.000000}, Pass: {result.Passed}, Assigned Band: {score}");
            }

            return score;
        }

        #endregion GetPracticalScore

        #region CalculateAggregateScore
        // ✅ If UseMetricScoring == true:
        // Applies traditional metric scoring: rescaled scores are weighted and logarithmically scaled.
        // Metrics that exceed their thresholds are capped to avoid over-contributing.
        // ✅ If UseMetricScoring == false (the new default):
        // Uses weighted practical scoring: banded scores (Perfect, Pass, NearMiss, Fail) reflect cryptographic robustness more realistically.
        // Prioritizes metrics based on importance, not raw scale, providing clearer separation of weak vs strong sequences.
        public double CalculateAggregateScore(List<AnalysisResult> results, bool useMetricScoring,
            string logFilePath = null)
        {
            if (useMetricScoring)
            {
                double rawScore = ComputeMetricScore(results, logFilePath);
                return ApplyLogScaling(rawScore, 100); // Apply logarithmic scaling for better score distribution
            }
            return ComputePracticalScore(results, verbose: false);
        }

        private double ComputeMetricScore(List<AnalysisResult> results, string logFilePath)
        {
            double totalWeightedScore = 0;
            double maxPossibleScore = 0;
            bool loggingEnabled = !string.IsNullOrEmpty(logFilePath);

            using (StreamWriter logWriter = loggingEnabled ? new StreamWriter(logFilePath, true) : null)
            {
                if (loggingEnabled)
                {
                    logWriter.WriteLine("=== AggregateScore Debugging ===");
                    logWriter.WriteLine();
                }

                foreach (var result in results)
                {
                    if (!MetricsRegistry.TryGetValue(result.Name, out var metricInfo))
                    {
                        throw new KeyNotFoundException($"Metric '{result.Name}' is not found in MetricsRegistry.");
                    }

                    double weight = metricInfo.Weight;

                    // 🔥 Compute Rescaled Score INLINE (No need to store it!)
                    double rescaledScore = metricInfo.ComputeRescaledScore(result.Score); // 👈 Now calling from MetricInfo

                    // Apply weight
                    double weightedScore = rescaledScore * weight;
                    totalWeightedScore += weightedScore;
                    maxPossibleScore += 100.0 * weight;

                    // Debug Logging
                    if (loggingEnabled)
                    {
                        logWriter.WriteLine($"Metric: {result.Name}");
                        logWriter.WriteLine($"  Raw Value: {result.Score:F10}");
                        logWriter.WriteLine($"  Rescaled Score: {rescaledScore:F4}");
                        logWriter.WriteLine($"  Weight: {weight:F4}");
                        logWriter.WriteLine($"  Weighted Contribution: {weightedScore:F4}");
                        logWriter.WriteLine($"  Accumulated Aggregate Score: {totalWeightedScore:F4}");
                        logWriter.WriteLine($"  Accumulated Max Score: {maxPossibleScore:F4}");
                        logWriter.WriteLine();
                    }
                }

                double rawAggregate = maxPossibleScore > 0 ? (totalWeightedScore / maxPossibleScore) * 100.0 : 0.0;

                if (loggingEnabled)
                {
                    logWriter.WriteLine("--- Final Computation ---");
                    logWriter.WriteLine($"Raw Aggregate Score: {rawAggregate:F10}");
                    logWriter.WriteLine();
                }

                return rawAggregate;
            }
        }

        // 🔥 ScoreChecker: This needs an update to match Mango's behavior
        private double ApplyLogScaling(double rawScore, double maxPossibleScore)
        {
            if (rawScore <= 1) return 0;  // Ensure near-zero raw scores stay near zero
            double scaled = (Math.Log(rawScore) / Math.Log(maxPossibleScore)) * 100;
            return Math.Max(0, Math.Min(scaled, 100)); // Clamp to [0,100]
        }
        #endregion CalculateAggregateScore


        #region AnalyzeContendersHandler
#if false
        public  (string, ConsoleColor) AnalyzeContendersHandler()
        {
            string logFileName = "ContenderLog.txt";
            var result = AnalyzeContenders(new string[] { logFileName });

            return result;
        }
        public  (string, ConsoleColor) AnalyzeContenders(string[] args)
        {
            if (args.Length == 0)
            {
                return ("Usage: analyze <path_to_contender_log>", ConsoleColor.Yellow);
            }

            string contenderLogPath = args[0];

            if (!File.Exists(contenderLogPath))
            {
                return ($"Contender log file not found at {contenderLogPath}.", ConsoleColor.Red);
            }

            try
            {
                var contenders = new List<Contender>();

                // Read and parse the file
                var lines = File.ReadAllLines(contenderLogPath);
                ParseContenders(lines, contenders);

                // Analyze contenders
                var result = AnalyzeContenders(contenders);
                return (result, ConsoleColor.Green);
            }
            catch (Exception ex)
            {
                return ($"Error analyzing contenders: {ex.Message}", ConsoleColor.Red);
            }
        }
        private  string AnalyzeContenders(List<Contender> contenders)
        {
            var summary = new StringBuilder();
            summary.AppendLine("** Contender Analysis **");

            int totalContenders = contenders.Count;
            double averagePassCount = contenders.Average(c => c.PassCount);

            summary.AppendLine($"Total Contenders: {totalContenders}");
            summary.AppendLine($"Average Pass Count: {averagePassCount:F2}");

            // Find the best contender
            var bestContender = contenders.OrderByDescending(c => c.AggregateScore).First();
            summary.AppendLine($"Best Contender: {bestContender.Sequence} with Score {bestContender.AggregateScore:F4}");
            summary.AppendLine($"Pass Count: {bestContender.PassCount}");

            // Metric frequency analysis
            var metricFrequency = new Dictionary<string, int>();
            foreach (var contender in contenders)
            {
                foreach (var metric in contender.Metrics.Where(m => m.Passed))
                {
                    if (!metricFrequency.ContainsKey(metric.Name))
                    {
                        metricFrequency[metric.Name] = 0;
                    }
                    metricFrequency[metric.Name]++;
                }
            }

            summary.AppendLine("\nMetric Frequencies:");
            foreach (var (metric, count) in metricFrequency.OrderByDescending(kvp => kvp.Value))
            {
                summary.AppendLine($"- {metric}: {count} contenders passed");
            }

            return summary.ToString();
        }

        private  void ParseContenders(string[] lines, List<Contender> contenders)
        {
            Contender current = null;

            foreach (string line in lines)
            {
                if (line.StartsWith("Contender #"))
                {
                    if (current != null)
                    {
                        contenders.Add(current);
                    }
                    current = new Contender();
                }
                else if (line.StartsWith("Sequence:"))
                {
                    current.Sequence = line.Substring("Sequence:".Length).Trim();
                }
                else if (line.StartsWith("Aggregate Score:"))
                {
                    current.AggregateScore = double.Parse(line.Split(':')[1].Trim());
                }
                else if (line.StartsWith("Pass Count:"))
                {
                    current.PassCount = int.Parse(line.Split('/')[0].Split(':')[1].Trim());
                }
                else if (line.StartsWith("- "))
                {
                    current.Metrics.Add(ParseMetric(line));
                }
            }

            if (current != null)
            {
                contenders.Add(current);
            }
        }

        private  Metric ParseMetric(string line)
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

            if (notesLineMatch.Success)
            {
                metric.Notes = notesLineMatch.Groups[1].Value;
            }

            return metric;
        }
#endif
        #endregion AnalyzeContendersHandler

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
        const bool LongForm = true;

        public List<string> BuildLog(ExecutionEnvironment localEnv, int maxContenders = 10)
        {
            TrimContenders(localEnv.Globals.DesiredContenders);

            List<string> logOutput = new();

            // 🔹 Generate standardized header
            logOutput.AddRange(UtilityHelpers.GenerateHeader(localEnv, title: "** Analysis Summary **", options: UtilityHelpers.HeaderOptions.AllExecution));

            int contenderNumber = 1;

            foreach (var (sequence, aggregateScore, metrics) in contenders
                         .OrderByDescending(c => c.AggregateScore)
                         .Take(maxContenders)) // ✅ Limit to top 10 contenders
            {
                int passCount = metrics.Count(result => result.Passed);

                logOutput.Add($"<Yellow>Contender #{contenderNumber++}</Yellow>");
                logOutput.Add($"<Gray>Sequence:</Gray> <Green>{string.Join(" -> ", sequence.Select(id => localEnv.Crypto.TransformRegistry[id].Name))}</Green>");

                logOutput.Add(LongForm
                    ? $"<Gray>Aggregate Score:</Gray> <Green>{aggregateScore:F10}</Green>"
                    : $"<Gray>Aggregate Score:</Gray> <Green>{aggregateScore:F4}</Green>");

                logOutput.Add($"<Gray>Pass Count:</Gray> <Green>{passCount} / {metrics.Count}</Green>");
                logOutput.Add($"<Cyan>Scores:</Cyan>");

                foreach (var result in metrics)
                {
                    string thresholdInfo = MetricsRegistry.TryGetValue(result.Name, out var metricInfo)
                        ? $"Threshold: {metricInfo.Threshold:F4}"
                        : "Threshold info unavailable";

                    string passFailColor = result.Passed ? "Green" : "Red";
                    logOutput.Add($"- <{passFailColor}>{result.Name}: {(result.Passed ? "PASS" : "FAIL")}</{passFailColor}>");

                    logOutput.Add(LongForm
                        ? $"  Metric: <Yellow>{result.Score:F10}</Yellow>, {thresholdInfo}"
                        : $"  Metric: <Yellow>{result.Score:F4}</Yellow>, {thresholdInfo}");

                    if (!string.IsNullOrEmpty(result.Notes))
                    {
                        logOutput.Add($"  <Gray>Notes:</Gray> {result.Notes}");
                    }
                }

                logOutput.Add(""); // Blank line between contenders
            }

            return logOutput;
        }
#if DEBUG
        private static bool _fileLocking = false;
#else
        private static bool _fileLocking = true;
#endif

        public void LogToFile(ExecutionEnvironment localEnv, string logFileName, int maxContenders = 0)
        {
            if (File.Exists(logFileName))
            {
                File.SetAttributes(logFileName, FileAttributes.Normal); // 🔓 Force unlock
            }

            try
            {
                using (var writer = new StreamWriter(logFileName))
                {
                    foreach (string line in BuildLog(localEnv, maxContenders))
                    {
                        writer.WriteLine(ColorConsole.RemoveColorTags(line)); // ✅ Strips color tags for file output
                    }
                }
            }
            finally
            {
                if (_fileLocking && File.Exists(logFileName))
                {
                    File.SetAttributes(logFileName, FileAttributes.ReadOnly); // 🔒 Re-lock after write
                }
            }
        }


        public bool LogToScreen(ExecutionEnvironment localEnv, InputType inputType, int maxContenders = 10)
        {
            Console.Clear();

            // Print the log to the screen with color
            foreach (string line in BuildLog(localEnv, maxContenders))
            {
                ColorConsole.WriteLine(line); // ✅ Keeps colors for screen output
            }

            return true;
        }


        #endregion Reporting and Logging
    }

    public class Metric
    {
        public string Name { get; set; }
        public bool Passed { get; set; }
        public double Value { get; set; }
        public double Threshold { get; set; }
        public string Notes { get; set; }
    }

    public class Contender
    {
        public string Sequence { get; set; }
        public double AggregateScore { get; set; }
        public int PassCount { get; set; }
        public List<Metric> Metrics { get; set; } = new List<Metric>();

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
            if (Metrics == null || Metrics.Count == 0)
            {
                return "No metrics available.";
            }

            var summary = new StringBuilder();
            foreach (var metric in Metrics)
            {
                summary.AppendLine($"{metric.Name}: Value={metric.Value:F4}, Threshold={metric.Threshold:F4}, Passed={metric.Passed}, Notes={metric.Notes ?? "None"}");
            }

            return summary.ToString();
        }

    }
}