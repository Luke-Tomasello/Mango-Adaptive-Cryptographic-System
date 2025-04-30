/*
 * InputProfiler Module
 * =============================================
 * Project: Mango
 * Purpose: Performs intelligent classification of input data into types such as
 *          Natural, Random, Sequence, or Combined using Mango's high-speed
 *          Multi-Sample Model (MSM) and classic entropy analysis techniques.
 *
 *          This module supports: 
 *            • MSM Mode: Fast heuristic analysis using strategic sampling and FSM
 *            • Classic Mode: Full-scan entropy and periodicity profiling (fallback)
 *            • RLE, entropy, uniqueness, periodicity, and alpha heuristics
 *            • Sequence detection via stride-aware delta matching
 *            • Known file type instant detection (PDF, ZIP, EXE, etc.)
 *            • Automatic selection of best cryptographic profile per input
 *
 *          Powers Mango's adaptive encryption by selecting the correct
 *          InputProfile, enabling optimized transform sequences for each input type.
 *
 * Author: [Luke Tomasello, luke@tomasello.com]
 * Created: November 2024
 * License: [MIT]
 * =============================================
 */

using System.Diagnostics;

namespace Mango.Adaptive;

public record InputProfile(
    string Name, // e.g., "Combined", "Natural", etc. — Workbench-friendly label
    (byte ID, byte TR)[] Sequence, // Transform sequence with rounds baked in
    int GlobalRounds // Required by core + Workbench for configuration
);

public class InputProfiler
{
    private static readonly Dictionary<string, InputProfile> BestProfiles = new()
    {
        // 🔐 Best Profile: Combined
        // -------------------------
        // ✅ Cryptographic Mode: GR:6, TRs: specified per transform
        // ✅ Derived from Munge(A)(6) L5 winner
        // ✅ Aggregate Score: 90.00 | Pass Count: 9/9
        // ✅ AES-class performance across all metrics
        //
        // Sequence:
        //   ButterflyTx(ID:8)(TR:3)
        // → SubBytesXorMaskInvTx(ID:10)(TR:1)
        // → ButterflyWithRotationFwdTx(ID:31)(TR:1)
        // → SubBytesXorMaskFwdTx(ID:9)(TR:1)
        // → ButterflyWithRotationFwdTx(ID:31)(TR:1)
        // → | (GR:6)
        //
        // 🔥 This is the baked-in god-sequence for Combined data.
        //    Selected for superior cryptographic metric shape under weighted analysis.
        {
            "Combined", new InputProfile("Combined", new (byte, byte)[]
            {
                (8, 3), // ButterflyTx
                (10, 1), // SubBytesXorMaskInvTx
                (31, 1), // ButterflyWithRotationFwdTx
                (9, 1), // SubBytesXorMaskFwdTx
                (31, 1) // ButterflyWithRotationFwdTx (again)
            }, 6)
        },

        // 🧠 Best Profile: Natural
        // -------------------------
        // ✅ Cryptographic Mode: GR:3, TRs: all 1s
        // ✅ Derived from Munge(A)(9) L5 winner
        // ✅ Aggregate Score: 91.43 | Pass Count: 9/9
        // ✅ AES-class performance across all metrics
        //
        // Sequence:
        //   ButterflyWithRotationFwdTx(ID:31)(TR:1)
        // → ButterflyWithPairsInvTx(ID:30)(TR:1)
        // → ChunkedFbTx(ID:40)(TR:1)
        // → BitFlipButterflyInvTx(ID:34)(TR:1)
        // → ButterflyWithPairsFwdTx(ID:29)(TR:1)
        // → | (GR:3)
        //
        // 🔥 Tuned for structure-rich Natural data.
        //    Balances bit symmetry, rotation, and inverse feedback.
        {
            "Natural", new InputProfile("Natural", new (byte, byte)[]
            {
                (31, 1), // ButterflyWithRotationFwdTx
                (30, 1), // ButterflyWithPairsInvTx
                (40, 1), // ChunkedFbTx
                (34, 1), // BitFlipButterflyInvTx
                (29, 1) // ButterflyWithPairsFwdTx
            }, 3)
        },

        // 🧠 Best Profile: Sequence
        // --------------------------
        // ✅ Cryptographic Mode: GR:5, TRs: all 1s
        // ✅ Derived from Munge(A)(9) L4 winner
        // ✅ Aggregate Score: 87.14 | Pass Count: 9/9
        // ✅ AES-class performance across all metrics
        //
        // Sequence:
        //   ShuffleNibblesInvTx(ID:19)(TR:1)
        // → ChunkedFbTx(ID:40)(TR:1)
        // → ShuffleNibblesFwdTx(ID:18)(TR:1)
        // → ButterflyWithPairsInvTx(ID:30)(TR:1)
        // → | (GR:5)
        //
        // 🔥 Specially crafted for structured, patterned input.
        //    Maximizes disruption of sequential predictability.
        {
            "Sequence", new InputProfile("Sequence", new (byte, byte)[]
            {
                (19, 1), // ShuffleNibblesInvTx
                (40, 1), // ChunkedFbTx
                (18, 1), // ShuffleNibblesFwdTx
                (30, 1) // ButterflyWithPairsInvTx
            }, 5)
        },


        // 🎲 Best Profile: Random
        // ------------------------
        // ✅ Cryptographic Mode: GR:3, TRs: all 1s
        // ✅ Derived from Munge(A)(6) L5 winner
        // ✅ Aggregate Score: 90.00 | Pass Count: 9/9
        //
        // Sequence:
        //   ButterflyTx(ID:8)(TR:1)
        // → NibbleSwapShuffleFwdTx(ID:13)(TR:1)
        // → NibbleSwapShuffleFwdTx(ID:13)(TR:1)
        // → BitFlipButterflyFwdTx(ID:33)(TR:1)
        // → ChunkedFbTx(ID:40)(TR:1)
        // → | (GR:3)
        //
        // 🔥 Optimized for high-entropy, structureless input.
        //    Deep nonlinear diffusion with symmetry disruption.
        {
            "Random", new InputProfile("Random", new (byte, byte)[]
            {
                (8, 1), // ButterflyTx
                (13, 1), // NibbleSwapShuffleFwdTx
                (13, 1), // NibbleSwapShuffleFwdTx
                (33, 1), // BitFlipButterflyFwdTx
                (40, 1) // ChunkedFbTx
            }, 3)
        }
    };

    public static InputProfile GetInputProfile(byte[] input)
    {
        var classification = ClassificationWorker(input);

        // 🔹 Normalize classification string to match what the Workbench expects
        classification = classification switch
        {
            "Random/Encrypted" => "Random",
            "Natural" => "Natural",
            "Sequence" => "Sequence",
            "Combined" => "Combined",
            "Media" => "Combined", // ✅ Media formats handled as "Combined"
            _ => "Combined" // ✅ Default fallback
        };

        if (!BestProfiles.TryGetValue(classification, out var profile))
            throw new InvalidOperationException($"No best profile defined for classification: {classification}");

        return profile;
    }

    private static string ClassificationWorker(byte[] data, bool useSampleMode = true)
    {
        const int iterations = 1;
        const bool verbose = false;

        //Console.WriteLine($"\nAnalyzing: {filePath} ({data.Length} bytes)");
        //Console.WriteLine($"Running {iterations} iterations for benchmarking...\n");

        var stopwatch = new Stopwatch();
        Dictionary<string, int> classificationCounts = new();
        string classification = null!;

        for (var i = 0; i < iterations; i++)
        {
            stopwatch.Restart();

            double avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow;
            Dictionary<int, (double, double, double, double, double, double, double)>? windowResults = null;

            if (useSampleMode)
                (classification, avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow,
                    windowResults) = AnalyzeDataMSM(data, i, verbose);
            else
                (classification, avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow, _) =
                    AnalyzeDataClassic(data, i);

            stopwatch.Stop();

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
    private static double ComputeEntropy(byte[] data)
    {
        var counts = new int[256];
        foreach (var b in data) counts[b]++;
        double entropy = 0;
        foreach (var count in counts)
        {
            if (count == 0) continue;
            var probability = count / (double)data.Length;
            entropy -= probability * Math.Log2(probability);
        }

        return entropy;
    }

    private static double ComputeUniqueness(byte[] data)
    {
        return data.Distinct().Count() / (double)data.Length;
    }

    private static double ComputePeriodicity(byte[] data)
    {
        var periodicityCount = 0;
        for (var i = 0; i < data.Length - 1; i++)
            if (data[i] == data[i + 1])
                periodicityCount++;
        return periodicityCount / (double)data.Length;
    }

    private static double ComputeByteDeviation(byte[] data)
    {
        var counts = new int[256];
        foreach (var b in data) counts[b]++;
        var avg = counts.Average();
        var stddev = Math.Sqrt(counts.Average(x => Math.Pow(x - avg, 2)));
        return stddev / avg;
    }

    private static double ComputeSlidingWindowSimilarity(byte[] data)
    {
        int matchCount = 0, totalCount = 0;
        for (var i = 0; i < data.Length - 8; i += 8)
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
        var stride = (window[1] - window[0] + 256) % 256;

        // Stride of 0 is NOT a sequence (all bytes the same).
        if (stride == 0)
            return false;

        const int strideTolerance = 2; // Allow stride variations up to ±2

        // Check for consistent stride across the entire window.
        for (var i = 2; i < window.Length; i++)
        {
            var currentStride = (window[i] - window[i - 1] + 256) % 256;
            if (Math.Abs(currentStride - stride) >
                strideTolerance) return false; // Inconsistent stride beyond allowed tolerance
        }

        return true; // Consistent stride found within tolerance
    }

    private static double ComputePercentAlphaAndWhite(byte[] data)
    {
        var count = data.Count(b => (b >= 'a' && b <= 'z') || b == ' ');
        return count / (double)data.Length;
    }

    private static double ComputeRLECompressionRatio(byte[] data)
    {
        if (data.Length == 0) return 1.0; // Avoid division by zero

        List<(byte value, int count)> rleEncoded = new();
        var lastByte = data[0];
        var count = 1;

        for (var i = 1; i < data.Length; i++)
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

        rleEncoded.Add((lastByte, count)); // Final sequence

        double compressedSize = rleEncoded.Count * 2; // Each entry = (byte, count)
        return compressedSize / data.Length; // RLE Compression Ratio
    }

    private static (string classification, double randomScore, double naturalScore) Score(double avgEntropy,
        double avgUniqueness, double avgByteDeviation, double avgPeriodicity, double avgSlidingWindow)
    {
        double randomScore = 0, naturalScore = 0;

        // Entropy Contribution (Boost Random if >7.0, Override Natural if >7.2)
        randomScore += Math.Min(1.5, (avgEntropy - 7.0) / 0.4); // Boosts when >7.0, caps at 1.5
        naturalScore += Math.Max(0.0, (6.5 - avgEntropy) / 0.5); // Penalizes if entropy <6.5

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
        var classification = randomScore >= 0.8 ? "Random/Encrypted" :
            naturalScore >= 0.8 ? "Natural" :
            "Combined";

        return (classification, randomScore, naturalScore);
    }

    private static (string classification, double avgEntropy, double avgUniqueness, double avgByteDeviation, double
        avgPeriodicity, double avgSlidingWindow, Dictionary<int, (double, double, double, double, double)>?
        windowResults) AnalyzeDataClassic(byte[] data, int iteration)
    {
        const int sampleSize = 4096;
        var random = new Random();
        List<byte[]> samples = new()
        {
            data!.Take(Math.Min(sampleSize, data!.Length)).ToArray(), // Start
            data.Skip(Math.Max(0, data.Length / 2 - sampleSize / 2)).Take(sampleSize).ToArray(), // Middle
            data.Skip(Math.Max(0, data.Length - sampleSize)).Take(sampleSize).ToArray(), // End
            data.OrderBy(_ => random.Next()).Take(sampleSize).ToArray() // Random bytes
        };

        var avgEntropy = samples.Average(ComputeEntropy);
        var avgUniqueness = samples.Average(ComputeUniqueness);
        var avgPeriodicity = samples.Average(ComputePeriodicity);
        var avgByteDeviation = samples.Average(ComputeByteDeviation);
        var avgSlidingWindow = samples.Average(ComputeSlidingWindowSimilarity);

        var (classification, _, _) =
            Score(avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow);

        return (classification, avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow, null);
    }

    #region AnalyzeDataMSM

    private enum State
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

    private static (string classification, double avgEntropy, double avgUniqueness, double avgByteDeviation, double
        avgPeriodicity, double avgSlidingWindow,
        Dictionary<int, (double, double, double, double, double, double, double)>? windowResults) AnalyzeDataMSM(
            byte[] data, int iteration, bool verbose)
    {
        var dataSize = data!.Length;
        var windowSize = Math.Min(1024, dataSize); // If file is smaller than default, adjust window size
        var stepSize = 512;
        Dictionary<int, (double, double, double, double, double, double, double)> windowResults = new();

        // === Integration Before FSM ===
        var fileType = KnownFileType(data);
        if (fileType != "Unknown")
        {
            var classification = "Other"; // Default for structured file types

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
        for (var i = 1; i <= 2; i++)
        {
            var nextStart = i * windowSize;
            var nextEnd = dataSize - (i + 1) * windowSize;
            if (nextStart + windowSize <= dataSize) sampleOffsets.Add(nextStart);
            if (nextEnd >= 0) sampleOffsets.Add(nextEnd);
        }

        Dictionary<string, int> classificationStreak = new();
        int sequenceWindows = 0, randomWindows = 0, naturalWindows = 0, combinedWindows = 0;

        for (var start = 0; start + windowSize <= data.Length; start += stepSize)
        {
            var window = data.Skip(start).Take(windowSize).ToArray();


            double alphaWhite = 0.0, entropy = 0.0, rleRatio = 1.0;
            double periodicity = 0.0, uniqueness = 0.0, byteDeviation = 0.0, slidingWindow = 0.0;

            var done = false;
            var state = State.START;

            while (!done)
                switch (state)
                {
                    case State.START:
                        state = State.CHECK_SEQUENCE;
                        break;

                    case State.CHECK_SEQUENCE:
                        if (IsSequenceData(window)) sequenceWindows++;
                        combinedWindows++;
                        state = State.CHECK_ALPHA_WHITE;
                        break;

                    case State.CHECK_ALPHA_WHITE:
                        alphaWhite = ComputePercentAlphaAndWhite(window);
                        if (alphaWhite > 0.90)
                        {
                            state = State.CLASSIFY_NATURAL;
                            naturalWindows++;
                            break;
                        }

                        if (alphaWhite < 10)
                        {
                            state = State.CHECK_ENTROPY;
                            break;
                        }

                        state = State.CHECK_ENTROPY;
                        break;

                    case State.CHECK_ENTROPY:
                        entropy = ComputeEntropy(window);
                        if (entropy > 7.5)
                        {
                            state = State.CLASSIFY_RANDOM;
                            randomWindows++;
                            break;
                        }

                        if (entropy < 6.5)
                        {
                            state = State.CLASSIFY_NATURAL;
                            naturalWindows++;
                            break;
                        }

                        state = State.CHECK_RLE;
                        break;

                    case State.CHECK_RLE:
                        rleRatio = ComputeRLECompressionRatio(window);
                        if (rleRatio <= 0.5)
                        {
                            state = State.CLASSIFY_NATURAL;
                            naturalWindows++;
                            break;
                        }

                        state = State.FULL_ANALYSIS;
                        break;

                    case State.FULL_ANALYSIS:
                        periodicity = ComputePeriodicity(window);
                        uniqueness = ComputeUniqueness(window);
                        byteDeviation = ComputeByteDeviation(window);
                        slidingWindow = ComputeSlidingWindowSimilarity(window);
                        state = State.CLASSIFY_OTHER;
                        break;

                    case State.CLASSIFY_NATURAL:
                    case State.CLASSIFY_RANDOM:
                    case State.CLASSIFY_OTHER:
                        done = true;
                        break;
                }

            // ✅ Always store results for the processed window before moving to the next one
            windowResults[start] = (entropy, periodicity, uniqueness, byteDeviation, slidingWindow, rleRatio,
                alphaWhite);
        }

        var avgEntropy = windowResults.Values.Average(v => v.Item1);
        var avgPeriodicity = windowResults.Values.Average(v => v.Item2);
        var avgUniqueness = windowResults.Values.Average(v => v.Item3);
        var avgByteDeviation = windowResults.Values.Average(v => v.Item4);
        var avgSlidingWindow = windowResults.Values.Average(v => v.Item5);

        // === Combined Classification Rules (Refined) ===

        // 1. Calculate weighted scores (as before, but no combinedScore yet).
        var sequenceScore = sequenceWindows * 3.0; // Sequence gets highest weight
        var randomScore = randomWindows * 1.0;
        var naturalScore = naturalWindows * 2.0; // Natural is in the middle

        // 2. Determine the dominant classification (if any).
        var dominantClassification = "Other"; // Default
        var dominantScore = 0.0;

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
        var totalWindows = sequenceWindows + randomWindows + naturalWindows;

        // 3. Check for Combined Data.  Pass totalWindows!
        if (IsCombinedData(sequenceWindows, randomWindows, naturalWindows, combinedWindows, totalWindows, sequenceScore,
                randomScore, naturalScore, avgEntropy))
            return ("Combined", avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow,
                windowResults);

        //var (classification, _, _) = Score(avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow);

        // 4. If not combined, return the dominant classification (or "Other" if none).
        return (dominantClassification, avgEntropy, avgUniqueness, avgByteDeviation, avgPeriodicity, avgSlidingWindow,
            windowResults);
    }

    // === Step 1: Known File Type Check (Instant Classification) ===
    private static string KnownFileType(byte[] data)
    {
        if (data!.Length < 4) return "Unknown";

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
            return "JPG"; // ✅ Return specific file type

        // PNG (Header: "\x89PNG\r\n\x1A\n")
        if (data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47)
            return "PNG"; // ✅ Return specific file type

        // MKV (Matroska Video File)
        if (data[0] == 0x1A && data[1] == 0x45 && data[2] == 0xDF && data[3] == 0xA3)
            return "MKV";

        // WAV (Waveform Audio File Format)
        if (data.Length >= 12 &&
            data[0] == 0x52 && data[1] == 0x49 && data[2] == 0x46 && data[3] == 0x46 && // "RIFF"
            data[8] == 0x57 && data[9] == 0x41 && data[10] == 0x56 && data[11] == 0x45) // "WAVE"
            return "WAV";

        // MSI (Microsoft Installer - PE format with MZ Header)
        if (data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 && data[3] == 0xE0)
            return "MSI";

        return "Unknown";
    }

    private static bool IsCombinedData(int sequenceWindows, int randomWindows, int naturalWindows, int combinedWindows,
        int totalWindows, double sequenceScore, double randomScore, double naturalScore, double avgEntropy)
    {
        // 1. Require a minimum proportion of "combinable" windows.
        // 🔹 Adaptive threshold for Combined classification
        var adaptiveCombinedThreshold = avgEntropy > 7.5 ? 0.55 : 0.40; // Stricter for high entropy, looser for low
        if (combinedWindows < totalWindows * adaptiveCombinedThreshold && totalWindows > 0) return false;

        const double sequenceConfidenceFloor = 5.0; // Minimum required strength for Sequence to dominate
        const double sequenceDominanceMargin = 0.2; // Adaptive margin

        if (sequenceScore > sequenceConfidenceFloor &&
            sequenceScore > randomScore + naturalScore + (randomScore + naturalScore) * sequenceDominanceMargin)
            return false; // Sequence truly dominates

        // 3. Check for dominance of other types (using counts).
        const double dominanceThreshold = 0.8;
        if (naturalWindows > totalWindows * dominanceThreshold) return false;
        if (randomWindows > totalWindows * dominanceThreshold) return false;

        // 4. Require at least two types to be *present* in significant amounts.
        var numSignificantTypes = 0;
        const double significantTypeThreshold = 0.1;
        var relevantTotal = combinedWindows > 0 ? combinedWindows : totalWindows;

        if (sequenceWindows >= totalWindows * significantTypeThreshold) numSignificantTypes++;
        if (naturalWindows >= relevantTotal * significantTypeThreshold) numSignificantTypes++;
        if (randomWindows >= relevantTotal * significantTypeThreshold) numSignificantTypes++;

        if (numSignificantTypes < 2) return false;

        return true; // Meets the criteria for combined data
    }

    #endregion AnalyzeDataMSM
}