/*
 * RegressionTests Module
 * =============================================
 * Project: Mango
 * Purpose: Runs full-system regression tests to validate core cryptographic
 *          and parsing functionality, ensuring stable and correct behavior
 *          across all major components.
 *
 *          Included tests:
 *            • End-to-End encryption roundtrip
 *            • Sequence parsing and formatting verification
 *            • Global state (Push/Pop) integrity
 *            • Block-mode encryption pipeline validation
 *            • Data classification accuracy
 *            • Transform reversibility for all registered transforms
 *
 *          These tests should be run regularly after changes to ensure
 *          no regressions are introduced into Mango’s adaptive cryptographic flow.
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
using System.Diagnostics;
using static Mango.Utilities.UtilityHelpers;

namespace Mango.Utilities;

public static class RegressionTests
{
    public static void RunRegressionTests(ExecutionEnvironment parentEnv)
    {
        var localEnv = new ExecutionEnvironment(parentEnv);
        RunTest(EndToEndEncryptionTest, localEnv, "End-to-End Encryption Test");
        RunTest(SequenceSanityTest, localEnv, "Sequence Parsing & Roundtrip Test");
        RunTest(PushPopGlobalsTest, localEnv, "Push/Pop Global State Test");
        RunTest(FullEncryptionPipelineTest, localEnv, "Full Encryption Pipeline Test");
        RunTest(ClassificationProfileAuditTest, localEnv, "Data Classification Test");
        RunTest(TransformReversibilityTest, localEnv, "Transform Reversibility Test");
        RunTest(_ => ValidateBlockModeRoundtrip(), localEnv, "Block Mode Roundtrip Test");
        RunTest(SmallBlockTest, localEnv, "Small Block Test");
        RunTest(ConstrainedPermutationTest, localEnv, "Constrained Permutation Test");
        RunTest(CoinTableSensitivityTest, localEnv, "CoinTable Sensitivity Test");
        // if you're interested turn this on - just too slow for every run and doesn't change/drift
        //RunTest(Rfc2898Benchmark, localEnv, "Rfc2898 Benchmark Test");
        RunTest(RoundsVsLengthTest, localEnv, "Rounds vs Length Test");
        RunTest(AesSanityTest, localEnv, "AES Sanity Test");
        RunTest(RunMesaToleranceTest, localEnv, "Run Mesa Tolerance Test");

        if (IsInteractiveWorkbench(parentEnv))
            PressAnyKey();
    }

    public static void RunMesaToleranceTest(ExecutionEnvironment parentEnv)
    {
        // Define the target InputTypes
        var inputTypes = new[] { InputType.Random, InputType.Sequence, InputType.Natural, InputType.Combined };
        var results = new List<string>();

        foreach (var inputType in inputTypes)
        {
            var localEnv = new ExecutionEnvironment(parentEnv);
            localEnv.Globals.UpdateSetting("InputType", inputType);

            // Get baseline input (from loaded Mango source)
            byte[] baselineInput = localEnv.Globals.Input;
            var profile = InputProfiler.GetInputProfile(baselineInput, localEnv.Globals.Mode, localEnv.Globals.ScoringMode);

            // Analyze Mango on baseline
            double baselineScore = AnalyzeProfile(localEnv, profile, baselineInput, out int baselinePasses, out List<string> mangoFailedMetrics);

            #region Analyze AES on same baseline input
            var aesEncrypted = AesEncrypt(baselineInput, GlobalsInstance.Password, out var saltLen, out var padLen);
            var aesPayload = ExtractAESPayload(aesEncrypted, saltLen, padLen);
            var (_, aesAv, _, aesKd) = ProcessAvalancheAndKeyDependency(
                localEnv.Crypto,
                baselineInput,
                GlobalsInstance.Password,
                profile,
                processAes: true);

            var aesResults = localEnv.CryptoAnalysis.RunCryptAnalysis(aesPayload, aesAv, aesKd, baselineInput);
            var aesScore = localEnv.CryptoAnalysis.CalculateAggregateScore(aesResults, localEnv.Globals.ScoringMode);
            int aesPasses = aesResults.Count(r => r.Passed);
            var aesFailedMetrics = aesResults
                .Where(m => !m.Passed)
                .Select(m => m.Name)
                .ToList();
            #endregion Analyze AES on same baseline input

            // Mutate input intelligently per InputType
            byte[] mutatedInput = inputType switch
            {
                InputType.Random => GenerateRandomInput(4096),
                InputType.Sequence => baselineInput.Select(b => (byte)(b + 1)).ToArray(),
                InputType.Natural => MutateNaturalCasing(baselineInput),
                InputType.Combined => CombineInputs(
                    GenerateRandomInput(1365),
                    baselineInput.Skip(1365).Take(1365).Select(b => (byte)(b + 1)).ToArray(),
                    MutateNaturalCasing(baselineInput.Skip(2730).Take(1366).ToArray())
                ),
                _ => throw new NotSupportedException($"Unsupported InputType: {inputType}")
            };

            // Re-analyze Mango on mutated input
            double mutatedScore = AnalyzeProfile(localEnv, profile, mutatedInput, out int mutatedPasses, out mangoFailedMetrics);

            mangoFailedMetrics.Sort();
            var mangoFailedSummary = mangoFailedMetrics.Count == 0
                ? ""
                : $"\n❌ Mango Failed Metrics: {string.Join(", ", mangoFailedMetrics)}";

            aesFailedMetrics.Sort();
            var aesFailedSummary = aesFailedMetrics.Count == 0
                ? ""
                : $"\n❌ AES Failed Metrics: {string.Join(", ", aesFailedMetrics)}";

            results.Add(
                $"\n=== {inputType} ===\n" +
                $"Mango (Baseline):  {baselineScore:F4}, Passes: {baselinePasses}/9\n" +
                $"AES             :  {aesScore:F4}, Passes: {aesPasses}/9\n" +
                $"Mango (Mutated):  {mutatedScore:F4}, Passes: {mutatedPasses}/9" +
                mangoFailedSummary +
                aesFailedSummary);

        }

        Console.WriteLine(string.Join("\n", results));
    }

    public static byte[] GenerateRandomInput(int size)
    {
        var rng = new Random(1337); // Fixed seed for reproducibility
        var buffer = new byte[size];
        rng.NextBytes(buffer);
        return buffer;
    }
    private static byte[] MutateNaturalCasing(byte[] input)
    {
        var rng = new Random(42);
        byte[] mutated = (byte[])input.Clone();
        for (int i = 0; i < mutated.Length; i++)
        {
            if (char.IsLetter((char)mutated[i]) && rng.NextDouble() < 0.1)
            {
                char flipped = char.IsUpper((char)mutated[i])
                    ? char.ToLower((char)mutated[i])
                    : char.ToUpper((char)mutated[i]);
                mutated[i] = (byte)flipped;
            }
        }
        return mutated;
    }

    private static byte[] CombineInputs(byte[] part1, byte[] part2, byte[] part3)
    {
        var combined = new byte[4096];
        Buffer.BlockCopy(part1, 0, combined, 0, part1.Length);
        Buffer.BlockCopy(part2, 0, combined, part1.Length, part2.Length);
        Buffer.BlockCopy(part3, 0, combined, part1.Length + part2.Length, part3.Length);
        return combined;
    }

    private static double AnalyzeProfile(
        ExecutionEnvironment env,
        InputProfile profile,
        byte[] input,
        out int passCount,
        out List<string> failedMetrics)
    {
        var crypto = env.Crypto;
        var encrypted = crypto.Encrypt(profile.Sequence, profile.GlobalRounds, input);
        var payload = crypto.GetPayloadOnly(encrypted);

        var (avalanche, _, keydep, _) =
            ProcessAvalancheAndKeyDependency(crypto, input, GlobalsInstance.Password, profile);

        var results = env.CryptoAnalysis.RunCryptAnalysis(payload, avalanche, keydep, input);

        // ✅ Count metrics that passed
        passCount = results.Count(m => m.Passed);

        failedMetrics = results
            .Where(m => !m.Passed)
            .Select(m => m.Name)
            .ToList();

        return env.CryptoAnalysis.CalculateAggregateScore(results, env.Globals.ScoringMode);
    }

    public static void AesSanityTest(ExecutionEnvironment localEnv)
    {
        byte[] key = new byte[32]; // AES-256
        byte[] iv = new byte[16];
        byte[] plaintext = new byte[32];

        for (int i = 0; i < plaintext.Length; i++)
            plaintext[i] = (byte)i;

        for (int i = 0; i < key.Length; i++)
            key[i] = (byte)(0xA5 ^ i);

        for (int i = 0; i < iv.Length; i++)
            iv[i] = (byte)(0x3C ^ i);

        var aesManaged = System.Security.Cryptography.Aes.Create();
        aesManaged.Key = key;
        aesManaged.IV = iv;
        aesManaged.Mode = System.Security.Cryptography.CipherMode.CBC;
        aesManaged.Padding = System.Security.Cryptography.PaddingMode.PKCS7;

        byte[] expected;
        using (var enc = aesManaged.CreateEncryptor())
        {
            expected = enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
        }

        var aesSoft = new AesSoftwareCore.AesSoftwareCore(key);
        var actual = aesSoft.EncryptCbc(plaintext, iv);

        bool match = expected.Length == actual.Length;
        for (int i = 0; i < expected.Length && match; i++)
            match &= expected[i] == actual[i];

        if (match)
            Console.WriteLine("✅ AES sanity test passed — software core matches .NET AES-256.");
        else
            Console.WriteLine("❌ AES sanity test failed — mismatch detected.");
    }
    private static void RoundsVsLengthTest(ExecutionEnvironment localEnv)
    {
        var sequences = new[]
        {
        new
        {
            Label = "L3 Optimized",
            Sequence = new (byte ID, byte TR)[]
            { //CascadeSub3xFwdTx(ID:47)(TR:9) -> NibbleInterleaverTx(ID:39)(TR:1) -> MaskBasedSBoxFwdTx(ID:16)(TR:1) | (GR:7)
                (47, 9), // CascadeSub3xFwdTx
                (39, 1), // NibbleInterleaverTx
                (16, 1), // MaskBasedSBoxFwdTx
            },
            GlobalRounds = 7
        },
        new
        {
            Label = "L4 Raw",
            Sequence = new (byte ID, byte TR)[]
            { // SubBytesXorMaskFwdTx(ID:9)(TR:1) -> ShuffleNibblesFwdTx(ID:18)(TR:1) ->
              // SlidingMaskOverlayTx(ID:23)(TR:1) -> ShuffleBitsFwdTx(ID:4)(TR:1)
                (9, 1),  // SubBytesXorMaskFwdTx
                (18, 1), // ShuffleNibblesFwdTx
                (23, 1), // SlidingMaskOverlayTx
                (4, 1),  // ShuffleBitsFwdTx
            },
            GlobalRounds = 6
        }
    };
        localEnv.Globals.UpdateSetting("InputType", InputType.Combined);

        foreach (var seq in sequences)
        {
            var profile = new InputProfile(seq.Label, seq.Sequence, seq.GlobalRounds, 0);
            var crypto = new CryptoLib(GlobalsInstance.Password, new CryptoLibOptions(Scoring.MangoSalt));

            var sw = Stopwatch.StartNew();
            var encrypted = crypto.Encrypt(profile.Sequence, profile.GlobalRounds, localEnv.Globals.Input);
            sw.Stop();

            var payload = crypto.GetPayloadOnly(encrypted);
            var decrypted = crypto.Decrypt(encrypted);

            if (!decrypted.SequenceEqual(localEnv.Globals.Input))
                throw new Exception($"{seq.Label}: Pipeline is not reversible.");

            var (avalanche, _, keydep, _) =
                ProcessAvalancheAndKeyDependency(crypto, localEnv.Globals.Input, GlobalsInstance.Password, profile);

            var results = localEnv.CryptoAnalysis.RunCryptAnalysis(payload, avalanche, keydep, localEnv.Globals.Input);

            localEnv.Globals.UpdateSetting("ScoringMode", ScoringModes.Metric);
            var metricScore = localEnv.CryptoAnalysis.CalculateAggregateScore(results, localEnv.Globals.ScoringMode);

            localEnv.Globals.UpdateSetting("ScoringMode", ScoringModes.Practical);
            var practicalScore = localEnv.CryptoAnalysis.CalculateAggregateScore(results, localEnv.Globals.ScoringMode);

            Console.WriteLine($"\n🏁 {seq.Label} (GR: {seq.GlobalRounds})");
            Console.WriteLine($"⏱️  Time: {sw.Elapsed.TotalMilliseconds:F3} ms");
            Console.WriteLine($"✅  Reversible: Yes");
            Console.WriteLine($"📊  Metric Score: {metricScore:F4}");
            Console.WriteLine($"📊  Practical Score: {practicalScore:F4}");
        }
    }

    private static void Rfc2898Benchmark(ExecutionEnvironment localEnv)
    {
        var formattedSequence =
            "ApplyMaskBasedMixingTx -> MicroBlockSwapFwdTx -> AesMixColumnsFwdTx -> MicroBlockSwapFwdTx";

        var sequenceIDs = new SequenceHelper(localEnv.Crypto).GetIDs(formattedSequence);
        var profile = new InputProfile("PBKDF2-Test",
            sequenceIDs.Select(id => (id, (byte)1)).ToArray(),
            GlobalRounds: 6,
            AggregateScore: 0.0
        );
        using (new LocalEnvironment(localEnv, formattedSequence))
        {
            localEnv.Globals.UpdateSetting("InputType", InputType.Combined);
            localEnv.Globals.UpdateSetting("Mode", OperationModes.Cryptographic);
            localEnv.Globals.UpdateSetting("Rounds", 6);


            var input = localEnv.Globals.Input;
            var salt = Scoring.MangoSalt;
            var password = GlobalsInstance.Password;

            double scoreWithPBKDF2 = 0.0;
            double scoreWithoutPBKDF2 = 0.0;
            int loop_count = 400;

            var sw = Stopwatch.StartNew();
            for (int i = 0; i < loop_count; i++)
            {
                var options = new CryptoLibOptions(salt, behavior: Behaviors.Rfc2898);
                var crypto = new CryptoLib(password, options);
            }

            sw.Stop();
            Console.WriteLine($"⏱️ With PBKDF2: {sw.ElapsedMilliseconds} ms");

            sw.Restart();
            for (int i = 0; i < loop_count; i++)
            {
                var options = new CryptoLibOptions(salt, behavior: Behaviors.None);
                var crypto = new CryptoLib(password, options);
            }

            sw.Stop();
            Console.WriteLine($"⏱️ Without PBKDF2: {sw.ElapsedMilliseconds} ms");

            var optionsPBK = new CryptoLibOptions(salt, behavior: Behaviors.Rfc2898);
            var cryptoPBK = new CryptoLib(password, optionsPBK);
            var payloadPBK = cryptoPBK.GetPayloadOnly(cryptoPBK.Encrypt(profile.Sequence, profile.GlobalRounds, input));
            var (avalanche1, _, keydep1, _) = ProcessAvalancheAndKeyDependency(cryptoPBK, input, password, profile);
            var resultsPBK = localEnv.CryptoAnalysis.RunCryptAnalysis(payloadPBK, avalanche1, keydep1, input);
            scoreWithPBKDF2 = localEnv.CryptoAnalysis.CalculateAggregateScore(resultsPBK, localEnv.Globals.ScoringMode);

            var optionsRaw = new CryptoLibOptions(salt, behavior: Behaviors.None);
            var cryptoRaw = new CryptoLib(password, optionsRaw);
            var payloadRaw = cryptoRaw.GetPayloadOnly(cryptoRaw.Encrypt(profile.Sequence, profile.GlobalRounds, input));
            var (avalanche2, _, keydep2, _) = ProcessAvalancheAndKeyDependency(cryptoRaw, input, password, profile);
            var resultsRaw = localEnv.CryptoAnalysis.RunCryptAnalysis(payloadRaw, avalanche2, keydep2, input);
            scoreWithoutPBKDF2 = localEnv.CryptoAnalysis.CalculateAggregateScore(resultsRaw, localEnv.Globals.ScoringMode);

            Console.WriteLine($"\n🎯 Aggregate Score With PBKDF2:     {scoreWithPBKDF2:F4}");
            Console.WriteLine($"🎯 Aggregate Score Without PBKDF2:  {scoreWithoutPBKDF2:F4}");
            Console.WriteLine($"📊 Score Delta: {Math.Abs(scoreWithPBKDF2 - scoreWithoutPBKDF2):F4}");
        }
    }

    private static void CoinTableSensitivityTest(ExecutionEnvironment localEnv)
    {
        var formattedSequence =
            "FrequencyEqualizerInvTx -> SlidingMaskOverlayTx -> MicroBlockShufflerInvTx -> FrequencyEqualizerFwdTx";

        var sequenceIDs = new SequenceHelper(localEnv.Crypto).GetIDs(formattedSequence);
        var profile = new InputProfile("SaltTest",
            sequenceIDs.Select(id => (id, (byte)1)).ToArray(),
            GlobalRounds: 9,
            AggregateScore: 0.0
        );

        double? baselineMetricScore = null;
        double? baselinePracticalScore = null;
        double maxMetricDeviation = 0.0;
        double maxPracticalDeviation = 0.0;

        using (new LocalEnvironment(localEnv, formattedSequence))
        {
            localEnv.Globals.UpdateSetting("InputType", InputType.Combined);
            localEnv.Globals.UpdateSetting("Mode", OperationModes.Cryptographic);
            localEnv.Globals.UpdateSetting("Rounds", 9);

            for (int i = 0; i < 16; i++)
            {
                // Vary salt
                byte[] salt = Enumerable.Range(0, 12)
                    .Select(b => (byte)((i * 17 + b * 23) % 256)).ToArray();

                // Vary password
                string password = $"password_variant_{i}";

                var options = new CryptoLibOptions(salt);
                var crypto = new CryptoLib(password, options);

                var encrypted = crypto.Encrypt(profile.Sequence, profile.GlobalRounds, localEnv.Globals.Input);
                var payload = crypto.GetPayloadOnly(encrypted);
                var decrypted = crypto.Decrypt(encrypted);

                if (!decrypted.SequenceEqual(localEnv.Globals.Input))
                    throw new Exception($"Salt #{i}: Pipeline is not reversible.");

                var (avalanche, _, keydep, _) =
                    ProcessAvalancheAndKeyDependency(crypto, localEnv.Globals.Input, password, profile);

                var results = localEnv.CryptoAnalysis.RunCryptAnalysis(payload, avalanche, keydep, localEnv.Globals.Input);

                localEnv.Globals.UpdateSetting("ScoringMode", ScoringModes.Metric);
                var metricScore = localEnv.CryptoAnalysis.CalculateAggregateScore(results, localEnv.Globals.ScoringMode);

                localEnv.Globals.UpdateSetting("ScoringMode", ScoringModes.Practical);
                var practicalScore = localEnv.CryptoAnalysis.CalculateAggregateScore(results, localEnv.Globals.ScoringMode);

                if (i == 0)
                {
                    baselineMetricScore = metricScore;
                    baselinePracticalScore = practicalScore;
                }
                else
                {
                    var metricDeviation = Math.Abs(metricScore - baselineMetricScore!.Value);
                    var practicalDeviation = Math.Abs(practicalScore - baselinePracticalScore!.Value);

                    if (metricDeviation > maxMetricDeviation)
                        maxMetricDeviation = metricDeviation;

                    if (practicalDeviation > maxPracticalDeviation)
                        maxPracticalDeviation = practicalDeviation;
                }
            }
        }

        Console.WriteLine($"📊 Max Metric Score Deviation: {maxMetricDeviation:F4}");
        Console.WriteLine($"📊 Max Practical Score Deviation: {maxPracticalDeviation:F4}");
    }

    // 🔹 Regression Test: ConstrainedPermutationTest
    //
    // ✅ Validates that CountFilteredPermutations and GeneratePermutations
    //    produce the same number of sequences under constraints.
    // ✅ Helps ensure time estimates and iteration behavior match in Munge.
    // ✅ Flags any discrepancy in permutation logic or filtering.
    private static void ConstrainedPermutationTest(ExecutionEnvironment localEnv)
    {
        var transformPool = Enumerable.Range(0, 45).Select(i => (byte)i).ToList(); // Simulate 45 registered transforms
        var required = new List<byte> { 41, 43, 45 };                              // AES Core transforms (must appear)
        var noRepeat = new List<byte> { 41, 43, 45 };                              // These must not repeat
        int length = 5;

        // 🔢 Step 1: Count permutations using the estimation method
        long estimatedCount = PermutationEngine.CountFilteredPermutations(
            transformPool,
            length,
            required: required,
            allowWildcardRepeat: true,
            noRepeat: noRepeat);

        // 🔁 Step 2: Count actual sequences generated
        int generatedCount = 0;
        foreach (var seq in PermutationEngine.GeneratePermutations(
                     transformPool,
                     length,
                     required: required,
                     allowWildcardRepeat: true,
                     noRepeat: noRepeat))
        {
            generatedCount++;
        }

        // ✅ Step 3: Assert match
        if (estimatedCount != generatedCount)
        {
            throw new Exception($"[ConstrainedPermutationTest] Mismatch: Estimated={estimatedCount}, Generated={generatedCount}");
        }

        //Console.WriteLine($"[ConstrainedPermutationTest] PASS: Total={generatedCount} sequences");
    }

    // 🔹 Regression Test: Validate Transform Robustness on Small Buffers
    //
    // ✅ Loops over input sizes from 1 to 5 bytes
    // ✅ For each built-in InputType (Sequence, Random, Natural, Combined)
    // ✅ Profiles input to get adaptive sequence and rounds (god-sequence)
    // ✅ Encrypts/decrypts and ensures correct roundtrip behavior
    //
    // ✅ Separately iterates every transform (excluding ExcludeFromPermutations)
    // ✅ Applies each transform alone, then its inverse, to inputs of size 1–5
    // ✅ Confirms transform modifies data (if applicable) and roundtrips successfully
    //
    // 🔥 This test ensures every transform in Mango handles tiny inputs safely.
    //    If this fails, it likely indicates incorrect length assumptions, padding logic,
    //    or unsafe buffer access inside a transform.
    private static void SmallBlockTest(ExecutionEnvironment localEnv)
    {
        var builtInTypes = new Dictionary<InputType, string>
    {
        { InputType.Sequence, "Sequence" },
        { InputType.Random, "Random" },
        { InputType.Natural, "Natural" },
        { InputType.Combined, "Combined" }
    };

        // ✅ PHASE 1: Test God-sequence profiles on small blocks
        foreach (var (inputType, _) in builtInTypes)
            using (new LocalEnvironment(localEnv))
            {
                localEnv.Globals.UpdateSetting("InputType", inputType);
                var fullInput = localEnv.Globals.Input;

                var profile = InputProfiler.GetInputProfile(fullInput, OperationModes.Cryptographic, ScoringModes.Practical);

                for (int len = 1; len <= 5; len++)
                {
                    var testInput = fullInput.Take(len).ToArray();

                    var encrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, testInput);
                    if (encrypted.SequenceEqual(testInput))
                        throw new Exception($"[GodSeq] Encryption failed to alter buffer (InputType={inputType}, len={len})");

                    var decrypted = localEnv.Crypto.Decrypt(encrypted);
                    if (!decrypted.SequenceEqual(testInput))
                        throw new Exception($"[GodSeq] Decryption failed (InputType={inputType}, len={len})");
                }
            }

        // 🧪 PHASE 2: Individually test all transforms on 1–5 byte inputs
        var referenceInput = Enumerable.Range(0, 32).Select(i => (byte)i).ToArray(); // Common base data
        var registry = localEnv.Crypto.TransformRegistry;

        foreach (var kvp in registry)
        {
            var id = (byte)kvp.Key;
            var transform = kvp.Value;

            if (transform.ExcludeFromPermutations)
                continue; // Skip known no-ops like PassthroughTx

            var inverseId = (byte)transform.InverseId;

            for (int len = 1; len <= 5; len++)
            {
                using (new LocalEnvironment(localEnv))
                {
                    var testInput = referenceInput.Take(len).ToArray();

                    // Build single-transform profile
                    var profile = InputProfiler.CreateInputProfile(name: $"SingleTx-ID:{id}",
                        sequence: new[] { id },
                        tRs: new[] { (byte)1 },
                        globalRounds: 1
                    );

                    // Encrypt
                    var encrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, testInput);

                    // Verify it alters input (only if transform != inverse)
                    if (id != inverseId && encrypted.SequenceEqual(testInput))
                        throw new Exception($"[SingleTx] ID:{id} ({transform.Name}) failed to alter input (len={len})");

                    // ✅ Header-based decryption (no inverse sequence needed)
                    var decrypted = localEnv.Crypto.Decrypt(encrypted);

                    if (!decrypted.SequenceEqual(testInput))
                        throw new Exception($"[SingleTx] ID:{id} ({transform.Name}) failed round-trip (len={len})");
                }
            }

        }
    }

    // 🔹 Regression Test: Validate Block Mode Roundtrip Integrity
    //
    // ✅ Splits a 64KB buffer into 64 x 1KB chunks
    // ✅ Uses the first block to extract the adaptive sequence
    // ✅ Encrypts the first block with header (calls Encrypt)
    // ✅ Encrypts remaining blocks without header (EncryptBlock)
    // ✅ Reinitializes CryptoLib to simulate external consumer
    // ✅ Decrypts the first block (restores header config)
    // ✅ Decrypts the remaining blocks (DecryptBlock)
    // ✅ Verifies full roundtrip: input == output
    //
    // 🔥 This test validates Mango’s ability to operate as a streaming block-mode cipher.
    //    If this fails, it indicates a header caching, transform setup, or IV issue.
    private static void ValidateBlockModeRoundtrip()
    {
        // 📦 Step 1: Create input blocks (64KB split into 64 blocks of 1024 bytes)
        List<byte[]> inputBlocks = Enumerable.Range(0, 64)
            .Select(i => Enumerable.Range(0, 1024).Select(b => (byte)((i + b) % 256)).ToArray())
            .ToList();

        // 🔐 Step 2: Encrypt Phase
        byte[] Salt = Scoring.MangoSalt;
        var options = new CryptoLibOptions(Salt);
        var crypto = new CryptoLib("my password", options);

        var profile = InputProfiler.GetInputProfile(inputBlocks[0], OperationModes.Cryptographic, ScoringModes.Practical);

        List<byte[]> outputBlocks = new();
        var encryptedFirst = crypto.Encrypt(profile.Sequence, profile.GlobalRounds, inputBlocks[0]);
        outputBlocks.Add(encryptedFirst);

        for (var i = 1; i < inputBlocks.Count; i++)
        {
            var encrypted = crypto.EncryptBlock(inputBlocks[i]);
            outputBlocks.Add(encrypted);
        }

        // 🔄 Step 3: Simulate decrypting on a new session / machine
        // same options as above
        var new_crypto = new CryptoLib("my password", options);

        List<byte[]> decryptedBlocks = new();
        var decryptedFirst = new_crypto.Decrypt(outputBlocks[0]);
        decryptedBlocks.Add(decryptedFirst);

        for (var i = 1; i < outputBlocks.Count; i++)
        {
            var decrypted = new_crypto.DecryptBlock(outputBlocks[i]);
            decryptedBlocks.Add(decrypted);
        }

        // ✅ Step 4: Compare flattened buffers
        var original = Flatten(inputBlocks);
        var restored = Flatten(decryptedBlocks);

        if (!original.SequenceEqual(restored))
            throw new Exception("Block mode roundtrip failed: output does not match input.");
    }

    // 🔧 Helper: Flattens a list of blocks into a single array
    private static byte[] Flatten(List<byte[]> blocks)
    {
        return blocks.SelectMany(b => b).ToArray();
    }

    // 🔹 End-to-End Encryption/Decryption Sanity Test
    //
    // ✔ Verifies the encryption pipeline by performing a full round-trip:
    //    1. Encrypts a sample input with a predefined transform sequence.
    //    2. Decrypts the result using the correct inverse transform sequence.
    //    3. Asserts that the decrypted output perfectly matches the original input.
    //    4. Confirms input integrity by verifying the original input checksum.
    //
    // 🛡 This test safeguards against:
    //    - Incorrect transform reversibility
    //    - Accidental input corruption
    //    - Regression issues after in-place transform refactoring
    private static void EndToEndEncryptionTest(ExecutionEnvironment localEnv)
    {
        var sampleInput = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 };
        var checksum = sampleInput.Sum(b => (int)b);

        var profile = InputProfiler.CreateInputProfile(name: "EndToEndTest",
            sequence: new byte[] { 25, 23, 27, 24 },
            tRs: new byte[] { 1, 1, 1, 1 },
            globalRounds: 1
        );

        var encrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, sampleInput);
        var decrypted = localEnv.Crypto.Decrypt(encrypted); // ✅ Header-driven decryption

        if (!decrypted.SequenceEqual(sampleInput))
            throw new Exception("Decryption failed: output does not match original input.");

        if (checksum != sampleInput.Sum(b => (int)b))
            throw new Exception("Input corruption detected: original input was modified.");

        // test two
        encrypted = localEnv.Crypto.Encrypt(profile.Sequence, profile.GlobalRounds, sampleInput);

        // 🔄 Step 3: Simulate decrypting on a new session / machine
        var crypto = new CryptoLib(GlobalsInstance.Password, localEnv.Crypto.Options);

        decrypted = crypto.Decrypt(encrypted); // ✅ Header-driven decryption

        if (!decrypted.SequenceEqual(sampleInput))
            throw new Exception("Decryption failed: output does not match original input.");

        if (checksum != sampleInput.Sum(b => (int)b))
            throw new Exception("Input corruption detected: original input was modified.");

    }

    // 🔹 Run Sequence Tests & Handle Failures Gracefully
    //
    // ✅ Executes `RunSequenceTests()` to validate sequence parsing & transformation logic.
    // ✅ Operates in "quiet mode"—only outputs results if failures occur.
    // ✅ If any test fails, prompts the user to review the failures before proceeding.
    // ✅ Uses `ColorConsole.WriteLine()` for improved visibility in debug mode.
    //
    // 🔥 This ensures that regression tests run unobtrusively, while still providing 
    //    clear feedback when something goes wrong.
    private static void SequenceSanityTest(ExecutionEnvironment localEnv)
    {
        //Sequence test = new Sequence(localEnv.Crypto);
        //if (test.RunSequenceTests(quiet: true) != 0)
        //{
        //    throw new Exception("Sequence parsing test failed.");
        //}

        if (SequenceParserTests.Run(localEnv.Crypto, true) != 0) throw new Exception("Sequence parsing test failed.");
    }

    // 🔹 Regression Test: Validate PushAllGlobals/PopAllGlobals Functionality
    //
    // ✅ Ensures that global settings are correctly saved and restored.
    // ✅ Modifies multiple settings (`MaxSequenceLen` and `InputType`), then verifies restoration.
    // ✅ Uses `PushAllGlobals()` to store the current global state.
    // ✅ Updates settings to new valid values to simulate changes.
    // ✅ Calls `PopAllGlobals()` to revert all changes.
    // ✅ Uses assertions to confirm that original values are properly restored.
    //
    // 🔥 This test guarantees that global state management remains consistent and reliable.
    private static void PushPopGlobalsTest(ExecutionEnvironment localEnv)
    {
        using (var localStatEnvironment = new LocalEnvironment(localEnv))
        {
            localStatEnvironment.Rsm.PushAllGlobals();
            localStatEnvironment.Rsm.PopAllGlobals();
            localStatEnvironment.Rsm.PushAllGlobals();
            localStatEnvironment.Rsm.PopAllGlobals();
        }

        using (var localStatEnvironment = new LocalEnvironment(localEnv))
        {
            var maxSequenceLen = localEnv.Globals.MaxSequenceLen;
            var inputType = localEnv.Globals.InputType;

            localStatEnvironment.Rsm.PushAllGlobals();
            localEnv.Globals.MaxSequenceLen = maxSequenceLen + 1;
            localEnv.Globals.InputType =
                Enum.GetValues(typeof(InputType)).Cast<InputType>().First(t => t != inputType);
            localStatEnvironment.Rsm.PopAllGlobals();

            if (localEnv.Globals.MaxSequenceLen != maxSequenceLen || localEnv.Globals.InputType != inputType)
                throw new Exception("Push/Pop globals failed to restore values.");
        }
    }

    // 🔹 Full Regression Test: Mango Encryption Pipeline & Cryptanalysis Validation
    //
    // ✅ Uses **4096-byte Combined test input**
    // ✅ Runs **encryption** using Mango's top-ranked sequence.
    // ✅ Extracts the **encrypted payload** (removing any metadata or headers).
    // ✅ Reconstructs the **inverse sequence** and runs **decryption**.
    // ✅ Ensures that the **decrypted output perfectly matches the original input**.
    // ✅ Performs **Avalanche & Key Dependency Analysis** to measure cryptographic quality.
    // ✅ Runs **full cryptanalysis** on the encrypted data and checks the aggregate score.
    // ✅ Asserts that Mango produces a **stable, high-scoring, and fully reversible transformation**.
    //
    // 🔥 This is the **ultimate integration test**—any failure here signals a fundamental issue.
    //    If this test ever fails, Mango's cryptographic integrity must be re-evaluated immediately.
    private static void FullEncryptionPipelineTest(ExecutionEnvironment localEnv)
    {
        var formattedSequence = "ApplyMaskBasedMixingTx -> MicroBlockSwapFwdTx -> AesMixColumnsFwdTx -> MicroBlockSwapFwdTx";
        var sequenceHelper = new SequenceHelper(localEnv.Crypto);
        var idsOnly = sequenceHelper.GetIDs(formattedSequence);

        localEnv.Globals.UpdateSetting("InputType", InputType.Combined);
        localEnv.Globals.UpdateSetting("Mode", OperationModes.Cryptographic);

        var profile = new InputProfile("Combined.Test",
            idsOnly.Select(id => (id, (byte)1)).ToArray(),
            GlobalRounds: 6,
            AggregateScore: 0.0
        );

        var testCases = new[]
        {
        new { Label = "With PBKDF2", Behavior = Behaviors.Rfc2898, ExpectedMetric = 73.346473981888565, ExpectedPractical = 92.365929530053435 },
        new { Label = "Without PBKDF2", Behavior = Behaviors.None, ExpectedMetric = 70.6061711385166, ExpectedPractical = 82.757262159024 }
        };

        foreach (var test in testCases)
        {
            var crypto = new CryptoLib(GlobalsInstance.Password, new CryptoLibOptions(Scoring.MangoSalt, behavior: test.Behavior));

            var encrypted = crypto.Encrypt(profile.Sequence, profile.GlobalRounds, localEnv.Globals.Input);
            var payload = crypto.GetPayloadOnly(encrypted);
            var decrypted = crypto.Decrypt(encrypted);

            if (!decrypted.SequenceEqual(localEnv.Globals.Input))
                throw new Exception($"{test.Label}: Pipeline is not reversible.");

            var (avalanche, _, keydep, _) =
                ProcessAvalancheAndKeyDependency(crypto, localEnv.Globals.Input, GlobalsInstance.Password, profile);

            var results = localEnv.CryptoAnalysis.RunCryptAnalysis(payload, avalanche, keydep, localEnv.Globals.Input);

            localEnv.Globals.UpdateSetting("ScoringMode", ScoringModes.Metric);
            var metricScore = localEnv.CryptoAnalysis.CalculateAggregateScore(results, localEnv.Globals.ScoringMode);

            localEnv.Globals.UpdateSetting("ScoringMode", ScoringModes.Practical);
            var practicalScore = localEnv.CryptoAnalysis.CalculateAggregateScore(results, localEnv.Globals.ScoringMode);

#if DEBUG
            if (Math.Abs(metricScore - test.ExpectedMetric) > 0.0001)
                Console.WriteLine($"⚠️ {test.Label}: Metric score mismatch (expected {test.ExpectedMetric:F15}).");

            if (Math.Abs(practicalScore - test.ExpectedPractical) > 0.0001)
                Console.WriteLine($"⚠️ {test.Label}: Practical score mismatch (expected {test.ExpectedPractical:F15}).");
#else
        if (Math.Abs(metricScore - test.ExpectedMetric) > 0.0001)
            throw new Exception($"{test.Label}: Metric score mismatch.");
        if (Math.Abs(practicalScore - test.ExpectedPractical) > 0.0001)
            throw new Exception($"{test.Label}: Practical score mismatch.");
#endif
        }
    }

    // 🔹 Regression Test: Validate Profile Selection and Scoring Integrity
    //
    // ✅ Iterates over all supported `InputType` classifications: Sequence, Natural, Random, and Combined.
    // ✅ For each, retrieves the optimal profile using `InputProfiler` under both `.Fast` and `.Best` modes.
    // ✅ Executes the selected profile using the full cryptographic pipeline.
    // ✅ Measures execution time and calculates the final aggregate score.
    // ✅ Verifies that the profile’s naming aligns with the expected input classification (e.g., "Natural.Fast").
    //
    // 🔒 Guarantees:
    //    - Mango’s classification logic selects correct, type-aligned profiles.
    //    - Performance and scoring are stable and regressions are detectable.
    //    - Output includes explicit timing and score summaries for visibility.
    //
    // 🛠️ This test ensures the integrity of the evolving profile system, 
    //     provides a sanity check on scoring drift, and aids in long-term reliability of optimizations.
    private static void ClassificationProfileAuditTest(ExecutionEnvironment localEnv)
    {
        var expected = new Dictionary<InputType, string>
        {
            { InputType.Sequence, "Sequence" },
            { InputType.Random, "Random" },
            { InputType.Natural, "Natural" },
            { InputType.Combined, "Combined" }
        };

        foreach (EncryptionPerformanceMode performance in Enum.GetValues(typeof(EncryptionPerformanceMode)))
        {
            Console.WriteLine($"\n🔧 Testing performance mode: {performance}\n");

            foreach (var (inputType, expectedLabel) in expected)
            {
                using (new LocalEnvironment(localEnv))
                {
                    localEnv.Globals.UpdateSetting("InputType", inputType);

                    var profile = InputProfiler.GetInputProfile(
                        localEnv.Globals.Input,
                        OperationModes.Cryptographic,
                        ScoringModes.Practical,
                        performance);

                    double elapsedMs;
                    var metrics = Mango.Workbench.Handlers.RunSequenceAndAnalyze(localEnv, profile, $"Original (Munge(A)({profile.GlobalRounds}))", out elapsedMs);
                    var score = localEnv.CryptoAnalysis.CalculateAggregateScore(metrics, localEnv.Globals.ScoringMode);

                    string baseName = profile.Name.Split('.')[0];
                    bool isMatch = baseName == expectedLabel;
                    string icon = isMatch ? "🔍" : "⚠️";
                    string expectedSuffix = isMatch ? "" : $" (Expected Base: {expectedLabel})";

                    Console.WriteLine($"{icon} InputType: {inputType} => Profile Selected: {profile.Name}{expectedSuffix} ({score:F4}) ({elapsedMs:F2}ms)");
                }
            }
        }
    }

    // 🔹 Regression Test: Validate Transform Reversibility (One-by-One)
    //
    // ✅ Iterates through **every registered transform** in the TransformRegistry.
    // ✅ Applies each transform individually to known input, followed by its inverse.
    // ✅ Confirms that the original input is perfectly restored (i.e., full reversibility).
    // ✅ Flags and reports any transform that fails this fundamental cryptographic guarantee.
    //
    // 🔥 This ensures every atomic transform maintains **lossless and reversible behavior**, a core requirement for secure encryption.
    private static void TransformReversibilityTest(ExecutionEnvironment localEnv)
    {
        var failed = new List<string>();

        using (new LocalEnvironment(localEnv))
        {
            localEnv.Globals.UpdateSetting("InputType", InputType.Random);
            localEnv.Globals.UpdateSetting("Mode", OperationModes.Cryptographic);
            localEnv.Globals.UpdateSetting("Rounds", 1);

            var input = localEnv.Globals.Input;
            var registry = localEnv.Crypto.TransformRegistry;

            foreach (var kvp in registry)
            {
                var id = (byte)kvp.Key;
                var transform = kvp.Value;
                var inverseId = (byte)transform.InverseId;

                // ✅ Forward test: A ➡ B⁻¹ ➡ A
                var forwardProfile = InputProfiler.CreateInputProfile(name: "ForwardTest",
                    sequence: new[] { id },
                    tRs: new[] { (byte)1 },
                    globalRounds: 1
                );
                var encrypted = localEnv.Crypto.Encrypt(forwardProfile.Sequence, forwardProfile.GlobalRounds, input);

                var reverseProfile = InputProfiler.CreateInputProfile(name: "ReverseTest",
                    sequence: new[] { inverseId },
                    tRs: new[] { (byte)1 },
                    globalRounds: 1
                );
                var decrypted = localEnv.Crypto.Decrypt(encrypted);

                if (!decrypted.SequenceEqual(input))
                    failed.Add($"Forward mismatch: {id} ({transform.Name}) ➡ {inverseId}");

                // ✅ Reverse test: B ➡ A⁻¹ ➡ B
                var inverseEncrypted = localEnv.Crypto.Encrypt(reverseProfile.Sequence, reverseProfile.GlobalRounds, input);
                var roundTrip = localEnv.Crypto.Decrypt(inverseEncrypted);

                if (!roundTrip.SequenceEqual(input))
                    failed.Add($"Reverse mismatch: {inverseId} ({registry[inverseId].Name}) ➡ {id}");
            }
        }

        if (failed.Count > 0)
            throw new Exception($"🔁 Non-reversible transforms detected:\n{string.Join("\n", failed)}");
    }
    private static void RunTest(Action<ExecutionEnvironment> testFunc, ExecutionEnvironment localEnv, string testName)
    {
        Console.WriteLine($"▶️  Running {testName}...");
        try
        {
            testFunc(localEnv);
            Console.WriteLine($"✅ {testName} passed.\n");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"❌ {testName} failed — {ex.Message}\n");
            throw new Exception($"❌ Regression test failed: {testName} — {ex.Message}", ex);
        }
    }
}

public static class SequenceParserTests
{
    public static int Run(CryptoLib? cryptoLib, bool quiet = false)
    {
        var logMessages = new List<string>();
        var errors = 0;

        var testCases = new List<(
            string input,
            SequenceFormat format,
            List<(string, int, int)> expected,
            Dictionary<string, string> expectedAttributes,
            bool shouldThrow)>
        {
            ("TransformA(ID:1)(TR:3) -> TransformB(ID:2)(TR:1) | (GR:2)",
                SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes,
                new List<(string, int, int)> { ("TransformA", 1, 3), ("TransformB", 2, 1) },
                new Dictionary<string, string> { { "GR", "2" } }, false),

            ("TransformC(ID:3)", SequenceFormat.ID,
                new List<(string, int, int)> { ("TransformC", 3, 1) }, null, false)!,

            ("TransformD", SequenceFormat.None, null, null, true)!,

            ("TransformE(ID:5)", SequenceFormat.ID,
                new List<(string, int, int)> { ("TransformE", 5, 1) }, null, false)!,

            ("TransformF(ID:6)(TR:4", SequenceFormat.ID | SequenceFormat.TRounds, null, null, true)!,

            ("  TransformG (ID:7) (TR:2)  ->   TransformH(ID:8)(TR:3) | (GR:4)  ",
                SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes,
                new List<(string, int, int)> { ("TransformG", 7, 2), ("TransformH", 8, 3) },
                new Dictionary<string, string> { { "GR", "4" } }, false),

            ("TransformI(ID:9), TransformJ(ID:10) -> TransformK(ID:11) - TransformL(ID:12)",
                SequenceFormat.ID,
                new List<(string, int, int)>
                    { ("TransformI", 9, 1), ("TransformJ", 10, 1), ("TransformK", 11, 1), ("TransformL", 12, 1) },
                null, false)!,

            ("", SequenceFormat.None, null, null, true)!,

            ("TransformA(ID:1)(TR:2) | (Mode:Exploratory) (InputType:Combined)",
                SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes,
                new List<(string, int, int)> { ("TransformA", 1, 2) },
                new Dictionary<string, string> { { "Mode", "Exploratory" }, { "InputType", "Combined" } }, false),

            ("TransformX(ID:99)(TR:5)",
                SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes,
                null, null, true)!
        };

        foreach (var (input, format, expected, expectedAttributes, shouldThrow) in testCases)
            try
            {
                var seqHelper = new SequenceHelper(cryptoLib);
                var parsedSequence = seqHelper.ParseSequenceFull(input, format);

                var transformsMatch = expected != null &&
                                      parsedSequence.Transforms
                                          .Select(t => (t.Name, (int)t.ID, t.TR))
                                          .SequenceEqual(expected);

                var attributesMatch = (expectedAttributes == null && parsedSequence.SequenceAttributes.Count == 0) ||
                                      (expectedAttributes != null &&
                                       parsedSequence.SequenceAttributes.OrderBy(kv => kv.Key)
                                           .SequenceEqual(expectedAttributes.OrderBy(kv => kv.Key)));

                var success = transformsMatch && attributesMatch;
                if (!success) errors++;

                logMessages.Add(success
                    ? $"✅ Test passed for input: {input}"
                    : $"❌ Test failed for input: {input}");
            }
            catch (Exception ex)
            {
                var caughtExpected = shouldThrow;
                logMessages.Add(caughtExpected
                    ? $"✅ Expected exception caught for input: {input} - {ex.Message}"
                    : $"❌ Unexpected exception for input: {input} - {ex.Message}");

                if (!caughtExpected) errors++;
            }

        if (!quiet || errors > 0)
        {
            Console.WriteLine("Running Sequence Tests...");
            foreach (var message in logMessages) Console.WriteLine(message);
            Console.WriteLine("Sequence Tests Completed.");
        }

        return errors;
    }
}