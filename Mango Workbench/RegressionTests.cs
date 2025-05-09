﻿/*
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
using Mango.Cipher;
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
        RunTest(DataEvaluatorClassificationTest, localEnv, "Data Classification Test");
        RunTest(TransformReversibilityTest, localEnv, "Transform Reversibility Test");
        RunTest(_ => ValidateBlockModeRoundtrip(), localEnv, "Block Mode Roundtrip Test");
        RunTest(SmallBlockTest, localEnv, "Small Block Test");
    }

    private static void RunTest(Action<ExecutionEnvironment> testFunc, ExecutionEnvironment localEnv, string testName)
    {
        try
        {
            testFunc(localEnv);
        }
        catch (Exception ex)
        {
            throw new Exception($"❌ Regression test failed: {testName} — {ex.Message}", ex);
        }
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

                var profile = InputProfiler.GetInputProfile(fullInput);

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

                    var encrypted = localEnv.Crypto.Encrypt(new[] { id }, testInput);

                    if (id != inverseId && encrypted.SequenceEqual(testInput))
                        throw new Exception($"[SingleTx] ID:{id} ({transform.Name}) failed to alter input (len={len})");

                    var decrypted = localEnv.Crypto.Decrypt(new[] { inverseId }, encrypted);

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
        var crypto = new CryptoLib("my password");

        var profile = InputProfiler.GetInputProfile(inputBlocks[0]);

        List<byte[]> outputBlocks = new();
        var encryptedFirst = crypto.Encrypt(profile.Sequence, profile.GlobalRounds, inputBlocks[0]);
        outputBlocks.Add(encryptedFirst);

        for (var i = 1; i < inputBlocks.Count; i++)
        {
            var encrypted = crypto.EncryptBlock(inputBlocks[i]);
            outputBlocks.Add(encrypted);
        }

        // 🔄 Step 3: Simulate decrypting on a new session / machine
        crypto = new CryptoLib("my password");

        List<byte[]> decryptedBlocks = new();
        var decryptedFirst = crypto.Decrypt(outputBlocks[0]);
        decryptedBlocks.Add(decryptedFirst);

        for (var i = 1; i < outputBlocks.Count; i++)
        {
            var decrypted = crypto.DecryptBlock(outputBlocks[i]);
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

        var encrypted = localEnv.Crypto.Encrypt(new byte[] { 25, 23, 27, 24 }, sampleInput);
        var decrypted = localEnv.Crypto.Decrypt(new byte[] { 25, 26, 23, 24 }, encrypted);

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
            var saveCryptoRounds = localEnv.Crypto.Options.Rounds;
            var saveGlobalRounds = localEnv.Globals.Rounds;
            localStatEnvironment.Rsm.IncGlobalRound();
            if (localEnv.Crypto.Options.Rounds != saveCryptoRounds + 1 ||
                localEnv.Globals.Rounds != saveGlobalRounds + 1)
                throw new Exception("Global rounds increment did not apply correctly.");

            localStatEnvironment.Rsm.GlobalRounds = 6;
            if (localEnv.Crypto.Options.Rounds != 6 || localStatEnvironment.Rsm.GlobalRounds != 6)
                throw new Exception("Global rounds assignment failed.");

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
    // ✅ Generates **4096-byte test inputs** from **Natural, Sequence, and Random** categories.
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
        // benchmark sequence
        var formattedSequence =
            "FrequencyEqualizerInvTx -> SlidingMaskOverlayTx -> MicroBlockShufflerInvTx -> FrequencyEqualizerFwdTx";

        using (new LocalEnvironment(localEnv, formattedSequence))
        {
            localEnv.Globals.UpdateSetting("InputType", InputType.Combined);
            localEnv.Globals.UpdateSetting("Mode", OperationModes.Cryptographic);
            localEnv.Globals.UpdateSetting("Rounds", 9);

            var seq = new SequenceHelper(localEnv.Crypto);
            var sequence = seq.GetIDs(formattedSequence);
            var encrypted = localEnv.Crypto.Encrypt(sequence.ToArray(), localEnv.Globals.Input);
            var payload = localEnv.Crypto.GetPayloadOnly(encrypted);
            var reverseSequence = GenerateReverseSequence(localEnv.Crypto, sequence.ToArray());
            var decrypted = localEnv.Crypto.Decrypt(reverseSequence, encrypted);

            if (!decrypted!.SequenceEqual(localEnv.Globals.Input))
                throw new Exception("Pipeline is not reversible.");

            var (avalanche, _, keydep, _) =
                ProcessAvalancheAndKeyDependency(localEnv, GlobalsInstance.Password, sequence);
            var analysisResults =
                localEnv.CryptoAnalysis.RunCryptAnalysis(payload, avalanche, keydep, localEnv.Globals.Input);

            localEnv.Globals.UpdateSetting("UseMetricScoring", true);
            var metricScore = localEnv.CryptoAnalysis.CalculateAggregateScore(analysisResults, true);

            localEnv.Globals.UpdateSetting("UseMetricScoring", false);
            var practicalScore = localEnv.CryptoAnalysis.CalculateAggregateScore(analysisResults, false);

            if (Math.Abs(metricScore - 78.708213502546386) > 0.0001)
                throw new Exception("Metric score mismatch.");
            if (Math.Abs(practicalScore - 58.571428571428584) > 0.0001)
                throw new Exception("Practical score mismatch.");
        }
    }

    // 🔹 Regression Test: Validate DataEvaluator Classification Accuracy
    //
    // ✅ Configures `InputType` to each possible data classification: Sequence, Natural, Random, and Combined.
    // ✅ Runs the DataEvaluator to verify **correct classification**.
    // ✅ Uses assertions to confirm that the detected type matches the expected type.
    // ✅ Ensures DataEvaluator works within the expected environment setup.
    //
    // 🔥 This guarantees that Mango's classification logic remains **accurate and consistent across all data types**.
    private static void DataEvaluatorClassificationTest(ExecutionEnvironment localEnv)
    {
        var expected = new Dictionary<InputType, string>
        {
            { InputType.Sequence, "Sequence" },
            { InputType.Random, "Random" },
            { InputType.Natural, "Natural" },
            { InputType.Combined, "Combined" }
        };

        foreach (var (inputType, expectedLabel) in expected)
            using (new LocalEnvironment(localEnv))
            {
                localEnv.Globals.UpdateSetting("InputType", inputType);
                var actual = InputProfiler.GetInputProfile(localEnv.Globals.Input).Name;
                if (actual != expectedLabel)
                    throw new Exception($"Classification mismatch: expected {expectedLabel}, got {actual}");
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

            foreach (var kvp in localEnv.Crypto.TransformRegistry)
            {
                var id = (byte)kvp.Key;
                var inverse = (byte)kvp.Value.InverseId;

                var encrypted = localEnv.Crypto.Encrypt(new[] { id }, input);
                var decrypted = localEnv.Crypto.Decrypt(new[] { inverse }, encrypted);

                if (!decrypted.SequenceEqual(input))
                    failed.Add($"ID: {id} ({kvp.Value.Name})");
            }
        }

        if (failed.Count > 0)
            throw new Exception($"Non-reversible transforms detected: {string.Join(", ", failed)}");
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