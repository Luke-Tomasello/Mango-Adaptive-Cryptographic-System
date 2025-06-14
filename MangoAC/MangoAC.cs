/*
 * MangoAC Module
 * =============================================
 * Project: Mango
 * Purpose: Standalone entry point demonstrating Mango’s adaptive encryption engine.
 *          Profiles input data to select the best cryptographic configuration and
 *          executes a full Encrypt → Decrypt → Verify pipeline.
 *
 *          This example:
 *            • Instantiates CryptoLib with a user-defined password
 *            • Automatically classifies input using InputProfiler
 *            • Retrieves the optimal transform sequence and rounds
 *            • Encrypts and decrypts data using the embedded header
 *            • Verifies round-trip integrity
 *
 *          Acts as the reference implementation for Mango’s
 *          runtime-adaptive cryptographic system (MangoAC).
 *
 * Author: [Luke Tomasello, luke@tomasello.com]
 * Created: November 2024
 * License: [MIT]
 * =============================================
 */

using Mango.Adaptive;
using Mango.AnalysisCore; // InputProfiler lives here
using Mango.Cipher;

namespace MangoAC;

internal class MangoAC
{
    private static void Main(string[] args)
    {
        // 🔐 Step 1: Create your cryptographic engine
        byte[] Salt = [0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5];
        var options = new CryptoLibOptions(Salt);
        var crypto = new CryptoLib("my password", options);

        // 📦 Step 2: Load or define your input data
        var input = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

        // 🔍 Step 3: Profile the input (detect type, best sequence + rounds)
        var profile = InputProfiler.GetInputProfile(input, OperationModes.Cryptographic, ScoringModes.Practical);

        // 🔒 Step 4: Encrypt using adaptive configuration
        var encrypted = crypto.Encrypt(profile, input);

        // 🔓 Step 5: Decrypt (CryptoLib pulls everything it needs from the header)
        var decrypted = crypto.Decrypt(encrypted);

        // ✅ Step 6: Verify 
        var match = input.SequenceEqual(decrypted!);
        Console.WriteLine(match ? "✅ Decryption successful!" : "❌ Decryption failed.");
    }
}