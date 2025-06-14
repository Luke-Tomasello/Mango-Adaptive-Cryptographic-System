/*
 * MangoZI Module
 * =============================================
 * Project: Mango
 * Purpose: Standalone entry point demonstrating Mango’s zone-influenced adaptive encryption engine.
 *          Profiles input data to select the best cryptographic configuration,
 *          optionally applies a ZoneInfo label, and executes a full Encrypt → Decrypt → Verify pipeline.
 *
 *          This example:
 *            • Instantiates CryptoLib with a user-defined password and ZoneInfo
 *            • Automatically classifies input using InputProfiler
 *            • Retrieves the optimal transform sequence and rounds
 *            • Encrypts and decrypts data using the embedded header
 *            • Verifies round-trip integrity
 *
 *          Acts as the reference implementation for Mango’s
 *          zone-enhanced adaptive cryptographic system (MangoZI).
 *
 * Author: [Luke Tomasello, luke@tomasello.com]
 * Created: April 2025
 * License: [MIT]
 * =============================================
 */

using Mango.Adaptive;
using Mango.AnalysisCore; // InputProfiler lives here
using Mango.Cipher;

namespace MangoZI;

internal class MangoZI
{
    private static void Main(string[] args)
    {
        // 🔐 Step 1: Create your cryptographic engine with optional ZoneInfo
        byte[] Salt = [0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5];
        var options = new CryptoLibOptions(Salt, zoneInfo: "XYZ Corp. Marketing"u8.ToArray());
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