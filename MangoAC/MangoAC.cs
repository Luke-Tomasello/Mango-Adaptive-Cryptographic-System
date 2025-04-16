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

using Mango.Adaptive; // InputProfiler lives here
using Mango.Cipher;

namespace MangoAC
{
    internal class MangoAC
    {
        static void Main(string[] args)
        {
            // 🔐 Step 1: Create your cryptographic engine
            var crypto = new CryptoLib("my password");

            // 📦 Step 2: Load or define your input data
            byte[] input = Enumerable.Range(0, 256).Select(i => (byte)i).ToArray();

            // 🔍 Step 3: Profile the input (detect type, best sequence + rounds)
            InputProfile profile = InputProfiler.GetInputProfile(input);

            // 🔒 Step 4: Encrypt using adaptive configuration
            byte[] encrypted = crypto.Encrypt(profile.Sequence, profile.GlobalRounds, input);

            // 🔓 Step 5: Decrypt (CryptoLib pulls everything it needs from the header)
            byte[] decrypted = crypto.Decrypt(encrypted);

            // ✅ Step 6: Verify
            bool match = input.SequenceEqual(decrypted);
            Console.WriteLine(match ? "✅ Decryption successful!" : "❌ Decryption failed.");
        }
    }
}