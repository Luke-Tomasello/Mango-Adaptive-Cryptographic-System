/*
 * MangoBM Module
 * =============================================
 * Project: Mango
 * Purpose: Demonstrates block-based encryption and decryption using Mango's
 *          adaptive transform engine. This example provides a low-friction
 *          template for encrypting large data streams using chunked processing.
 *
 *          Features:
 *            • Encrypts and decrypts 64KB of input as 64 separate blocks
 *            • First block embeds the full Mango header (TRs, GR, IV, Hash)
 *            • Remaining blocks are compact, headerless, and auto-synchronized
 *            • Stateless per-block calls via EncryptBlock / DecryptBlock
 *
 *          This demo forms the basis for implementing conventional block modes:
 *            → ECB (demonstrated)
 *            → CBC, CTR (extendable with external XOR or counter logic)
 *
 *          Limitations:
 *            • No padding — input must be block-aligned
 *            • No internal chaining — chaining logic must be externalized
 *            • Transform profile is fixed per session (from first block)
 *
 * Author: [Luke Tomasello, luke@tomasello.com]
 * Created: November 2024
 * License: [MIT]
 * =============================================
 */

using Mango.Adaptive;
using Mango.AnalysisCore;
using Mango.Cipher;

namespace MangoBM;
// ==========================================================
// 🧩 MangoBM – Block-Based Encryption & Decryption Demo
// ==========================================================
//
// 🔍 What This Module Demonstrates:
// ----------------------------------
// ✅ Encrypting large data split into discrete blocks
// ✅ First block embeds the Mango encryption header (TRs, GR, IV, Hash)
// ✅ Remaining blocks are headerless (compact)
// ✅ The header is auto-cached on first Encrypt/Decrypt
// ✅ Fully symmetric: chunked encryption + decryption roundtrip verified
//
// 🚀 What Developers Can Extend From Here:
// -----------------------------------------
// While this sample uses a basic block mode (no chaining, no IV feedback),
// it lays the groundwork for building conventional modes such as:
//
// • ECB (Electronic Codebook) – ✅ Already implemented.
//   - Each block is encrypted independently.
//   - No chaining, no dependencies between blocks.
//   - Already demonstrated in this module.
//
// • CBC (Cipher Block Chaining) – 🟡 Developer-extendable
//   - Requires XOR of each plaintext block with the **previous ciphertext block**.
//   - First block uses IV from Mango header (already included).
//   - Developers can insert XOR logic before/after Mango encryption.
//
// • CTR (Counter Mode) – 🟡 Developer-extendable
//   - Requires a nonce + counter for each block.
//   - Would involve custom transform logic outside of Mango core.
//   - Still feasible, but may require custom preprocessing.
//
// • CFB/OFB – 🔴 Not directly supported
//   - Require more complex feedback chaining across blocks.
//   - Would need custom feedback wiring and Mango transform sequencing.
//   - May be possible, but requires deep familiarity with Mango internals.
//
// ⚠️ Caveats:
// -----------------------------------------
// - MangoBM does not do padding. Your data should be block-aligned.
// - For deterministic outputs (CTR-like behavior), careful control of IV and transform state is required.
// - This demo assumes a static transform profile across all blocks (from first block).
//
// ✨ Summary:
// -----------------------------------------
// This is a low-friction, high-performance chunked encryption model.
// It shows **what's possible**, but encourages developers to build their
// own flavor of chaining, padding, or nonce-driven schemes on top of Mango.
//
// "We hand you the forge. What you craft is up to you." 🛠️

internal class MangoBM
{
    private static void Main(string[] args)
    {
        // 📦 Step 1: Create input blocks (64KB split into 64 blocks of 1024 bytes)
        List<byte[]> inputBlocks = Enumerable.Range(0, 64)
            .Select(i => Enumerable.Range(0, 1024).Select(b => (byte)((i + b) % 256)).ToArray())
            .ToList();

        byte[] Salt = [0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5];
        var options = new CryptoLibOptions(Salt);
        var crypto = new CryptoLib("my password", options);

        // 📊 Step 2: Analyze first block
        var profile = InputProfiler.GetInputProfile(inputBlocks[0], OperationModes.Cryptographic, ScoringModes.Practical);

        // 🔐 Step 3: Encrypt first block (header included)
        List<byte[]> outputBlocks = new();
        var encryptedFirst = crypto.Encrypt(profile, inputBlocks[0]);
        outputBlocks.Add(encryptedFirst!);

        // 🔐 Step 4: Encrypt remaining blocks (headerless)
        for (var i = 1; i < inputBlocks.Count; i++)
        {
            var encrypted = crypto.EncryptBlock(inputBlocks[i]);
            outputBlocks.Add(encrypted!);
        }

        // 🔓 Step 5: Decrypt first block (reads + caches config)
        List<byte[]> decryptedBlocks = new();
        var decryptedFirst = crypto.Decrypt(outputBlocks[0]);
        decryptedBlocks.Add(decryptedFirst!);

        // 🔓 Step 6: Decrypt remaining blocks
        for (var i = 1; i < outputBlocks.Count; i++)
        {
            var decrypted = crypto.DecryptBlock(outputBlocks[i]);
            decryptedBlocks.Add(decrypted!);
        }

        // ✅ Step 7: Validate result
        var original = Flatten(inputBlocks);
        var restored = Flatten(decryptedBlocks);

        Console.WriteLine(original.SequenceEqual(restored)
            ? "✅ Block-mode roundtrip successful!"
            : "❌ Block-mode roundtrip failed.");
    }

    private static byte[] Flatten(List<byte[]> blocks)
    {
        return blocks.SelectMany(b => b!).ToArray();
    }
}