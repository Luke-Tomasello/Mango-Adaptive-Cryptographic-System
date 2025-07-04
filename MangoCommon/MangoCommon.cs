﻿using Mango.Cipher;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Mango.Common;

public class InputProfileDto
{
    public List<List<byte>> Sequence { get; set; } = new();
    public int GlobalRounds { get; set; }
    public double AggregateScore { get; set; }
}
public class Scoring
{
    public static readonly byte[] MangoSalt = [0x1A, 0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92, 0xA3, 0xB4, 0xC5];
    public static readonly byte[] MutationSeed = [0x1D, 0x13, 0x28, 0x12];

    public static (byte[] MangoAvalanchePayload, byte[] MangoKeyDependencyPayload)
        ProcessAvalancheAndKeyDependency(
            CryptoLib cryptoLib,
            byte[] input,
            string password,
            InputProfile profile)
    {
        // 🧠 Mutation Seed Change (2025-05-29):
        // We previously derived the mutation seed from the reversed profile sequence:
        // var mutationSeed = ReverseSequence.Select(p => p.ID).ToArray();
        // This introduced non-determinism: profile changes caused mutation changes,
        // which led to "score drift" in Avalanche and KeyDependency metrics.
        // To ensure stable, repeatable results across time, machines, and profile edits,
        // we now use a fixed, static seed:
        var mutationSeed = MutationSeed;

        // ✏️ Modify input and password using reverse sequence
        var modifiedInput = ModifyInput(mutationSeed, input);
        var modifiedPasswordBytes = ModifyInput(mutationSeed, Encoding.UTF8.GetBytes(password));
        var modifiedPassword = Encoding.UTF8.GetString(modifiedPasswordBytes!);

        // 🔐 Avalanche: Mango encryption with modified input
        var mangoAvalanchePayload = cryptoLib.Encrypt(profile, modifiedInput);
        mangoAvalanchePayload = cryptoLib.GetPayloadOnly(mangoAvalanchePayload);

        // 🔑 KeyDependency: New CryptoLib with modified password and same rounds
        var keyDepOptions = new CryptoLibOptions(
            MangoSalt
        );
        var keyDepCryptoLib = new CryptoLib(modifiedPassword, keyDepOptions);

        var mangoKeyDependencyPayload = keyDepCryptoLib.Encrypt(profile, input);
        mangoKeyDependencyPayload = keyDepCryptoLib.GetPayloadOnly(mangoKeyDependencyPayload);

        return (mangoAvalanchePayload, mangoKeyDependencyPayload);
    }

    /// <summary>
    /// Modifies the input buffer by flipping a single bit determined by hashing the provided mutationSeed.
    /// This ensures deterministic input mutation for avalanche and key dependency testing.
    /// </summary>
    /// <param name="mutationSeed">A byte sequence used as the mutation seed (now static for consistency).</param>
    /// <param name="input">The original input buffer to be modified.</param>
    /// <returns>A new byte array with one deterministically selected bit flipped.</returns>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static byte[] ModifyInput(byte[] mutationSeed, byte[] input)
    {
        // Hash the mutation seed to determine the bit to flip
        using var sha256 = SHA256.Create();
        var seedHash = sha256.ComputeHash(mutationSeed);
        var hashValue = BinaryPrimitives.ReadInt64LittleEndian(seedHash); // Convert first 8 bytes to a long

        var totalBits = input.Length * 8; // Total number of bits in the input
        var bitToFlip = (int)(Math.Abs(hashValue) % totalBits); // Map hash to a valid bit index

        // Create a copy of the input and flip the calculated bit
        var mutatedInput = (byte[])input.Clone();
        var byteIndex = bitToFlip / 8;
        var bitIndex = bitToFlip % 8;
        mutatedInput[byteIndex] ^= (byte)(1 << bitIndex); // Flip the bit

        return mutatedInput;
    }
}

public static class MangoPaths
{
    private static string? _resolvedBaseDirectory;
    private static string? _resolvedDataDirectory;

    public static string GetProjectBaseDirectory()
    {
        if (_resolvedBaseDirectory != null)
            return _resolvedBaseDirectory;

        var current = new DirectoryInfo(AppContext.BaseDirectory);
        var anchorFolderName = "Mango Workbench";

        // Walk up the directory tree until we find "Mango Workbench"
        while (current != null && !current.Name.Equals(anchorFolderName, StringComparison.OrdinalIgnoreCase))
        {
            current = current.Parent;
        }

        // If we found the anchor folder, return its parent
        if (current?.Parent != null)
        {
            _resolvedBaseDirectory = current.Parent.FullName;
            return _resolvedBaseDirectory;
        }

        // Fallbacks: known application data locations or current base
        var fallbackPaths = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mango"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Mango"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Mango"),
            AppContext.BaseDirectory // Last resort
        };

        _resolvedBaseDirectory = fallbackPaths.FirstOrDefault(Directory.Exists)
                                 ?? Path.GetFullPath(AppContext.BaseDirectory);

        return _resolvedBaseDirectory;
    }

    public static string GetProgectDataDirectory()
    {
        if (_resolvedDataDirectory != null)
            return _resolvedDataDirectory;

        var baseDir = GetProjectBaseDirectory();
        var dataDir = Path.Combine(baseDir, "Data");

        _resolvedDataDirectory = Directory.Exists(dataDir)
            ? Path.GetFullPath(dataDir)
            : baseDir;

        return _resolvedDataDirectory;
    }

    public static string GetProjectOutputDirectory()
    {
        var path = Path.Combine(MangoPaths.GetProjectBaseDirectory(), "Output");
        Directory.CreateDirectory(path); // Ensure it exists
        return path;
    }
    //Contender Archive
    public static string GetProjectDirectory(string folder)
    {
        var path = Path.Combine(MangoPaths.GetProjectBaseDirectory(), folder);
        Directory.CreateDirectory(path); // Ensure it exists
        return path;
    }
}


