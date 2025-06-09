using Mango.Cipher;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Mango.Common;
public record InputProfile(
    string Name,                    // e.g., "Combined", "Natural", etc. — Workbench-friendly label
    (byte ID, byte TR)[] Sequence,  // Transform sequence with rounds baked in
    int GlobalRounds,               // Required by core + Workbench for configuration
    double AggregateScore
);
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
        var mangoAvalanchePayload = cryptoLib.Encrypt(profile.Sequence, profile.GlobalRounds, modifiedInput);
        mangoAvalanchePayload = cryptoLib.GetPayloadOnly(mangoAvalanchePayload);

        // 🔑 KeyDependency: New CryptoLib with modified password and same rounds
        var keyDepOptions = new CryptoLibOptions(
            MangoSalt
        );
        var keyDepCryptoLib = new CryptoLib(modifiedPassword, keyDepOptions);

        var mangoKeyDependencyPayload = keyDepCryptoLib.Encrypt(profile.Sequence, profile.GlobalRounds, input);
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

    public static string GetProgectBaseDirectory()
    {
        if (_resolvedBaseDirectory != null)
            return _resolvedBaseDirectory;

        var current = AppContext.BaseDirectory;
        var marker = "Mango Systems";

        // Build list of probe paths in order of preference
        var probePaths = new List<string>();

        var markerIndex = current.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (markerIndex >= 0)
            probePaths.Add(current.Substring(0, markerIndex + marker.Length));

        probePaths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "Mango"));
        probePaths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "Mango"));
        probePaths.Add(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "Mango"));
        probePaths.Add(current); // Fallback

        // Normalize all candidate paths
        probePaths = probePaths
            .Select(p => Path.GetFullPath(p.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)))
            .ToList();

        // Use the first path that exists
        _resolvedBaseDirectory = probePaths.FirstOrDefault(Directory.Exists) ?? Path.GetFullPath(current);
        return _resolvedBaseDirectory;
    }

    public static string GetProgectDataDirectory()
    {
        if (_resolvedDataDirectory != null)
            return _resolvedDataDirectory;

        var baseDir = GetProgectBaseDirectory();
        var dataDir = Path.Combine(baseDir, "Data");

        _resolvedDataDirectory = Directory.Exists(dataDir)
            ? Path.GetFullPath(dataDir)
            : baseDir;

        return _resolvedDataDirectory;
    }

    public static string GetProjectOutputDirectory()
    {
        var path = Path.Combine(MangoPaths.GetProgectBaseDirectory(), "Output");
        Directory.CreateDirectory(path); // Ensure it exists
        return path;
    }
    //Contender Archive
    public static string GetProjectDirectory(string folder)
    {
        var path = Path.Combine(MangoPaths.GetProgectBaseDirectory(), folder);
        Directory.CreateDirectory(path); // Ensure it exists
        return path;
    }
}


