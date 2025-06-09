namespace Mango.Adaptive;
[Flags]
public enum TSVResultFlags
{
    None = 0,
    AsciiText = 1 << 0,
    Html = 1 << 1,
    CodeLike = 1 << 2,
    Binary = 1 << 3,
    HighEntropy = 1 << 4,
    Executable = 1 << 5,
    StructuredTelemetry = 1 << 6
}

/// <summary>
/// Produces a 32-byte Tomasello Signature Vector (TSV) from raw input data.
/// Unlike cryptographic hashes, the TSV captures structural and semantic features 
/// (e.g., entropy, binary density, textual or telemetry hints), enabling input-aware adaptation.
/// 
/// Mango uses the TSV for classification, regression validation, and cryptographic shaping,
/// without depending on any specific interpretation of its structure.
/// 
/// While opaque to most consumers, optional semantic flags and pretty-printing tools
/// allow deeper inspection for debugging and analysis.
/// </summary>
public static class TomaselloSignatureVector
{
    static bool _debugOutput = false;
    /// <summary>
    /// Computes the Tomasello Signature Vector (TSV) for the given input.
    /// Analyzes structural characteristics such as entropy, repetition, token patterns,
    /// printability, and format signatures to produce a deterministic 32-byte fingerprint.
    /// 
    /// The resulting TSV preserves high-level features of the input while remaining compact
    /// and opaque. It is used internally for classification, input profiling, and cryptographic shaping,
    /// but can also be introspected via interpretation tools for debugging or regression analysis.
    /// </summary>
    /// <param name="data">The raw input data to analyze.</param>
    /// <returns>A 32-byte TSV fingerprint representing the input's structural profile.</returns>
    public static byte[] Compute(ReadOnlySpan<byte> data, out TSVResultFlags flags)
    {
        Span<byte> result = stackalloc byte[32];
        flags = TSVResultFlags.None;

        // --- Designator bytes (0–15) ---
        if (LooksAsciiText(data))
        {
            result[0] |= 1 << 0;
            flags |= TSVResultFlags.AsciiText;
        }

        if (LooksLikeHtml(data))
        {
            result[0] |= 1 << 1;
            flags |= TSVResultFlags.Html;
        }

        if (LooksCodeLike(data))
        {
            result[0] |= 1 << 2;
            flags |= TSVResultFlags.CodeLike;
        }

        if (LooksBinary(data))
        {
            result[1] |= 1 << 0;
            flags |= TSVResultFlags.Binary;
        }

        if (LooksHighEntropy(data))
        {
            result[1] |= 1 << 1;
            flags |= TSVResultFlags.HighEntropy;
        }

        if (LooksExecutable(data))
        {
            result[3] |= 1 << 0;
            flags |= TSVResultFlags.Executable;
        }

        if (LooksStructuredTelemetry(data))
        {
            result[5] |= 1 << 0;
            flags |= TSVResultFlags.StructuredTelemetry;
        }

        // --- Attribute bytes (16–31) ---
        result[16] = (byte)(EstimateEntropy(data) * 255); // normalized
        result[17] = (byte)Math.Min(Math.Sqrt(MeasureTokenVariance(data)) * 10, 255);
        result[18] = (byte)Math.Min(Math.Sqrt(MeasureRepetition(data)) * 10, 255);

        return result.ToArray();
    }
    public static byte[] Compute(ReadOnlySpan<byte> data) =>
        Compute(data, out _);

    #region Helpers
    static bool LooksAsciiText(ReadOnlySpan<byte> data)
    {
        int printable = 0, total = Math.Min(data.Length, 2048);
        for (int i = 0; i < total; i++)
        {
            byte b = data[i];
            if (b >= 0x20 && b <= 0x7E || b == 0x0A || b == 0x0D || b == 0x09)
                printable++;
        }
        if (_debugOutput) Console.WriteLine($"[TextCheck] Printable ratio: {(double)printable / total:P1}");
        return printable > total * 0.85;
    }

    static bool LooksLikeHtml(ReadOnlySpan<byte> data)
    {
        var text = System.Text.Encoding.UTF8.GetString(data[..Math.Min(data.Length, 4096)]);
        bool found = text.Contains("<html") || text.Contains("<div") || text.Contains("<!DOCTYPE html");
        if (_debugOutput) Console.WriteLine($"[HTMLCheck] HTML tags found: {found}");
        return found;
    }

    static bool LooksCodeLike(ReadOnlySpan<byte> data)
    {
        var text = System.Text.Encoding.UTF8.GetString(data[..Math.Min(data.Length, 4096)]);
        bool found = text.Contains("public") || text.Contains("class") || text.Contains("#include") || text.Contains("def ");
        if (_debugOutput) Console.WriteLine($"[CodeCheck] Code-like patterns found: {found}");
        return found;
    }

    static bool LooksBinary(ReadOnlySpan<byte> data)
    {
        int zeroes = 0;
        for (int i = 0; i < Math.Min(data.Length, 1024); i++)
            if (data[i] == 0x00) zeroes++;
        if (_debugOutput) Console.WriteLine($"[BinaryCheck] Zero bytes: {zeroes}");
        return zeroes > 10;
    }

    static bool LooksHighEntropy(ReadOnlySpan<byte> data)
    {
        double entropy = EstimateEntropy(data);
        if (_debugOutput) Console.WriteLine($"[EntropyCheck] Normalized entropy: {entropy:F3}");
        return entropy > 0.85;
    }

    static bool LooksExecutable(ReadOnlySpan<byte> data)
    {
        bool mz = data.Length > 2 && data[0] == 0x4D && data[1] == 0x5A;
        if (_debugOutput) Console.WriteLine($"[ExecCheck] MZ header: {mz}");
        return mz;
    }

    static bool LooksStructuredTelemetry(ReadOnlySpan<byte> data)
    {
        double entropy = EstimateEntropy(data);
        int repetition = MeasureRepetition(data);
        int printable = 0;
        int count = Math.Min(data.Length, 2048);
        for (int i = 0; i < count; i++)
        {
            byte b = data[i];
            if (b >= 0x20 && b <= 0x7E || b == 0x0A || b == 0x0D || b == 0x09)
                printable++;
        }
        double printableRatio = printable / (double)count;

        bool looksStructured = printableRatio > 0.95 && entropy > 0.3 && entropy < 0.65 && repetition > 50;
        if (_debugOutput) Console.WriteLine($"[TelemetryCheck] Looks structured telemetry: {looksStructured}");
        return looksStructured;
    }

    static double EstimateEntropy(ReadOnlySpan<byte> data)
    {
        Span<int> counts = stackalloc int[256];
        int len = Math.Min(data.Length, 8192);
        for (int i = 0; i < len; i++) counts[data[i]]++;

        double entropy = 0.0;
        for (int i = 0; i < 256; i++)
        {
            if (counts[i] == 0) continue;
            double p = (double)counts[i] / len;
            entropy -= p * Math.Log2(p);
        }
        return entropy / 8.0; // normalize to [0,1]
    }

    static int MeasureTokenVariance(ReadOnlySpan<byte> data)
    {
        int words = 0, totalLen = 0, currentLen = 0;
        for (int i = 0; i < Math.Min(data.Length, 2048); i++)
        {
            byte b = data[i];
            if (b == ' ' || b == '\n' || b == '\r' || b == '\t')
            {
                if (currentLen > 0) { words++; totalLen += currentLen; currentLen = 0; }
            }
            else currentLen++;
        }
        if (words == 0) return 0;
        int avg = totalLen / words;
        int score = Math.Abs(avg - 5) * 10;
        if (_debugOutput) Console.WriteLine($"[TokenVar] Word count: {words}, AvgLen: {avg}, Score: {score}");
        return score;
    }

    static int MeasureRepetition(ReadOnlySpan<byte> data)
    {
        int repeats = 0;
        for (int i = 1; i < Math.Min(data.Length, 2048); i++)
            if (data[i] == data[i - 1]) repeats++;
        if (_debugOutput) Console.WriteLine($"[RepeatCheck] Repeat count: {repeats}");
        return repeats;
    }
#endregion Helpers
}
