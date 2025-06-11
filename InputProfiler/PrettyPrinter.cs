namespace Mango.Adaptive;

public static class TSVPrettyPrinter
{
    private static readonly Dictionary<TSVResultFlags, string> descriptions = new()
    {
        { TSVResultFlags.AsciiText, "<yellow>Mostly printable text</yellow>" },
        { TSVResultFlags.Html, "<yellow>May contain HTML or markup</yellow>" },
        { TSVResultFlags.CodeLike, "<yellow>Code-like structure (braces, keywords)</yellow>" },
        { TSVResultFlags.Binary, "<green>Binary or non-textual data</green>" },
        { TSVResultFlags.HighEntropy, "<green>High entropy signal</green>" },
        { TSVResultFlags.Executable, "<green>Executable or machine code</green>" },
        { TSVResultFlags.StructuredTelemetry, "<yellow>Structured telemetry format</yellow>" }
    };

    public static string[] PrettyPrint(byte[] tsv, TSVResultFlags flags)
    {
        var result = new List<string>
        {
            "TSV Pretty Print:",
            "\n Byte | Hex | Flags                          | Meaning",
            "------+-----+-------------------------------+--------------------------------------------"
        };

        // Flag summary row
        var matchedFlags = Enum.GetValues<TSVResultFlags>()
            .Where(f => f != TSVResultFlags.None && flags.HasFlag(f))
            .ToArray();

        if (matchedFlags.Length == 0)
        {
            result.Add($"    * | --  | None                           | <gray>No semantic meaning assigned</gray>");
        }
        else
        {
            result.Add($"    * | --  | {string.Join(" | ", matchedFlags),-30} | {string.Join(", ", matchedFlags.Select(f => descriptions.TryGetValue(f, out var d) ? d : $"<gray>{f}</gray>"))}");
        }

        // Scalar-based interpretation (bytes 16–31)
        for (int i = 16; i < tsv.Length; i++)
        {
            byte b = tsv[i];

            string label = (i switch
            {
                16 => "Entropy",
                17 => "TokenVar",
                18 => "Repetition",
                _ => null
            })!;
            if (label == null)
                continue;

            string meaning = label switch
            {
                "Entropy" => b switch
                {
                    0 => "<red>Very low entropy</red>",
                    <= 85 => "<yellow>Low entropy</yellow>",
                    <= 170 => "<green>Moderate entropy</green>",
                    _ => "<green>Very high entropy</green>"
                },
                "TokenVar" => b switch
                {
                    0 => "<red>No token variety</red>",
                    <= 50 => "<yellow>Low token variety</yellow>",
                    <= 100 => "<green>Moderate token variety</green>",
                    _ => "<green>Highly variable tokens</green>"
                },
                "Repetition" => b switch
                {
                    0 => "<green>No repetition</green>",
                    <= 60 => "<green>Low repetition</green>",
                    <= 120 => "<yellow>Moderate repetition</yellow>",
                    _ => "<red>Heavy repetition</red>"
                },
                _ => "<gray>No semantic meaning assigned</gray>"
            };

            result.Add($"{i,5} | {b:X2}  | {label,-30} | {meaning}");
        }

        return result.ToArray();
    }
}








