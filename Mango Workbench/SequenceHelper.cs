/*
 * SequenceHelper Module
 * =============================================
 * Project: Mango
 * Purpose: Provides canonical parsing, formatting, and validation logic
 *          for transform sequences within the Mango cryptographic system.
 *
 *          All sequence-aware components (e.g., Munge, RunSequence,
 *          ComparativeAnalysis) must route through this class to ensure
 *          consistent sequence handling.
 *
 *          Core responsibilities include:
 *            • Parsing string and byte[] sequences into structured forms.
 *            • Formatting sequences for CLI output and reporting.
 *            • Supporting TR/GR metadata, chunked views, and attribute extraction.
 *
 * Author: [Luke Tomasello, luke@tomasello.com]
 * Created: November 2024
 * License: [MIT]
 * =============================================
 */

using Mango.Cipher;
using Mango.Common;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;

namespace Mango.Utilities;

#region Sequence Management

[Flags]
public enum SequenceFormat
{
    None = 0x0,
    Bare = 0x01,
    ID = 0x02,
    TRounds = 0x04, // 🔹 Transform Rounds (formerly Rounds)
    GRounds = 0x08, // 🔹 Global Sequence Rounds
    InferTRounds = 0x10, // 🔹 Dynamically fetch transform rounds from the registry
    InferGRounds = 0x20, // 🔹 Dynamically fetch global rounds from StateManager GlobalRounds
    RightSideAttributes = 0x40 // 🔹 Includes right-side decorations if detected (e.g., Mode, InputType)
}

public class SequenceHelper
{
    private readonly CryptoLib _cryptoLib;

    public SequenceHelper(CryptoLib? cryptoLib)
    {
        _cryptoLib = cryptoLib ?? throw new ArgumentNullException(nameof(cryptoLib));
    }

    // 🔁 Formatter for InputProfile → string or List<string>
    //    Delegates to core FormatParsedSequence<T> after converting InputProfile into ParsedSequence.
    public T FormattedSequence<T>(InputProfile inputProfile, int chunks = 0, bool indent = false)
        where T : class
    {
        var parsed = new ParsedSequence();
        foreach (var (id, tr) in inputProfile.Sequence)
        {
            if (!_cryptoLib.TransformRegistry.TryGetValue(id, out var transform))
                throw new KeyNotFoundException($"Transform ID {id} not found.");

            parsed.Transforms.Add(new TransformDefinition(transform.Name, id, tr));
        }

        parsed.SequenceAttributes["GR"] = inputProfile.GlobalRounds.ToString();
        return FormatParsedSequence<T>(parsed,
            SequenceFormat.ID | SequenceFormat.TRounds | SequenceFormat.RightSideAttributes, chunks, indent);
    }

    // 🔁 Formatter for ParsedSequence → string or List<string>
    //    Delegates to core FormatParsedSequence<T> to maintain consistent formatting behavior.
    public T FormattedSequence<T>(ParsedSequence parsedSequence, SequenceFormat format, int chunks = 0,
        bool indent = false)
        where T : class
    {
        return FormatParsedSequence<T>(parsedSequence, format, chunks, indent);
    }

    // 🧠 Shared parser for InputProfile → ParsedSequence
    private ParsedSequence ConvertToParsedSequence(InputProfile profile)
    {
        var parsed = new ParsedSequence();
        foreach (var (id, tr) in profile.Sequence)
        {
            if (!_cryptoLib.TransformRegistry.TryGetValue(id, out var transform))
                throw new KeyNotFoundException($"Transform ID {id} not found.");

            parsed.Transforms.Add(new TransformDefinition(transform.Name, id, tr));
        }

        parsed.SequenceAttributes["GR"] = profile.GlobalRounds.ToString();
        return parsed;
    }

    // 🧱 Core Generic Formatter
    private T FormatParsedSequence<T>(ParsedSequence parsedSequence, SequenceFormat format, int chunks = 0,
        bool indent = false)
        where T : class
    {
        var inferTRounds = format.HasFlag(SequenceFormat.InferTRounds);

        var formattedTransforms = parsedSequence.Transforms.Select(t =>
        {
            if (!_cryptoLib.TransformRegistry.TryGetValue(t.ID, out var transform))
                throw new KeyNotFoundException($"Transform ID {t.ID} not found in registry.");

            //var tRounds = inferTRounds ? transform.Rounds : t.TR;
            var tRounds = t.TR;
            return FormattedTransform((transform.Name, t.ID, tRounds), format);
        }).ToList();

        List<string> rightSideAttributes = new();
        if (format.HasFlag(SequenceFormat.RightSideAttributes) && parsedSequence.SequenceAttributes.Any())
            rightSideAttributes.AddRange(parsedSequence.SequenceAttributes.Select(kvp => $"({kvp.Key}:{kvp.Value})"));

        if (format.HasFlag(SequenceFormat.InferGRounds) && !parsedSequence.SequenceAttributes.ContainsKey("GR"))
        {
            // the crypto lib no longer knows anything about 'static' global rounds. All global rounds are now passed
            //  to crypto lib via a profile
            //var globalRounds = _cryptoLib.Options.Rounds;
            //rightSideAttributes.Add($"(GR:{globalRounds})");
        }

        if (typeof(T) == typeof(List<string>))
        {
            var result = new List<string>(formattedTransforms);
            if (rightSideAttributes.Any())
                result.Add("| " + string.Join(" ", rightSideAttributes));
            return (result as T)!;
        }

        if (typeof(T) == typeof(string))
        {
            var joinedTransforms = chunks > 0
                ? FormatChunks(ChunkedSequence(formattedTransforms, chunks, indent))
                : string.Join(" -> ", formattedTransforms);

            var rightSide = rightSideAttributes.Any() ? " | " + string.Join(" ", rightSideAttributes) : "";
            return (joinedTransforms + rightSide as T)!;
        }

        throw new InvalidOperationException($"FormattedSequence<T> does not support return type {typeof(T).Name}.");
    }

    // ✅ Format single transform
    public string FormattedTransform((string name, int id, int tRounds) transform, SequenceFormat format)
    {
        var sb = new StringBuilder(transform.name);
        if (format.HasFlag(SequenceFormat.ID)) sb.Append($"(ID:{transform.id})");
        if (format.HasFlag(SequenceFormat.TRounds) || format.HasFlag(SequenceFormat.InferTRounds))
            sb.Append($"(TR:{transform.tRounds})");
        return sb.ToString();
    }
    // ✅ Format from (byte ID, byte TR)[]
    public string FormattedSequence(
        (byte ID, byte TR)[] sequenceWithRounds,
        SequenceFormat format,
        int chunks = 0,
        bool indent = false)
    {
        var parsed = new ParsedSequence();

        foreach (var (id, tr) in sequenceWithRounds)
        {
            if (!_cryptoLib.TransformRegistry.TryGetValue(id, out var transform))
                throw new KeyNotFoundException($"Transform ID {id} not found in registry.");

            parsed.Transforms.Add(new TransformDefinition(transform.Name, id, tr));
        }

        // the crypto lib no longer knows anything about 'static' global rounds. All global rounds are now passed
        //  to crypto lib via a profile
        //parsed.SequenceAttributes["GR"] = _cryptoLib.Options.Rounds.ToString(); // Optional fallback
        return FormatParsedSequence<string>(parsed, format, chunks, indent);
    }

    // ✅ Format from byte[]
    public string? FormattedSequence(byte[] sequence, SequenceFormat format, int chunks = 0, bool indent = false)
    {
        if (sequence == null || sequence.Length == 0) return null;
        var rawSequence = string.Join(" -> ",
            sequence.Select(id =>
                _cryptoLib.TransformRegistry.TryGetValue(id, out var transform) ? transform.Name : $"Unknown ({id})"));
        return FormattedSequence(rawSequence, format, chunks, indent);
    }

    // ✅ Format from string
    public string FormattedSequence(string rawSequence, SequenceFormat format, int chunks = 0, bool indent = false)
    {
        var (transforms, globalRounds) = ParseSequenceSummary(rawSequence, format);
        var formattedTransforms = transforms.Select(t => FormattedTransform(t, format)).ToList();
        var formattedSequence = chunks > 0
            ? FormatChunks(ChunkedSequence(formattedTransforms, chunks, indent))
            : string.Join(" -> ", formattedTransforms);
        return $"{formattedSequence} | (GR:{globalRounds})";
    }

    #region Utilities
    public int GetGlobalRounds(ParsedSequence parsed)
    {
        if (parsed == null)
            throw new ArgumentNullException(nameof(parsed));

        return parsed.SequenceAttributes.TryGetValue("GR", out var grValue) && int.TryParse(grValue, out var gr)
            ? gr
            : 1; // Default fallback if not set
    }


    /// Chunks a list of transform strings into lines of fixed size with optional indentation.
    public static string ChunkedSequence(List<string> transforms, int chunkSize, bool indent)
    {
        if (transforms == null || transforms.Count == 0)
            return string.Empty;

        var chunkedLines = Enumerable.Range(0, (transforms.Count + chunkSize - 1) / chunkSize)
            .Select(i => string.Join(" ", transforms.Skip(i * chunkSize).Take(chunkSize)))
            .ToList();

        if (indent)
            for (var i = 1; i < chunkedLines.Count; i++)
                chunkedLines[i] = "\t" + chunkedLines[i];

        return string.Join("\n", chunkedLines);
    }

    /// Formats chunked transform lines by inserting " -> " separators and appending right-side attributes.
    public static string FormatChunks(string chunked, string? rightSideAttr = null)
    {
        if (string.IsNullOrWhiteSpace(chunked))
            return string.Empty;

        // ✅ Strip any existing right-side (e.g., "| (GR:7)")
        string? inferredRightSide = null;

        // Attempt to extract right-side attributes (regardless of spacing)
        var pipeIndex = chunked.LastIndexOf('|');
        if (pipeIndex != -1)
        {
            // Extract everything after the pipe (trimmed)
            inferredRightSide = chunked.Substring(pipeIndex + 1).Trim();

            // Remove everything from the pipe onward from the chunked input
            chunked = chunked.Substring(0, pipeIndex).TrimEnd();

            return FormatChunks(chunked, inferredRightSide);
        }

        var lines = chunked.Split('\n').ToList();

        for (var i = 0; i < lines.Count; i++)
        {
            var parts = lines[i].Split(' ', StringSplitOptions.RemoveEmptyEntries);
            lines[i] = string.Join(" -> ", parts);

            if (i < lines.Count - 1) lines[i] += " ->";
        }

        if (!string.IsNullOrWhiteSpace(rightSideAttr)) lines[^1] += " | " + rightSideAttr;

        return string.Join("\n", lines);
    }

    public SequenceFormat DetermineFormat(string sequenceInput)
    {
        var format = SequenceFormat.None; // Start with an empty format

        // 🔹 Use _ParseSequence to extract left & right-side attributes
        var parsedSequence = ParseRawSequence(sequenceInput);

        // 🔹 Left-side parsing (Transform Rounds only)
        if (parsedSequence.Transforms.Any(t => t.TR != 1))
            format |= SequenceFormat.TRounds;
        else
            format |= SequenceFormat.InferTRounds;

        // ❌ REMOVE: Left-side GR parsing (GR is now sequence-wide)
        // if (parsedSequence.Transforms.Any(t => t.GR != 1))
        //     format |= SequenceFormat.GRounds;
        // else
        //     format |= SequenceFormat.InferGRounds;

        // 🔹 Right-side parsing (Detecting sequence-wide attributes)
        foreach (var key in parsedSequence.SequenceAttributes.Keys)
            if (typeof(GlobalsInstance).GetProperty(key, BindingFlags.Public | BindingFlags.Instance) != null)
            {
                format |= SequenceFormat.RightSideAttributes;
                break; // No need to continue checking once a valid attribute is found
            }

        return format;
    }

    // 🟢 Extracts a list of transform IDs from a formatted sequence string ✅
    public List<byte> GetIDs(string formattedSequence)
    {
        if (string.IsNullOrWhiteSpace(formattedSequence))
            return new List<byte>();

        return ParseRawSequence(formattedSequence).Transforms
            .Select(t => t.ID)
            .ToList();
    }

    // ✅ Takes a List<string> and calls the existing GetIDs(string)
    public List<byte> GetIDs(List<string> formattedSequenceList)
    {
        if (formattedSequenceList == null || formattedSequenceList.Count == 0)
            return new List<byte>(); // ✅ Return empty list instead of crashing

        // ✅ Filter out "(GR:X)" entries before processing
        var filteredList = formattedSequenceList.Where(s => !s.StartsWith("(GR:")).ToList();

        return GetIDs(string.Join(" -> ", filteredList));
    }

    // ✅ NEW Overload: Extract IDs directly from an already-parsed sequence
    public List<byte> GetIDs(ParsedSequence parsedSequence)
    {
        if (parsedSequence == null || parsedSequence.Transforms.Count == 0)
            return new List<byte>(); // ✅ Return empty list if sequence is null/empty

        return parsedSequence.Transforms.Select(t => t.ID).ToList();
    }

    public List<string> GetNames(List<byte> sequence)
    {
        if (sequence == null || sequence.Count == 0)
            return new List<string>(); // ✅ Return empty list instead of crashing

        return sequence.Select(id =>
            _cryptoLib.TransformRegistry.TryGetValue(id, out var transform)
                ? transform.Name
                : throw new KeyNotFoundException($"Unknown transform ID: {id}")
        ).ToList();
    }

    #endregion Utilities

    #region Sequence Parser

    // ✅ Data structure to store parsed sequence details
    public class ParsedSequence
    {
        public List<TransformDefinition> Transforms { get; } = new();

        public Dictionary<string, string> SequenceAttributes { get; } =
            new(); // Example: { "GR", "9" }, { "InputType", "Combined" }

        public override string ToString()
        {
            var transforms = string.Join(" -> ", Transforms);
            var sequenceAttrs = string.Join(", ", SequenceAttributes.Select(kvp => $"{kvp.Key}:{kvp.Value}"));
            return $"{transforms} | ({sequenceAttrs})";
        }
    }

    // ✅ Struct to represent a transform definition with metadata
    public struct TransformDefinition
    {
        public string Name { get; }
        public byte ID { get; }
        public int TR { get; } // ✅ Keep only TR, remove GR

        public TransformDefinition(string name, byte id, int tr) // ✅ Updated constructor
        {
            Name = name;
            ID = id;
            TR = tr;
        }

        public override string ToString()
        {
            return $"{Name}(ID:{ID})(TR:{TR})";
            // ✅ Remove GR from output
        }
    }

    /// <summary>
    /// Parses a raw sequence string into a simplified summary:
    /// (name, id, TR) list + global rounds (GR).
    /// Use <c>ParseSequenceFull</c> if full metadata is needed.
    /// </summary>
    public (List<(string Name, int, int TR)>, int globalRounds)
        ParseSequenceSummary(string rawSequence, SequenceFormat format = SequenceFormat.None)
    {
        var parsedSequence = ParseRawSequence(rawSequence, format);

        // ✅ Extract GR value, defaulting to 1 if not present
        var globalRounds = parsedSequence.SequenceAttributes.TryGetValue("GR", out var grValue)
            ? int.Parse(grValue)
            : 1;

        return (parsedSequence.Transforms.Select(t => (t.Name, (int)t.ID, t.TR)).ToList(), globalRounds);
    }

    public ParsedSequence ParseSequenceFull(string rawSequence, SequenceFormat format = SequenceFormat.None)
    {
        return ParseRawSequence(rawSequence, format); // ✅ Full result including right-side attributes
    }

    public ParsedSequence ParseSequenceFull(List<string> sequenceParts, SequenceFormat format = SequenceFormat.None)
    {
        if (sequenceParts == null || sequenceParts.Count == 0)
            throw new ArgumentException("Sequence parts cannot be null or empty.", nameof(sequenceParts));

        string rawSequence;

        // ✅ Check if the last element contains right-side attributes (not a transform decoration)
        var lastPart = sequenceParts.Last().Trim();
        if (sequenceParts.Count > 1 && lastPart.StartsWith("(") && lastPart.EndsWith(")"))
        {
            // 🔹 Separate transforms from right-side attributes
            var transformsPart = string.Join(" -> ", sequenceParts.Take(sequenceParts.Count - 1));
            var attributesPart = lastPart;

            rawSequence = $"{transformsPart} | {attributesPart}"; // ✅ Properly formatted sequence
        }
        else
        {
            // 🔹 If no right-side attributes, join normally
            rawSequence = string.Join(" -> ", sequenceParts);
        }

        // ✅ Delegate to the existing string-based function
        return ParseSequenceFull(rawSequence, format);
    }

    // ✅ Parses the sequence string into structured components
    private ParsedSequence ParseRawSequence(string rawSequence, SequenceFormat format = SequenceFormat.None)
    {
        if (string.IsNullOrWhiteSpace(rawSequence))
            throw new ArgumentException("Sequence cannot be null or empty.", nameof(rawSequence));

        var parsedSequence = new ParsedSequence();

        // 🔹 Step 1: Split raw sequence into left-side (transforms) and right-side (attributes)
        var parts = rawSequence.Split('|', 2);
        var transformPart = parts[0].Trim();
        var attributesPart = parts.Length > 1 ? parts[1].Trim() : string.Empty;

        // 🔹 Step 2: Parse Transforms (Handles multiple delimiters)
        var transformRegex = new Regex(@"(\w+)(?:\s*\(ID:(\d+)\))?(?:\s*\(TR:(\d+)\))?");
        var transformMatches = transformRegex.Matches(transformPart);

        foreach (Match match in transformMatches)
        {
            var name = match.Groups[1].Value.Trim();

            // ✅ Ensure the transform ID exists in the registry
            byte id;
            if (match.Groups[2].Success)
            {
                id = byte.Parse(match.Groups[2].Value);

                // 🔥 Ensure the ID exists in the registry
                if (!_cryptoLib.TransformRegistry.ContainsKey(id))
                    throw new ArgumentException($"Unknown transform ID: {id}");
            }
            else
            {
                // ✅ Lookup by name if ID was not provided
                id = (byte)(_cryptoLib.TransformRegistry.Values
                                .FirstOrDefault(t => t.Name!.Equals(name, StringComparison.OrdinalIgnoreCase))?.Id
                            ?? throw new ArgumentException($"Unknown transform: {name}"));
            }


            // ✅ Extract TR (Default to registry value if missing)
            var tr = match.Groups[3].Success ? int.Parse(match.Groups[3].Value)
                //: format.HasFlag(SequenceFormat.InferTRounds) ? _cryptoLib.TransformRegistry[id].Rounds : 1;
                : 1;

            parsedSequence.Transforms.Add(new TransformDefinition(name, id, tr));
        }

        // 🔹 Step 3: Parse Right-Side Attributes (e.g., Mode, InputType, Rounds)
        if (!string.IsNullOrEmpty(attributesPart))
        {
            parsedSequence.SequenceAttributes.Clear();
            foreach (var kvp in ParseSequenceAttributes(attributesPart))
                parsedSequence.SequenceAttributes[kvp.Key] = kvp.Value;
        }

        // 🔹 Step 4: Determine and Store GR Value
        // the crypto lib no longer knows anything about 'static' global rounds. All global rounds are now passed
        //  to crypto lib via a profile
        //if (!parsedSequence.SequenceAttributes.TryGetValue("GR", out var grValue))
        //    if (format.HasFlag(SequenceFormat.InferGRounds)) // ✅ Only infer if explicitly requested
        //        parsedSequence.SequenceAttributes["GR"] = _cryptoLib.Options.Rounds.ToString();

        return parsedSequence;
    }

    private Dictionary<string, string> ParseSequenceAttributes(string attributesPart)
    {
        var attributes = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // 🔹 Match key-value pairs like `(mode:exploratory)`, `(MaxSequenceLen: 6)`
        var matches = Regex.Matches(attributesPart, @"\((\w+):\s*([^)]+)\)");

        foreach (Match match in matches)
        {
            var key = match.Groups[1].Value.Trim();

            // ✅ Normalize "GR" to "Rounds" to match the actual global setting name
            if (key.Equals("GR", StringComparison.OrdinalIgnoreCase))
                key = "Rounds";

            var value = match.Groups[2].Value.Trim();

            // 🔹 Validate key exists in `Globals`
            var propInfo = typeof(GlobalsInstance).GetProperties(BindingFlags.Public | BindingFlags.Instance)
                .FirstOrDefault(p => p.Name.Equals(key, StringComparison.OrdinalIgnoreCase));

            if (propInfo == null)
                throw new ArgumentException($"Unknown sequence-wide property: {key}");

            // 🔹 Ensure value type is valid for the setting
            object? parsedValue;
            if (propInfo.PropertyType.IsEnum)
            {
                if (!Enum.TryParse(propInfo.PropertyType, value, true, out parsedValue))
                    throw new ArgumentException(
                        $"Invalid value '{value}' for {key}. Allowed values: {string.Join(", ", Enum.GetNames(propInfo.PropertyType))}");
            }
            else if (propInfo.PropertyType == typeof(int))
            {
                if (!int.TryParse(value, out var intValue))
                    throw new ArgumentException($"Invalid integer value for {key}: {value}");
                parsedValue = intValue;
            }
            else
            {
                parsedValue = value; // Assume it's a valid string
            }

            attributes[key.Equals("Rounds", StringComparison.OrdinalIgnoreCase) ? "GR" : key] = parsedValue.ToString()!;
        }

        return attributes;
    }

    #endregion Sequence Parser
}

#endregion Sequence Management