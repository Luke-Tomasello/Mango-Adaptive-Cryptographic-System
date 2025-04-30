/*
 * MangoReport Module
 * =============================================
 * Project: Mango
 * Purpose: Provides rich reporting capabilities for analysis and visualization
 *          of cryptographic metrics and evaluation summaries. Supports multiple
 *          output formats including plain text, CSV, and RTF.
 *
 *          This module enables:
 *            • Multi-format exports: SCR, TXT, CSV, and RTF
 *            • Seamless screen output using ColorConsole
 *            • Auto-tag stripping and formatting conversion
 *            • Section-aware rendering and reporting pipelines
 *            • Color tag translation to RTF with dynamic palette mapping
 *
 *          Often used in:
 *            → Output rendering for comparative analysis
 *            → Post-Munge reports for contender inspection
 *            → Diagnostic snapshots in both dev and production runs
 *
 * Author: [Luke Tomasello, luke@tomasello.com]
 * Created: November 2024
 * License: [MIT]
 * =============================================
 */

using Mango.Utilities;
using System.Text;
using System.Text.RegularExpressions;

namespace Mango.Reporting;

public class ReportHelper
{
    [Flags]
    public enum ReportFormat
    {
        TXT = 1,
        RTF = 2,
        CSV = 4,
        SCR = 8
    }

    /// <summary>
    /// Writes the formatted report output to the specified destinations.
    /// </summary>
    public static void Report(ReportFormat formats, List<string>[] sections, params string[]? outputFiles)
    {
        // Ensure outputFiles is never null
        outputFiles ??= [];

        // Compute required file count
        var requiredFiles = CountSetBits((int)formats) - (formats.HasFlag(ReportFormat.SCR) ? 1 : 0);

        // ✅ Gracefully handle missing filenames
        if (outputFiles.Length != requiredFiles)
        {
            if (requiredFiles == 0)
                // No output files expected (only SCR)
                outputFiles = [];
            else
                throw new ArgumentException($"Expected {requiredFiles} file names, but received {outputFiles.Length}.");
        }

        var fileIndex = 0;

        // ✅ Handle SCR (screen output)
        if (formats.HasFlag(ReportFormat.SCR))
            foreach (var section in sections)
            foreach (var line in section)
            {
                if (line.Equals(_sectionBreak, StringComparison.Ordinal))
                    continue;

                ColorConsole.WriteLine(line);
            }

        // ✅ Handle TXT Output (Remove color tags & ignore section breaks)
        if (formats.HasFlag(ReportFormat.TXT) && fileIndex < outputFiles.Length)
            File.WriteAllLines(outputFiles[fileIndex++],
                sections.SelectMany(section => section)
                    .Where(line => !line.Equals(_sectionBreak, StringComparison.Ordinal)) // 🚀 Ignore section breaks
                    .Select(ColorConsole.RemoveColorTags));

        // ✅ Handle RTF
        if (formats.HasFlag(ReportFormat.RTF) && fileIndex < outputFiles.Length)
            File.WriteAllText(outputFiles[fileIndex++], ConvertToRTF(sections.SelectMany(s => s).ToList()));

        // ✅ Handle CSV Output (Remove color tags, escape quotes, and ignore section breaks)
        if (formats.HasFlag(ReportFormat.CSV) && fileIndex < outputFiles.Length)
            File.WriteAllLines(outputFiles[fileIndex++],
                sections.SelectMany(section => section)
                    .Where(line => !line.Equals(_sectionBreak, StringComparison.Ordinal)) // 🚀 Ignore section breaks
                    .Select(line => "\"" + ColorConsole.RemoveColorTags(line).Replace("\"", "\"\"") + "\""));
    }


    public static void Report(ReportFormat formats, List<string> section, params string[] outputFiles)
    {
        Report(formats, new List<string>[] { section }, outputFiles);
    }

    public static void WriteLine(ReportFormat formats, string message, params string[] outputFiles)
    {
        // Append a newline to ensure proper separation
        Report(formats, new List<string> { message + Environment.NewLine }, outputFiles);
    }

    public static void Write(ReportFormat formats, string message, params string[] outputFiles)
    {
        // Append a newline to ensure proper separation
        Report(formats, new List<string> { message }, outputFiles);
    }

    /// <summary>
    /// Counts the number of set bits in an integer (used for format counting).
    /// </summary>
    private static int CountSetBits(int value)
    {
        var count = 0;
        while (value > 0)
        {
            count += value & 1;
            value >>= 1;
        }

        return count;
    }

    private const string _sectionBreak = "<SECTION_BREAK>";
    public static List<string> SectionBreak => new() { _sectionBreak };

    /// <summary>
    /// Writes plain text output (removes color tags using ColorConsole).
    /// </summary>
    private static void WriteText(List<string> raw, string filePath)
    {
        File.WriteAllLines(filePath, raw.Select(ColorConsole.RemoveColorTags));
    }

    /// <summary>
    /// Converts color tags to RTF-compatible formatting, preserving colors.
    /// </summary>
    private static string ConvertToRTF(List<string> raw)
    {
        var sb = new StringBuilder();

        // Define RTF header with dynamically generated color table
        var colorMap = BuildRTFColorTable(raw);
        sb.Append(@"{\rtf1\ansi\deff0 {\colortbl;" + string.Join(";", colorMap.Values) + ";}");

        // Append all formatted lines with \par
        foreach (var lx in raw)
        {
            var line = lx;
            if (line.Equals(_sectionBreak, StringComparison.Ordinal))
                line = "";

            var formattedLine = ReplaceColorTagsWithRTF(line, colorMap);
            sb.Append(@"\par " + formattedLine);
        }

        // ✅ Ensure final newline consistency
        sb.Append(@"\par ");

        sb.Append("}"); // Explicitly close RTF

        return sb.ToString();
    }

    /// <summary>
    /// Builds an RTF color table based on detected color tags.
    /// </summary>
    private static Dictionary<string, string> BuildRTFColorTable(List<string> lines)
    {
        var colorTable = new Dictionary<string, string>();
        var colorIndex = 1; // RTF color table starts at index 1

        foreach (var line in lines)
        foreach (var tag in ExtractColorTags(line))
            if (!colorTable.ContainsKey(tag))
            {
                colorTable[tag] = ConvertColorTagToRTF(tag);
                colorIndex++;
            }

        return colorTable;
    }

    /// <summary>
    /// Extracts color tags from a given line.
    /// </summary>
    private static List<string> ExtractColorTags(string line)
    {
        var matches = Regex.Matches(line, @"<([A-Za-z]+)>");
        return matches.Cast<Match>().Select(m => m.Groups[1].Value).Distinct().ToList();
    }

    /// <summary>
    /// Converts color tags to their RTF equivalents.
    /// </summary>
    private static string ConvertColorTagToRTF(string colorTag)
    {
        return colorTag.ToLower() switch
        {
            "black" => @"\red0\green0\blue0",
            "red" => @"\red255\green0\blue0",
            "green" => @"\red0\green255\blue0",
            "blue" => @"\red0\green0\blue255",
            "yellow" => @"\red218\green165\blue32", // 🎨 Golden Yellow!
            "cyan" => @"\red0\green255\blue255",
            "magenta" => @"\red255\green0\blue255",
            "gray" => @"\red128\green128\blue128",
            "white" => @"\red255\green255\blue255",
            _ => @"\red0\green0\blue0" // Default to black
        };
    }


    /// <summary>
    /// Replaces color tags with RTF color references.
    /// </summary>
    private static string ReplaceColorTagsWithRTF(string line, Dictionary<string, string> colorMap)
    {
        foreach (var color in colorMap.Keys)
        {
            line = Regex.Replace(line, $@"<{color}>", $@"\cf{colorMap.Keys.ToList().IndexOf(color) + 1} ");
            line = Regex.Replace(line, $@"</{color}>", @"\cf0 "); // Reset to default color
        }

        return ColorConsole.RemoveColorTags(line); // Remove any unmatched tags
    }
}