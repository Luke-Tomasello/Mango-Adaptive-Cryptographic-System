/*
   * ColorConsole Module
   * =============================================
   * Project: Mango
   * Purpose: Enhances console output by enabling structured, color-tagged text 
   *          rendering. Used throughout Mango to improve readability, highlight 
   *          status messages, and provide dynamic formatting.
   * 
   *          This utility supports:
   *            • Inline color tags (e.g., <Green>, <Red>)
   *            • Push/pop color stack for scoped formatting
   *            • Multi-line, tag-safe rendering for complex output
   *            • Console-safe text stripping (RemoveColorTags)
   * 
   *          Frequently used in:
   *            → Logging diagnostic output
   *            → Command handlers and REPL feedback
   *            → RTF and plain-text dual-mode reports
   * 
   * Author: [Luke Tomasello, luke@tomasello.com]
   * Created: November 2024
   * License: [MIT]
   * =============================================
   */

namespace Mango.Utilities
{
    using System;
    using System.Collections.Generic;
    using System.Text;
    using System.Text.RegularExpressions;

    public static class ColorConsole
    {
        private static readonly Stack<ConsoleColor> ColorStack = new Stack<ConsoleColor>();

        public static void Write(string text, ConsoleColor? color = null)
        {
            // If a specific color is provided, push it onto the stack
            if (color.HasValue)
            {
                PushColor(color.Value);
            }

            try
            {
                // Process the message as usual (parsing tags and applying colors)
                WriteInternal(text, newline: false);
            }
            finally
            {
                // If a specific color was pushed, pop it off the stack
                if (color.HasValue)
                {
                    PopColor();
                }
            }
        }
        public static void WriteLine()
        {
            Console.WriteLine();
        }
        public static void WriteLine(string text, ConsoleColor? color = null)
        {
            // If a specific color is provided, push it onto the stack
            if (color.HasValue)
            {
                PushColor(color.Value);
            }

            try
            {
                // Process the message as usual (parsing tags and applying colors)
                WriteInternal(text, newline: true);
            }
            finally
            {
                // If a specific color was pushed, pop it off the stack
                if (color.HasValue)
                {
                    PopColor();
                }
            }
        }
        private static void WriteInternal(string text, bool newline)
        {
            var segments = ParseColorTags(text);
            var originalColor = Console.ForegroundColor;

            foreach (var segment in segments)
            {
                if (segment.IsColored)
                {
                    PushColor(segment.Color);
                    Console.Write(segment.Text);
                    PopColor();
                }
                else
                {
                    Console.Write(segment.Text);
                }
            }

            if (newline)
            {
                Console.WriteLine();
            }

            Console.ForegroundColor = originalColor; // Restore original color
        }
        public static void PushColor(ConsoleColor color)
        {
            ColorStack.Push(Console.ForegroundColor);
            Console.ForegroundColor = color;
        }
        public static void PopColor()
        {
            if (ColorStack.Count > 0)
                Console.ForegroundColor = ColorStack.Pop();
        }
        public static string RemoveColorTags(string input)
        {
            // Generate all color names from ConsoleColor enum dynamically
            string[] colorNames = Enum.GetNames(typeof(ConsoleColor));

            // Build regex pattern for tags like <Green> or </Green>
            string pattern = $"</?({string.Join("|", colorNames)})>";

            // Replace all matches with an empty string
            return Regex.Replace(input, pattern, "", RegexOptions.IgnoreCase);
        }

        // ✅ Overload: Takes List<string> and returns List<string>
        public static List<string> RemoveColorTags(List<string> inputList)
        {
            return inputList.Select(RemoveColorTags).ToList();
        }

        private static readonly HashSet<string> ValidColors = Enum.GetNames(typeof(ConsoleColor)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        private static readonly Regex tagPattern = BuildTagRegex();
        private static Regex BuildTagRegex()
        {
            string colorPattern = string.Join("|", ValidColors); // Only valid colors like "Red|Green|Blue"
            string pattern = $@"<(?<open>{colorPattern})>|</(?<close>{colorPattern})>|(?<text><[^<>]+>|[^<>]+)";
            return new Regex(pattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
        }

#if true
        private static List<ColorSegment> ParseColorTags(string input)
        {
            var segments = new List<ColorSegment>();
            var stack = new Stack<ConsoleColor>();  // 🔥 Tracks nested colors
            var sb = new StringBuilder();
            ConsoleColor currentColor = ConsoleColor.Gray; // Default color

            int i = 0;
            while (i < input.Length)
            {
                if (input[i] == '<') // Possible start of a color tag
                {
                    int endTag = input.IndexOf('>', i);
                    if (endTag > i + 1) // Ensure it's a valid tag
                    {
                        string tag = input.Substring(i + 1, endTag - i - 1).Trim();

                        // 🔥 BEFORE CHANGING COLOR, STORE PREVIOUS TEXT SEGMENT
                        if (sb.Length > 0)
                        {
                            segments.Add(new ColorSegment(sb.ToString(), currentColor));
                            sb.Clear();  // **Make sure no extra `>` characters leak!**
                        }

                        if (tag.StartsWith("/")) // Closing tag detected
                        {
                            if (stack.Count > 0) currentColor = stack.Pop(); // Restore previous color
                        }
                        else if (Enum.TryParse(tag, true, out ConsoleColor newColor)) // Opening tag detected
                        {
                            stack.Push(currentColor); // Save previous color
                            currentColor = newColor; // Apply new color
                        }

                        // ✅ **Move past the tag completely**
                        i = endTag + 1;
                        continue;
                    }
                }

                // Append normal text
                sb.Append(input[i]);
                i++;

                // 🔥 If we reach end of input or whitespace, store the segment
                if (i >= input.Length || char.IsWhiteSpace(input[i]))
                {
                    if (sb.Length > 0)
                    {
                        segments.Add(new ColorSegment(sb.ToString(), currentColor));
                        sb.Clear();  // **Ensure no contamination of the next segment**
                    }
                }
            }

            return segments;
        }

#else
        private static List<ColorSegment> ParseColorTags(string input)
        {
            var segments = new List<ColorSegment>();

            // ✅ Extract all known console colors (Red, Green, Blue, etc.)
            var colorNames = Enum.GetNames(typeof(ConsoleColor));

            // ✅ Build regex pattern for explicit `<Color>` and `</Color>` wrapping
            string colorPattern = string.Join("|", colorNames);
            var tagRegex = new Regex($@"<(?'color'{colorPattern})>(?'text'.*?)<\/\k'color'>",
                RegexOptions.IgnoreCase | RegexOptions.Singleline);


            int lastIndex = 0;

            foreach (Match match in tagRegex.Matches(input))
            {
                // ✅ Preserve any text before the match
                if (match.Index > lastIndex)
                {
                    string preText = input.Substring(lastIndex, match.Index - lastIndex);
                    segments.Add(new ColorSegment(preText, ConsoleColor.Gray)); // Default to Gray
                }

                // ✅ Extract color name and text inside the tag
                string colorName = match.Groups["color"].Value;
                string text = match.Groups["text"].Value;

                if (Enum.TryParse(colorName, true, out ConsoleColor color))
                {
                    segments.Add(new ColorSegment(text, color));
                }

                // ✅ Update last processed index
                lastIndex = match.Index + match.Length;
            }

            // ✅ Preserve any remaining text
            if (lastIndex < input.Length)
            {
                string remainingText = input.Substring(lastIndex);
                segments.Add(new ColorSegment(remainingText, ConsoleColor.Gray));
            }

            return segments;
        }

#endif
        private class ColorSegment
        {
            public string Text { get; }
            public bool IsColored { get; }
            public ConsoleColor Color { get; }

            public ColorSegment(string text, ConsoleColor color = ConsoleColor.Gray)
            {
                Text = text;
                IsColored = color != ConsoleColor.Gray;
                Color = color;
            }
        }
    }
}

