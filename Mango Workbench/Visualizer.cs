/*
   * Visualizer Module
   * =============================================
   * Project: Mango
   * Purpose: Renders visual comparisons of input and transformed data for
   *          cryptographic sequence analysis.
   * Author: [Luke Tomasello, luke@tomasello.com]
   * Created: November 2024
   * License: [MIT]
   * =============================================
   *
   * Description:
   * This module provides visual analysis tools for cryptographic transforms.
   * It highlights differences between original and transformed data using
   * bit-level and byte-level comparison with optional color tagging.
   *
   * Key Features:
   * - Supports both BITS and BYTES display modes
   * - Highlights differing bits/bytes with <Yellow> tags
   * - Configurable rows, columns, offsets, and output format
   * - Generates string-based visual diagnostics for debugging
   *
   * Example Usage:
   * var result = Visualizer.Format(original, output, "BYTES", rows: 8, columns: 64);
   *
   * =============================================
   */



namespace Mango.Analysis
{
    // Module: Visualizer
    // Purpose: Provides utilities for formatting and rendering visualizations of cryptographic transform sequences.
    // The module converts data from cryptographic operations into structured visual outputs, with options for bit/byte-based alignment,
    // color-coded differences, and customizable formatting.

    using System;
    using System.Collections.Generic;
    using System.Text;

    public static class Visualizer
    {
        /// <summary>
        /// Formats input and transformed data into a string representation for visualization.
        /// </summary>
        /// <param name="input">The original data before transformation.</param>
        /// <param name="transformed">The data after transformation.</param>
        /// <param name="mode">Visualization mode: BITS or BYTES.</param>
        /// <param name="rows">Number of rows to display.</param>
        /// <param name="columns">Number of columns to display.</param>
        /// <param name="offset">Starting byte position in the data.</param>
        /// <param name="format">Data display format: HEX (default) or ASCII.</param>
        /// <returns>A string representation of the visualization with embedded color tags.</returns>
        public static List<string> Format(byte[] input, byte[] transformed, string mode = "BITS", int rows = 10, int columns = 80, int offset = 0, string format = "HEX")
        {
            var rowsList = new List<string>();

            int bytesPerColumn = mode.Equals("BITS", StringComparison.OrdinalIgnoreCase) ? 1 : columns;
            int totalLength = Math.Min(input.Length, transformed.Length);
            int start = Math.Min(offset, totalLength);

            for (int row = 0; row < rows; row++)
            {
                int position = start + row * columns;
                if (position >= totalLength) break;

                var builder = new StringBuilder();

                for (int col = 0; col < columns; col++)
                {
                    int index = position + col;
                    if (index >= totalLength) break;

                    byte inputByte = input[index];
                    byte transformedByte = transformed[index];

                    if (mode.Equals("BITS", StringComparison.OrdinalIgnoreCase))
                    {
                        string inputBits = Convert.ToString(inputByte, 2).PadLeft(8, '0');
                        string transformedBits = Convert.ToString(transformedByte, 2).PadLeft(8, '0');

                        for (int bit = 0; bit < 8; bit++)
                        {
                            if (inputBits[bit] != transformedBits[bit])
                                builder.Append($"<Yellow>{transformedBits[bit]}</Yellow>");
                            else
                                builder.Append(transformedBits[bit]);
                        }
                        builder.Append(" ");
                    }
                    else if (mode.Equals("BYTES", StringComparison.OrdinalIgnoreCase))
                    {
                        string transformedHex = transformedByte.ToString("X2");
                        if (inputByte != transformedByte)
                            builder.Append($"<Yellow>{transformedHex}</Yellow> ");
                        else
                            builder.Append(transformedHex + " ");
                    }
                }

                rowsList.Add(builder.ToString().Trim());
            }

            return rowsList;
        }

#if false
        public static string Format(byte[] input, byte[] transformed, string mode = "BITS", int rows = 10, int columns = 80, int offset = 0, string format = "HEX")
        {
            var builder = new StringBuilder();

            int bytesPerColumn = mode.Equals("BITS", StringComparison.OrdinalIgnoreCase) ? 1 : columns;
            int totalLength = Math.Min(input.Length, transformed.Length);
            int start = Math.Min(offset, totalLength);

            for (int row = 0; row < rows; row++)
            {
                int position = start + row * columns;
                if (position >= totalLength) break;

                builder.Append($"Row {row + 1:D2}: ");

                for (int col = 0; col < columns; col++)
                {
                    int index = position + col;
                    if (index >= totalLength) break;

                    byte inputByte = input[index];
                    byte transformedByte = transformed[index];

                    if (mode.Equals("BITS", StringComparison.OrdinalIgnoreCase))
                    {
                        string inputBits = Convert.ToString(inputByte, 2).PadLeft(8, '0');
                        string transformedBits = Convert.ToString(transformedByte, 2).PadLeft(8, '0');

                        for (int bit = 0; bit < 8; bit++)
                        {
                            if (inputBits[bit] != transformedBits[bit])
                                builder.Append($"<Yellow>{transformedBits[bit]}</Yellow>");
                            else
                                builder.Append(transformedBits[bit]);
                        }
                        builder.Append(" ");
                    }
                    else if (mode.Equals("BYTES", StringComparison.OrdinalIgnoreCase))
                    {
                        string transformedHex = transformedByte.ToString("X2");
                        if (inputByte != transformedByte)
                            builder.Append($"<Yellow>{transformedHex}</Yellow> ");
                        else
                            builder.Append(transformedHex + " ");
                    }
                }

                builder.AppendLine();
            }

            return builder.ToString();
        }
#endif

    }
}
