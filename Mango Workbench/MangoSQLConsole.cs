/*
 * MangoSQLConsole Module
 * =============================================
 * Project: Mango
 * Purpose: Provides an interactive query interface for analyzing cryptographic 
 *          contenders and metrics stored in the Mango SQLite database.
 * 
 *          This module supports:
 *            • SQL-style queries for direct inspection and diagnostics.
 *            • Custom meta-commands (e.g., GOOD, TOUGH) for metric-based filtering.
 *            • Lightweight contender visualization, ordering, and threshold analysis.
 *            • Integrated help system with syntax-aware command hints.
 * 
 *          Used primarily for:
 *            → Manual review of top-performing sequences
 *            → Debugging cryptographic metric anomalies
 *            → Exploring trends across transform behavior
 * 
 * Author: [Luke Tomasello, luke@tomasello.com]
 * Created: November 2024
 * License: [MIT]
 * =============================================
 */

using Mango.Utilities;
using System.Data.SQLite;
using System.Text;
using System.Text.RegularExpressions;

namespace Mango.Analysis
{
    public static class QueryLibrary
    {
        public static List<Contender> GetAllContenders()
        {
            using var connection = new SQLiteConnection("Data Source=temp.db;Version=3;");
            connection.Open();

            var contenders = new Dictionary<string, Contender>();

            // Fetch Contenders with Metrics
            using var command = new SQLiteCommand(@"
        SELECT c.Sequence, c.AggregateScore, c.PassCount, 
               m.Name AS MetricName, m.Passed, m.Value, m.Threshold, m.Notes
        FROM Contenders c
        LEFT JOIN Metrics m ON c.Id = m.ContenderId;", connection);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                var sequence = reader["Sequence"].ToString();
                if (!contenders.ContainsKey(sequence))
                {
                    contenders[sequence] = new Contender
                    {
                        Sequence = sequence,
                        AggregateScore = double.Parse(reader["AggregateScore"].ToString()),
                        PassCount = int.Parse(reader["PassCount"].ToString()),
                        Metrics = new List<Metric>()
                    };
                }

                // Add Metric if Exists
                if (!reader.IsDBNull(reader.GetOrdinal("MetricName")))
                {
                    contenders[sequence].Metrics.Add(new Metric
                    {
                        Name = reader["MetricName"].ToString(),
                        Passed = reader["Passed"].ToString() == "1",
                        Value = double.Parse(reader["Value"].ToString()),
                        Threshold = double.Parse(reader["Threshold"].ToString()),
                        Notes = reader["Notes"].ToString()
                    });
                }
            }

            return contenders.Values.ToList();
        }

#if false
        public static List<Contender> GetAllContenders()
        {
            using var connection = new SQLiteConnection("Data Source=temp.db;Version=3;");
            connection.Open();

            var contenders = new List<Contender>();

            using var command = new SQLiteCommand("SELECT * FROM Contenders;", connection);
            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                contenders.Add(new Contender
                {
                    Sequence = reader["Sequence"].ToString(),
                    AggregateScore = double.Parse(reader["AggregateScore"].ToString()),
                    PassCount = int.Parse(reader["PassCount"].ToString())
                });
            }

            return contenders;
        }
#endif
        public static List<Contender> ApplyCondition(List<Contender> contenders, string condition)
        {
            if (string.IsNullOrEmpty(condition)) return contenders;

            // Handle conditions like "SlidingWindow PASS" or "AggregateScore > 0.95"
            if (condition.Contains("PASS") || condition.Contains("FAIL"))
            {
                var metricName = condition.Split(' ')[0];
                var passFail = condition.Split(' ')[1];
                return contenders.Where(c =>
                    c.Metrics.Any(m =>
                        m.Name.Equals(metricName, StringComparison.OrdinalIgnoreCase) &&
                        m.Passed == (passFail.Equals("PASS", StringComparison.OrdinalIgnoreCase))
                    )).ToList();
            }
            else if (condition.Contains(">") || condition.Contains("="))
            {
                var match = Regex.Match(condition, @"(\w+)\s*(>|=)\s*([\d.]+)");
                if (match.Success)
                {
                    var field = match.Groups[1].Value;
                    var op = match.Groups[2].Value;
                    var value = double.Parse(match.Groups[3].Value);

                    return contenders.Where(c =>
                    {
                        var fieldValue = c.GetFieldValue(field);
                        return op == ">" ? fieldValue > value : fieldValue == value;
                    }).ToList();
                }
            }

            return contenders;
        }

        public static List<Contender> ApplyOrdering(List<Contender> contenders, string orderBy)
        {
            return orderBy switch
            {
                "score" => contenders.OrderByDescending(c => c.AggregateScore).ToList(),
                "passcount" => contenders.OrderByDescending(c => c.PassCount).ToList(),
                _ => contenders
            };
        }

        public static List<Contender> ApplyLimit(List<Contender> contenders, int limit)
        {
            return contenders.Take(limit).ToList();
        }
        public static double? ExtractMinThreshold(string args)
        {
            var match = Regex.Match(args, @"MIN\s+([\d.]+)", RegexOptions.IgnoreCase);
            return match.Success ? double.Parse(match.Groups[1].Value) : (double?)null;
        }
        public static List<Contender> ApplyThreshold(List<Contender> contenders, string metric, double threshold)
        {
            // Filter contenders where the specified metric meets the threshold
            return contenders.Where(c =>
                c.Metrics.Any(m =>
                    m.Name.Equals(metric, StringComparison.OrdinalIgnoreCase) &&
                    m.Value >= threshold
                )).ToList();
        }

    }

    public static class MangoSQLConsole
    {
        public static (string, ConsoleColor) CountContenders(string target, string condition)
        {
            var contenders = QueryLibrary.GetAllContenders();
            contenders = QueryLibrary.ApplyCondition(contenders, condition);

            return ($"Count: {contenders.Count()}", ConsoleColor.Green);
        }

        public static (string, ConsoleColor) ListContenders(string target, string orderBy, int limit)
        {
            var contenders = QueryLibrary.GetAllContenders();
            contenders = QueryLibrary.ApplyOrdering(contenders, orderBy);
            contenders = QueryLibrary.ApplyLimit(contenders, limit);

            var result = new StringBuilder();
            foreach (var contender in contenders)
            {
                result.AppendLine($"Sequence: {contender.Sequence}, Score: {contender.AggregateScore:F4}, Pass Count: {contender.PassCount}");
            }

            return (result.ToString(), ConsoleColor.Green);
        }

        public static (string, ConsoleColor) ShowMetricsForContender(string contenderId)
        {
            using var connection = new SQLiteConnection("Data Source=temp.db;Version=3;");
            connection.Open();

            var metrics = new List<Metric>();
            using var command = new SQLiteCommand($"SELECT * FROM Metrics WHERE ContenderId = @ContenderId;", connection);
            command.Parameters.AddWithValue("@ContenderId", contenderId);

            using var reader = command.ExecuteReader();
            while (reader.Read())
            {
                metrics.Add(new Metric
                {
                    Name = reader["Name"].ToString(),
                    Value = double.Parse(reader["Value"].ToString()),  // Corrected field name
                    Threshold = double.Parse(reader["Threshold"].ToString()),
                    Passed = reader["Passed"].ToString() == "1", // SQLite stores BOOLEAN as INTEGER
                    Notes = reader["Notes"].ToString()
                });
            }

            if (!metrics.Any()) return ($"No metrics found for contender {contenderId}.", ConsoleColor.Red);

            var result = new StringBuilder($"Metrics for Contender {contenderId}:\n");
            foreach (var metric in metrics)
            {
                result.AppendLine($"- {metric.Name}: {metric.Value:F4} (Threshold: {metric.Threshold:F4})");
            }

            return (result.ToString(), ConsoleColor.Green);
        }
        public static (string, ConsoleColor) GoodCommand(string args)
        {
            if (args.Contains("/h"))
            {
                return Help("GOOD");
            }

            // Parse the command arguments
            var tokens = args.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 4 || !tokens[0].Equals("FOR", StringComparison.OrdinalIgnoreCase) ||
                !tokens[2].Equals("IN", StringComparison.OrdinalIgnoreCase))
            {
                return ("Usage: GOOD FOR <Type> IN <Metric> [LIMIT <N>] [MIN <Threshold>] [VERBOSE] [ShowFailedOnly] [HighlightCriticalMetrics]", ConsoleColor.Red);
            }

            string type = tokens[1]; // Transform or Sequence
            string metric = tokens[3];
            int limit = args.Contains("LIMIT", StringComparison.OrdinalIgnoreCase) ? ExtractLimit(args) : 10;
            double? minThreshold = args.Contains("MIN", StringComparison.OrdinalIgnoreCase) ? QueryLibrary.ExtractMinThreshold(args) : null;
            bool isVerbose = args.Contains("VERBOSE", StringComparison.OrdinalIgnoreCase);
            bool showFailedOnly = args.Contains("ShowFailedOnly", StringComparison.OrdinalIgnoreCase);
            bool highlightCriticalMetrics = args.Contains("HighlightCriticalMetrics", StringComparison.OrdinalIgnoreCase);

            // Query the database
            var contenders = QueryLibrary.GetAllContenders();
            contenders = QueryLibrary.ApplyCondition(contenders, $"{metric} PASS");
            if (minThreshold.HasValue)
            {
                contenders = QueryLibrary.ApplyThreshold(contenders, metric, minThreshold.Value);
            }
            contenders = QueryLibrary.ApplyLimit(contenders, limit);

            // Format the output
            var result = new StringBuilder();
            result.AppendLine($"Top {limit} {type}s for {metric}:");
            int rank = 1;
            foreach (var contender in contenders)
            {
                if (isVerbose)
                {
                    result.AppendLine($"{rank}. {contender.Sequence}:");
                    result.AppendLine($"Score: {contender.AggregateScore:F4}, Pass Count: {contender.PassCount}, Details:");
                    foreach (var metricData in contender.Metrics)
                    {
                        if (showFailedOnly && metricData.Passed) continue;

                        if (highlightCriticalMetrics && metricData.Value < metricData.Threshold)
                        {
                            ColorConsole.WriteLine(
                                $"<Red>{metricData.Name}:</Red> Value=<Cyan>{metricData.Value:F4}</Cyan>, Critical Threshold=<Cyan>{metricData.Threshold:F4}</Cyan>, Passed=<Cyan>{metricData.Passed}</Cyan>, Notes=<Cyan>{metricData.Notes}</Cyan>");
                        }
                        else
                        {
                            ColorConsole.WriteLine(
                                $"<Green>{metricData.Name}:</Green> Value={metricData.Value:F4}, Threshold={metricData.Threshold:F4}, Passed={metricData.Passed}, Notes={metricData.Notes}");
                        }
                    }
                }
                else
                {
                    result.AppendLine($"{rank}. {contender.Sequence}: Score: {contender.AggregateScore:F4}, Pass Count: {contender.PassCount}");
                }
                rank++;
            }

            return (result.ToString(), ConsoleColor.Green);
        }

        public static (string, ConsoleColor) ToughCommand(string args)
        {
            if (args.Contains("/h"))
            {
                return Help("TOUGH");
            }

            // Parse the command arguments
            var tokens = args.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length < 3 || !tokens[0].Equals("FOR", StringComparison.OrdinalIgnoreCase))
            {
                return ("Usage: TOUGH FOR <Metric> [LIMIT <N>] [MIN <Threshold>] [VERBOSE] [ShowFailedOnly] [HighlightCriticalMetrics]", ConsoleColor.Red);
            }

            string metric = tokens[1];
            int limit = args.Contains("LIMIT", StringComparison.OrdinalIgnoreCase) ? ExtractLimit(args) : 10;
            double? minThreshold = args.Contains("MIN", StringComparison.OrdinalIgnoreCase) ? QueryLibrary.ExtractMinThreshold(args) : null;
            bool isVerbose = args.Contains("VERBOSE", StringComparison.OrdinalIgnoreCase);
            bool showFailedOnly = args.Contains("ShowFailedOnly", StringComparison.OrdinalIgnoreCase);
            bool highlightCriticalMetrics = args.Contains("HighlightCriticalMetrics", StringComparison.OrdinalIgnoreCase);

            // Query the database
            var contenders = QueryLibrary.GetAllContenders();
            contenders = QueryLibrary.ApplyCondition(contenders, $"{metric} PASS");
            if (minThreshold.HasValue)
            {
                contenders = QueryLibrary.ApplyThreshold(contenders, metric, minThreshold.Value);
            }
            contenders = QueryLibrary.ApplyOrdering(contenders, "score");
            contenders = QueryLibrary.ApplyLimit(contenders, limit);

            // Format the output
            var result = new StringBuilder();
            result.AppendLine($"<Yellow>Top {limit} contenders for tough metric {metric}:</Yellow>");
            int rank = 1;
            foreach (var contender in contenders)
            {
                result.AppendLine($"{rank}. <Cyan>{contender.Sequence}</Cyan>:");
                result.AppendLine($"  <Green>Score:</Green> {contender.AggregateScore:F4}, <Green>Pass Count:</Green> {contender.PassCount}, <Green>Details:</Green>");
                foreach (var metricData in contender.Metrics)
                {
                    if (showFailedOnly && metricData.Passed) continue;

                    if (highlightCriticalMetrics && metricData.Value < metricData.Threshold)
                    {
                        result.AppendLine($"    <Red>{metricData.Name}:</Red> Value=<Cyan>{metricData.Value:F4}</Cyan>, Critical Threshold=<Cyan>{metricData.Threshold:F4}</Cyan>, Passed=<Cyan>{metricData.Passed}</Cyan>, Notes=<Cyan>{metricData.Notes}</Cyan>");
                    }
                    else
                    {
                        result.AppendLine($"    <Green>{metricData.Name}:</Green> Value={metricData.Value:F4}, Threshold={metricData.Threshold:F4}, Passed={metricData.Passed}, Notes={metricData.Notes}");
                    }
                }
                rank++;
            }

            return (result.ToString(), ConsoleColor.Green);
        }

        public static (string, ConsoleColor) FindContenders(string target, string condition, string orderBy, int limit)
        {
            using var connection = new SQLiteConnection("Data Source=temp.db;Version=3;");
            connection.Open();

            // Query Contenders with optional condition, ordering, and limit
            var contendersQuery = new StringBuilder("SELECT Id, Sequence, AggregateScore, PassCount FROM Contenders");
            if (!string.IsNullOrEmpty(condition)) contendersQuery.Append($" WHERE {condition}");
            if (!string.IsNullOrEmpty(orderBy)) contendersQuery.Append($" ORDER BY {orderBy}");
            contendersQuery.Append($" LIMIT {limit};");

            using var contendersCommand = new SQLiteCommand(contendersQuery.ToString(), connection);
            using var contendersReader = contendersCommand.ExecuteReader();

            if (!contendersReader.HasRows) return ("No contenders found.", ConsoleColor.Red);

            var result = new StringBuilder();

            while (contendersReader.Read())
            {
                var contenderId = contendersReader.GetInt32(0);
                var sequence = contendersReader.GetString(1);
                var aggregateScore = contendersReader.GetDouble(2);
                var passCount = contendersReader.GetInt32(3);

                result.AppendLine("------------");
                result.AppendLine($"Id: {contenderId}");
                result.AppendLine($"Sequence: {sequence}");
                result.AppendLine($"AggregateScore: {aggregateScore:F4}");
                result.AppendLine($"PassCount: {passCount}");

                // Fetch metrics for this contender
                using var metricsCommand = new SQLiteCommand("SELECT Name, Value, Threshold, Passed FROM Metrics WHERE ContenderId = @ContenderId;", connection);
                metricsCommand.Parameters.AddWithValue("@ContenderId", contenderId);
                using var metricsReader = metricsCommand.ExecuteReader();

                result.AppendLine("Metrics:");
                while (metricsReader.Read())
                {
                    var name = metricsReader.GetString(0);
                    var value = metricsReader.GetDouble(1);
                    var threshold = metricsReader.GetDouble(2);
                    var passed = metricsReader.GetBoolean(3);

                    var status = passed ? "PASS" : "FAIL";
                    result.AppendLine($"- {name}: {status}");
                    result.AppendLine($"  Metric: {value:F4}, Threshold: {threshold:F4}");
                }
            }

            return (result.ToString(), ConsoleColor.Green);
        }
#if false
        private static string FormatMetaOutput(IEnumerable<Dictionary<string, object>> rows)
        {
            if (GlobalEnv.Globals.SqlCompact)
            {
                // Compact format: CSV-style
                var result = new StringBuilder();

                // Report column headers
                var headers = rows.FirstOrDefault()?.Keys ?? Enumerable.Empty<string>();
                result.AppendLine(string.Join(", ", headers));

                // Report rows
                foreach (var row in rows)
                {
                    result.AppendLine(string.Join(", ", row.Values));
                }

                return result.ToString();
            }
            else
            {
                // Verbose format: Line-by-line
                var result = new StringBuilder();

                foreach (var row in rows)
                {
                    result.AppendLine("------------");
                    foreach (var (key, value) in row)
                    {
                        result.AppendLine($"{key}: {value}");
                    }
                }

                return result.ToString();
            }
        }

        private static (string, ConsoleColor) FormatQueryOutput(SQLiteDataReader reader)
        {
            if (GlobalEnv.Globals.SqlCompact)
            {
                // Compact format: CSV-style, single-line per record
                var result = new StringBuilder();

                // Report column headers
                for (int i = 0; i < reader.FieldCount; i++)
                {
                    result.Append(reader.GetName(i));
                    if (i < reader.FieldCount - 1) result.Append(", ");
                }
                result.AppendLine();

                // Report rows
                while (reader.Read())
                {
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        result.Append(reader.GetValue(i));
                        if (i < reader.FieldCount - 1) result.Append(", ");
                    }
                    result.AppendLine();
                }

                return (result.ToString(), ConsoleColor.Green);
            }
            else
            {
                // Verbose format: Line-based, detailed records
                var result = new StringBuilder();

                // Process each row
                while (reader.Read())
                {
                    result.AppendLine("------------");
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        result.AppendLine($"{reader.GetName(i)}: {reader.GetValue(i)}");
                    }
                }

                return (result.ToString(), ConsoleColor.Green);
            }
        }
#endif
        public static (string, ConsoleColor) ExecuteRawSql(string query, ExecutionEnvironment localEnv)
        {
            using var connection = new SQLiteConnection("Data Source=temp.db;Version=3;");
            connection.Open();

            var result = new StringBuilder();
            bool isVerbose = !localEnv.Globals.SqlCompact;

            using var command = new SQLiteCommand(query, connection);
            using var reader = command.ExecuteReader();

            // Add headers in compact mode
            if (!isVerbose)
            {
                var headers = Enumerable.Range(0, reader.FieldCount).Select(reader.GetName);
                result.AppendLine(string.Join(", ", headers));
            }

            while (reader.Read())
            {
                if (isVerbose)
                {
                    result.AppendLine("------------");
                    for (int i = 0; i < reader.FieldCount; i++)
                    {
                        result.AppendLine($"{reader.GetName(i)}: {reader.GetValue(i)}");
                    }
                }
                else
                {
                    var row = Enumerable.Range(0, reader.FieldCount).Select(reader.GetValue);
                    result.AppendLine(string.Join(", ", row));
                }
            }

            return (result.ToString(), ConsoleColor.Green);
        }

        public static (string, ConsoleColor) ListMetrics(ExecutionEnvironment localEnv)
        {
            string query = @"
            SELECT m.Name, COUNT(*) AS PassedCount
            FROM Metrics m
            WHERE m.Passed = 1
            GROUP BY m.Name
            ORDER BY PassedCount DESC;";

            return ExecuteRawSql(query, localEnv);
        }

        public static void RunQueryConsole(ExecutionEnvironment localEnv)
        {
            Console.WriteLine("Entering Query Console. Type 'exit' to return to Mango.");

            while (true)
            {
                Console.Write("Query> ");
                var input = Console.ReadLine()?.Trim();

                if (string.IsNullOrEmpty(input)) continue;
                if (input.Equals("exit", StringComparison.OrdinalIgnoreCase)) break;

                try
                {
                    // Pass input to QueryMetaLanguageHandler for processing
                    var (output, color) = QueryMetaLanguageHandler(input, localEnv);
                    ColorConsole.WriteLine(output, color);

                }
                catch (Exception ex)
                {
                    ColorConsole.WriteLine($"Error: {ex.Message}", ConsoleColor.Red);
                }
            }

            Console.WriteLine("Exiting Query Console.");
        }
        public static (string, ConsoleColor) QueryMetaLanguageHandler(string input, ExecutionEnvironment localEnv)
        {
            var tokens = input.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            if (tokens.Length == 0) return ("No command entered.", ConsoleColor.Red);

            string command = tokens[0].ToUpperInvariant();
            string args = string.Join(' ', tokens.Skip(1));

            return command switch
            {
                "GOOD" => GoodCommand(args),
                "TOUGH" => ToughCommand(args),
                "HELP" => args.Length > 0 ? Help(args) : Help(),
                "FIND" => FindContenders("contenders", ExtractCondition(input), ExtractOrderBy(input), ExtractLimit(input)),
                "LIST" => ListMetrics(localEnv),
                "SHOW" => tokens.Length >= 4 && tokens[1].ToUpperInvariant() == "METRICS" && tokens[2].ToUpperInvariant() == "FOR"
                    ? ShowMetricsForContender(tokens[3])
                    : ("Usage: SHOW metrics FOR contender <Id>", ConsoleColor.Yellow),
                "COUNT" => CountContenders("contenders", ExtractCondition(input)),
                _ => ExecuteRawSql(input, localEnv) // Assume raw SQL for unknown commands
            };
        }

#if false
        public static (string, ConsoleColor) QueryMetaLanguageHandler(string input)
        {
            var tokens = input.Split(' ', StringSplitOptions.RemoveEmptyEntries);

            if (tokens.Length == 0) return ("No command entered.", ConsoleColor.Red);

            string command = tokens[0].ToUpperInvariant();
            string condition = input.Contains("WHERE") ? ExtractCondition(input) : null;
            string orderBy = input.Contains("ORDER BY") ? ExtractOrderBy(input) : null;
            int limit = input.Contains("LIMIT") ? ExtractLimit(input) : int.MaxValue;

            return command switch
            {
                "FIND" => FindContenders("contenders", condition, orderBy, limit),
                "LIST" => ListMetrics(),
                "SHOW" =>
                    tokens.Length >= 4 && tokens[1].ToUpperInvariant() == "METRICS" && tokens[2].ToUpperInvariant() == "FOR"
                        ? int.TryParse(tokens[4], out int contenderId)
                            ? ShowMetricsForContender(contenderId.ToString())
                            : ("Usage: SHOW metrics FOR contender <Id>", ConsoleColor.Yellow)
                        : ("Usage: SHOW metrics FOR contender <Id>", ConsoleColor.Yellow),
                "COUNT" => CountContenders("contenders", condition),
                "HELP" => DisplayHelp(),
                _ => ExecuteRawSql(input) // Assume raw SQL for unknown commands
            };
        }
#endif
        private static readonly Dictionary<string, string> HelpText = new()
{
    {
        "GOOD",
        "GOOD Command: Identifies transforms or sequences contributing positively to a metric.\n" +
        "Usage: GOOD FOR <Type> IN <Metric> [LIMIT <N>] [MIN <Threshold>] [VERBOSE] [ShowFailedOnly] [HighlightCriticalMetrics]\n" +
        "Examples:\n" +
        "  Compact: GOOD FOR Transform IN SlidingWindow LIMIT 10\n" +
        "  Verbose: GOOD FOR Transform IN SlidingWindow LIMIT 10 VERBOSE\n" +
        "  ShowFailedOnly: GOOD FOR Transform IN SlidingWindow LIMIT 10 VERBOSE ShowFailedOnly\n" +
        "  HighlightCriticalMetrics: GOOD FOR Transform IN SlidingWindow LIMIT 10 VERBOSE HighlightCriticalMetrics"
    },
    {
        "TOUGH",
        "TOUGH Command: Identifies contenders excelling in tough metrics.\n" +
        "Usage: TOUGH FOR <Metric> [LIMIT <N>] [MIN <Threshold>] [VERBOSE] [ShowFailedOnly] [HighlightCriticalMetrics]\n" +
        "Examples:\n" +
        "  Compact: TOUGH FOR SlidingWindow LIMIT 10\n" +
        "  Verbose: TOUGH FOR Entropy MIN 0.75 LIMIT 10 VERBOSE\n" +
        "  ShowFailedOnly: TOUGH FOR Entropy MIN 0.75 LIMIT 10 VERBOSE ShowFailedOnly\n" +
        "  HighlightCriticalMetrics: TOUGH FOR Entropy MIN 0.75 LIMIT 10 VERBOSE HighlightCriticalMetrics"
    },
    {
        "FIND",
        "FIND Command: Retrieve data from the Contenders table.\n" +
        "Usage: FIND contenders WHERE <condition> ORDER BY <field> <direction> LIMIT <N>\n" +
        "Example: FIND contenders WHERE PassCount >= 6 ORDER BY AggregateScore DESC LIMIT 5"
    },
    {
        "LIST",
        "LIST Command: Display metrics summary (e.g., pass counts for each metric).\n" +
        "Usage: LIST metrics\n" +
        "Example: LIST metrics"
    },
    {
        "SHOW",
        "SHOW Command: Display detailed metrics for a specific contender.\n" +
        "Usage: SHOW metrics FOR contender <Id>\n" +
        "Example: SHOW metrics FOR contender 1"
    },
    {
        "COUNT",
        "COUNT Command: Get a count of matching contenders based on a condition.\n" +
        "Usage: COUNT contenders WHERE <condition>\n" +
        "Example: COUNT contenders WHERE AggregateScore > 0.95"
    },
    {
        "SQL",
        "SQL Command: Execute raw SQL queries directly.\n" +
        "Usage: <valid SQL query>\n" +
        "Example: SELECT * FROM Contenders LIMIT 5"
    },
    {
        "HELP",
        "HELP Command: Displays this help information or detailed help for a specific command.\n" +
        "Usage: HELP [<Command>]\n" +
        "Example: HELP GOOD"
    }
};



        public static (string, ConsoleColor) Help(string command = null)
        {
            if (string.IsNullOrEmpty(command))
            {
                // Show general help with a list of available commands
                var allHelp = new StringBuilder("Available Commands:\n");
                foreach (var cmd in HelpText.Keys)
                {
                    allHelp.AppendLine($"- {cmd}");
                }
                allHelp.AppendLine("\nUse HELP <Command> for detailed help on a specific command.");
                return (allHelp.ToString(), ConsoleColor.Green);
            }

            // Normalize command input
            command = command.Trim().ToUpperInvariant();

            // Show detailed help for a specific command
            if (HelpText.TryGetValue(command, out var helpContent))
            {
                return (helpContent, ConsoleColor.Green);
            }

            return ($"No help available for '{command}'.\nUse HELP to see the list of available commands.", ConsoleColor.Red);
        }


        private static (string, ConsoleColor) DisplayHelp()
        {
            var helpText = new StringBuilder();
            helpText.AppendLine("** Query Console Help **");
            helpText.AppendLine("Available Commands:");

            helpText.AppendLine("\nFIND");
            helpText.AppendLine("  Description: Retrieve data from the Contenders table.");
            helpText.AppendLine("  Syntax: FIND contenders WHERE <condition> ORDER BY <field> <direction> LIMIT <N>");
            helpText.AppendLine("  Example: FIND contenders WHERE PassCount >= 6 ORDER BY AggregateScore DESC LIMIT 5");

            helpText.AppendLine("\nLIST");
            helpText.AppendLine("  Description: Display metrics summary (e.g., pass counts for each metric).");
            helpText.AppendLine("  Syntax: LIST metrics");
            helpText.AppendLine("  Example: LIST metrics");

            helpText.AppendLine("\nSHOW");
            helpText.AppendLine("  Description: Display detailed metrics for a specific contender.");
            helpText.AppendLine("  Syntax: SHOW metrics FOR contender <Id>");
            helpText.AppendLine("  Example: SHOW metrics FOR contender 1");

            helpText.AppendLine("\nCOUNT");
            helpText.AppendLine("  Description: Get a count of matching contenders based on a condition.");
            helpText.AppendLine("  Syntax: COUNT contenders WHERE <condition>");
            helpText.AppendLine("  Example: COUNT contenders WHERE AggregateScore > 0.95");

            helpText.AppendLine("\nSQL");
            helpText.AppendLine("  Description: Execute raw SQL queries directly.");
            helpText.AppendLine("  Syntax: <valid SQL query>");
            helpText.AppendLine("  Example: SELECT * FROM Contenders LIMIT 5");

            helpText.AppendLine("\nHELP");
            helpText.AppendLine("  Description: Display this help information.");
            helpText.AppendLine("  Syntax: HELP");
            helpText.AppendLine("  Example: HELP");

            return (helpText.ToString(), ConsoleColor.Green);
        }

        private static string ExtractCondition(string query)
        {
            var match = Regex.Match(query, @"WHERE (.+?)(?: ORDER BY| LIMIT|$)", RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value.Trim() : null;
        }
        private static string ExtractOrderBy(string query)
        {
            var match = Regex.Match(query, @"ORDER BY (.+?)(?: LIMIT|$)", RegexOptions.IgnoreCase);
            return match.Success ? match.Groups[1].Value.Trim() : null;
        }
        private static int ExtractLimit(string query)
        {
            var match = Regex.Match(query, @"LIMIT (\d+)", RegexOptions.IgnoreCase);
            return match.Success && int.TryParse(match.Groups[1].Value, out int limit) ? limit : int.MaxValue;
        }
    }
}