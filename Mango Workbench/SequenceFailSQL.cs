/*
 * SequenceFailSQL Module
 * =============================================
 * Project: Mango
 * Purpose: Implements persistent failure tracking for transform sequences
 *          using a lightweight SQLite database. This module supports
 *          BTR (Best Transform Round) evaluations by remembering sequences
 *          that failed under specific conditions and avoiding redundant tests.
 *
 *          Key responsibilities:
 *            • Maintain an in-memory + persistent database of failures.
 *            • Provide thread-safe access to check and record bad sequences.
 *            • Support key generation via failure context (method, mode, rounds, etc).
 *
 * Author: [Luke Tomasello, luke@tomasello.com]
 * Created: November 2024
 * License: [MIT]
 * =============================================
 */

using Mango.Utilities;
using System.Data.SQLite;
using System.Text;

namespace Mango.SQL;

public static class SequenceFailSQL
{
    private static string _dbName = null!;
    private static readonly Dictionary<string, HashSet<string>> BadSequences = new();
    private static bool _createFailDb;
    private static readonly object DbLock = new();
    private static bool _isDatabaseInitialized = false;
    private static SQLiteConnection? _persistentConnection = null;

    public static void OpenDatabase(string dbName, bool createMode)
    {
        if (string.IsNullOrWhiteSpace(dbName))
            throw new ArgumentException("Database name cannot be null or empty.", nameof(dbName));

        if (dbName != _dbName)
            lock (DbLock)
            {
                BadSequences.Clear();
            }

        _dbName = dbName;
        _createFailDb = createMode;
        _isDatabaseInitialized = false;

        if (!File.Exists(_dbName)) SQLiteConnection.CreateFile(_dbName);

        lock (DbLock)
        {
            if (File.Exists(_dbName)) File.SetAttributes(_dbName, FileAttributes.Normal); // 🔓 Force-unlock

            try
            {
                _persistentConnection = new SQLiteConnection($"Data Source={_dbName};Version=3;");
                _persistentConnection.Open();

                using (var command = new SQLiteCommand(@"
CREATE TABLE IF NOT EXISTS BTRFailSequences (
    Sequence BLOB,
    FailureKey TEXT,
    PRIMARY KEY (Sequence, FailureKey)
);", _persistentConnection))
                {
                    command.ExecuteNonQuery();
                }

                using (var command = new SQLiteCommand("SELECT Sequence, FailureKey FROM BTRFailSequences;",
                           _persistentConnection))
                using (var reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        var sequenceKey = Convert.ToBase64String((byte[])reader["Sequence"]);
                        var failureKey = reader["FailureKey"].ToString();

                        if (!BadSequences.TryGetValue(sequenceKey, out var failureSet))
                        {
                            failureSet = new HashSet<string>();
                            BadSequences[sequenceKey] = failureSet;
                        }

                        if (!string.IsNullOrEmpty(failureKey))
                            failureSet.Add(failureKey);

                    }
                }
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"🚨 Database initialization failed: {ex.Message}", ex);
            }

            _isDatabaseInitialized = true;
        }
    }

    public static void CloseDatabase()
    {
        lock (DbLock)
        {
            if (_persistentConnection != null)
            {
                _persistentConnection.Close();
                _persistentConnection.Dispose();
                _persistentConnection = null;
            }
        }
    }

    private static void EnsureDatabaseInitialized()
    {
        if (!_isDatabaseInitialized)
            throw new InvalidOperationException("BTRFailSQL has not been initialized. Call OpenDatabase() first.");
    }

    public static bool IsBadSequence(List<byte> sequence, string failureKey)
    {
        EnsureDatabaseInitialized();

        if (sequence == null || sequence.Count == 0)
            throw new ArgumentException("Sequence cannot be null or empty.", nameof(sequence));

        var sequenceKey = Convert.ToBase64String(sequence.ToArray());

        lock (DbLock)
        {
            var bad = BadSequences.TryGetValue(sequenceKey, out var failureSet) && failureSet.Contains(failureKey);
            return bad;
        }
    }

    public static void RecordBadSequence(List<byte> sequence, string failureKey)
    {
        EnsureDatabaseInitialized();

        if (sequence == null || sequence.Count == 0)
            throw new ArgumentException("Sequence cannot be null or empty.", nameof(sequence));

        if (string.IsNullOrWhiteSpace(failureKey))
            throw new ArgumentException("Failure key cannot be null or empty.", nameof(failureKey));

        var sequenceKey = Convert.ToBase64String(sequence.ToArray());

        lock (DbLock)
        {
            if (!BadSequences.TryGetValue(sequenceKey, out var failureSet))
            {
                failureSet = new HashSet<string>();
                BadSequences[sequenceKey] = failureSet;
            }

            if (!failureSet.Add(failureKey))
                return;

            if (_createFailDb && _persistentConnection != null)
                using (var command = new SQLiteCommand(@"
INSERT OR IGNORE INTO BTRFailSequences (Sequence, FailureKey) 
VALUES (@seq, @failKey);", _persistentConnection))
                {
                    command.Parameters.AddWithValue("@seq", sequence.ToArray());
                    command.Parameters.AddWithValue("@failKey", failureKey);
                    command.ExecuteNonQuery();
                }
        }
    }

    public static int TotalBadSequences(string failureKey)
    {
        EnsureDatabaseInitialized();

        if (string.IsNullOrWhiteSpace(failureKey))
            throw new ArgumentException("Failure key cannot be null or empty.", nameof(failureKey));

        lock (DbLock)
        {
            return BadSequences.Count(kvp => kvp.Value.Contains(failureKey));
        }
    }

    public static class Tools
    {
        private static string MakeKey(params object[] factors)
        {
            return Convert.ToBase64String(Encoding.UTF8.GetBytes(string.Join("-", factors)));
        }

        public static string GenerateFailureKey(ExecutionEnvironment localEnv, string methodology, int exitCount,
            int scopeCeiling, int? round = null)
        {
            var resolvedRound = round ?? new StateManager(localEnv).GlobalRounds;

            return MakeKey(
                localEnv.Globals.Mode.ToString(),
                methodology,
                exitCount,
                localEnv.Globals.PassCount,
                resolvedRound,
                scopeCeiling
            );
        }
    }
}