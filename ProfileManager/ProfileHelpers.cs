using Mango.AnalysisCore;
using Mango.Cipher;
using Mango.Common;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace Mango.ProfileHelpers
{
    public static class ProfileIOUtils
    {
        public static string GetInputProfilesPath() =>
            Path.Combine(MangoPaths.GetProgectDataDirectory(), "InputProfiles.json");

        public static Dictionary<string, InputProfileDto> LoadProfiles()
        {
            var path = GetInputProfilesPath();
            if (!File.Exists(path))
                return new Dictionary<string, InputProfileDto>(StringComparer.OrdinalIgnoreCase);

            try
            {
                var json = File.ReadAllText(path);
                var raw = JsonSerializer.Deserialize<Dictionary<string, InputProfileDto>>(json)
                          ?? new Dictionary<string, InputProfileDto>();

                // 🔁 Re-wrap in a case-insensitive dictionary
                var caseInsensitive = new Dictionary<string, InputProfileDto>(StringComparer.OrdinalIgnoreCase);
                foreach (var kvp in raw)
                    caseInsensitive[kvp.Key] = kvp.Value;

                return caseInsensitive;
            }
            catch
            {
                return new Dictionary<string, InputProfileDto>(StringComparer.OrdinalIgnoreCase);
            }
        }


        public static bool SaveProfiles(Dictionary<string, InputProfileDto> profiles)
        {
            var path = GetInputProfilesPath();
            try
            {
                var json = JsonSerializer.Serialize(profiles, new JsonSerializerOptions { WriteIndented = true });
                File.WriteAllText(path, json);
                return true;
            }
            catch
            {
                return false;
            }
        }

        public static InputProfileDto ToDto(InputProfile profile) => new()
        {
            Sequence = profile.Sequence.Select(p => new List<byte> { p.ID, p.TR }).ToList(),
            GlobalRounds = profile.GlobalRounds,
            AggregateScore = profile.AggregateScore
        };

        public static InputProfile FromDto(string name, InputProfileDto dto) =>
            new(name,
                dto.Sequence.Select(pair => ((byte)pair[0], (byte)pair[1])).ToArray(),
                dto.GlobalRounds,
                dto.AggregateScore);
    }

    public static class ProfileScoreUtils
    {
        public static double RecalculateAggregateScore(
            CryptoLib crypto,
            byte[] input,
            string password,
            OperationModes weightMode,
            ScoringModes scoringMode,
            InputProfile profile)
        {
            var analysisCore = new CryptoAnalysisCore(weightMode);
            var encrypted = crypto.Encrypt(profile, input);
            var payload = crypto.GetPayloadOnly(encrypted);

            var (avalanche, keydep) =
                Scoring.ProcessAvalancheAndKeyDependency(crypto, input, password, profile);

            var analysis = analysisCore.RunCryptAnalysis(payload, avalanche, keydep, input);
            return analysisCore.CalculateAggregateScore(analysis, scoringMode);
        }
    }

    public static class SequenceParser
    {
        public static (byte ID, byte TR)[] ParseSequenceLine(string sequenceLine)
        {
            return sequenceLine.Split("->", StringSplitOptions.RemoveEmptyEntries)
                .Select(part =>
                {
                    var idMatch = Regex.Match(part, "ID:(\\d+)");
                    var trMatch = Regex.Match(part, "TR:(\\d+)");
                    if (!idMatch.Success || !trMatch.Success)
                        throw new InvalidDataException($"Invalid sequence part: {part.Trim()}");
                    return ((byte)int.Parse(idMatch.Groups[1].Value), (byte)int.Parse(trMatch.Groups[1].Value));
                })
                .ToArray();
        }

        public static bool TryGetGlobalRounds(Dictionary<string, string> attributes, out int globalRounds)
        {
            globalRounds = 0;
            return attributes.TryGetValue("GR", out var value) && int.TryParse(value, out globalRounds);
        }
    }
}
