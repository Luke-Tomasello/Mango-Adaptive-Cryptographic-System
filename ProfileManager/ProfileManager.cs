using Mango.AnalysisCore;
using Mango.Cipher;
using Mango.Common;
using Mango.ProfileHelpers;
using System.Text.RegularExpressions;
using static Mango.ProfileHelpers.ProfileIOUtils;

namespace Mango.ProfileManager
{
    public static class ProfileService
    {
        public static InputProfile? LoadProfile(string profileName)
        {
            if (string.IsNullOrWhiteSpace(profileName))
                return null;

            var profiles = LoadProfiles();
            if (!profiles.TryGetValue(profileName, out var dto))
                return null;

            return FromDto(profileName, dto);
        }

        public static bool UpdateProfile(string profileName, InputProfile profile)
        {
            var profiles = LoadProfiles();

            // Remove any existing entry with the same name, case-insensitively
            var existingKey = profiles.Keys
                .FirstOrDefault(k => string.Equals(k, profileName, StringComparison.OrdinalIgnoreCase));

            if (existingKey != null && existingKey != profileName)
                profiles.Remove(existingKey);

            // Save using user-supplied casing
            profiles[profileName] = ToDto(profile);
            return SaveProfiles(profiles);
        }

        public static bool ProfileExists(string profileName)
        {
            if (string.IsNullOrWhiteSpace(profileName))
                return false;

            var profiles = LoadProfiles();
            return profiles.ContainsKey(profileName);
        }

        public static bool ReplaceProfile(InputProfile profile)
        {
            var profiles = LoadProfiles();

            // Remove any existing profile with the same name (case-insensitive)
            profiles.Remove(profile.Name); // Safe because LoadProfiles uses OrdinalIgnoreCase

            // Add the updated profile
            profiles[profile.Name] = ToDto(profile);

            // Save updated dictionary
            return SaveProfiles(profiles);
        }

        public static InputProfile RecalculateProfileScore(
            InputProfile profile,
            CryptoLib crypto,
            byte[] input,
            string password,
            OperationModes weightMode,
            ScoringModes scoringMode)
        {
            var encrypted = crypto.Encrypt(profile, input);
            var payload = crypto.GetPayloadOnly(encrypted);

            var (avalanche, keydep) =
                Scoring.ProcessAvalancheAndKeyDependency(crypto, input, password, profile);

            var analysisCore = new CryptoAnalysisCore(weightMode);
            var analysis = analysisCore.RunCryptAnalysis(payload, avalanche, keydep, input);
            var aggregateScore = analysisCore.CalculateAggregateScore(analysis, scoringMode);

            return profile with { AggregateScore = aggregateScore };
        }

        public static bool DeleteProfile(string profileName)
        {
            if (string.IsNullOrWhiteSpace(profileName))
                return false;

            var profiles = LoadProfiles();
            if (!profiles.ContainsKey(profileName))
                return false;

            profiles.Remove(profileName);
            return SaveProfiles(profiles);
        }

        public static bool RenameProfile(string oldName, string newName)
        {
            if (string.IsNullOrWhiteSpace(oldName) || string.IsNullOrWhiteSpace(newName))
                return false;

            var profiles = LoadProfiles();

            if (!profiles.TryGetValue(oldName, out var dto))
                return false;

            if (profiles.ContainsKey(newName))
                return false;

            profiles.Remove(oldName);
            profiles[newName] = dto;

            return SaveProfiles(profiles);
        }
        public static List<(string Name, InputProfileDto Profile)> FilterProfiles(string pattern)
        {
            var profiles = LoadProfiles();

            var regex = new Regex(pattern, RegexOptions.IgnoreCase);

            return profiles
                .Where(kvp => regex.IsMatch(kvp.Key))
                .OrderBy(kvp => kvp.Key)
                .Select(kvp => (kvp.Key, kvp.Value))
                .ToList();
        }
        public static List<InputProfile> GetAllProfiles()
        {
            var profiles = LoadProfiles();

            return profiles.Select(kvp => FromDto(kvp.Key, kvp.Value)).ToList();
        }
        public static double? FetchScore(string profileName)
        {
            if (string.IsNullOrWhiteSpace(profileName))
                return null;

            var profiles = LoadProfiles();

            return profiles.TryGetValue(profileName, out var dto)
                ? dto.AggregateScore
                : null;
        }

        public static bool TryProcessContenderFile(
            string path,
            string profileName,
            Dictionary<string, InputProfileDto> db,
            List<string> created,
            List<string> updated)
        {
            if (!File.Exists(path))
            {
                return false;
            }

            string[] lines = File.ReadAllLines(path);
            int index = Array.FindIndex(lines, l => l.Trim().StartsWith("Contender #1"));
            if (index == -1)
            {
                return false;
            }

            string sequenceLine = lines.Skip(index).FirstOrDefault(l => l.Trim().StartsWith("Sequence:"))?.Trim()!;
            if (string.IsNullOrWhiteSpace(sequenceLine))
            {
                return false;
            }

            sequenceLine = sequenceLine.Replace("Sequence:", "").Trim();

            var match = Regex.Match(sequenceLine, @"\|\s*\(GR:(\d+)\)");
            if (!match.Success)
            {
                return false;
            }

            int gr = int.Parse(match.Groups[1].Value);

            var sequence = SequenceParser.ParseSequenceLine(sequenceLine);

            var dto = new InputProfileDto
            {
                Sequence = sequence.Select(p => new List<byte> { p.ID, p.TR }).ToList(),
                GlobalRounds = gr,
                AggregateScore = 0
            };

            if (db.ContainsKey(profileName))
            {
                db[profileName] = dto;
                updated.Add(profileName);
            }
            else
            {
                db[profileName] = dto;
                created.Add(profileName);
            }

            return true;
        }

    }
}