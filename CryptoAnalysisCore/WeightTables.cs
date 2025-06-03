namespace Mango.AnalysisCore;

public partial class CryptoAnalysisCore
{
    private static readonly Dictionary<OperationModes, Dictionary<string, double>> modeWeights = new()
    {
        {
            OperationModes.Cryptographic, new Dictionary<string, double>
            {
                { "Entropy", 0.3 },
                { "BitVariance", 0.2 },
                { "SlidingWindow", 0.1 }, // De-emphasized
                { "FrequencyDistribution", 0.1 }, // De-emphasized
                { "PeriodicityCheck", 0.1 },
                { "MangosCorrelation", 0.3 },
                { "PositionalMapping", 0.3 },
                { "AvalancheScore", 0.4 }, // Emphasized
                { "KeyDependency", 0.3 } // Important for cryptographic robustness
            }
        },
        {
            OperationModes.Exploratory, new Dictionary<string, double>
            {
                { "Entropy", 0.2 },
                { "BitVariance", 0.2 },
                { "SlidingWindow", 0.3 }, // Emphasized
                { "FrequencyDistribution", 0.3 }, // Emphasized
                { "PeriodicityCheck", 0.1 },
                { "MangosCorrelation", 0.2 },
                { "PositionalMapping", 0.2 },
                { "AvalancheScore", 0.2 }, // De-emphasized
                { "KeyDependency", 0.2 } // Secondary in exploratory analysis
            }
        },
        {
            OperationModes.Flattening, new Dictionary<string, double>
            {
                { "Entropy", 1.5 }, // 🚀 More weight to ensure full entropy neutralization.
                { "BitVariance", 1.0 }, // 🔥 Maintain uniform bit variance.
                { "SlidingWindow", 1.5 }, // 🔥 Ensure local patterns do not persist.
                { "FrequencyDistribution", 1.0 }, // ✅ Keep bytes evenly distributed.
                { "PeriodicityCheck", 1.0 }, // ✅ Ensure no periodic patterns remain.
                { "MangosCorrelation", 0.001 },
                { "PositionalMapping", 0.001 },
                { "AvalancheScore", 0.001 },
                { "KeyDependency", 0.001 }
            }
        },
        {
            OperationModes.None, new Dictionary<string, double>
            {
                { "Entropy", 1.0 },
                { "BitVariance", 1.0 },
                { "SlidingWindow", 1.0 },
                { "FrequencyDistribution", 1.0 },
                { "PeriodicityCheck", 1.0 },
                { "MangosCorrelation", 1.0 },
                { "PositionalMapping", 1.0 },
                { "AvalancheScore", 1.0 },
                { "KeyDependency", 1.0 }
            }
        },
        {
        OperationModes.Zero, new Dictionary<string, double>
        {
            { "Entropy", 0.0 },
            { "BitVariance", 0.0 },
            { "SlidingWindow", 0.0 },
            { "FrequencyDistribution", 0.0 },
            { "PeriodicityCheck", 0.0 },
            { "MangosCorrelation", 0.0 },
            { "PositionalMapping", 0.0 },
            { "AvalancheScore", 0.0 },
            { "KeyDependency", 0.0 }
        }
    }
    };

    public void ApplyWeights(OperationModes mode)
    {
        if (!modeWeights.TryGetValue(mode, out var weights))
            throw new ArgumentOutOfRangeException(nameof(mode), $"No weight table defined for mode '{mode}'.");

        foreach (var (metricName, metricInfo) in MetricsRegistry)
        {
            if (weights.TryGetValue(metricName, out var weight))
                metricInfo.Weight = weight;
            else
                metricInfo.Weight = 0.0; // 🚫 Metric not defined in this mode — disable it
        }
    }

    public bool TryGetWeights(OperationModes mode, out Dictionary<string, double> weights)
    {
        return modeWeights.TryGetValue(mode, out weights!);
    }

}

