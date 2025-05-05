/*
 * CryptoLib Module
 * =============================================
 * Project: Mango
 * Purpose: Implements Mango’s core cryptographic engine. Responsible for adaptive
 *          transform-based encryption, deterministic coin generation, and
 *          feedback-free input entanglement.
 *
 *          This module provides:
 *            • Session-based encryption using TR/GR metadata
 *            • Dynamic transform registry with benchmark-aware tuning
 *            • Stateless coin model for input-sensitive variability
 *            • High-speed in-place transform engine with aggressive inlining
 *            • Transform registry with reversibility guarantees and TR support
 *            • Full Encrypt/Decrypt APIs with embedded headers and auto-reversal
 *            • Internal benchmark cache and scratch buffer pooling for speed
 *
 *          CryptoLib is responsible for cryptographic correctness, performance,
 *          and secure reversibility across all input types and transform sequences.
 *
 * Author: [Luke Tomasello, luke@tomasello.com]
 * Created: November 2024
 * License: [MIT]
 * =============================================
 */

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Mango.Cipher
{
    public class CryptoLibOptions
    {
        public CryptoLibOptions(
            int rounds = 9,
            byte[] sessionIv = null!,
            string zoneInfo = null!,
            Behaviors behavior = Behaviors.None)
        {
            Rounds = rounds;
            SessionIv = sessionIv ?? new CryptoUtils().GenerateSecureIv();
            ZoneInfo = zoneInfo;
            Behavior = behavior;
        }

        public CryptoLibOptions? Dupe()
        {
            return new CryptoLibOptions(
                Rounds,
                (byte[])SessionIv.Clone(),
                ZoneInfo,
                Behavior
            );
        }

        /// <summary>
        /// Default Initialization Vector (IV) used in encryption/decryption.
        /// </summary>
        public byte[] SessionIv { get; set; }

        /// <summary>
        /// Optional zone-specific label. 
        /// If set, it is appended to the password before cryptographic key (CBox) generation.
        /// If null, standard password-only behavior is used.
        /// </summary>
        public string ZoneInfo { get; set; }

        /// <summary>
        /// Number of default rounds for transformations.
        /// </summary>
        public int Rounds { get; set; }

        /// <summary>
        /// Flags for CryptoLib Behaviors.
        /// </summary>
        public Behaviors Behavior { get; set; }
    }

    [Flags]
    public enum Behaviors
    {
        None = 0x00,
        AssignBenchmarkValues = 0x01
    }

    public class CryptoLib
    {
        private const int HashLength = 32;
        private const int IvLength = 12;

        #region Construction

        public readonly byte[] CBox;         // 1D array of session-specific masks
        public readonly byte[] InverseCBox;  // 1D array for inverse mapping of masks
        public CryptoLibOptions Options;
        // 🧠 Stores the most recent header written or read by Encrypt/Decrypt.
        // 
        // Used internally to support block-based operations (EncryptBlock/DecryptBlock),
        // where only the first block includes a full header and subsequent blocks rely
        // on this cached metadata (e.g., transform config, hash, IV, GR).
        //
        // This field is automatically updated by:
        // - Encrypt(...) → saves header metadata for downstream EncryptBlock()
        // - Decrypt(...) → loads header metadata for downstream DecryptBlock()
        //
        // ❗ Not exposed externally — intended solely for managing block-mode state.
        private byte[] _lastHeader = [];

        public Dictionary<int, TransformInfo> TransformRegistry { get; private set; } = null!;

        public CryptoLib(string password, CryptoLibOptions? options = null) : this(Encoding.UTF8.GetBytes(password),
            options)
        {
        }

        public CryptoLib(byte[] seed, CryptoLibOptions? options = null)
        {
            Options = options ?? new CryptoLibOptions();

            // 🔹 If ZoneInfo is provided, append it to the seed before CBox generation
            if (!string.IsNullOrEmpty(Options.ZoneInfo))
            {
                var zoneBytes = Encoding.UTF8.GetBytes(Options.ZoneInfo);
                var combined = new byte[seed.Length + zoneBytes.Length];
                Buffer.BlockCopy(seed, 0, combined, 0, seed.Length);
                Buffer.BlockCopy(zoneBytes, 0, combined, seed.Length, zoneBytes.Length);
                seed = combined;
            }

            (CBox, InverseCBox) = GenerateCBox(seed);
            InitializeTransformRegistry();
        }

        private (byte[], byte[]) GenerateCBox(byte[] seed)
        {
            // Step 1: Initialize CBox with values 0-255
            var cBox = new byte[256];
            var inverseCBox = new byte[256];
            for (var i = 0; i < 256; i++) cBox[i] = (byte)i;

            // Step 2: Shuffle CBox using a modified Fisher-Yates algorithm
            using (var sha256 = SHA256.Create())
            {
                var hash = sha256.ComputeHash(seed);
                var hashIndex = 0;
                for (var i = 255; i > 0; i--)
                {
                    var j = hash[hashIndex % hash.Length];
                    var swapIndex = (j + i) % (i + 1);
                    Swap(cBox, i, swapIndex);
                    hashIndex++;
                }
            }

            // Step 3: Populate InverseCBox
            for (var i = 0; i < 256; i++) inverseCBox[cBox[i]] = (byte)i;

            return (cBox, inverseCBox);
        }
        private void Swap(byte[] array, int i, int j)
        {
            (array[i], array[j]) = (array[j], array[i]);
        }

        #endregion Construction

        #region Transform Registry

        private void InitializeTransformRegistry()
        {
            TransformRegistry = new Dictionary<int, TransformInfo>
            {
                {
                    1,
                    new TransformInfo
                        { Name = "XORTx", Id = 1, InverseId = 1, Implementation = XorTx, BenchmarkTimeMs = 0.0 }
                },
                {
                    2,
                    new TransformInfo
                    {
                        Name = "BitRandFlipTx", Id = 2, InverseId = 2, Implementation = BitRandFlipTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    3,
                    new TransformInfo
                    {
                        Name = "PassthroughTx", Id = 3, InverseId = 3, Implementation = PassthroughTx,
                        ExcludeFromPermutations = true, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    4,
                    new TransformInfo
                    {
                        Name = "ShuffleBitsFwdTx", Id = 4, InverseId = 5, Implementation = ShuffleBitsFwdTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    5,
                    new TransformInfo
                    {
                        Name = "ShuffleBitsInvTx", Id = 5, InverseId = 4, Implementation = ShuffleBitsInvTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    6,
                    new TransformInfo
                    {
                        Name = "MaskedDoubleSubFwdTx", Id = 6, InverseId = 7, Implementation = MaskedDoubleSubFwdTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    7,
                    new TransformInfo
                    {
                        Name = "MaskedDoubleSubInvTx", Id = 7, InverseId = 6, Implementation = MaskedDoubleSubInvTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    8,
                    new TransformInfo
                    {
                        Name = "ButterflyTx", Id = 8, InverseId = 8, Implementation = ButterflyTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    9,
                    new TransformInfo
                    {
                        Name = "SubBytesXorMaskFwdTx", Id = 9, InverseId = 10, Implementation = SubBytesXorMaskFwdTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    10,
                    new TransformInfo
                    {
                        Name = "SubBytesXorMaskInvTx", Id = 10, InverseId = 9, Implementation = SubBytesXorMaskInvTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    11,
                    new TransformInfo
                    {
                        Name = "SubBytesFwdTx", Id = 11, InverseId = 12, Implementation = SubBytesFwdTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    12,
                    new TransformInfo
                    {
                        Name = "SubBytesInvTx", Id = 12, InverseId = 11, Implementation = SubBytesInvTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    13,
                    new TransformInfo
                    {
                        Name = "NibbleSwapShuffleFwdTx", Id = 13, InverseId = 14,
                        Implementation = NibbleSwapShuffleFwdTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    14,
                    new TransformInfo
                    {
                        Name = "NibbleSwapShuffleInvTx", Id = 14, InverseId = 13,
                        Implementation = NibbleSwapShuffleInvTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    15,
                    new TransformInfo
                    {
                        Name = "ApplyMaskBasedMixingTx", Id = 15, InverseId = 15,
                        Implementation = ApplyMaskBasedMixingTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    16,
                    new TransformInfo
                    {
                        Name = "MaskBasedSBoxFwdTx", Id = 16, InverseId = 17, Implementation = MaskBasedSBoxFwdTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    17,
                    new TransformInfo
                    {
                        Name = "MaskBasedSBoxInvTx", Id = 17, InverseId = 16, Implementation = MaskBasedSBoxInvTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    18,
                    new TransformInfo
                    {
                        Name = "ShuffleNibblesFwdTx", Id = 18, InverseId = 19, Implementation = ShuffleNibblesFwdTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    19,
                    new TransformInfo
                    {
                        Name = "ShuffleNibblesInvTx", Id = 19, InverseId = 18, Implementation = ShuffleNibblesInvTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    20,
                    new TransformInfo
                    {
                        Name = "ShuffleBytesFwdTx", Id = 20, InverseId = 21, Implementation = ShuffleBytesFwdTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    21,
                    new TransformInfo
                    {
                        Name = "ShuffleBytesInvTx", Id = 21, InverseId = 20, Implementation = ShuffleBytesInvTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    22,
                    new TransformInfo
                    {
                        Name = "BitFlipCascadeTx", Id = 22, InverseId = 22, Implementation = BitFlipCascadeTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    23,
                    new TransformInfo
                    {
                        Name = "SlidingMaskOverlayTx", Id = 23, InverseId = 23, Implementation = SlidingMaskOverlayTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    24,
                    new TransformInfo
                    {
                        Name = "FrequencyEqualizerFwdTx", Id = 24, InverseId = 25,
                        Implementation = FrequencyEqualizerFwdTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    25,
                    new TransformInfo
                    {
                        Name = "FrequencyEqualizerInvTx", Id = 25, InverseId = 24,
                        Implementation = FrequencyEqualizerInvTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    26,
                    new TransformInfo
                    {
                        Name = "MicroBlockShufflerFwdTx", Id = 26, InverseId = 27,
                        Implementation = MicroBlockShufflerFwdTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    27,
                    new TransformInfo
                    {
                        Name = "MicroBlockShufflerInvTx", Id = 27, InverseId = 26,
                        Implementation = MicroBlockShufflerInvTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    28,
                    new TransformInfo
                    {
                        Name = "PatternEqualizerTx", Id = 28, InverseId = 28, Implementation = PatternEqualizerTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    29,
                    new TransformInfo
                    {
                        Name = "ButterflyWithPairsFwdTx", Id = 29, InverseId = 30,
                        Implementation = ButterflyWithPairsFwdTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    30,
                    new TransformInfo
                    {
                        Name = "ButterflyWithPairsInvTx", Id = 30, InverseId = 29,
                        Implementation = ButterflyWithPairsInvTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    31,
                    new TransformInfo
                    {
                        Name = "ButterflyWithRotationFwdTx", Id = 31, InverseId = 32,
                        Implementation = ButterflyWithRotationFwdTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    32,
                    new TransformInfo
                    {
                        Name = "ButterflyWithRotationInvTx", Id = 32, InverseId = 31,
                        Implementation = ButterflyWithRotationInvTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    33,
                    new TransformInfo
                    {
                        Name = "BitFlipButterflyFwdTx", Id = 33, InverseId = 34, Implementation = BitFlipButterflyFwdTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    34,
                    new TransformInfo
                    {
                        Name = "BitFlipButterflyInvTx", Id = 34, InverseId = 33, Implementation = BitFlipButterflyInvTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    35,
                    new TransformInfo
                    {
                        Name = "MaskedCascadeSubFwdFbTx", Id = 35, InverseId = 36,
                        Implementation = MaskedCascadeSubFwdFbTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    36,
                    new TransformInfo
                    {
                        Name = "MaskedCascadeSubInvFbTx", Id = 36, InverseId = 35,
                        Implementation = MaskedCascadeSubInvFbTx, BenchmarkTimeMs = 0.0
                    }
                },
                {
                    37,
                    new TransformInfo
                    {
                        Name = "MicroBlockSwapFwdTx", Id = 37, InverseId = 38, Implementation = MicroBlockSwapFwdTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    38,
                    new TransformInfo
                    {
                        Name = "MicroBlockSwapInvTx", Id = 38, InverseId = 37, Implementation = MicroBlockSwapInvTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    39,
                    new TransformInfo
                    {
                        Name = "NibbleInterleaverTx", Id = 39, InverseId = 39, Implementation = NibbleInterleaverTx,
                        BenchmarkTimeMs = 0.0
                    }
                },
                {
                    40,
                    new TransformInfo
                    {
                        Name = "ChunkedFbTx", Id = 40, InverseId = 40, Implementation = ChunkedFbTx,
                        BenchmarkTimeMs = 0.0
                    }
                }
            };
            ValidateTransformRegistry();
            AssignCoinPreferences();
            AssignBenchmarkValues();
        }

        // Ensures all transform IDs are sequential and gap-free, starting from ID 1.
        public void ValidateTransformRegistry()
        {
            var expectedId = 1;

            foreach (var transform in TransformRegistry)
            {
                if (transform.Key != expectedId)
                    throw new InvalidOperationException(
                        $"Transform ID sequence is broken. Expected ID {expectedId}, but found {transform.Key}.");

                expectedId++;
            }
        }

        private static Dictionary<int, double>? _benchmarkCache;

        private static readonly object CacheLock = new();

        public void AssignBenchmarkValues()
        {
            if (Options.Behavior.HasFlag(Behaviors.AssignBenchmarkValues))
            {
                // Lazy load cache once (thread-safe)
                if (_benchmarkCache == null)
                    lock (CacheLock)
                    {
                        _benchmarkCache ??= LoadBenchmarkCache();
                    }

                // Populate registry from static cache
                foreach (var transform in TransformRegistry.Values)
                    if (_benchmarkCache!.TryGetValue(transform.Id, out var timePerOpMs))
                        transform.BenchmarkTimeMs = timePerOpMs;
                    else
                        throw new InvalidOperationException(
                            $"[Error] Benchmark missing for Transform ID {transform.Id} ({transform.Name}). Ensure all benchmarks are present in TransformBenchmarkResults.json.");
            }
        }

        private static Dictionary<int, double>? LoadBenchmarkCache()
        {
            try
            {
                var json = File.ReadAllText("TransformBenchmarkResults.json");
                var parsed = System.Text.Json.JsonSerializer.Deserialize<List<TransformBenchmark>>(json);

                return parsed!.ToDictionary(x => x.Id, x => x.TimePerOpMs);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Error] Failed to load benchmark cache: {ex.Message}");
                throw; // Fail loudly since benchmarks are required!
            }
        }

        public static void FlushAndReloadBenchmarkCache()
        {
            lock (CacheLock)
            {
                // Clear existing cache
                _benchmarkCache = null;

                // Reload benchmark data from disk
                _benchmarkCache = LoadBenchmarkCache();
                //Console.WriteLine("[Info] Benchmark cache flushed and reloaded successfully.");
            }
        }

        private class TransformBenchmark
        {
            //public string Name { get; set; }
            public int Id { get; set; }
            public double TimePerOpMs { get; set; }
        }

        private void AssignCoinPreferences()
        {
            byte currentCoinIndex = 0;

            foreach (var transform in TransformRegistry.Values)
            {
                // Assign the next available coin index
                transform.CoinPreference = currentCoinIndex++;

                // Ensure inverse transform shares the same CoinPreference
                if (transform.InverseId != 0 &&
                    TransformRegistry.TryGetValue(transform.InverseId, out var inverseTransform))
                    inverseTransform.CoinPreference = transform.CoinPreference;
            }
        }

        public class TransformInfo
        {
            public required string Name { get; set; }
            public int Id { get; set; }
            public int InverseId { get; set; }
            public Action<byte[], byte>? Implementation { get; set; }
            public bool ExcludeFromPermutations { get; set; } = false; // Default to included
            public byte CoinPreference { get; set; } = 0; // Default to coin1
            public byte Rounds { get; set; } = 1; // Default 1 round

            /// <summary>
            /// Pre-calculated benchmark time for this transform, measured in milliseconds.
            /// Used for performance estimation and adaptive benchmarking routines.
            /// Value is derived from running the transform 1000x on a 4096-byte input.
            /// </summary>
            public double BenchmarkTimeMs { get; set; } = 0.0;
        }

        #endregion Transform Registry

        #region Transforms

        // Batch 1 refactored for ScratchBufferPool & non-nullable coins

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ChunkedFbTx(byte[] input, byte coin)
        {
            ChunkedFbTxWorker(input, coin, 256);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ChunkedFbTxWorker(byte[] input, byte coin, int chunkSize)
        {
            if (chunkSize <= 0)
                throw new ArgumentException("Chunk size must be greater than 0.", nameof(chunkSize));

            for (var i = 0; i < input.Length; i++)
            {
                var chunkSeed = (byte)(coin + i / chunkSize);
                var prng = new TomRandom(this, chunkSeed);
                input[i] ^= prng.NextMask();
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void NibbleInterleaverTx(byte[] input, byte coin)
        {
            for (var i = 0; i < input.Length; i++)
                if (i % 2 == 1)
                {
                    var high = (byte)((input[i] & 0xF0) >> 4);
                    var low = (byte)(input[i] & 0x0F);
                    input[i] = (byte)((low << 4) | high);
                }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void MicroBlockSwapFwdTx(byte[] input, byte coin)
        {
            var blockSize = 4;
            if (input.Length % blockSize != 0)
                throw new ArgumentException("Input length must be a multiple of block size.");

            var scratch = ScratchBufferPool.Rent(blockSize);

            for (var blockStart = 0; blockStart < input.Length; blockStart += blockSize)
            {
                scratch[0] = input[blockStart + 3];
                scratch[1] = input[blockStart + 1];
                scratch[2] = input[blockStart + 0];
                scratch[3] = input[blockStart + 2];

                for (var j = 0; j < blockSize; j++)
                    input[blockStart + j] = scratch[j];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void MicroBlockSwapInvTx(byte[] input, byte coin)
        {
            var blockSize = 4;
            if (input.Length % blockSize != 0)
                throw new ArgumentException("Input length must be a multiple of block size.");

            var scratch = ScratchBufferPool.Rent(blockSize);

            for (var blockStart = 0; blockStart < input.Length; blockStart += blockSize)
            {
                scratch[0] = input[blockStart + 2];
                scratch[1] = input[blockStart + 1];
                scratch[2] = input[blockStart + 3];
                scratch[3] = input[blockStart + 0];

                for (var j = 0; j < blockSize; j++)
                    input[blockStart + j] = scratch[j];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void MaskedCascadeSubFwdFbTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);

            for (var i = 0; i < input.Length; i++)
            {
                var randomMask = prng.NextMask();
                var transformedByte = (byte)(input[i] ^ randomMask);
                transformedByte = (byte)Tables.SBox[CBox[transformedByte]];
                input[i] = transformedByte;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void MaskedCascadeSubInvFbTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);

            for (var i = 0; i < input.Length; i++)
            {
                var transformedByte = (byte)Tables.InverseSBox[input[i]];
                transformedByte = InverseCBox[transformedByte];
                var randomMask = prng.NextMask();
                input[i] = (byte)(transformedByte ^ randomMask);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ButterflyWithRotationFwdTx(byte[] input, byte coin)
        {
            for (var ix = 0; ix < input.Length; ix++)
            {
                var swapped = (byte)((input[ix] >> 4) | (input[ix] << 4));
                if (ix % 2 == 0)
                    swapped = (byte)((swapped >> 2) | (swapped << 6));
                else
                    swapped = (byte)((swapped << 3) | (swapped >> 5));
                input[ix] = swapped;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ButterflyWithRotationInvTx(byte[] input, byte coin)
        {
            for (var ix = 0; ix < input.Length; ix++)
            {
                var swapped = input[ix];
                if (ix % 2 == 0)
                    swapped = (byte)((swapped << 2) | (swapped >> 6));
                else
                    swapped = (byte)((swapped >> 3) | (swapped << 5));
                input[ix] = (byte)((swapped >> 4) | (swapped << 4));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void BitFlipButterflyFwdTx(byte[] input, byte coin)
        {
            for (var ix = 0; ix < input.Length; ix++)
            {
                var swapped = (byte)((input[ix] >> 4) | (input[ix] << 4));
                if (ix % 2 == 1)
                    swapped ^= 0b00001000;
                input[ix] = swapped;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void BitFlipButterflyInvTx(byte[] input, byte coin)
        {
            for (var ix = 0; ix < input.Length; ix++)
            {
                var swapped = input[ix];
                if (ix % 2 == 1)
                    swapped ^= 0b00001000;
                input[ix] = (byte)((swapped >> 4) | (swapped << 4));
            }
        }


        // Refactor Batch #2 - In-Place Model + Scratch Buffer API

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ButterflyWithPairsFwdTx(byte[] input, byte coin)
        {
            byte prevByte = 0;
            for (var ix = 0; ix < input.Length; ix++)
            {
                var swapped = (byte)((input[ix] >> 4) | (input[ix] << 4));
                swapped ^= (byte)((prevByte >> 1) & 0xF0);
                prevByte = input[ix];
                input[ix] = swapped;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ButterflyWithPairsInvTx(byte[] input, byte coin)
        {
            byte prevByte = 0;
            for (var ix = 0; ix < input.Length; ix++)
            {
                var swapped = (byte)(input[ix] ^ ((prevByte >> 1) & 0xF0));
                var result = (byte)((swapped >> 4) | (swapped << 4));
                prevByte = result;
                input[ix] = result;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void PatternEqualizerTx(byte[] input, byte coin)
        {
            const int windowSize = 8;
            var prng = new TomRandom(this, coin);

            var rollingPattern = 0;
            var patternCounts = new int[1 << windowSize];

            for (var i = 0; i < input.Length * 8; i++)
            {
                var byteIndex = i / 8;
                var bitIndex = i % 8;
                var bit = (input[byteIndex] >> bitIndex) & 1;
                rollingPattern = ((rollingPattern << 1) | bit) & ((1 << windowSize) - 1);
                if (i >= windowSize - 1) patternCounts[rollingPattern]++;
            }

            for (var i = 0; i < input.Length; i++)
                if (prng.Next(2) == 1)
                    input[i] ^= (byte)(1 << prng.Next(8));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void BitFlipCascadeTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            for (var i = 0; i < input.Length; i++)
                for (var bit = 0; bit < 8; bit++)
                    if ((i + bit) % 3 == 0 || prng.Next(2) == 1)
                        input[i] ^= (byte)(1 << bit);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void SlidingMaskOverlayTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            var slidingMask = (byte)prng.Next(256);

            for (var i = 0; i < input.Length; i++)
            {
                input[i] ^= slidingMask;
                slidingMask = (byte)((slidingMask >> 1) | (prng.Next(256) << 7));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void MicroBlockShufflerFwdTx(byte[] input, byte coin)
        {
            const int blockSize = 4;
            var prng = new TomRandom(this, coin);

            for (var blockStart = 0; blockStart < input.Length; blockStart += blockSize)
            {
                var blockEnd = Math.Min(blockStart + blockSize, input.Length);
                var indices = new int[blockEnd - blockStart];
                for (var i = 0; i < indices.Length; i++)
                    indices[i] = i;

                for (var i = indices.Length - 1; i > 0; i--)
                {
                    var j = prng.Next(i + 1);
                    (indices[i], indices[j]) = (indices[j], indices[i]);
                }

                var scratch = ScratchBufferPool.Rent(blockSize);
                for (var i = 0; i < indices.Length; i++) scratch[i] = input[blockStart + indices[i]];
                for (var i = 0; i < indices.Length; i++) input[blockStart + i] = scratch[i];
                ScratchBufferPool.Return(scratch);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void MicroBlockShufflerInvTx(byte[] input, byte coin)
        {
            const int blockSize = 4;
            var prng = new TomRandom(this, coin);

            for (var blockStart = 0; blockStart < input.Length; blockStart += blockSize)
            {
                var blockEnd = Math.Min(blockStart + blockSize, input.Length);
                var indices = new int[blockEnd - blockStart];
                for (var i = 0; i < indices.Length; i++)
                    indices[i] = i;

                for (var i = indices.Length - 1; i > 0; i--)
                {
                    var j = prng.Next(i + 1);
                    (indices[i], indices[j]) = (indices[j], indices[i]);
                }

                var scratch = ScratchBufferPool.Rent(blockSize);
                for (var i = 0; i < indices.Length; i++) scratch[indices[i]] = input[blockStart + i];
                for (var i = 0; i < indices.Length; i++) input[blockStart + i] = scratch[i];
                ScratchBufferPool.Return(scratch);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void FrequencyEqualizerFwdTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            for (var i = 0; i < input.Length; i++) input[i] = (byte)((input[i] + prng.Next(256)) % 256);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void FrequencyEqualizerInvTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            for (var i = 0; i < input.Length; i++) input[i] = (byte)((input[i] - prng.Next(256) + 256) % 256);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void XorTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            for (var ix = 0; ix < input.Length; ix++) input[ix] ^= prng.NextMask();
        }


        // Refactor Batch #3 - In-Place Model + Scratch Buffer API

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void BitRandFlipTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            for (var ix = 0; ix < input.Length; ix++)
            {
                var bitsToFlip = prng.Next(1, 5);
                for (var i = 0; i < bitsToFlip; i++)
                {
                    var bitToFlip = prng.Next(8);
                    input[ix] ^= (byte)(1 << bitToFlip);
                }
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void PassthroughTx(byte[] input, byte coin)
        {
            // No-op. Passthrough is now in-place.
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ShuffleNibblesFwdTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            var totalNibbles = input.Length * 2;
            var scratch = ScratchBufferPool.Rent(totalNibbles);

            for (var i = 0; i < input.Length; i++)
            {
                scratch[i * 2] = (byte)((input[i] >> 4) & 0x0F);
                scratch[i * 2 + 1] = (byte)(input[i] & 0x0F);
            }

            for (var i = totalNibbles - 1; i > 0; i--)
            {
                var j = prng.NextMask() % (i + 1);
                (scratch[i], scratch[j]) = (scratch[j], scratch[i]);
            }

            for (var i = 0; i < input.Length; i++) input[i] = (byte)((scratch[i * 2] << 4) | scratch[i * 2 + 1]);

            ScratchBufferPool.Return(scratch);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ShuffleNibblesInvTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            var totalNibbles = input.Length * 2;
            var scratch = ScratchBufferPool.Rent(totalNibbles);

            for (var i = 0; i < input.Length; i++)
            {
                scratch[i * 2] = (byte)((input[i] >> 4) & 0x0F);
                scratch[i * 2 + 1] = (byte)(input[i] & 0x0F);
            }

            var indices = new Stack<int>();
            for (var i = totalNibbles - 1; i > 0; i--) indices.Push(prng.NextMask() % (i + 1));
            for (var i = 1; i < totalNibbles; i++)
            {
                var j = indices.Pop();
                (scratch[i], scratch[j]) = (scratch[j], scratch[i]);
            }

            for (var i = 0; i < input.Length; i++) input[i] = (byte)((scratch[i * 2] << 4) | scratch[i * 2 + 1]);

            ScratchBufferPool.Return(scratch);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ShuffleBytesFwdTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            var scratch = ScratchBufferPool.Rent(input.Length);

            Array.Copy(input, scratch, input.Length);
            for (var i = input.Length - 1; i > 0; i--)
            {
                var j = prng.NextMask() % (i + 1);
                (scratch[i], scratch[j]) = (scratch[j], scratch[i]);
            }

            Array.Copy(scratch, input, input.Length);

            ScratchBufferPool.Return(scratch);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ShuffleBytesInvTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            var scratch = ScratchBufferPool.Rent(input.Length);

            Array.Copy(input, scratch, input.Length);

            var indices = new Stack<int>();
            for (var i = input.Length - 1; i > 0; i--) indices.Push(prng.NextMask() % (i + 1));
            for (var i = 1; i < input.Length; i++)
            {
                var j = indices.Pop();
                (scratch[i], scratch[j]) = (scratch[j], scratch[i]);
            }

            Array.Copy(scratch, input, input.Length);

            ScratchBufferPool.Return(scratch);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ShuffleBitsFwdTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            var totalBits = input.Length * 8;
            var scratch = ScratchBufferPool.Rent(totalBits);

            for (var i = 0; i < totalBits; i++) scratch[i] = (byte)(((input[i / 8] >> (i % 8)) & 1) != 0 ? 1 : 0);

            for (var i = totalBits - 1; i > 0; i--)
            {
                var j = prng.NextMask() % (i + 1);
                (scratch[i], scratch[j]) = (scratch[j], scratch[i]);
            }

            Array.Clear(input);
            for (var i = 0; i < totalBits; i++)
                if (scratch[i] != 0)
                    input[i / 8] |= (byte)(1 << (i % 8));

            ScratchBufferPool.Return(scratch);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ShuffleBitsInvTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            var totalBits = input.Length * 8;
            var scratch = ScratchBufferPool.Rent(totalBits);

            for (var i = 0; i < totalBits; i++) scratch[i] = (byte)(((input[i / 8] >> (i % 8)) & 1) != 0 ? 1 : 0);

            var indices = new Stack<int>();
            for (var i = totalBits - 1; i > 0; i--) indices.Push(prng.NextMask() % (i + 1));
            for (var i = 1; i < totalBits; i++)
            {
                var j = indices.Pop();
                (scratch[i], scratch[j]) = (scratch[j], scratch[i]);
            }

            Array.Clear(input);
            for (var i = 0; i < totalBits; i++)
                if (scratch[i] != 0)
                    input[i / 8] |= (byte)(1 << (i % 8));

            ScratchBufferPool.Return(scratch);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void MaskedDoubleSubFwdTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            for (var ix = 0; ix < input.Length; ix++)
            {
                var mask = prng.NextMask();
                input[ix] = (byte)(Tables.SBox[input[ix]] ^ mask);
                input[ix] = (byte)Tables.SBox[input[ix]];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void MaskedDoubleSubInvTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            for (var ix = 0; ix < input.Length; ix++)
            {
                var mask = prng.NextMask();
                input[ix] = (byte)Tables.InverseSBox[input[ix]];
                input[ix] = (byte)Tables.InverseSBox[input[ix] ^ mask];
            }
        }


        // Refactor Batch #4 - Final Transforms to In-Place Model

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ButterflyTx(byte[] input, byte coin)
        {
            for (var ix = 0; ix < input.Length; ix++) input[ix] = (byte)((input[ix] >> 4) | (input[ix] << 4));
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void SubBytesXorMaskFwdTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            for (var ix = 0; ix < input.Length; ix++)
            {
                var mask = prng.NextMask();
                input[ix] = (byte)(Tables.SBox[input[ix]] ^ mask);
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void SubBytesXorMaskInvTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            for (var ix = 0; ix < input.Length; ix++)
            {
                var mask = prng.NextMask();
                input[ix] = Tables.InverseSBox[(byte)(input[ix] ^ mask)];
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void SubBytesFwdTx(byte[] input, byte coin)
        {
            for (var ix = 0; ix < input.Length; ix++) input[ix] = (byte)Tables.SBox[input[ix]];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void SubBytesInvTx(byte[] input, byte coin)
        {
            for (var ix = 0; ix < input.Length; ix++) input[ix] = Tables.InverseSBox[input[ix]];
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void NibbleSwapShuffleFwdTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);

            for (var i = 0; i < input.Length; i++)
            {
                var swapIndex = prng.NextMask() % input.Length;

                var lowerNibble = (byte)(input[i] & 0x0F);
                var upperNibble = (byte)(input[swapIndex] & 0xF0);
                input[i] = (byte)((input[i] & 0xF0) | (upperNibble >> 4));
                input[swapIndex] = (byte)((input[swapIndex] & 0x0F) | (lowerNibble << 4));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void NibbleSwapShuffleInvTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);

            var indices = new Stack<int>();
            for (var i = 0; i < input.Length; i++)
            {
                var swapIndex = prng.NextMask() % input.Length;
                indices.Push(swapIndex);
            }

            while (indices.Count > 0)
            {
                var i = indices.Count - 1;
                var swapIndex = indices.Pop();

                var lowerNibble = (byte)(input[i] & 0x0F);
                var upperNibble = (byte)(input[swapIndex] & 0xF0);
                input[i] = (byte)((input[i] & 0xF0) | (upperNibble >> 4));
                input[swapIndex] = (byte)((input[swapIndex] & 0x0F) | (lowerNibble << 4));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private void ApplyMaskBasedMixingTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);

            for (var i = 0; i < input.Length; i++)
            {
                var targetByte = input[i];

                byte sBoxValue;
                do
                {
                    var randomIndex = prng.Next(256);
                    sBoxValue = Tables.SBox[randomIndex];
                } while (sBoxValue == 0);

                while ((sBoxValue & 0xF0) == 0) sBoxValue = (byte)((sBoxValue << 1) | (sBoxValue >> 7));

                var maskNibble = (byte)((sBoxValue & 0xF0) >> 4);

                input[i] = (byte)(
                    ((targetByte & 0xF0) ^ (maskNibble << 4)) |
                    (targetByte & 0x0F));
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void MaskBasedSBoxFwdTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            var sBox = Tables.SBox;

            for (var i = 0; i < input.Length; i++)
            {
                var maskIndex = prng.NextMask();
                var sBoxValue = sBox[maskIndex];
                input[i] ^= sBoxValue;
            }
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public void MaskBasedSBoxInvTx(byte[] input, byte coin)
        {
            var prng = new TomRandom(this, coin);
            var sBox = Tables.SBox;

            for (var i = 0; i < input.Length; i++)
            {
                var maskIndex = prng.NextMask();
                var sBoxValue = sBox[maskIndex];
                input[i] ^= sBoxValue;
            }
        }

        #endregion Transforms

        #region Experimental

        public class LatticeTransform
        {
            private readonly int[,] _matrix = { { 3, 5 }, { 2, 7 } }; // Example lattice matrix
            private readonly int[,] _inverseMatrix;
            private const int Base = 256; // Modulo base

            public LatticeTransform()
            {
                // Precompute the inverse matrix
                _inverseMatrix = ComputeInverseMatrix(_matrix);
            }

            // Forward transformation
            public byte[] Apply(byte[] input)
            {
                var isPadded = false;

                // Pad input if length is odd
                if (input.Length % 2 != 0)
                {
                    input = input.Concat(new byte[] { 0 }).ToArray();
                    isPadded = true;
                }

                var output = new byte[input.Length];
                for (var i = 0; i < input.Length; i += 2)
                {
                    int x = input[i];
                    int y = input[i + 1];

                    // Matrix multiplication
                    output[i] = (byte)((_matrix[0, 0] * x + _matrix[0, 1] * y) % Base);
                    output[i + 1] = (byte)((_matrix[1, 0] * x + _matrix[1, 1] * y) % Base);
                }

                // Add a marker for padding if needed
                return isPadded ? output.Concat(new byte[] { 1 }).ToArray() : output;
            }


            // Reverse transformation
            public byte[] Reverse(byte[] input)
            {
                // Check for padding marker
                var isPadded = input[^1] == 1;
                if (isPadded) input = input.Take(input.Length - 1).ToArray();

                var output = new byte[input.Length];
                for (var i = 0; i < input.Length; i += 2)
                {
                    int x = input[i];
                    int y = input[i + 1];

                    // Matrix multiplication with inverse matrix
                    output[i] = (byte)((_inverseMatrix[0, 0] * x + _inverseMatrix[0, 1] * y) % Base);
                    output[i + 1] = (byte)((_inverseMatrix[1, 0] * x + _inverseMatrix[1, 1] * y) % Base);
                }

                // Remove padding if it was added
                return isPadded ? output.Take(output.Length - 1).ToArray() : output;
            }


            // Compute the inverse of a 2x2 matrix mod Base
            private int[,] ComputeInverseMatrix(int[,] matrix)
            {
                int a = matrix[0, 0], b = matrix[0, 1];
                int c = matrix[1, 0], d = matrix[1, 1];

                // Compute determinant
                var det = (a * d - b * c) % Base;
                if (det < 0) det += Base; // Ensure positive determinant

                // Modular multiplicative inverse of determinant
                var detInv = ModularInverse(det, Base);

                // Compute inverse matrix
                return new int[,]
                {
                    { d * detInv % Base, (-b * detInv + Base) % Base },
                    { (-c * detInv + Base) % Base, a * detInv % Base }
                };
            }

            // Compute modular inverse using extended Euclidean algorithm
            private int ModularInverse(int value, int mod)
            {
                int t = 0, newT = 1;
                int r = mod, newR = value;

                while (newR != 0)
                {
                    var quotient = r / newR;
                    (t, newT) = (newT, t - quotient * newT);
                    (r, newR) = (newR, r - quotient * newR);
                }

                if (r > 1) throw new InvalidOperationException("Value is not invertible.");
                if (t < 0) t += mod;

                return t;
            }
        }

        #endregion Experimental

        #region API

        public record InputProfile(
            string Name, // e.g., "Combined", "Natural", etc. — Workbench-friendly label
            (byte ID, byte TR)[] Sequence, // Transform sequence with rounds baked in
            int GlobalRounds // Required by core + Workbench for configuration
        );

        internal static class HeaderProfile
        {
            private const int GlobalRounds = 6;
            private const int PerTransformRounds = 3;
            private const int RequiredCount = 5;
            private const byte InitialTransformId = 35; // MaskedCascadeSubFwdFbTx

            internal static InputProfile GetHeaderProfile(CryptoLib cryptoLib)
            {
                byte[] cbox = cryptoLib.CBox;
                List<(byte ID, byte TR)> sequence = new();
                sequence.Add((InitialTransformId, PerTransformRounds)); // Always start with strong input destroyer

                foreach (var t in cbox)
                {
                    if (t < 1 || t > 40) continue;

                    if (!cryptoLib.TransformRegistry.TryGetValue(t, out var info)) continue;
                    if (info.ExcludeFromPermutations) continue;

                    sequence.Add((t, PerTransformRounds));
                    if (sequence.Count == RequiredCount + 1) break;
                }

                if (sequence.Count < RequiredCount + 1)
                    throw new InvalidOperationException("Insufficient eligible transforms in CBox.");

                return new InputProfile("HeaderEncryption", sequence.ToArray(), GlobalRounds);
            }
        }

        #region Header Management

        private const int FixedHeaderPortionLength =
    2                // Version
    + HashLength
    + IvLength
    + 1                // Rounds
    + 1                // SequenceLength
    + 1;               // KPI padding byte

        private byte[] EncryptHeader(byte[] input)
        {
            InputProfile headerProfile = HeaderProfile.GetHeaderProfile(this);
            var trConfig = headerProfile.Sequence;
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(CBox);
            var saveRounds = SaveTransformRounds();

            if (CheckVersion(trConfig, out var required) == false)
                throw new InvalidOperationException($"Encrypted packet requires CryptoLib version {required} or higher. Decryption aborted.");

            var rounds = headerProfile.GlobalRounds;
            ApplyTransformRounds(trConfig);
            var constructedIv = CBox.Take(12).ToArray();
            var combinedHash = CombineHashAndNonce(hash, constructedIv);
            var coins = GetCoins(combinedHash);
            var idOnlySequence = trConfig.Select(p => p.ID).ToArray();

            // Encrypt PART 1 (fixed header portion)
            var part1Plain = input[..(FixedHeaderPortionLength - 1)];
            var part1Encrypted = ApplyTransformationsRepeated(part1Plain, idOnlySequence, coins, false, rounds);

            // Encrypt PART 2 (remainder of header)
            var part2Plain = input[(FixedHeaderPortionLength - 1)..];
            var part2Encrypted = ApplyTransformationsRepeated(part2Plain, idOnlySequence, coins, false, rounds);

            RestoreTransformRounds(saveRounds);
            return CombineArrays(part1Encrypted, part2Encrypted);
        }

        private byte[] DecryptHeader(byte[] input)
        {
            InputProfile headerProfile = HeaderProfile.GetHeaderProfile(this);
            var trConfig = GenerateReverseSequence(headerProfile.Sequence);
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(CBox);
            var saveRounds = SaveTransformRounds();

            var rounds = headerProfile.GlobalRounds;
            ApplyTransformRounds(trConfig);
            var constructedIv = CBox.Take(12).ToArray();
            var combinedHash = CombineHashAndNonce(hash, constructedIv);
            var coins = GetCoins(combinedHash);
            var idOnlySequence = trConfig.Select(p => p.ID).ToArray();

            // Decrypt PART 1
            var part1Encrypted = input[..FixedHeaderPortionLength];
            var part1Decrypted = ApplyTransformationsRepeated(part1Encrypted, idOnlySequence, coins, true, rounds);

            // Extract SequenceLength from decrypted PART 1
            var sequenceLengthOffset = 2 + HashLength + IvLength + 1;
            var sequenceLength = part1Decrypted[sequenceLengthOffset];
            var fullHeaderSize = FixedHeaderPortionLength + sequenceLength * 2;

            // Decrypt PART 2 (if present)
            byte[] part2Decrypted = Array.Empty<byte>();
            if (input.Length > FixedHeaderPortionLength)
            {
                var availablePart2 = input.Length - FixedHeaderPortionLength;

                // 🔐 Part 2 was padded to 16 bytes + 1 bp
                var part2PlainLength = sequenceLength * 2;
                var paddedLength = ((part2PlainLength + 15) / 16) * 16;
                var expectedPart2Length = paddedLength + 1;

                if (availablePart2 >= expectedPart2Length)
                {
                    var part2Encrypted = input[FixedHeaderPortionLength..(FixedHeaderPortionLength + expectedPart2Length)];
                    part2Decrypted = ApplyTransformationsRepeated(part2Encrypted, idOnlySequence, coins, true, rounds);
                }
            }

            RestoreTransformRounds(saveRounds);
            return CombineArrays(part1Decrypted, part2Decrypted);
        }

        private byte[] DecryptHeaderOnly(byte[] encrypted)
        {
            if (encrypted == null) throw new ArgumentNullException(nameof(encrypted));

            // Step 1: Fully decrypt the header (removes 2 pb bytes internally)
            var decryptedHeader = DecryptHeader(encrypted);

            // ✅ Validate header size before attempting to split
            if (decryptedHeader.Length < FixedHeaderPortionLength - 1)
                throw new InvalidOperationException("Header is shorter than expected.");

            // Step 2: Dynamically compute the encrypted header length
            int blockSize = 16;
            int part1PlainLength = FixedHeaderPortionLength - 1;
            int part2PlainLength = decryptedHeader.Length - part1PlainLength;

            int part1PaddedLength = GetPaddedLength(part1PlainLength, blockSize);
            int part2PaddedLength = GetPaddedLength(part2PlainLength, blockSize);
            int encryptedHeaderLength = part1PaddedLength + part2PaddedLength;

            // Step 3: Slice off the remaining encrypted body
            var fullEncryptedBody = encrypted.AsSpan(encryptedHeaderLength);
            if (fullEncryptedBody.Length < 1)
                throw new InvalidOperationException("Encrypted body too short after header.");

#if DEBUG
            // ParseHeaderForDebug(decryptedHeader);
#endif

            // Step 5: Return [decrypted header || remaining encrypted body]
            return CombineArrays(decryptedHeader, fullEncryptedBody.ToArray());
        }
        static int GetPaddedLength(int length, int blockSize)
        {
            int padding = (length % blockSize == 0) ? 0 : blockSize - (length % blockSize);
            return length + padding + 1; // +1 for pb
        }

        private byte[] ApplyTransformationsRepeated(byte[] input, byte[] idSequence, byte[] coins, bool reverse, int rounds)
        {
            var buffer = ScratchBufferPool.Rent(input.Length);
            Buffer.BlockCopy(input, 0, buffer, 0, input.Length);

            var result = ApplyTransformations(idSequence, buffer, coins, reverse, rounds);

            ScratchBufferPool.Return(buffer); // Safe to return after use
            return result; // Result is a freshly allocated array
        }

#if DEBUG
        private void ParseHeaderForDebug(byte[] decryptedHeader)
        {
            // 📜 Debug header parser: Extracts and displays fields from a decrypted Mango header.
            var offset = 0;

            var versionMajor = decryptedHeader[offset++];
            var versionMinor = decryptedHeader[offset++];

            var hash = new byte[HashLength];
            Buffer.BlockCopy(decryptedHeader, offset, hash, 0, HashLength);
            offset += HashLength;

            var iv = new byte[IvLength];
            Buffer.BlockCopy(decryptedHeader, offset, iv, 0, IvLength);
            offset += IvLength;

            var roundsByte = decryptedHeader[offset++];
            var sequenceLengthByte = decryptedHeader[offset++];

            List<(byte ID, byte TR)> idTrPairs = new();
            for (var i = 0; i < sequenceLengthByte; i++)
            {
                var id = decryptedHeader[offset++];
                var tr = decryptedHeader[offset++];
                idTrPairs.Add((id, tr));
            }

            // 🌟 Output
            Console.WriteLine($"Version: {versionMajor}.{versionMinor}");
            Console.WriteLine($"Hash: {string.Join(",", hash)}");
            Console.WriteLine($"IV: {string.Join(",", iv)}");
            Console.WriteLine($"Rounds: {roundsByte}");
            Console.WriteLine($"Sequence Length: {sequenceLengthByte}");

            Console.WriteLine("Transform Sequence:");
            foreach (var (id, tr) in idTrPairs) Console.WriteLine($"  ID: {id}, TR: {tr}");
        }
#endif

        //[MethodImpl(MethodImplOptions.AggressiveInlining)]
        private byte[] CombineArrays(byte[] a, byte[] b)
        {
            var result = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            return result;
        }

        #endregion Header Management

        public byte[] Encrypt(byte[] input)
        {
            InputProfile headerProfile = HeaderProfile.GetHeaderProfile(this);
            return Encrypt(headerProfile.Sequence, headerProfile.GlobalRounds, input);
        }

        public byte[] EncryptBlock(byte[] input)
        {
            if (_lastHeader == null || _lastHeader.Length == 0)
                throw new InvalidOperationException("❌ First block must be encrypted before EncryptBlock can be used.");

            // Extract the transform config from the stored header
            var (hash, iv, rounds, trConfig, _) = ExtractHeaderAndCiphertext(_lastHeader, HashLength, IvLength);

            // Ensure all transforms in the sequence are supported by the current library version.
            // If any transform ID exceeds the supported set, this indicates a version mismatch.
            if (CheckVersion(trConfig, out var required) == false)
                throw new InvalidOperationException(
                    $"Encrypted packet requires CryptoLib version {required} or higher. Decryption aborted.");

            // Set GR and TRs from header
            Options.Rounds = rounds;
            ApplyTransformRounds(trConfig);

            // Compute derived Coins
            var combinedHash = CombineHashAndNonce(hash, iv);
            var coins = GetCoins(combinedHash);

            // Prepare a copy of the input
            var data = new byte[input.Length];
            Array.Copy(input, data, input.Length);

            // Get just the transform IDs
            var idOnlySequence = trConfig.Select(p => p.ID).ToArray();

            // Apply the transformations (forward direction)
            //for (var i = 0; i < Options.Rounds; i++) 
            data = ApplyTransformations(idOnlySequence, data, coins, false, Options.Rounds);

            return data; // ✅ Encrypted payload without header
        }

        public byte[] Encrypt((byte ID, byte TR)[] sequence, int globalRounds, byte[] input)
        {
            // Set GR and TRs from profile
            Options.Rounds = globalRounds;
            ApplyTransformRounds(sequence);

            // Extract just the IDs for encryption
            var idOnlySequence = sequence.Select(p => p.ID).ToArray();

            // Run encryption
            var encrypted = Encrypt(idOnlySequence, input);

            // done!
            return encrypted;
        }

        public byte[] Decrypt(byte[] originalEncryptedInput)
        {
            // 🔓 Decrypt the encrypted header and reattach it to the ciphertext for normal parsing
            var decryptedHeaderInput = DecryptHeaderOnly(originalEncryptedInput);

            // Extract header and transform config
            var (_, _, rounds, trConfig, ciphertext) =
                ExtractHeaderAndCiphertext(decryptedHeaderInput, HashLength, IvLength);

            // Ensure all transforms in the sequence are supported by the current library version.
            // If any transform ID exceeds the supported set, this indicates a version mismatch.
            if (CheckVersion(trConfig, out var required) == false)
                throw new InvalidOperationException(
                    $"Encrypted packet requires CryptoLib version {required} or higher. Decryption aborted.");

            // Generate reverse sequence
            trConfig = GenerateReverseSequence(trConfig);

            // Set GR and TRs from extracted config
            Options.Rounds = rounds;
            ApplyTransformRounds(trConfig);

            var sequence = trConfig.Select(t => t.ID).ToArray();

            return Decrypt(sequence, originalEncryptedInput);
        }

        public byte[] DecryptBlock(byte[] input)
        {
            if (_lastHeader == null || _lastHeader.Length == 0)
                throw new InvalidOperationException("❌ First block must be decrypted before DecryptBlock can be used.");

            // Extract config from stored header (no payload in LastHeader)
            var (hash, iv, rounds, trConfig, _) = ExtractHeaderAndCiphertext(_lastHeader, HashLength, IvLength);

            // Ensure all transforms in the sequence are supported by the current library version.
            // If any transform ID exceeds the supported set, this indicates a version mismatch.
            if (CheckVersion(trConfig, out var required) == false)
                throw new InvalidOperationException(
                    $"Encrypted packet requires CryptoLib version {required} or higher. Decryption aborted.");

            // Invert the transform config (both ID and order)
            var inverseConfig = GenerateReverseSequence(trConfig);

            // Set GR and TRs from reversed config
            Options.Rounds = rounds;
            ApplyTransformRounds(inverseConfig);

            // Prepare data for decryption
            var data = new byte[input.Length];
            Array.Copy(input, data, input.Length);

            // Compute Coins
            var combinedHash = CombineHashAndNonce(hash, iv);
            var coins = GetCoins(combinedHash);

            // Extract just the reversed transform IDs
            var reverseSequence = inverseConfig.Select(p => p.ID).ToArray();

            // Apply reverse transformations over all rounds
            //for (var i = 0; i < Options.Rounds; i++) 
            data = ApplyTransformations(reverseSequence, data, coins, true, Options.Rounds);

            return data; // ✅ Decrypted plaintext
        }

        public byte[] Encrypt(byte[] sequence, byte[] input, CryptoLibOptions? options = null)
        {
            // ✅ Use provided options or fallback to defaults
            options ??= Options ?? new CryptoLibOptions();

            // ✅ Validate nonce length for consistency with internal assumptions
            if (options.SessionIv!.Length != IvLength)
                throw new ArgumentException($"Nonce/IV must be {IvLength} bytes.");

            // ✅ Compute a hash of the input data (used for coin generation)
            using var sha256 = SHA256.Create();
            var hash = sha256.ComputeHash(input);

            // ✅ Combine hash and nonce to generate randomness (coins)
            var combinedHash = CombineHashAndNonce(hash, options.SessionIv);
            var coins = GetCoins(combinedHash);

            // ✅ Copy the input so we don’t mutate it
            var data = new byte[input.Length];
            Array.Copy(input, data, input.Length);

            // ✅ Apply forward transformations for the configured number of rounds
            //for (var i = 0; i < options.Rounds; i++) 
            data = ApplyTransformations(sequence, data, coins, false, options.Rounds);

            // ✅ Encode transform-based version for header compatibility check.
            var version = GetLibVersion();

            // ✅ Infer (ID, TR) pairs based on the transform registry
            var trConfig = InferTransformRounds(sequence);

            // ✅ Create a minimal header (no ciphertext) and store it
            var header = PackHeaderAndCiphertext(version.major, version.minor, hash, options.SessionIv,
                (byte)options.Rounds, trConfig, Array.Empty<byte>());
            _lastHeader = header;

            // 🔐 Encrypt the header (protects sequence, IV, and metadata from exposure)
            var encryptedHeader = EncryptHeader(header);
#if DEBUG
            var cleartextHeader = DecryptHeader(encryptedHeader);
            //Debug.Assert(cleartextHeader.SequenceEqual(header));
            if (!cleartextHeader.SequenceEqual(header))
            {
                Console.WriteLine("🔴 Header mismatch detected.");
                Console.WriteLine("Original:   " + string.Join(",", header));
                Console.WriteLine("Decrypted:  " + string.Join(",", cleartextHeader));

                // CBox & SessionIv snapshots:
                Console.WriteLine("CBox:       " + string.Join(",", CBox));
                Console.WriteLine("SessionIv:  " + string.Join(",", options.SessionIv));
                Debugger.Break();
            }
#endif
            // ✅ Allocate and merge the final encrypted output
            var fullOutput = new byte[encryptedHeader.Length + data.Length];
            Buffer.BlockCopy(encryptedHeader, 0, fullOutput, 0, encryptedHeader.Length);
            Buffer.BlockCopy(data, 0, fullOutput, encryptedHeader.Length, data.Length);

            return fullOutput;
        }

        public byte[] Decrypt(byte[] sequence, byte[] input)
        {
            if (sequence == null) throw new ArgumentNullException(nameof(sequence));
            if (input == null) throw new ArgumentNullException(nameof(input));

            // 🔓 Decrypt the encrypted header and reattach it to the ciphertext for normal parsing
            input = DecryptHeaderOnly(input);

            // Extract the hash, IV, rounds, transform config (ID:TR pairs), and ciphertext.
            // Note: trConfig is now used for version compatibility checking, but the TR values
            // are not applied here. In Workbench and high-level API flows (e.g., MangoAC),
            // transform rounds are already applied to the registry **before** this core decrypt is called.
            var (hash, iv, rounds, trConfig, ciphertext) = ExtractHeaderAndCiphertext(input, HashLength, IvLength);

            // Ensure all transforms in the sequence are supported by the current library version.
            // If any transform ID exceeds the supported set, this indicates a version mismatch.
            if (CheckVersion(trConfig, out var required) == false)
                throw new InvalidOperationException(
                    $"Encrypted packet requires CryptoLib version {required} or higher. Decryption aborted.");

            // ✅ Store only the header portion, trimming off the ciphertext.
            _lastHeader = input.Take(input.Length - ciphertext!.Length).ToArray();

            // Validate IV length
            if (iv.Length != IvLength)
                throw new ArgumentException("Nonce/IV must be 12 bytes.");

            // Combine the extracted hash and IV for preprocessing
            var combinedHash = CombineHashAndNonce(hash, iv);

            // Get coins from the hash
            var coins = GetCoins(combinedHash);

            // Reverse transforms over multiple rounds
            var data = ciphertext;
            //for (var i = 0; i < rounds; i++)
            data = ApplyTransformations(sequence, data, coins, true, rounds); // Reverse order of transformations

            return data;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        /// <summary>
        /// Applies a sequence of transforms to the input buffer.
        /// In forward mode, it pads the input with CBox entropy and appends a 1-byte padding length marker.
        /// In reverse mode, it removes the padding marker byte, applies the transforms, and then strips the CBox padding.
        /// </summary>
        public byte[] ApplyTransformations(byte[] sequence, byte[] input, byte[] coins, bool reverse, int globalRounds)
        {
            if (sequence == null) throw new ArgumentNullException(nameof(sequence));
            if (input == null) throw new ArgumentNullException(nameof(input));

            const int blockSize = 16;
            byte[] workingBuffer;
            byte[] result;
            bool forward = !reverse;

            if (forward)
            {
                // Step 1: Pad input to a block-aligned size using CBox bytes
                int paddingNeeded = (blockSize - (input.Length % blockSize)) % blockSize;
                int paddedLength = input.Length + paddingNeeded;

                workingBuffer = ScratchBufferPool.Rent(paddedLength);
                Buffer.BlockCopy(input, 0, workingBuffer, 0, input.Length);
                if (paddingNeeded > 0)
                    Buffer.BlockCopy(CBox, 0, workingBuffer, input.Length, paddingNeeded);
            }
            else
            {
                int padding = input[^1];
                int bufferLength = input.Length - 1;

                if (padding > bufferLength)
                    throw new InvalidOperationException("Invalid padding value.");

                workingBuffer = ScratchBufferPool.Rent(bufferLength);
                Buffer.BlockCopy(input, 0, workingBuffer, 0, bufferLength);
            }

            try
            {
                // Step 2 (forward) or Step 3 (reverse): Apply transform sequence
                for (int globalRound = 0; globalRound < globalRounds; globalRound++)
                    foreach (var transformId in sequence)
                    {
                        if (!TransformRegistry.TryGetValue(transformId, out var transformInfo))
                            throw new ApplicationException($"Unknown transformation ID: {transformId}");

                        for (byte round = 0; round < transformInfo.Rounds; round++)
                        {
                            var selectedCoin = SelectCoin(
                                transformInfo.CoinPreference, round, reverse, transformInfo.Rounds);

                            transformInfo.Implementation!(workingBuffer, coins[selectedCoin]);
                        }
                    }

                if (forward)
                {
                    int paddingNeeded = (blockSize - (input.Length % blockSize)) % blockSize;
                    result = new byte[workingBuffer.Length + 1];
                    Buffer.BlockCopy(workingBuffer, 0, result, 0, workingBuffer.Length);
                    result[^1] = (byte)paddingNeeded;
                }
                else
                {
                    int padding = input[^1];
                    int unpaddedLength = workingBuffer.Length - padding;

                    if (unpaddedLength < 0)
                        throw new InvalidOperationException("Padding length exceeds buffer size.");

                    result = new byte[unpaddedLength];
                    Buffer.BlockCopy(workingBuffer, 0, result, 0, unpaddedLength);
                }

                return result;
            }
            finally
            {
                ScratchBufferPool.Return(workingBuffer);
            }
        }

        private void ApplyTransformRounds((byte ID, byte TR)[] sequence)
        {
            foreach (var (id, tr) in sequence)
                if (TransformRegistry.TryGetValue(id, out var tx))
                    tx.Rounds = tr;
                else
                    throw new InvalidOperationException($"Transform ID {id} not found in registry.");
        }

        private byte[] SaveTransformRounds()
        {
            // ✅ Save all transform rounds assuming dense, consecutive IDs starting from 1
            var roundsSnapshot = new byte[TransformRegistry.Count];

            foreach (var kvp in TransformRegistry)
            {
                var index = kvp.Key - 1; // IDs start from 1, adjust for 0-based array
                roundsSnapshot[index] = kvp.Value.Rounds;
            }

            return roundsSnapshot;
        }

        private void RestoreTransformRounds(byte[] savedRounds)
        {
            if (savedRounds.Length != TransformRegistry.Count)
                throw new InvalidOperationException("Saved rounds array size mismatch.");

            foreach (var kvp in TransformRegistry)
            {
                var index = kvp.Key - 1;
                kvp.Value.Rounds = savedRounds[index];
            }
        }

        #region Versioning

        // ======================================================================================
        // Versioning Model for Mango Transform Compatibility
        // ======================================================================================
        // - Each transform has a unique Transform ID (starting from 1).
        // - TransformRegistry defines the full list of available transforms, in order.
        // - Transform ID 1 corresponds to ordinal 0, Transform ID 2 → ordinal 1, etc.
        // - Version 1 of the CryptoLib supports 40 transforms (IDs 1 through 40).
        // - Each additional transform (ID > 40) increases the required version:
        //     ID 41 → Version 2
        //     ID 42 → Version 3
        //     ...
        // - All encrypted packets include their required transform sequence.
        // - During decryption, the library confirms that all transforms used are supported.
        //   If not, decryption fails with a version incompatibility notice.
        // ======================================================================================

        private const byte CoreVersion = 40;

        /// <summary>
        /// Returns the current library version based on the number of registered transforms.
        /// Version 1 == 40 transforms. Each additional transform increments the version.
        /// </summary>
        public (byte major, byte minor) GetLibVersion()
        {
            var count = TransformRegistry.Count;

            // Version 1 supports 40 transforms (IDs 1–40). Each additional transform increases the version.
            var major = (byte)Math.Max(1, count - CoreVersion + 1);
            byte minor = 0; // Reserved for future use, optional override elsewhere

            return (major, minor);
        }

        /// <summary>
        /// Checks if all transforms in the sequence are supported by the current library version.
        /// Outputs the required version if any transform exceeds the supported set.
        /// </summary>
        public bool CheckVersion((byte ID, byte TR)[] sequence, out byte requiredVersion)
        {
            int maxTransformId = sequence.Max(t => t.ID);
            var currentMaxId = TransformRegistry.Count; // Last valid ID equals transform count

            if (maxTransformId <= currentMaxId)
            {
                requiredVersion = 0;
                return true;
            }
#if DEBUG
            System.Diagnostics.Debugger.Break();
#endif
            // Example: ID 41 → Version 2, ID 42 → Version 3, etc.
            requiredVersion = (byte)(maxTransformId - CoreVersion + 1);
            return false;
        }

        #endregion Versioning

        private (byte ID, byte TR)[] GenerateReverseSequence((byte ID, byte TR)[] forward)
        {
            return forward
                .Reverse()
                .Select(pair =>
                {
                    var inverseId = GetInverseTransformByte(pair.ID); // use your robust check
                    return (ID: inverseId, TR: pair.TR); // keep original TR
                })
                .ToArray();
        }

        private byte GetInverseTransformByte(byte transformByte)
        {
            if (!TransformRegistry.TryGetValue(transformByte, out var originalTransform))
                throw new InvalidOperationException($"❌ Transformation not found: {transformByte}");

            if (!TransformRegistry.TryGetValue(originalTransform.InverseId, out var inverseTransform))
                throw new InvalidOperationException(
                    $"❌ No inverse transformation found for: {originalTransform.Name} (ID: {originalTransform.Id})");

            return (byte)inverseTransform.Id;
        }

        private (byte ID, byte TR)[] InferTransformRounds(byte[] sequence)
        {
            return sequence
                .Select(id =>
                {
                    if (!TransformRegistry.TryGetValue(id, out var tx))
                        throw new InvalidOperationException($"Transform ID {id} not found in registry.");

                    return (ID: id, TR: tx.Rounds);
                })
                .ToArray();
        }

        private byte SelectCoin(byte coinBase, byte round, bool reverse, byte totalRounds)
        {
            var adjustedRound = reverse ? (byte)(totalRounds - round - 1) : round;
            return (byte)((coinBase + adjustedRound) & 0xFF);
        }

        /// <summary>
        /// Packages the encrypted output with a structured header.
        /// Header layout:
        /// [VERSION_MAJOR][VERSION_MINOR][HASH][IV][ROUNDS][SEQLEN][ID:TR pairs...][CIPHERTEXT]
        /// </summary>
        private byte[] PackHeaderAndCiphertext(
            byte versionMajor,
            byte versionMinor,
            byte[] hash,
            byte[] iv,
            byte rounds,
            (byte ID, byte TR)[] trConfig,
            byte[] ciphertext)
        {
            if (hash == null || iv == null || ciphertext == null || trConfig == null)
                throw new ArgumentNullException("One or more input parameters are null.");

            var sequenceLen = trConfig.Length;
            var trConfigBytes = sequenceLen * 2; // Each ID:TR pair = 2 bytes

            // Total header size:
            // 2 (version) + hash + iv + 1 (rounds) + 1 (sequenceLen) + 2 * sequenceLen + ciphertext
            var output = new byte[
                2 + hash.Length + iv.Length + 1 + 1 + trConfigBytes + ciphertext.Length
            ];

            var offset = 0;

            output[offset++] = versionMajor;
            output[offset++] = versionMinor;

            Buffer.BlockCopy(hash, 0, output, offset, hash.Length);
            offset += hash.Length;

            Buffer.BlockCopy(iv, 0, output, offset, iv.Length);
            offset += iv.Length;

            output[offset++] = rounds;
            output[offset++] = (byte)sequenceLen;

            foreach (var (id, tr) in trConfig)
            {
                output[offset++] = id;
                output[offset++] = tr;
            }

            Buffer.BlockCopy(ciphertext, 0, output, offset, ciphertext.Length);

            return output;
        }

        /// <summary>
        /// Parses the structured header and extracts the hash, nonce, rounds, sequence, and ciphertext.
        /// Expects header layout:
        /// [VERSION_MAJOR][VERSION_MINOR][HASH][IV][ROUNDS][SEQLEN][ID:TR pairs...][CIPHERTEXT]
        /// </summary>
        private (byte[] hash, byte[] nonce, byte rounds, (byte ID, byte TR)[] sequence, byte[] ciphertext)
            ExtractHeaderAndCiphertext(byte[] input, int hashLength, int nonceLength)
        {
            if (input.Length < 2 + hashLength + nonceLength + 2) // +2 for version, +2 for rounds + seqLen
                throw new ArgumentException("Input data is too short to contain a valid header.");

            var offset = 0;

            // Skip versionMajor and versionMinor
            var versionMajor = input[offset++];
            var versionMinor = input[offset++];

            var hash = input.Skip(offset).Take(hashLength).ToArray();
            offset += hashLength;

            var nonce = input.Skip(offset).Take(nonceLength).ToArray();
            offset += nonceLength;

            var rounds = input[offset++];
            var sequenceLen = input[offset++];

            if (input.Length < offset + sequenceLen * 2)
                throw new ArgumentException("Input data is too short to contain sequence metadata.");

            var sequence = new (byte ID, byte TR)[sequenceLen];
            for (var i = 0; i < sequenceLen; i++)
            {
                var id = input[offset++];
                var tr = input[offset++];
                sequence[i] = (id, tr);
            }

            var ciphertext = input.Skip(offset).ToArray();

            return (hash, nonce, rounds, sequence, ciphertext);
        }

        public byte[] GetPayloadOnly(byte[] encrypted)
        {
            if (encrypted == null)
                throw new ArgumentNullException(nameof(encrypted), "Encrypted data cannot be null.");

            encrypted = DecryptHeaderOnly(encrypted);

            var (_, _, _, _, payload) = ExtractHeaderAndCiphertext(encrypted, HashLength, IvLength);

            if (payload == null || payload.Length == 0)
                throw new InvalidOperationException("Extracted payload is empty or malformed.");

            // 🩹 NEW: Trim the final padding byte
            int paddingByte = payload[^1];
            int originalLength = payload.Length - paddingByte - 1;

            if (originalLength < 0)
                throw new InvalidOperationException("Payload padding value is invalid.");

            var trimmed = new byte[originalLength];
            Buffer.BlockCopy(payload, 0, trimmed, 0, originalLength);
            return trimmed;
        }

        private byte[] CombineHashAndNonce(byte[] hash, byte[] nonce)
        {
            using var sha256 = SHA256.Create();

            // Combine hash and nonce in a meaningful way
            var concatenated = new byte[hash.Length + nonce.Length];
            Buffer.BlockCopy(hash, 0, concatenated, 0, hash.Length);
            Buffer.BlockCopy(nonce, 0, concatenated, hash.Length, nonce.Length);

            // Hash the combined result
            return sha256.ComputeHash(concatenated);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public byte[] GetCoins(byte[] hash)
        {
            if (hash == null || hash.Length == 0)
                throw new ArgumentException("A non-empty combined hash is required.", nameof(hash));

            // Create a table of 256 bytes (0-255)
            var coins = new byte[256];
            for (var i = 0; i < coins.Length; i++) coins[i] = (byte)i;

            // Use the combined hash to deterministically shuffle the Coins array
            var hashIndex = 0;
            for (var i = coins.Length - 1; i > 0; i--)
            {
                // Generate a deterministic "random" index using the combined hash
                hashIndex = (hashIndex + 1) % hash.Length;
                var swapIndex = (hash[hashIndex] + i) % (i + 1);

                // Swap elements at indices i and swapIndex
                (coins[i], coins[swapIndex]) = (coins[swapIndex], coins[i]);
            }

            return coins;
        }

        #endregion API
    }

    #region Utilities

    public static class ScratchBufferPool
    {
        // 🟢 Per-thread buffer cache (keyed by requested size)
        [ThreadStatic] private static Dictionary<int, byte[]>? _buffers;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static byte[] Rent(int size)
        {
            // Lazily initialize the per-thread dictionary
            if (_buffers == null)
                _buffers = new Dictionary<int, byte[]>();

            // Fast-path: re-use existing buffer
            if (_buffers.TryGetValue(size, out var buffer))
                return buffer;

            // Allocate new buffer if needed
            buffer = new byte[size];
            _buffers[size] = buffer;
            return buffer;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ClearBuffer(byte[] buffer)
        {
            // Zero out only if needed (or config-driven)
            Array.Clear(buffer, 0, buffer.Length);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Return(byte[] buffer)
        {
            // No-op for now since Rent already caches it
            // But here for future extensibility (e.g., pool policies)
        }
    }

    public class CryptoUtils
    {
        private const int IvLength = 12; // Set your specific length here

        public byte[] GenerateSecureIv()
        {
            var iv = new byte[IvLength];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(iv); // Fills the array with cryptographically secure random bytes.
            }

            return iv;
        }
    }

    #endregion Utilities

    #region TOM_Random

    public class TomRandom
    {
        private int _state;
        private readonly byte[] CBox;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public TomRandom(CryptoLib cryptoLib, int seed = 0, bool useInverse = false)
        {
            CBox = useInverse ? cryptoLib!.InverseCBox : cryptoLib!.CBox; // Select CBox or InverseCBox based on flag
            _state = seed; // Initial state
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public byte NextMask()
        {
            // Normalize the index
            var index = Math.Abs(_state % CBox.Length); // Always positive
            var mask = CBox[index];

            // Update the state using the LCG formula
            _state = (int)((_state * 6364136223846793005L + mask) & 0xFFFFFFFF);

            // Remap zero using Next(min, max) logic
            return mask == 0 ? (byte)Next(1, 256) : mask;
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public int Next(int max)
        {
            if (max <= 0)
                throw new ArgumentException("max must be greater than 0.", nameof(max));

            // Normalize the index
            var index = Math.Abs(_state % CBox.Length); // Always positive
            var mask = CBox[index];

            // Update the state using the LCG formula
            _state = (int)((_state * 6364136223846793005L + mask) & 0xFFFFFFFF);

            // Mitigate modulo bias
            var bound = int.MaxValue - int.MaxValue % max;
            while (_state >= bound) _state = (int)((_state * 6364136223846793005L + mask) & 0xFFFFFFFF);

            var result = _state % max;
            if (result < 0)
                result += max;

            return result; // No need for special cases
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public int Next(int min, int max)
        {
            if (min > max)
                throw new ArgumentException("min must be less than or equal to max.", nameof(min));

            if (min == max)
                return min; // Deterministic result for a single-value range

            var range = max - min;
            return min + Next(range);
        }
    }

    #endregion TOM_Random
}

namespace Mango.Cipher
{
    public static class Tables
    {
        public static readonly byte[] SBox = new byte[256]
        {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
        };

        public static readonly byte[] InverseSBox = new byte[256]
        {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        };
    }
}