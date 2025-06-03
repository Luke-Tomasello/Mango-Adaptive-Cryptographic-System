namespace Mango.AesSoftwareCore
{
    using System;

    public partial class AesSoftwareCore
    {
        private readonly byte[] _expandedKey;
        private readonly int _rounds;

        private const int BlockSize = 16;

        private static readonly byte[] Rcon = new byte[]
        {
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36
        };

        public AesSoftwareCore(byte[] key)
        {
            if (key.Length == 16)
            {
                _rounds = 10;
                _expandedKey = ExpandKey128(key);
            }
            else if (key.Length == 32)
            {
                _rounds = 14;
                _expandedKey = ExpandKey256(key);
            }
            else
            {
                throw new ArgumentException("Key must be 16 (AES-128) or 32 (AES-256) bytes.");
            }
        }


        public byte[] EncryptCbc(byte[] input, byte[] iv)
        {
            if (iv.Length != BlockSize)
                throw new ArgumentException("IV must be 16 bytes for CBC mode.");

            input = ApplyPKCS7Padding(input);
            byte[] output = new byte[input.Length];
            byte[] block = new byte[BlockSize];
            byte[] xorBuffer = new byte[BlockSize];
            Buffer.BlockCopy(iv, 0, xorBuffer, 0, BlockSize);

            for (int i = 0; i < input.Length; i += BlockSize)
            {
                for (int j = 0; j < BlockSize; j++)
                    block[j] = (byte)(input[i + j] ^ xorBuffer[j]);

                EncryptBlock(block, xorBuffer);
                Buffer.BlockCopy(xorBuffer, 0, output, i, BlockSize);
            }

            return output;
        }

        public byte[] DecryptCbc(byte[] input, byte[] iv)
        {
            if (input.Length % BlockSize != 0)
                throw new ArgumentException("Encrypted data length must be a multiple of 16.");

            byte[] output = new byte[input.Length];
            byte[] block = new byte[BlockSize];
            byte[] decrypted = new byte[BlockSize];
            byte[] prevCipher = new byte[BlockSize];
            Buffer.BlockCopy(iv, 0, prevCipher, 0, BlockSize);

            for (int i = 0; i < input.Length; i += BlockSize)
            {
                Buffer.BlockCopy(input, i, block, 0, BlockSize);
                DecryptBlock(block, decrypted);

                for (int j = 0; j < BlockSize; j++)
                    output[i + j] = (byte)(decrypted[j] ^ prevCipher[j]);

                Buffer.BlockCopy(block, 0, prevCipher, 0, BlockSize);
            }

            return RemovePKCS7Padding(output);
        }

        public void EncryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            if (input.Length != BlockSize || output.Length != BlockSize)
                throw new ArgumentException("Block size must be 16 bytes.");

            Span<byte> state = stackalloc byte[BlockSize];
            input.CopyTo(state);

            AddRoundKey(state, 0);

            for (int round = 1; round < _rounds; round++)
            {
                SubBytes(state);
                ShiftRows(state);
                MixColumns(state);
                AddRoundKey(state, round);
            }

            SubBytes(state);
            ShiftRows(state);
            AddRoundKey(state, _rounds);

            state.CopyTo(output);
        }

        public void DecryptBlock(ReadOnlySpan<byte> input, Span<byte> output)
        {
            Span<byte> state = stackalloc byte[16];
            input.CopyTo(state);

            AddRoundKey(state, _rounds); // Last round key first

            for (int round = _rounds - 1; round > 0; round--)
            {
                InvShiftRows(state);
                InvSubBytes(state);
                AddRoundKey(state, round);
                InvMixColumns(state);
            }

            InvShiftRows(state);
            InvSubBytes(state);
            AddRoundKey(state, 0);

            state.CopyTo(output);
        }
        private static void InvShiftRows(Span<byte> state)
        {
            byte temp;

            // Row 1: shift right by 1
            temp = state[13];
            state[13] = state[9];
            state[9] = state[5];
            state[5] = state[1];
            state[1] = temp;

            // Row 2: shift right by 2
            (state[2], state[6], state[10], state[14]) = (state[10], state[14], state[2], state[6]);

            // Row 3: shift right by 3 (i.e., left by 1)
            temp = state[3];
            state[3] = state[7];
            state[7] = state[11];
            state[11] = state[15];
            state[15] = temp;
        }

        private static void InvSubBytes(Span<byte> state)
        {
            for (int i = 0; i < 16; i++)
                state[i] = InvSBox[state[i]];
        }

        private static void InvMixColumns(Span<byte> state)
        {
            for (int c = 0; c < 4; c++)
            {
                int i = c * 4;
                byte a0 = state[i];
                byte a1 = state[i + 1];
                byte a2 = state[i + 2];
                byte a3 = state[i + 3];

                state[i] = (byte)(Mul(0x0e, a0) ^ Mul(0x0b, a1) ^ Mul(0x0d, a2) ^ Mul(0x09, a3));
                state[i + 1] = (byte)(Mul(0x09, a0) ^ Mul(0x0e, a1) ^ Mul(0x0b, a2) ^ Mul(0x0d, a3));
                state[i + 2] = (byte)(Mul(0x0d, a0) ^ Mul(0x09, a1) ^ Mul(0x0e, a2) ^ Mul(0x0b, a3));
                state[i + 3] = (byte)(Mul(0x0b, a0) ^ Mul(0x0d, a1) ^ Mul(0x09, a2) ^ Mul(0x0e, a3));
            }
        }
        private static byte Mul(byte a, byte b)
        {
            byte result = 0;
            while (b != 0)
            {
                if ((b & 1) != 0)
                    result ^= a;
                bool hiBitSet = (a & 0x80) != 0;
                a <<= 1;
                if (hiBitSet)
                    a ^= 0x1B;
                b >>= 1;
            }
            return result;
        }

        private static byte[] ExpandKey128(byte[] key)
        {
            byte[] expanded = new byte[176];
            Array.Copy(key, expanded, 16);

            int bytesGenerated = 16;
            int rconIteration = 1;
            byte[] temp = new byte[4];

            while (bytesGenerated < 176)
            {
                Array.Copy(expanded, bytesGenerated - 4, temp, 0, 4);

                if (bytesGenerated % 16 == 0)
                {
                    byte t = temp[0];
                    temp[0] = (byte)(SBox[temp[1]] ^ Rcon[rconIteration]);
                    temp[1] = SBox[temp[2]];
                    temp[2] = SBox[temp[3]];
                    temp[3] = SBox[t];
                    rconIteration++;
                }

                for (int i = 0; i < 4; i++)
                {
                    expanded[bytesGenerated] = (byte)(expanded[bytesGenerated - 16] ^ temp[i]);
                    bytesGenerated++;
                }
            }

            return expanded;
        }
        private static byte[] ExpandKey256(byte[] key)
        {
            const int keyWords = 8;
            const int totalWords = 60; // 4 words × 15 rounds
            byte[] expanded = new byte[totalWords * 4];
            Buffer.BlockCopy(key, 0, expanded, 0, key.Length);

            byte[] temp = new byte[4];
            int rconIndex = 1;

            for (int i = keyWords; i < totalWords; i++)
            {
                int prev = (i - 1) * 4;
                int back = (i - keyWords) * 4;
                Array.Copy(expanded, prev, temp, 0, 4);

                if (i % keyWords == 0)
                {
                    RotWord(temp);
                    SubWord(temp);
                    temp[0] ^= Rcon[rconIndex++];
                }
                else if (i % keyWords == 4)
                {
                    SubWord(temp); // Only for AES-256
                }

                for (int j = 0; j < 4; j++)
                {
                    expanded[i * 4 + j] = (byte)(expanded[back + j] ^ temp[j]);
                }
            }

            return expanded;
        }
        private static void RotWord(byte[] word)
        {
            byte t = word[0];
            word[0] = word[1];
            word[1] = word[2];
            word[2] = word[3];
            word[3] = t;
        }

        private static void SubWord(byte[] word)
        {
            for (int i = 0; i < 4; i++)
                word[i] = SBox[word[i]];
        }

        private static void SubBytes(Span<byte> state)
        {
            for (int i = 0; i < state.Length; i++)
                state[i] = SBox[state[i]];
        }

        private static void ShiftRows(Span<byte> state)
        {
            byte temp;

            temp = state[1];
            state[1] = state[5];
            state[5] = state[9];
            state[9] = state[13];
            state[13] = temp;

            temp = state[2];
            byte temp2 = state[6];
            state[2] = state[10];
            state[6] = state[14];
            state[10] = temp;
            state[14] = temp2;

            temp = state[3];
            state[3] = state[15];
            state[15] = state[11];
            state[11] = state[7];
            state[7] = temp;
        }

        private void AddRoundKey(Span<byte> state, int round)
        {
            int offset = round * BlockSize;
            for (int i = 0; i < BlockSize; i++)
            {
                state[i] ^= _expandedKey[offset + i];
            }
        }

        private static void MixColumns(Span<byte> state)
        {
            for (int c = 0; c < 4; c++)
            {
                int i = c * 4;
                byte a0 = state[i];
                byte a1 = state[i + 1];
                byte a2 = state[i + 2];
                byte a3 = state[i + 3];

                byte r0 = (byte)(Gmul2(a0) ^ Gmul3(a1) ^ a2 ^ a3);
                byte r1 = (byte)(a0 ^ Gmul2(a1) ^ Gmul3(a2) ^ a3);
                byte r2 = (byte)(a0 ^ a1 ^ Gmul2(a2) ^ Gmul3(a3));
                byte r3 = (byte)(Gmul3(a0) ^ a1 ^ a2 ^ Gmul2(a3));

                state[i] = r0;
                state[i + 1] = r1;
                state[i + 2] = r2;
                state[i + 3] = r3;
            }
        }

        private static byte Gmul2(byte b) => (byte)(((b << 1) ^ ((b & 0x80) != 0 ? 0x1B : 0)) & 0xFF);
        private static byte Gmul3(byte b) => (byte)(Gmul2(b) ^ b);

        private static byte[] ApplyPKCS7Padding(byte[] data)
        {
            int padding = BlockSize - (data.Length % BlockSize);
            byte[] result = new byte[data.Length + padding];
            Buffer.BlockCopy(data, 0, result, 0, data.Length);
            for (int i = data.Length; i < result.Length; i++)
                result[i] = (byte)padding;
            return result;
        }

        private static byte[] RemovePKCS7Padding(byte[] data)
        {
            int padLen = data[^1];
            if (padLen < 1 || padLen > BlockSize)
                throw new InvalidOperationException("Invalid PKCS7 padding.");
            for (int i = data.Length - padLen; i < data.Length; i++)
            {
                if (data[i] != padLen)
                    throw new InvalidOperationException("Invalid PKCS7 padding.");
            }
            byte[] result = new byte[data.Length - padLen];
            Buffer.BlockCopy(data, 0, result, 0, result.Length);
            return result;
        }
    }

    public partial class AesSoftwareCore
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

        public static readonly byte[] InvSBox = new byte[256]
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
