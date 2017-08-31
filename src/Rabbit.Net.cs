using System;
using System.Linq;
using System.Security.Cryptography;

/*
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

MIT License

Copyright(c) 2017 Crypt0z

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/*
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * 
 * This Is a Implementation of the Rabbit Cipher originally written in C
 * by Martin Boesgaard, Mette Vesterager, Thomas Pedersen, Jesper Christiansen and Ove Scavenius.
 * 
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

//ANY PROBLEMS TALK TO ME ON DISCORD @ Crypt0z#3656

namespace Rabbit.Net
{
    public class RabbitCipher : SymmetricAlgorithm
    {
        private byte[] _rabbitKey = null;
        private byte[] _rabbitIV = null;
        private readonly uint RabbitKeySize = 0;
        private readonly uint IVSize = 0;
        private readonly uint EncryptedBitsPerIteration = 0;
        private const UInt32 INIT_EMPTY = 0;
        /// <summary>
        /// Used to Initialize Startup Objects/Values
        /// </summary>
        public RabbitCipher()
        {
            RabbitKeySize = 128;
            IVSize = 64;
            EncryptedBitsPerIteration = 128;
            LegalBlockSizesValue = new[] { new KeySizes(128, 128, 0) };
            LegalKeySizesValue = new[] { new KeySizes(128, 128, 0) };
            BlockSizeValue = 128;
            KeySizeValue = 128;
        }
        public uint IVBitSize { get { return this.IVSize; } }
        public uint KeyBitSize { get { return this.RabbitKeySize; } }
        public uint BitsEncryptedPerIteration { get { return this.EncryptedBitsPerIteration; } }
        /// <summary>
        /// Checks To Make sure the entered IV is valid and can be used for encryption/decryption
        /// </summary>
        /// <param name="iv"></param>
        public void CheckIV(byte[] iv)
        {
            if (iv == null)
                throw new ArgumentNullException("iv");
            else if (iv.Length == 0 || iv.Length < 8 || iv.Length > 8)
                throw new ArgumentOutOfRangeException("iv");
            else if (iv.Length % 8 != 0)
                throw new Exception("IV Has An Invalid Bit Size (IV Should Be 64 Bits | 8 Bytes)");
        }
        /// <summary>
        /// Checks To Make sure the entered Key is valid and can be used for encryption/decryption
        /// </summary>
        /// <param name="iv"></param>
        public void CheckKey(byte[] key)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            else if (key.Length == 0 || key.Length < 16 || key.Length > 16)
                throw new ArgumentOutOfRangeException("iv");
            else if (key.Length % 8 != 0)
                throw new Exception("Key Has An Invalid Bit Size (Key Should Be 128 Bits | 16 Bytes)");
        }
        /// <summary>
        /// Creates A Decryptor that will be used to Decrypt Encrypted Data using a 128 bit-Key and An 64 bit-IV
        /// </summary>
        /// <param name="rgbKey"></param>
        /// <param name="rgbIV"></param>
        /// <returns></returns>
        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            if (rgbKey == null)
                throw new ArgumentNullException("rgbKey");
            else if (rgbKey.Length != 16)
                throw new ArgumentOutOfRangeException("rgbKey");
            if(rgbIV == null)
                throw new ArgumentNullException("rgbIV");
            else if(rgbIV.Length != 8)
                throw new ArgumentOutOfRangeException("rgbIV");
            return CreateEncryptor(rgbKey, rgbIV);
        }
        /// <summary>
        /// Creates A Encryptor that will be used to Decrypt Encrypted Data using a 128 bit-Key and An 64 bit-IV
        /// </summary>
        /// <param name="rgbKey"></param>
        /// <param name="rgbIV"></param>
        /// <returns></returns>
        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            if (rgbKey == null)
                throw new ArgumentNullException("rgbKey");
            else if (rgbKey.Length != 16)
                throw new ArgumentOutOfRangeException("rgbKey");
            if (rgbIV == null)
                throw new ArgumentNullException("rgbIV");
            else if (rgbIV.Length != 8)
                throw new ArgumentOutOfRangeException("rgbIV");
            return new RabbitCryptoTransform(rgbKey, rgbIV);
        }
        /// <summary>
        /// Generates A Pseudorandom IV
        /// </summary>
        public override void GenerateIV()
        {
            IV = GetRandomBytes((int)IVSize / 8);
        }
        /// <summary>
        /// Generates A Pseudorandom Key
        /// </summary>
        public override void GenerateKey()
        {
            Key = GetRandomBytes((int)RabbitKeySize / 8);
        }
        /// <summary>
        /// Sets the IV to a custom IV
        /// </summary>
        public override byte[] IV
        {
            get
            {
                return _rabbitIV;
            }
            set
            {
                CheckIV(value);
                _rabbitIV = value;
            }
        }
        /// <summary>
        /// Sets the Key to a custom Key
        /// </summary>
        public override byte[] Key
        {
            get
            {
                return _rabbitKey;
            }
            set
            {
                CheckKey(value);
                _rabbitKey = value;
            }
        }
        /// <summary>
        /// Gets a {x} amount of PseudoRandom Bytes
        /// </summary>
        /// <param name="byteCount"></param>
        /// <returns></returns>
        private byte[] GetRandomBytes(int byteCount)
        {
            byte[] bytes = new byte[byteCount];
            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
                rng.GetBytes(bytes);
            return bytes;
        }
        /// <summary>
        /// This is the Crypto Transform Class where Encrytion/Decryption is Deined
        /// </summary>
        private sealed class RabbitCryptoTransform : ICryptoTransform
        {
            public int InputBlockSize => 128;
            public int OutputBlockSize => 128;
            public bool CanTransformMultipleBlocks => true;
            public bool CanReuseTransform => false;
            private uint[] m_state;
            private uint[] m_counter;
            private uint[] w_state;
            private uint[] w_counter;
            private bool MasterBit = false;
            private bool WorkBit = false;
            /// <summary>
            /// Sets Up The KeySetup and IVSetup used for Encryption
            /// </summary>
            /// <param name="key"></param>
            /// <param name="iv"></param>
            public RabbitCryptoTransform(byte[] key, byte[] iv)
            {
                Init(key, iv);
            }
            /// <summary>
            /// Cleans up resources used during Encrytion/Decryption
            /// </summary>
            public void Dispose()
            {
                if (MasterBit == true)
                    MasterBit = false;
                if (WorkBit == true)
                    WorkBit = false;
                Array.Clear(m_state, 0, m_state.Length);
                Array.Clear(m_counter, 0, m_counter.Length);
                Array.Clear(w_state, 0, w_state.Length);
                Array.Clear(w_counter, 0, w_counter.Length);
            }
            /// <summary>
            /// Encrypts the The Data(byte[]) in perfect blocks and excludes the last block if not 16 bytes
            /// </summary>
            /// <param name="inputBuffer"></param>
            /// <param name="inputOffset"></param>
            /// <param name="inputCount"></param>
            /// <param name="outputBuffer"></param>
            /// <param name="outputOffset"></param>
            /// <returns></returns>
            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                if (inputBuffer == null || inputBuffer.Length < 1)
                    throw new ArgumentNullException("inputBuffer");
                if (inputOffset >= inputBuffer.Length || inputOffset < 0)
                    throw new ArgumentOutOfRangeException("inputOffset");
                if (inputCount == 0 || inputCount < 0 || inputCount > (inputBuffer.Length - inputOffset))
                    throw new ArgumentOutOfRangeException("inputCount");
                if (outputBuffer == null)
                    throw new ArgumentNullException("outputBuffer");
                if (outputOffset > 0 || outputOffset > outputBuffer.Length)
                    throw new ArgumentOutOfRangeException("outputOffset");

                int bytesTransformed = 0;

                while(inputCount > 0)
                {
                    NEXT_STATE(w_state, w_counter, WorkBit);
                    byte[] temp0 = BitConverter.GetBytes(ToUInt32(inputBuffer, inputOffset) ^ UINT_LITTLE(w_state[0] ^ (w_state[5] >> 16) ^ (w_state[3] << 16)));
                    byte[] temp1 = BitConverter.GetBytes(ToUInt32(inputBuffer, inputOffset + 4) ^ UINT_LITTLE(w_state[2] ^ (w_state[7] >> 16) ^ w_state[5] << 16));
                    byte[] temp2 = BitConverter.GetBytes(ToUInt32(inputBuffer, inputOffset + 8) ^ UINT_LITTLE(w_state[4] ^ (w_state[1] >> 16) ^ (w_state[7] << 16)));
                    byte[] temp3 = BitConverter.GetBytes(ToUInt32(inputBuffer, inputOffset + 12) ^ UINT_LITTLE(w_state[6] ^ (w_state[3] >> 16) ^ (w_state[1] << 16)));
                    temp0.CopyTo(outputBuffer, outputOffset); temp1.CopyTo(outputBuffer, outputOffset + 4); temp2.CopyTo(outputBuffer, outputOffset + 8); temp3.CopyTo(outputBuffer, outputOffset + 12);

                    bytesTransformed += 16;
                    inputCount -= 16;
                    outputOffset += 16;
                    inputOffset += 16;
                }
                return bytesTransformed;
            }
            /// <summary>
            /// Transforms the Final Block only if Final Block is less than 16 bytes in length
            /// </summary>
            /// <param name="inputBuffer"></param>
            /// <param name="inputOffset"></param>
            /// <param name="inputCount"></param>
            /// <returns></returns>
            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                if (inputBuffer == null)
                    throw new ArgumentNullException("inputBuffer");
                if (inputCount < 0)
                    throw new ArgumentOutOfRangeException("inputCount");
                if(inputOffset < 0)
                    throw new ArgumentOutOfRangeException("inputOffset");

                byte[] output_buff = new byte[inputCount];
                byte[] buffer = new byte[16];
                //Final Block
                NEXT_STATE(w_state, w_counter, WorkBit);
                byte[] buff0 = SwapEndianess(BitConverter.GetBytes(w_state[0] ^ (w_state[5] >> 16) ^ (w_state[3] << 16)));
                byte[] buff1 = SwapEndianess(BitConverter.GetBytes(w_state[2] ^ (w_state[7] >> 16) ^ (w_state[5] << 16)));
                byte[] buff2 = SwapEndianess(BitConverter.GetBytes(w_state[4] ^ (w_state[1] >> 16) ^ (w_state[7] << 16)));
                byte[] buff3 = SwapEndianess(BitConverter.GetBytes(w_state[6] ^ (w_state[3] >> 16) ^ (w_state[1] << 16)));
                buff0.CopyTo(buffer, 0); buff1.CopyTo(buffer, 4); buff2.CopyTo(buffer, 8); buff3.CopyTo(buffer, 12);
                for (int i = 0; i < inputCount; i++)
                    output_buff[i] = (byte)(inputBuffer[inputOffset + i] ^ buffer[i]);
                return output_buff;
            }
            /// <summary>
            /// Rotates Bytes
            /// </summary>
            /// <param name="v"></param>
            /// <param name="c"></param>
            /// <returns></returns>
            private uint Rotate(uint v, int c)
            {
                return (v << c) | (v >> (32 - c));
            }
            /// <summary>
            /// Converts UInt32 to little endian
            /// </summary>
            /// <param name="data"></param>
            /// <returns></returns>
            private UInt32 UINT_LITTLE(UInt32 data)
            {
                byte[] b = new byte[4];
                b[0] = (byte)data;
                b[1] = (byte)(((uint)data >> 8) & 0xFF);
                b[2] = (byte)(((uint)data >> 16) & 0xFF);
                b[3] = (byte)(((uint)data >> 24) & 0xFF);
                return BitConverter.ToUInt32(b, 0);
            }
            /// <summary>
            /// The Rabbit G Function Used in the Next_State Function
            /// </summary>
            /// <param name="word"></param>
            /// <returns></returns>
            private UInt32 RabbitGFunc(UInt32 word)
            {
                UInt32 a = INIT_EMPTY;
                UInt32 b = INIT_EMPTY;
                UInt32 h = INIT_EMPTY;
                UInt32 l = INIT_EMPTY;
                a = word & 0xFFFF;
                b = word >> 16;
                h = ((((UInt32)(a * a) >> 17) + (UInt32)(a * b)) >> 15) + b * b;
                l = word * word;
                return (UInt32)(h ^ l);
            }
            /// <summary>
            /// Key Setup and IV Setup
            /// </summary>
            /// <param name="key"></param>
            /// <param name="iv"></param>
            private void Init(byte[] key, byte[] iv)
            {
                UInt32 k0, k1, k2, k3;
                k0 = ToUInt32(key, 0); k1 = ToUInt32(key, 4); k2 = ToUInt32(key, 8); k3 = ToUInt32(key, 12);
                m_state = new UInt32[8];
                m_state[0] = k0;
                m_state[2] = k1;
                m_state[4] = k2;
                m_state[6] = k3;
                m_state[1] = (k3 << 16) | (k2 >> 16);
                m_state[3] = (k0 << 16) | (k3 >> 16);
                m_state[5] = (k1 << 16) | (k0 >> 16);
                m_state[7] = (k2 << 16) | (k1 >> 16);
                m_counter = new UInt32[8];
                m_counter[0] = Rotate(k2, 16);
                m_counter[2] = Rotate(k3, 16);
                m_counter[4] = Rotate(k0, 16);
                m_counter[6] = Rotate(k1, 16);
                m_counter[1] = (k0 & 0xFFFF0000) | (k1 & 0xFFFF);
                m_counter[3] = (k1 & 0xFFFF0000) | (k2 & 0xFFFF);
                m_counter[5] = (k2 & 0xFFFF0000) | (k3 & 0xFFFF);
                m_counter[7] = (k3 & 0xFFFF0000) | (k0 & 0xFFFF);
                MasterBit = false;
                //iterate state - 4 times
                for (int i = 0; i < 4; i++)
                {
                    NEXT_STATE(m_state, m_counter, MasterBit);
                }
                //-----------------------
                for (int i = 0; i < 8; i++)
                    m_counter[i] ^= m_state[(i + 4) & 0x7];
                w_state = new UInt32[8];
                w_counter = new UInt32[8];
                for (int i = 0; i < 8; i++)
                {
                    w_state[i] = m_state[i];
                    w_counter[i] = m_counter[i];
                }
                WorkBit = MasterBit;
                UInt32 i0, i1, i2, i3;
                i0 = ToUInt32(iv, 0); i2 = ToUInt32(iv, 4); i1 = (i0 >> 16) | (i2 & 0xFFFF0000); i3 = (i2 << 16) | (i0 & 0x0000FFFF);
                w_counter[0] = m_counter[0] ^ i0;
                w_counter[1] = m_counter[1] ^ i1;
                w_counter[2] = m_counter[2] ^ i2;
                w_counter[3] = m_counter[3] ^ i3;
                w_counter[4] = m_counter[4] ^ i0;
                w_counter[5] = m_counter[5] ^ i1;
                w_counter[6] = m_counter[5] ^ i1;
                w_counter[7] = m_counter[7] ^ i3;
                for (int i = 0; i < 8; i++)
                    w_state[i] = m_state[i];
                WorkBit = MasterBit;
                for (int i = 0; i < 4; i++)
                    NEXT_STATE(w_state, w_counter, WorkBit);
            }
            /// <summary>
            /// NEXT_STATE Function used in the Process of Key/IV Set ups and Encryption/Decryption
            /// </summary>
            /// <param name="state"></param>
            /// <param name="counter"></param>
            /// <param name="bitcarrier"></param>
            private void NEXT_STATE(UInt32[] state, UInt32[] counter, bool bitcarrier)
            {
                UInt32[] g = new UInt32[8], c_old = new UInt32[8];
                for (int i = 0; i < 8; i++)
                    c_old[i] = counter[i];
                if(bitcarrier == true)
                    counter[0] = counter[0] + 0x4D34D34D + 1;
                else
                    counter[0] = counter[0] + 0x4D34D34D;
                if (counter[0] < c_old[0])
                    counter[1] = counter[1] + 0xD34D34D3 + 1;
                else
                    counter[1] = counter[1] + 0xD34D34D3;
                if (counter[1] < c_old[1])
                    counter[2] = counter[2] + 0x34D34D34 + 1;
                else
                    counter[2] = counter[2] + 0x34D34D34;
                if (counter[2] < c_old[2])
                    counter[3] = counter[3] + 0x4D34D34D + 1;
                else
                    counter[3] = counter[3] + 0x4D34D34D;
                if (counter[3] < c_old[3])
                    counter[4] = counter[4] + 0xD34D34D3 + 1;
                else
                    counter[4] = counter[4] + 0xD34D34D3;
                if (counter[4] < c_old[4])
                    counter[5] = counter[5] + 0x34D34D34 + 1;
                else
                    counter[5] = counter[5] + 0x34D34D34;
                if (counter[5] < c_old[5])
                    counter[6] = counter[6] + 0x4D34D34D + 1;
                else
                    counter[6] = counter[6] + 0x4D34D34D;
                if (counter[6] < c_old[6])
                    counter[7] = counter[7] + 0xD34D34D3 + 1;
                else
                    counter[7] = counter[7] + 0xD34D34D3;
                if (counter[7] < c_old[7])
                    bitcarrier = true;
                else
                    bitcarrier = false;
                for (int i = 0; i < 8; i++)
                    g[i] = RabbitGFunc(state[i] + counter[i]);
                state[0] = g[0] + Rotate(g[7], 16) + Rotate(g[6], 16);
                state[1] = g[1] + Rotate(g[0], 8) + g[7];
                state[2] = g[2] + Rotate(g[1], 16) + Rotate(g[0], 16);
                state[3] = g[3] + Rotate(g[2], 8) + g[1];
                state[4] = g[4] + Rotate(g[3], 16) + Rotate(g[2], 16);
                state[5] = g[5] + Rotate(g[4], 8) + g[3];
                state[6] = g[6] + Rotate(g[5], 16) + Rotate(g[4], 16);
                state[7] = g[7] + Rotate(g[6], 8) + g[5];
            }
            /// <summary>
            /// A Function for Generating a PseudoRandom KeyStream
            /// </summary>
            /// <param name="state"></param>
            /// <param name="master"></param>
            /// <param name="outputKeyStream"></param>
            /// <param name="startOffset"></param>
            /// <param name="KeyStreamCount"></param>
            public void GenerateKeyStreamEx(UInt32[] state, UInt32 master, byte[] outputKeyStream, int startOffset, UInt32 KeyStreamCount)
            {
                byte[] buffer = new byte[16];
                while (KeyStreamCount >= 16)
                {
                    NEXT_STATE(w_state, w_counter, WorkBit);

                    byte[] pseudorandom_data = GetRandomBytes(16);
                    pseudorandom_data.CopyTo(outputKeyStream, 0);

                    startOffset += 16;
                    KeyStreamCount -= 16;
                }
                if (KeyStreamCount % 16 != 0)
                {
                    NEXT_STATE(w_state, w_counter, WorkBit);

                    buffer = GetRandomBytes(16);
                    for (int i = 0; i < KeyStreamCount; i++)
                        outputKeyStream[i] = buffer[i];
                }
            }
            /// <summary>
            /// A Function for Generating a PseudoRandom KeyStream
            /// </summary>
            /// <param name="state"></param>
            /// <param name="master"></param>
            /// <param name="outputKeyStream"></param>
            /// <param name="startOffset"></param>
            /// <param name="KeyStreamCount"></param>
            public void GenerateKeyStream(UInt32[] state, byte[] outputKeyStream, int startOffset, UInt32 KeyStreamCount)
            {
                byte[] buffer = new byte[16];
                while (KeyStreamCount >= 16)
                {
                    NEXT_STATE(w_state, w_counter, WorkBit);

                    byte[] word0 = SwapEndianess(BitConverter.GetBytes(state[0] ^ (state[5] >> 16) ^ (state[3] << 16)));
                    byte[] word1 = SwapEndianess(BitConverter.GetBytes(state[2] ^ (state[7] >> 16) ^ (state[5] << 16)));
                    byte[] word2 = SwapEndianess(BitConverter.GetBytes(state[4] ^ (state[1] >> 16) ^ (state[7] << 16)));
                    byte[] word3 = SwapEndianess(BitConverter.GetBytes(state[6] ^ (state[3] >> 16) ^ (state[1] << 16)));
                    word0.CopyTo(outputKeyStream, 0); word1.CopyTo(outputKeyStream, 4); word2.CopyTo(outputKeyStream, 8); word3.CopyTo(outputKeyStream, 12);

                    startOffset += 16;
                    KeyStreamCount -= 16;
                }
                if (KeyStreamCount % 16 != 0)
                {
                    NEXT_STATE(w_state, w_counter, WorkBit);

                    byte[] buff0 = SwapEndianess(BitConverter.GetBytes(state[0] ^ (state[5] >> 16) ^ (state[3] << 16)));
                    byte[] buff1 = SwapEndianess(BitConverter.GetBytes(state[2] ^ (state[7] >> 16) ^ (state[5] << 16)));
                    byte[] buff2 = SwapEndianess(BitConverter.GetBytes(state[4] ^ (state[1] >> 16) ^ (state[7] << 16)));
                    byte[] buff3 = SwapEndianess(BitConverter.GetBytes(state[6] ^ (state[3] >> 16) ^ (state[1] << 16)));
                    buff0.CopyTo(buffer, 0); buff1.CopyTo(buffer, 4); buff2.CopyTo(buffer, 8); buff3.CopyTo(buffer, 12);

                    for (int i = 0; i < KeyStreamCount; i++)
                        outputKeyStream[i] = buffer[i];
                }
            }
            /// <summary>
            /// Gets a {x} amount of PseudoRandom Bytes
            /// </summary>
            /// <param name="byteCount"></param>
            /// <returns></returns>
            private byte[] GetRandomBytes(int byteCount)
            {
                byte[] bytes = new byte[byteCount];
                using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
                    rng.GetBytes(bytes);
                return bytes;
            }
            /// <summary>
            /// Swaps the Endianess of a Byte[] Array { LE -> BE || BE -> LE }
            /// </summary>
            /// <param name="buffer"></param>
            /// <returns></returns>
            private byte[] SwapEndianess(byte[] buffer)
            {
                return buffer.Reverse().ToArray();
            }
            /// <summary>
            /// Converts a byte[] array to a UInt32
            /// </summary>
            /// <param name="input"></param>
            /// <param name="inputOffset"></param>
            /// <returns></returns>
            private uint ToUInt32(byte[] input, int inputOffset)
            {
                return unchecked((uint)(((input[inputOffset] | (input[inputOffset + 1] << 8)) | (input[inputOffset + 2] << 16)) | (input[inputOffset + 3] << 24)));
            }
        }
    }
}
