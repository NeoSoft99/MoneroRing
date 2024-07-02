/*
 * Original code from MoneroSharp project
 * Copyright (C) 2022, Tabby Labs Inc.
 * Author: Oğuzhan Eroğlu <rohanrhu2@gmail.com> (https://oguzhaneroglu.com)
 *
 * Modifications made to fix serious bugs in Base58 decoding
 * Copyright (c) 2024 MystSafe (https://mystsafe.com)
 * Copyright (c) 2024 crypticana <crypticana@proton.me>
 * 
 * Licensed under MIT (See ORIGINAL LICENSE files)
 */

namespace MoneroSharp;

public static class Base58
{
    public static readonly char[] Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".ToCharArray();
    public static readonly int[] EncodedBlockSizes = { 0, 2, 3, 5, 6, 7, 9, 10, 11 };

    public static void EncodeBlock(byte[] data, int index, byte[] encoded)
    {
        byte[] raw = data.Skip(index * 8).Take(8).ToArray();
        raw = raw.Reverse().ToArray();
        int block_len = raw.Length;
        if ((block_len < 1) || (block_len > 11))
        {
            throw new Exception("Invalid block size!");
        }

        byte[] block = new byte[8];
        for (int i = 0; i < raw.Length; i++)
        {
            block[i] = raw[i];
        }

        for (int i = raw.Length; i < block_len; i++)
        {
            block[i] = 0;
        }

        ulong scalar = BitConverter.ToUInt64(block, 0);
        int j = EncodedBlockSizes[block_len] - 1;
        while (scalar > 0)
        {
            int remainder = (int)(scalar % 58);
            scalar = scalar / 58;
            encoded[index * 11 + j] = (byte)(Alphabet[remainder]);
            j--;
        }
    }

    public static byte[] Encode(byte[] data)
    {
        int blocks_length = data.Length / 8;
        int remaining_length = data.Length % 8;

        int encoded_length = (data.Length / 8) * 11 + EncodedBlockSizes[remaining_length];
        byte[] encoded = new byte[encoded_length];

        for (int i = 0; i < encoded.Length; i++)
        {
            encoded[i] = (byte)(Alphabet[0]);
        }

        for (int i = 0; i < blocks_length; i++)
        {
            EncodeBlock(data, i, encoded);
        }

        if (remaining_length > 0)
        {
            EncodeBlock(data, blocks_length, encoded);
        }

        return encoded;
    }

    public static void DecodeBlock(byte[] data, int index, int block_length, byte[] decoded)
    {
        byte[] raw = data.Skip(index * 11).Take(11).ToArray();

        ulong scalar = 0;
        ulong order = 1;
        for (int i = raw.Length - 1; i >= 0; i--)
        {
            int digit = Array.IndexOf(Alphabet, (char)raw[i]);
            if (digit < 0)
            {
                throw new Exception("Invalid digit!");
            }

            scalar += order * (ulong)digit;
            order *= 58;
        }

        byte[] decoded_block = BitConverter.GetBytes(scalar).Reverse().ToArray();
        Array.Copy(decoded_block, decoded_block.Length - block_length, decoded, index * 8, block_length);
    }

    public static byte[] Decode(byte[] data)
    {
        int blocks_length = data.Length / 11;
        int remaining_length = data.Length % 11;
        int last_block_decoded_length = remaining_length > 0 ? Array.IndexOf(EncodedBlockSizes, remaining_length) : 0;
        if (remaining_length > 0 && last_block_decoded_length <= 0)
        {
            throw new Exception("Invalid encoded size!");
        }

        int decoded_length = blocks_length * 8 + last_block_decoded_length;
        byte[] decoded = new byte[decoded_length];
        for (int i = 0; i < blocks_length; i++)
        {
            DecodeBlock(data, i, 8, decoded);
        }

        if (remaining_length > 0)
        {
            DecodeBlock(data, blocks_length, last_block_decoded_length, decoded);
        }

        return decoded;
    }
}
