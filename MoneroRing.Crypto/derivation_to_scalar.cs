/*
 * MoneroRing, C# .NET implementation of Monero keys, signatures, ring signatures, and key images
 * Github: https://github.com/MystSafe/MoneroRing
 *
 * Copyright (C) 2024, MystSafe (https://mystsafe.com)
 * Copyright (C) 2024, Author: crypticana <crypticana@proton.me>
 * MystSafe is the only privacy preserving password manager
 *
 * Licensed under MIT (See LICENSE file)
 */

using MoneroSharp.NaCl.Internal.Ed25519Ref10;

namespace MoneroRing.Crypto;

public static partial class RingSig
{
    struct derivation_buffer
    {
        public byte[] derivation;
        public byte[] output_index;

        public derivation_buffer(byte[] derivation)
        {
            this.derivation = derivation;
            output_index = new byte[(4 * 8 + 6) / 7];
        }
       
        public byte[] ToByteArray(int index_length)
        {
            byte[] result = new byte[32 + index_length]; 
            Array.Copy(derivation, 0, result, 0, 32);
            Array.Copy(output_index, 0, result, 32, index_length);
            return result;
        }
    };
    
    public static int WriteVarInt(byte[] buffer, uint value)
    {
        int size = 0;
        while (value >= 0x80)
        {
            buffer[size] = (byte)(value | 0x80);
            value >>= 7;
            size++;
        }
        buffer[size] = (byte)value;
        size++;
        return size;
    }
    
    // generates shared secret (derivation)
    public static byte[] derivation_to_scalar(
        byte[] derivation, 
        uint output_index)
    {
        var buf = new derivation_buffer(derivation);
        //char *end = buf.output_index;
        // Encode the outputIndex as a varint and store it in the output_index array
        int indexLength = WriteVarInt(buf.output_index, output_index);
        if (indexLength <= 0 || indexLength > buf.output_index.Length)
        {
            throw new ArgumentOutOfRangeException(nameof(output_index), "Failed to encode output_index.");
        }

        byte[] buf_to_hash = buf.ToByteArray(indexLength);
        return hash_to_scalar(buf_to_hash);
    }
}

// void crypto_ops::derivation_to_scalar(const key_derivation &derivation, size_t output_index, ec_scalar &res) {
    //     struct {
    //         key_derivation derivation;
    //         char output_index[(sizeof(size_t) * 8 + 6) / 7];
    //     } buf;
    //     char *end = buf.output_index;
    //     buf.derivation = derivation;
    //     tools::write_varint(end, output_index);
    //     assert(end <= buf.output_index + sizeof buf.output_index);
    //     hash_to_scalar(&buf, end - reinterpret_cast<char *>(&buf), res);
    // }