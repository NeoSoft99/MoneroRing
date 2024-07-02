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

using MoneroSharp.NaCl;
using MoneroSharp.NaCl.Internal.Ed25519Ref10;

namespace MoneroRing.Crypto;

public static partial class RingSig
{
    public struct s_comm
    {
        public byte[] h;
        public byte[] key;
        public byte[] comm;
        
        public byte[] ToByteArray()
        {
            List<byte> bytes = new List<byte>();
            bytes.AddRange(h);
            bytes.AddRange(key);
            bytes.AddRange(comm);
            return bytes.ToArray();
        }
    }
    // struct s_comm {
    //     hash h;
    //     ec_point key;
    //     ec_point comm;
    // };

    // returns byte[] array containing ring signature
    public static byte[] generate_signature(byte[] prefix_hash, byte[] pub, byte[] sec)
    {
        signature sig;
        sig.r = new byte[32];
        GroupElementP3 tmp3;
        var k = new byte[32];
        s_comm buf;
        buf.h = prefix_hash;
        buf.key = pub;
        buf.comm = new byte[32];
        try_again:
        random_scalar(k);
        GroupOperations.ge_scalarmult_base(out tmp3, k, 0);
        GroupOperations.ge_p3_tobytes(buf.comm, 0, ref tmp3);
        sig.c = hash_to_scalar(buf.ToByteArray());
        if (sc_isnonzero(sig.c) == 0)
            goto try_again;
        sc_mulsub(sig.r, sig.c, sec, k);
        if (sc_isnonzero(sig.r) == 0)
            goto try_again;
        CryptoBytes.Wipe(k);
        return sig.ToByteArray();
    }

    /*public static void generate_signature(const hash  &prefix_hash, const public_key  &pub, const secret_key &sec, signature &sig)
    {
        ge_p3 tmp3;
        ec_scalar k;
        s_comm buf;
        {
            buf.h = prefix_hash;
            buf.key = pub;
            try_again:
            random_scalar(k);
            ge_scalarmult_base(&tmp3, &k);
            ge_p3_tobytes(&buf.comm, &tmp3);
            hash_to_scalar(&buf, sizeof(s_comm), sig.c);
            if (!sc_isnonzero((const unsigned  char *)sig.c.data))
            goto try_again;
            sc_mulsub(&sig.r, &sig.c, &unwrap(sec), &k);
            if (!sc_isnonzero((const unsigned  char *)sig.r.data))
            goto try_again;
            memwipe(&k, sizeof(k));
        }
    }*/
}