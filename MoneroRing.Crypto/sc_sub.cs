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

namespace MoneroRing.Crypto;

public static partial class RingSig
{
    static void sc_sub(byte[] s, byte[] a, byte[] b)
    {
        long a0 = 2097151 & load_3(a, 0);
        long a1 = 2097151 & (load_4(a, 2) >> 5);
        long a2 = 2097151 & (load_3(a, 5) >> 2);
        long a3 = 2097151 & (load_4(a, 7) >> 7);
        long a4 = 2097151 & (load_4(a, 10) >> 4);
        long a5 = 2097151 & (load_3(a, 13) >> 1);
        long a6 = 2097151 & (load_4(a, 15) >> 6);
        long a7 = 2097151 & (load_3(a, 18) >> 3);
        long a8 = 2097151 & load_3(a, 21);
        long a9 = 2097151 & (load_4(a, 23) >> 5);
        long a10 = 2097151 & (load_3(a, 26) >> 2);
        long a11 = (load_4(a, 28) >> 7);
        long b0 = 2097151 & load_3(b, 0);
        long b1 = 2097151 & (load_4(b, 2) >> 5);
        long b2 = 2097151 & (load_3(b, 5) >> 2);
        long b3 = 2097151 & (load_4(b, 7) >> 7);
        long b4 = 2097151 & (load_4(b, 10) >> 4);
        long b5 = 2097151 & (load_3(b, 13) >> 1);
        long b6 = 2097151 & (load_4(b, 15) >> 6);
        long b7 = 2097151 & (load_3(b, 18) >> 3);
        long b8 = 2097151 & load_3(b, 21);
        long b9 = 2097151 & (load_4(b, 23) >> 5);
        long b10 = 2097151 & (load_3(b, 26) >> 2);
        long b11 = (load_4(b, 28) >> 7);
        long s0 = a0 - b0;
        long s1 = a1 - b1;
        long s2 = a2 - b2;
        long s3 = a3 - b3;
        long s4 = a4 - b4;
        long s5 = a5 - b5;
        long s6 = a6 - b6;
        long s7 = a7 - b7;
        long s8 = a8 - b8;
        long s9 = a9 - b9;
        long s10 = a10 - b10;
        long s11 = a11 - b11;
        long s12 = 0;
        long carry0;
        long carry1;
        long carry2;
        long carry3;
        long carry4;
        long carry5;
        long carry6;
        long carry7;
        long carry8;
        long carry9;
        long carry10;
        long carry11;

        carry0 = (s0 + (1 << 20)) >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry2 = (s2 + (1 << 20)) >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry4 = (s4 + (1 << 20)) >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry6 = (s6 + (1 << 20)) >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry8 = (s8 + (1 << 20)) >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry10 = (s10 + (1 << 20)) >> 21; s11 += carry10; s10 -= carry10 << 21;

        carry1 = (s1 + (1 << 20)) >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry3 = (s3 + (1 << 20)) >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry5 = (s5 + (1 << 20)) >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry7 = (s7 + (1 << 20)) >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry9 = (s9 + (1 << 20)) >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry11 = (s11 + (1 << 20)) >> 21; s12 += carry11; s11 -= carry11 << 21;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;
        s12 = 0;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;
        carry11 = s11 >> 21; s12 += carry11; s11 -= carry11 << 21;

        s0 += s12 * 666643;
        s1 += s12 * 470296;
        s2 += s12 * 654183;
        s3 -= s12 * 997805;
        s4 += s12 * 136657;
        s5 -= s12 * 683901;

        carry0 = s0 >> 21; s1 += carry0; s0 -= carry0 << 21;
        carry1 = s1 >> 21; s2 += carry1; s1 -= carry1 << 21;
        carry2 = s2 >> 21; s3 += carry2; s2 -= carry2 << 21;
        carry3 = s3 >> 21; s4 += carry3; s3 -= carry3 << 21;
        carry4 = s4 >> 21; s5 += carry4; s4 -= carry4 << 21;
        carry5 = s5 >> 21; s6 += carry5; s5 -= carry5 << 21;
        carry6 = s6 >> 21; s7 += carry6; s6 -= carry6 << 21;
        carry7 = s7 >> 21; s8 += carry7; s7 -= carry7 << 21;
        carry8 = s8 >> 21; s9 += carry8; s8 -= carry8 << 21;
        carry9 = s9 >> 21; s10 += carry9; s9 -= carry9 << 21;
        carry10 = s10 >> 21; s11 += carry10; s10 -= carry10 << 21;

        unchecked
        {
            s[0] = (byte)(s0 >> 0);
            s[1] = (byte)(s0 >> 8);
            s[2] = (byte)((s0 >> 16) | (s1 << 5));
            s[3] = (byte)(s1 >> 3);
            s[4] = (byte)(s1 >> 11);
            s[5] = (byte)((s1 >> 19) | (s2 << 2));
            s[6] = (byte)(s2 >> 6);
            s[7] = (byte)((s2 >> 14) | (s3 << 7));
            s[8] = (byte)(s3 >> 1);
            s[9] = (byte)(s3 >> 9);
            s[10] = (byte)((s3 >> 17) | (s4 << 4));
            s[11] = (byte)(s4 >> 4);
            s[12] = (byte)(s4 >> 12);
            s[13] = (byte)((s4 >> 20) | (s5 << 1));
            s[14] = (byte)(s5 >> 7);
            s[15] = (byte)((s5 >> 15) | (s6 << 6));
            s[16] = (byte)(s6 >> 2);
            s[17] = (byte)(s6 >> 10);
            s[18] = (byte)((s6 >> 18) | (s7 << 3));
            s[19] = (byte)(s7 >> 5);
            s[20] = (byte)(s7 >> 13);
            s[21] = (byte)(s8 >> 0);
            s[22] = (byte)(s8 >> 8);
            s[23] = (byte)((s8 >> 16) | (s9 << 5));
            s[24] = (byte)(s9 >> 3);
            s[25] = (byte)(s9 >> 11);
            s[26] = (byte)((s9 >> 19) | (s10 << 2));
            s[27] = (byte)(s10 >> 6);
            s[28] = (byte)((s10 >> 14) | (s11 << 7));
            s[29] = (byte)(s11 >> 1);
            s[30] = (byte)(s11 >> 9);
            s[31] = (byte)(s11 >> 17);
        }
    }

}

