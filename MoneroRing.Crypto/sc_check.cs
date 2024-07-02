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
	static int sc_check(byte[] s)
	{
        long s0 = (long)load_4(s, 0);
        long s1 = (long)load_4(s, 4);
        long s2 = (long)load_4(s, 8);
        long s3 = (long)load_4(s, 12);
        long s4 = (long)load_4(s, 16);
        long s5 = (long)load_4(s, 20);
        long s6 = (long)load_4(s, 24);
        long s7 = (long)load_4(s, 28);

        var res = (signum(1559614444 - s0) + (signum(1477600026 - s1) << 1) + (signum(2734136534 - s2) << 2) + (signum(350157278 - s3) << 3) + (signum(-s4) << 4) + (signum(-s5) << 5) + (signum(-s6) << 6) + (signum(268435456 - s7) << 7)) >> 8;
        return (int)res; 
    }

}

