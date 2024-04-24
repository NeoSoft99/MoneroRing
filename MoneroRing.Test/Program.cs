/*
 * MoneroRing, C# .NET implementation of Monero ring signature and key image
 * 
 * Github: 
 * 
 * Copyright (C) 2024, MystSafe LLC (https://mystsafe.com)
 * Copyright (C) 2024, Author: crypticana <crypticana@proton.me> 
 *
 * Licensed under MIT (See LICENSE file)
 */

using MoneroSharp.Utils;
using MoneroRing.Crypto;

Console.WriteLine("Hello, C# Monero!");

byte[] hash = new byte[32];
RingSig.generate_random_bytes(hash, 32);

byte[] sec1 = new byte[32];
byte[] pub1 = new byte[32];
byte[] sec2 = new byte[32];
byte[] pub2 = new byte[32];
byte[] sec3 = new byte[32];
byte[] pub3 = new byte[32];

RingSig.generate_keys(pub1, sec1);
RingSig.generate_keys(pub2, sec2);
RingSig.generate_keys(pub3, sec3);

byte[] image = new byte[32];
RingSig.generate_key_image(pub2, sec2, image);

var pubs = new byte[3][];
pubs[0] = pub1;
pubs[1] = pub2;
pubs[2] = pub3;

byte[] sig = RingSig.generate_ring_signature(hash, image, pubs, 3, sec2, 1);

Console.WriteLine("ring length: " + sig.Length.ToString());
Console.WriteLine("ring HEX: " + MoneroUtils.BytesToHex(sig));

var ring_is_valid = RingSig.check_ring_signature(hash, image, pubs, 3, sig);
Console.WriteLine("ring is valid: " + ring_is_valid.ToString());
