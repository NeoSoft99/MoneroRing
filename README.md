# MoneroRing

MoneroRing is .NET implementation of Monero ring signature and key image.

## What can MoneroRing do?

MoneroRing contains C# code of cryptographic operations with elliptic curves developed by Monero project and
required to generate and validate key images and ring signatures, which are the building blocks of private transactions.
MoneroRing references and extends MoneroSharp library created by Oğuzhan Eroğlu,
which implements cryptographic operations with Monero keys and addresses.

## Unit tests
The unit tests cover several basic crypto functions and the main ones such as generate_key_image, generate_ring_signature, and check_ring_signature.
The test data, including expected results, is taken from Monero test data which ensures 100% compatibility with the original C/C++ implementation.

## License

The MIT License (MIT)

Copyright (c) 2024 MystSafe LLC (https://mystsafe.com)

Copyright (c) 2024 crypticana <crypticana@proton.me> 

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

Parts of the project are originally copyright (c) 2022 Tabby Labs Inc., Oğuzhan Eroğlu <rohanrhu2@gmail.com>,
distributed under the MIT licence.
