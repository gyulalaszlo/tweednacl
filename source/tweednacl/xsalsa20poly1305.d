/**
  $(BIG Secret-key authenticated encryption: crypto_secretbox)

  $(BIG Security model)

  The crypto_secretbox function is designed to meet the standard notions of
  privacy and authenticity for a secret-key authenticated-encryption scheme using
  nonces.

  For formal definitions see, e.g., B Bellare and Namprempre,
  $(I "Authenticated encryption: relations among notions and analysis of the generic
  composition paradigm,") Lecture Notes in Computer Science 1976 (2000), 531–545,
  $(LINK http://www-cse.ucsd.edu/~mihir/papers/oem.html)

  Note that the length is not hidden. Note also that it is the caller's
  responsibility to ensure the uniqueness of nonces—for example, by using nonce 1
  for the first message, nonce 2 for the second message, etc. Nonces are long
  enough that randomly generated nonces have negligible risk of collision.

  $(BIG Selected primitive)

  crypto_secretbox is crypto_secretbox_xsalsa20poly1305, a particular combination
  of Salsa20 and Poly1305 specified in "Cryptography in NaCl". This function is
  conjectured to meet the standard notions of privacy and authenticity.

*/
module tweednacl.xsalsa20poly1305;

import tweednacl.poly1305 : Poly1305;
import tweednacl.xsalsa20 : XSalsa20;

import std.experimental.crypto.nacl;

struct XSalsa20Poly1305 {
  mixin XSalsa20Poly1305Implementation!"D";

  alias afternm = box;
  alias openAfternm = open;

  alias Beforenm = Key;
  /**

    The crypto_secretbox function encrypts and authenticates a message m[0], m[1],
    ..., m[mlen-1] using a secret key k[0], ..., k[crypto_secretbox_KEYBYTES-1] and
    a nonce n[0], n[1], ..., n[crypto_secretbox_NONCEBYTES-1]. The crypto_secretbox
    function puts the ciphertext into c[0], c[1], ..., c[mlen-1]. It then returns
    0.

WARNING: $(I Messages in the C NaCl API are 0-padded versions of messages in the
C++ NaCl API. Specifically: The caller must ensure, before calling the C NaCl
crypto_secretbox function, that the first crypto_secretbox_ZEROBYTES bytes of
the message m are all 0. Typical higher-level applications will work with the
remaining bytes of the message; note, however, that mlen counts all of the
bytes, including the bytes required to be 0.)

---
| 0x00                     | 0x00                     | PlainText
+---+-----+----------------+---+-----+----------------+---+-----+--------------------+
| 0 | ... | BoxZeroBytes-1 | 0 | ... | BoxZeroBytes-1 | 0 | ... | PlainText.length-1 |
+---+-----+----------------+---+-----+----------------+---+-----+--------------------+
| 0                        | BoxZeroBytes             | ZeroBytes
---

Similarly, ciphertexts in the C NaCl API are 0-padded versions of messages in
the C++ NaCl API. Specifically: The crypto_secretbox function ensures that the
first crypto_secretbox_BOXZEROBYTES bytes of the ciphertext c are all 0.

---
| 0x00                             | CypherText + Auth
+---+---+---+-----+----------------+---+---+---+-----+------------+
| 0 | 1 | 2 | ... | BoxZeroBytes-1 | 0 | 1 | 2 | ... | c.length-1 |
+---+---+---+-----+----------------+---+---+---+-----+------------+
| 0                                | BoxZeroBytes
---

   */
  pure nothrow @safe @nogc
  static  bool box(
        ubyte[] c,const ubyte[] m,
        ref const XSalsa20Poly1305.Nonce n,
        ref const XSalsa20Poly1305.Key k)
    {
      immutable d = m.length;
      if (d < XSalsa20Poly1305.ZeroBytes) return false;
      XSalsa20.streamXor(c,m,d,n,k);
      Poly1305.onetimeauth(c[16..32],c[32..$],c[0..32]);
      foreach(i;0..XSalsa20Poly1305.BoxZeroBytes) c[i] = 0;
      return true;
    }

  /**

    The crypto_secretbox_open function verifies and decrypts a ciphertext c[0],
    c[1], ..., c[clen-1] using a secret key k[0], k[1], ...,
    k[crypto_secretbox_KEYBYTES-1] and a nonce n[0], ...,
    n[crypto_secretbox_NONCEBYTES-1]. The crypto_secretbox_open function puts the
    plaintext into m[0], m[1], ..., m[clen-1]. It then returns 0.

    If the ciphertext fails verification, crypto_secretbox_open instead returns -1,
    possibly after modifying m[0], m[1], etc.

    The caller must ensure, before calling the crypto_secretbox_open function, that
    the first crypto_secretbox_BOXZEROBYTES bytes of the ciphertext c are all 0.

    ---
    | 0x00                             | CypherText + Auth
    +---+---+---+-----+----------------+---+---+---+-----+------------+
    | 0 | 1 | 2 | ... | BoxZeroBytes-1 | 0 | 1 | 2 | ... | c.length-1 |
    +---+---+---+-----+----------------+---+---+---+-----+------------+
    | 0                                | BoxZeroBytes
    ---

    The crypto_secretbox_open function ensures (in case of success) that the first
    crypto_secretbox_ZEROBYTES bytes of the plaintext m are all 0.

    ---
    | 0x00                          | PlainText
    +---+---+---+-----+-------------+---+---+---+-----+------------+
    | 0 | 1 | 2 | ... | ZeroBytes-1 | 0 | 1 | 2 | ... | m.length-1 |
    +---+---+---+-----+-------------+---+---+---+-----+------------+
    | 0                             | ZeroBytes
    ---

   */
  pure nothrow @safe @nogc
    static bool open(
        ubyte[] m, const ubyte[] c,
        ref const XSalsa20Poly1305.Nonce n,
        ref const XSalsa20Poly1305.Key k)
    in {
      foreach(i;0..XSalsa20Poly1305.BoxZeroBytes) assert( c[i] == 0 );
    }
  body {
    immutable d = c.length;
    if (d < XSalsa20Poly1305.ZeroBytes) return false;
    ubyte x[32];
    XSalsa20.stream(x,32,n,k);
    if (!Poly1305.onetimeauthVerify(c[16..32], c[32..d],x)) return false;
    XSalsa20.streamXor(m,c,d,n,k);
    foreach(i;0..XSalsa20Poly1305.ZeroBytes) m[i] = 0;
    return true;
  }

}


version(TweedNaClTest_XSalsa20Poly1305)
{

  unittest {

    ubyte firstkey[32]
      = [ 0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51,
      0x19, 0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64,
      0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89 ];
    ubyte nonce[24] = [ 0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
    0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
    0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37 ];
    // API requires first 32 bytes to be 0
    ubyte m[163]
      = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0xbe, 0x07, 0x5f, 0xc5,
      0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b,
      0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4, 0x4b, 0x66, 0x84, 0x9b,
      0x64, 0x24, 0x4f, 0xfc, 0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a,
      0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29, 0x6c, 0xdc, 0x3c, 0x01,
      0x23, 0x35, 0x61, 0xf4, 0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31,
      0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d, 0xce, 0xea, 0x3a, 0x7f,
      0xa1, 0x34, 0x80, 0x57, 0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a,
      0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde, 0x04, 0x89, 0x77, 0xeb,
      0x48, 0xf5, 0x9f, 0xfd, 0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
      0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40, 0xe0, 0x82, 0xf9, 0x37,
      0x76, 0x38, 0x48, 0x64, 0x5e, 0x07, 0x05 ];
    // API requires first 16 bytes to be 0
    ubyte cRes[163]
      = [ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5,
      0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9, 0x8e, 0x99, 0x3b, 0x9f,
      0x48, 0x68, 0x12, 0x73, 0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce,
      0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4, 0x47, 0x6f, 0xb8, 0xc5,
      0x31, 0xa1, 0x18, 0x6a, 0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b,
      0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72, 0x71, 0xd2, 0xc2, 0x0f,
      0x9b, 0x92, 0x8f, 0xe2, 0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38,
      0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a, 0xb9, 0x32, 0x16, 0x45,
      0x48, 0xe5, 0x26, 0xae, 0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea,
      0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda, 0x99, 0x83, 0x2b, 0x61,
      0xca, 0x01, 0xb6, 0xde, 0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3,
      0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6, 0x59, 0x9b, 0x1f, 0x65,
      0x4c, 0xb4, 0x5a, 0x74, 0xe3, 0x55, 0xa5 ];
    ubyte c[163];

    XSalsa20Poly1305.box(c, m, nonce, firstkey);
    assert( c[16..163] == cRes[16..163]);


    ubyte m2[163];

    assert( XSalsa20Poly1305.open(m2, c, nonce, firstkey) );
    assert( m[32..163] == m2[32..163]);
    m2[] = 0;
    assert( XSalsa20Poly1305.open(m2, cRes, nonce, firstkey) );
    assert( m[32..163] == m2[32..163]);
  }

  unittest
  {
    import std.random;
    import tweednacl.random : randomBuffer;


    void testSecretbox(Impl)() {
      Impl.Key k;
      Impl.Nonce n;
      ubyte m[10000];
      ubyte c[10000];
      ubyte m2[10000];


      size_t mlen;
      size_t i;
      for (mlen = 0; mlen < 1000 && mlen + Impl.ZeroBytes < m.length;
           mlen = (mlen << 1) + 1) {
             immutable msgBlockLen = mlen + Impl.ZeroBytes;
             randomBuffer(k);
             randomBuffer(n);
             m[0..Impl.ZeroBytes] = 0;
             randomBuffer(m[Impl.ZeroBytes..msgBlockLen]);

             auto currentC = c[0..msgBlockLen];
             currentC[] = 0;

             Impl.box( currentC, m[0..msgBlockLen], n, k );
             assert(Impl.open(m2[0..msgBlockLen], currentC[], n, k),
                    "ciphertext fails verification");
             assert( m2[0..msgBlockLen] == m[0..msgBlockLen] );

             auto caught = 0;
             while (caught < 10) {
               // change a random byte
               auto idx = uniform(0u, mlen + Impl.ZeroBytes);
               c[idx] = uniform(ubyte.min, ubyte.max);
               // fix any errors that might trigger the first Impl.ZeroBytes
               // to be not 0, and thats invalid for the crypto_secretbox_open() interface
               // (it seems to work but the docs say they should not)
               c[0..Impl.ZeroBytes] = 0;

               if(Impl.open(m2[0..msgBlockLen], currentC, n, k)) {
                 assert( m2[0..msgBlockLen] == m[0..msgBlockLen], "foregery" );
               } else {
                 ++caught;
               }
             }
           }
    }

    testSecretbox!XSalsa20Poly1305();
  }

}