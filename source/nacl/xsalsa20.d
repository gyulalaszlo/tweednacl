/**
  $(BIG $(B Secret-key encryption: crypto_stream))

  $(BIG Security model)

  The crypto_stream function, viewed as a function of the nonce for a uniform
  random key, is designed to meet the standard notion of unpredictability
  ("PRF"). For a formal definition see, e.g., Section 2.3 of Bellare, Kilian, and
  Rogaway, $(I "The security of the cipher block chaining message authentication
  code,") Journal of Computer and System Sciences 61 (2000), 362–399;
  $(LINK http://www-cse.ucsd.edu/~mihir/papers/cbc.html).

  This means that an attacker cannot distinguish this function from a uniform
  random function. Consequently, if a series of messages is encrypted by
  crypto_stream_xor with a different nonce for each message, the ciphertexts are
  indistinguishable from uniform random strings of the same length.

  Note that the length is not hidden. Note also that it is the caller's
  responsibility to ensure the uniqueness of nonces—for example, by using nonce 1
  for the first message, nonce 2 for the second message, etc. Nonces are long
  enough that randomly generated nonces have negligible risk of collision.

  NaCl does not make any promises regarding the resistance of crypto_stream to
  "related-key attacks." It is the caller's responsibility to use proper
  key-derivation functions.

  $(BIG Selected primitive)

  crypto_stream is crypto_stream_xsalsa20, a particular cipher specified in
  "Cryptography in NaCl", Section 7. This cipher is conjectured to meet the
  standard notion of unpredictability.

*/
module nacl.xsalsa20;

import nacl.basics : sigma;
import nacl.salsa20 : Salsa20, HSalsa20;

struct XSalsa20 {

  enum Primitive = "xsalsa20";
  enum Implementation = "crypto_stream/xsalsa20/tweet";
  enum Version = "-";

  enum KeyBytes = 32;
  enum NonceBytes = 24;

  alias stream = crypto_stream;
  alias streamXor = crypto_stream_xor;

  alias Key = ubyte[KeyBytes];
  alias Nonce = ubyte[NonceBytes];
}
/**

  The crypto_stream function produces a stream c[0], c[1], ..., c[clen-1] as a
  function of a secret key k[0], k[1], ..., k[XSalsa20.KeyBytes-1] and a
  nonce n[0], n[1], ..., n[XSalsa20.NonceBytes-1]. The crypto_stream
  function then returns 0.

*/
pure nothrow @safe @nogc int crypto_stream(ubyte[] c,ulong d,
    ref const XSalsa20.Nonce nonce,
    ref const XSalsa20.Key k)
{
  ubyte s[32];
  HSalsa20.core(s,nonce[0..HSalsa20.InputBytes],k,sigma);
  return crypto_stream_salsa20(c,d,nonce[HSalsa20.InputBytes..$],s);
}

/**

  The crypto_stream_xor function encrypts a message m[0], m[1], ..., m[mlen-1]
  using a secret key k[0], k[1], ..., k[XSalsa20.KeyBytes-1] and a nonce
  n[0], n[1], ..., n[XSalsa20.NonceBytes-1]. The crypto_stream_xor function
  puts the ciphertext into c[0], c[1], ..., c[mlen-1]. It then returns 0.

  The crypto_stream_xor function guarantees that the ciphertext is the plaintext
  xor the output of crypto_stream. Consequently crypto_stream_xor can also be
  used to decrypt.

*/
pure nothrow @safe @nogc int crypto_stream_xor(ubyte[] c,const(ubyte)[] m,ulong d,
    ref const XSalsa20.Nonce nonce,
    ref const XSalsa20.Key k)
{
  import nacl.basics : sigma;
  ubyte s[32];
  HSalsa20.core(s,nonce[0..HSalsa20.InputBytes],k,sigma);
  return crypto_stream_salsa20_xor(c,m,d,nonce[HSalsa20.InputBytes..$],s);
}


private:
// Implementations for crypto_stream_salsa20
// -----------------------------------------
// the nonce bytes
enum salsaRoundNonceBytes = 8;

pure nothrow @safe @nogc int crypto_stream_salsa20_xor_impl(bool useMessage=true)(
    ubyte[] c,
    const(ubyte)[] m,
    ulong b,
    ref const ubyte[salsaRoundNonceBytes] n,
    ref const XSalsa20.Key k
    )
{
  import nacl.basics : sigma;
  ubyte[16] z;
  ubyte[64] x;
  uint u;
  if (!b) return 0;
  foreach(i;0..16) z[i] = 0;
  foreach(i;0..8) z[i] = n[i];
  while (b >= 64) {
    Salsa20.core(x,z,k,sigma);
    static if (useMessage)
      foreach(i;0..64) {
        c[i] = m[i] ^ x[i];
      }
    else
      foreach(i;0..64) c[i] = 0 ^ x[i];

    u = 1;
    for (uint i = 8;i < 16;++i) {
      u += uint(z[i]);
      z[i] = cast(ubyte)(u);
      u >>= 8;
    }
    b -= 64;
    c = c[64..$];
    static if (useMessage)
      m = m[64..$];
  }
  if (b) {
    Salsa20.core(x,z,k,sigma);
    static if (useMessage)
      foreach(i;0..b) {
        c[i] = m[i] ^ x[i];
      }
    else
      foreach(i;0..b) c[i] = 0 ^ x[i];
  }
  return 0;
}

const(const(ubyte)[]) nullBytes = [];

pure nothrow @safe @nogc int crypto_stream_salsa20(ubyte[] c,ulong d,
    ref const ubyte[salsaRoundNonceBytes] n,
    ref const XSalsa20.Key k)
{
  const ubyte[] nullBytes = [];
  return crypto_stream_salsa20_xor_impl!false(c,nullBytes,d,n,k);
}

pure nothrow @safe @nogc int crypto_stream_salsa20_xor(ubyte[] c, const(ubyte)[] m,ulong b,
    ref const ubyte[salsaRoundNonceBytes] n,
    ref const XSalsa20.Key k)
{
  return crypto_stream_salsa20_xor_impl!true(c,m,b,n,k);
}

unittest {
  ubyte firstkey[32]
    = [ 0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51,
      0x19, 0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64,
      0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89 ];
  ubyte nonce[24] = [ 0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
    0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
    0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37 ];
  ubyte output[4194304];

  import std.digest.sha;
  crypto_stream(output, 4194304, nonce, firstkey);
  assert( toHexString(sha256Of(output[])) == "662B9D0E3463029156069B12F918691A98F7DFB2CA0393C96BBFC6B1FBD630A2" );
}

// This test doubles the runtime of the tests...
version(TweedNaClLargeBufferTests) {
  unittest {
    ubyte output[4194304];
    ubyte h[32];
    ubyte[8] nonce = [0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37];
    ubyte[32] key =
      [ 0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9, 0x53, 0x62, 0x9b,
      0x73, 0x38, 0x20, 0x77, 0x88, 0x80, 0xf3, 0xce, 0xb4, 0x21, 0xbb,
      0x61, 0xb9, 0x1c, 0xbd, 0x4c, 0x3e, 0x66, 0x25, 0x6c, 0xe4];

    crypto_stream_salsa20(output, 4194304, nonce, key);

    import std.digest.sha;
    assert( toHexString(sha256Of(output[])) == "662B9D0E3463029156069B12F918691A98F7DFB2CA0393C96BBFC6B1FBD630A2" );
  }
}


unittest {
  ubyte[32] rs;
  ubyte[24] nonce =
      [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
      0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
      0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37];
  ubyte[32] firstkey =
      [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51,
      0x19, 0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64,
      0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89];
  crypto_stream(rs, 32, nonce, firstkey );

  assert( rs == [
      0xee,0xa6,0xa7,0x25,0x1c,0x1e,0x72,0x91
      ,0x6d,0x11,0xc2,0xcb,0x21,0x4d,0x3c,0x25
      ,0x25,0x39,0x12,0x1d,0x8e,0x23,0x4e,0x65
      ,0x2d,0x65,0x1f,0xa4,0xc8,0xcf,0xf8,0x80
      ] );
}

unittest {
  ubyte firstkey[32]
    = [ 0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51,
    0x19, 0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64,
    0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89 ];
  ubyte nonce[24] = [ 0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
        0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
        0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37];
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
  ubyte c[163];
  crypto_stream_xor(c, m, 163, nonce, firstkey);

  assert( c[32..163] == [
      0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73
      ,0xc2,0x96,0x50,0xba,0x32,0xfc,0x76,0xce
      ,0x48,0x33,0x2e,0xa7,0x16,0x4d,0x96,0xa4
      ,0x47,0x6f,0xb8,0xc5,0x31,0xa1,0x18,0x6a
      ,0xc0,0xdf,0xc1,0x7c,0x98,0xdc,0xe8,0x7b
      ,0x4d,0xa7,0xf0,0x11,0xec,0x48,0xc9,0x72
      ,0x71,0xd2,0xc2,0x0f,0x9b,0x92,0x8f,0xe2
      ,0x27,0x0d,0x6f,0xb8,0x63,0xd5,0x17,0x38
      ,0xb4,0x8e,0xee,0xe3,0x14,0xa7,0xcc,0x8a
      ,0xb9,0x32,0x16,0x45,0x48,0xe5,0x26,0xae
      ,0x90,0x22,0x43,0x68,0x51,0x7a,0xcf,0xea
      ,0xbd,0x6b,0xb3,0x73,0x2b,0xc0,0xe9,0xda
      ,0x99,0x83,0x2b,0x61,0xca,0x01,0xb6,0xde
      ,0x56,0x24,0x4a,0x9e,0x88,0xd5,0xf9,0xb3
      ,0x79,0x73,0xf6,0x22,0xa4,0x3d,0x14,0xa6
      ,0x59,0x9b,0x1f,0x65,0x4c,0xb4,0x5a,0x74
      ,0xe3,0x55,0xa5] );
}

