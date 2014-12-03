/**

  $(BIG $(B Public-key authenticated encryption: crypto_box))

  $(BIG Security model)

  The crypto_box function is designed to meet the standard notions of privacy and
  third-party unforgeability for a public-key authenticated-encryption scheme
  using nonces. For formal definitions see, e.g., Jee Hea An, $(I "Authenticated
  encryption in the public-key setting: security notions and analyses,")
  $(LINK http://eprint.iacr.org/2001/079).

  Distinct messages between the same {sender, receiver} set are required to have
  distinct nonces. For example, the lexicographically smaller public key can use
  nonce 1 for its first message to the other key, nonce 3 for its second message,
  nonce 5 for its third message, etc., while the lexicographically larger public
  key uses nonce 2 for its first message to the other key, nonce 4 for its second
  message, nonce 6 for its third message, etc. Nonces are long enough that
  randomly generated nonces have negligible risk of collision.

  There is no harm in having the same nonce for different messages if the
  {sender, receiver} sets are different. This is true even if the sets overlap.
  For example, a sender can use the same nonce for two different messages if the
  messages are sent to two different public keys.

  The crypto_box function is not meant to provide non-repudiation.
  On the contrary: the crypto_box function guarantees repudiability. A receiver
  can freely modify a boxed message, and therefore cannot convince third
  parties that this particular message came from the sender. The sender and
  receiver are nevertheless protected against forgeries by other parties. In
  the terminology of
  $(LINK http://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c),
  crypto_box uses "public-key authenticators" rather than "public-key
  signatures."

  Users who want public verifiability (or receiver-assisted public verifiability)
  should instead use crypto_sign() signatures (or signcryption).

  $(BIG Selected primitive)

  crypto_box is curve25519xsalsa20poly1305, a particular combination of
  Curve25519, Salsa20, and Poly1305 specified in $(I "Cryptography in NaCl"). This
  function is conjectured to meet the standard notions of privacy and third-party
  unforgeability.


  */
module nacl.curve25519xsalsa20poly1305;

import nacl.basics : _0, safeRandomBytes, sigma;
import nacl.curve25519 : Curve25519;
import nacl.xsalsa20poly1305 : XSalsa20Poly1305;


struct Curve25519XSalsa20Poly1305 {
  enum Primitive = "curve25519xsalsa20poly1305";
  enum Implementation = "crypto_box/curve25519xsalsa20poly1305/tweet";
  enum Version = "-";

  alias keypair = crypto_box_keypair;
  alias box = crypto_box;
  alias boxOpen = crypto_box_open;
  alias beforenm = crypto_box_beforenm;
  alias afternm = crypto_box_afternm;
  alias openAfternm = crypto_box_open_afternm;

  enum PublicKeyBytes = 32;
  enum SecretKeyBytes = 32;
  enum BeforeNmBytes = 32;
  enum NonceBytes = 24;
  /** The number of 0 bytes in front of the plaintext */
  enum ZeroBytes = 32;
  /** The number of 0 bytes in front of the encrypted box. */
  enum BoxZeroBytes = 16;

  alias PublicKey = ubyte[PublicKeyBytes];
  alias SecretKey = ubyte[SecretKeyBytes];
  alias Nonce = ubyte[NonceBytes];
  alias Beforenm = ubyte[BeforeNmBytes];
}

private alias CXSP = Curve25519XSalsa20Poly1305;

/**

  The crypto_box_keypair function randomly generates a secret key and a
  corresponding public key. It puts the secret key into sk[0], sk[1], ...,
  sk[crypto_box_SECRETKEYBYTES-1] and puts the public key into pk[0], pk[1], ...,
  pk[crypto_box_PUBLICKEYBYTES-1]. It then returns 0.

Params:
  safeRnd = a cryptographically safe random number generator like safeRandomBytes(ubyte[], size_t n)
  pk = the output for the public key
  sk = the output for the secret key
  */
int crypto_box_keypair(alias safeRnd)(
    ref CXSP.PublicKey pk,
    ref CXSP.SecretKey sk)
{
  safeRnd(sk,32);
  return Curve25519.scalarmultBase(pk,sk);
}


/**

  The crypto_box function encrypts and authenticates a message m[0], ...,
  m[mlen-1] using the sender's secret key sk[0], sk[1], ...,
  sk[crypto_box_SECRETKEYBYTES-1], the receiver's public key pk[0], pk[1],
  ..., pk[crypto_box_PUBLICKEYBYTES-1], and a nonce n[0], n[1], ...,
  n[crypto_box_NONCEBYTES-1]. The crypto_box function puts the ciphertext into
  c[0], c[1], ..., c[mlen-1]. It then returns 0.

  WARNING: Messages in the C NaCl API are 0-padded versions of messages in the
  C++ NaCl API. Specifically: The caller must ensure, before calling the C NaCl
  crypto_box function, that the first crypto_box_ZEROBYTES bytes of the message
  m are all 0. Typical higher-level applications will work with the remaining
  bytes of the message; note, however, that mlen counts all of the bytes,
  including the bytes required to be 0.
  */
pure nothrow @safe @nogc
bool crypto_box(
    ubyte[] cypherText,const ubyte[] m,
    ref const CXSP.Nonce nonce,
    ref const CXSP.PublicKey recvPk,
    ref const CXSP.SecretKey senderSk)
in {
  assert( m.length >= CXSP.ZeroBytes );
  assert( cypherText.length >= m.length );
  foreach(i;0..CXSP.ZeroBytes) assert( m[i] == 0 );
}
body {
  ubyte k[32];
  crypto_box_beforenm(k,recvPk,senderSk);
  return crypto_box_afternm(cypherText,m,nonce,k);
}

/**

  The crypto_box_open function verifies and decrypts a ciphertext c[0], ...,
  c[clen-1] using the receiver's secret key sk[0], sk[1], ...,
  sk[crypto_box_SECRETKEYBYTES-1], the sender's public key pk[0], pk[1], ...,
  pk[crypto_box_PUBLICKEYBYTES-1], and a nonce n[0], ...,
  n[crypto_box_NONCEBYTES-1]. The crypto_box_open function puts the plaintext
  into m[0], m[1], ..., m[clen-1]. It then returns 0.

  If the ciphertext fails verification, crypto_box_open instead returns -1,
  possibly after modifying m[0], m[1], etc.

  The caller must ensure, before calling the crypto_box_open function, that the
  first crypto_box_BOXZEROBYTES bytes of the ciphertext c are all 0. The
  crypto_box_open function ensures (in case of success) that the first
  crypto_box_ZEROBYTES bytes of the plaintext m are all 0.

  */
pure nothrow @safe @nogc
bool crypto_box_open(
    ubyte[] m,const ubyte[] cypherText,
    ref const CXSP.Nonce nonce,
    ref const CXSP.PublicKey senderPk,
    ref const CXSP.SecretKey recvSk)
in {
  assert( cypherText.length >= CXSP.BoxZeroBytes);
  assert( m.length >= cypherText.length );
  foreach(i;0..CXSP.BoxZeroBytes)
    assert( cypherText[i] == 0 );
}
body {
  ubyte k[32];
  crypto_box_beforenm(k,senderPk,recvSk);
  return crypto_box_open_afternm(m,cypherText,nonce,k);
}
/**

  $(BIG Precomputation interface)

  Applications that send several messages to the same receiver can gain speed
  by splitting crypto_box into two steps, crypto_box_beforenm and
  crypto_box_afternm. Similarly, applications that receive several messages
  from the same sender can gain speed by splitting crypto_box_open into two
  steps, crypto_box_beforenm and crypto_box_open_afternm.

  The intermediate data computed by crypto_box_beforenm is suitable for both
  crypto_box_afternm and crypto_box_open_afternm, and can be reused for any
  number of messages.
  */
pure nothrow @safe @nogc
int crypto_box_beforenm(
    ref CXSP.Beforenm k,
    ref const CXSP.PublicKey pk,
    ref const CXSP.SecretKey sk)
{
  import nacl.salsa20;
  ubyte s[32];
  Curve25519.scalarmult(s,sk,pk);
  return HSalsa20.core(k,_0,s,sigma);
}

/** ditto */
pure nothrow @safe @nogc
bool crypto_box_afternm(
    ubyte[] cypherText, const ubyte[] m,
    ref const CXSP.Nonce nonce,
    ref const CXSP.Beforenm k)
in {
  assert( m.length >= CXSP.ZeroBytes );
  assert( cypherText.length >= m.length );
  foreach(i;0..CXSP.ZeroBytes) assert( m[i] == 0 );
}
body {
  return XSalsa20Poly1305.secretbox(cypherText,m,nonce,k);
}

/** ditto */
pure nothrow @safe @nogc
bool crypto_box_open_afternm(
    ubyte[] m, const ubyte[] cypherText,
    ref const CXSP.Nonce nonce,
    ref const CXSP.Beforenm k)
in {
  foreach(i;0..CXSP.BoxZeroBytes)
    assert( cypherText[i] == 0 );
}
body {
  return XSalsa20Poly1305.secretboxOpen(m,cypherText,nonce,k);
}


unittest {

  ubyte alicesk[32]
    = [ 0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
      0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
      0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a ];

  ubyte alicepk[32]
    = [ 0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d,
    0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38,
    0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a ];
  ubyte bobsk[32]
    = [ 0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f,
    0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18,
    0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb ];

  ubyte bobpk[32]
    = [ 0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61,
      0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78,
      0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f ];
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
  ubyte c[163];
  ubyte[] cert = [
      0xf3,0xff,0xc7,0x70,0x3f,0x94,0x00,0xe5
      ,0x2a,0x7d,0xfb,0x4b,0x3d,0x33,0x05,0xd9
      ,0x8e,0x99,0x3b,0x9f,0x48,0x68,0x12,0x73
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
      ,0xe3,0x55,0xa5
    ];

  CXSP.Beforenm k;
  crypto_box(c, m, nonce, bobpk, alicesk);
  assert( c[16..163] == cert );
  c[] = 0;
  crypto_box_beforenm(k, bobpk, alicesk);
  crypto_box_afternm(c, m, nonce, k);
  assert( c[16..163] == cert );

  ubyte[163] decodedMsg;

  assert( crypto_box_open( decodedMsg, c, nonce, alicepk, bobsk ) );
  assert( decodedMsg[16..163] == m[16..163] );
}


unittest {

  ubyte bobsk[32]
    = [ 0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f,
    0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18,
    0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb ];
  ubyte alicepk[32]
    = [ 0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d,
    0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38,
    0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a ];
  ubyte nonce[24] = [ 0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
        0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
        0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37 ];
  // API requires first 16 bytes to be 0
  ubyte c[163]
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
  ubyte[] cert = [
    0xbe,0x07,0x5f,0xc5,0x3c,0x81,0xf2,0xd5
    ,0xcf,0x14,0x13,0x16,0xeb,0xeb,0x0c,0x7b
    ,0x52,0x28,0xc5,0x2a,0x4c,0x62,0xcb,0xd4
    ,0x4b,0x66,0x84,0x9b,0x64,0x24,0x4f,0xfc
    ,0xe5,0xec,0xba,0xaf,0x33,0xbd,0x75,0x1a
    ,0x1a,0xc7,0x28,0xd4,0x5e,0x6c,0x61,0x29
    ,0x6c,0xdc,0x3c,0x01,0x23,0x35,0x61,0xf4
    ,0x1d,0xb6,0x6c,0xce,0x31,0x4a,0xdb,0x31
    ,0x0e,0x3b,0xe8,0x25,0x0c,0x46,0xf0,0x6d
    ,0xce,0xea,0x3a,0x7f,0xa1,0x34,0x80,0x57
    ,0xe2,0xf6,0x55,0x6a,0xd6,0xb1,0x31,0x8a
    ,0x02,0x4a,0x83,0x8f,0x21,0xaf,0x1f,0xde
    ,0x04,0x89,0x77,0xeb,0x48,0xf5,0x9f,0xfd
    ,0x49,0x24,0xca,0x1c,0x60,0x90,0x2e,0x52
    ,0xf0,0xa0,0x89,0xbc,0x76,0x89,0x70,0x40
    ,0xe0,0x82,0xf9,0x37,0x76,0x38,0x48,0x64
    ,0x5e,0x07,0x05
    ];
  ubyte m[163];
  CXSP.Beforenm k;
  assert(crypto_box_open(m, c, nonce, alicepk, bobsk));
  assert( m[32..163] == cert);
  m[] = 0;
  crypto_box_beforenm(k, alicepk, bobsk);
  assert(crypto_box_open_afternm(m, c, nonce, k));
  assert( m[32..163] == cert);
}

unittest
{
  import std.random;

  CXSP.SecretKey alicesk;
  CXSP.PublicKey alicepk;
  CXSP.SecretKey bobsk;
  CXSP.PublicKey bobpk;
  CXSP.Nonce n;
  ubyte m[32000];
  ubyte c[32000];
  ubyte m2[32000];

  size_t mlen;
  // This test is reallly slow when incrementing 1-by-1
  for (mlen = 0; mlen < (2 << 16) && mlen + CXSP.ZeroBytes < m.length;
      mlen = (mlen << 1) + 1 )
  {
    immutable msgBlockLen = mlen + CXSP.ZeroBytes;

    crypto_box_keypair!safeRandomBytes(alicepk, alicesk);
    crypto_box_keypair!safeRandomBytes(bobpk, bobsk);
    foreach(ref e;n) n = uniform(ubyte.min, ubyte.max);
    foreach(ref e;m[CXSP.ZeroBytes..msgBlockLen]) e = uniform(ubyte.min, ubyte.max);
    crypto_box(c[0..msgBlockLen], m[0..msgBlockLen], n, bobpk, alicesk);
    assert( crypto_box_open(m2, c[0..msgBlockLen], n, alicepk, bobsk), "ciphertext fails verification");
    assert( m2[0..msgBlockLen] == m[0..msgBlockLen] );

    foreach(i;0..10) {
      c[uniform(0, msgBlockLen)] = uniform(ubyte.min,ubyte.max);
      c[0..CXSP.ZeroBytes] = 0;
      if (crypto_box_open(m2, c[0..msgBlockLen], n, alicepk, bobsk))
        assert( m2[0..msgBlockLen] == m[0..msgBlockLen], "forgery" );
    }
  }
}

