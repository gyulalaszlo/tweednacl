/**
  $(BIG Security model)

  The crypto_onetimeauth function, viewed as a function of the message for a
  uniform random key, is designed to meet the standard notion of unforgeability
  after a single message. After the sender authenticates one message, an
  attacker cannot find authenticators for any other messages.

  The sender must not use crypto_onetimeauth to authenticate more than one
  message under the same key. Authenticators for two messages under the same
  key should be expected to reveal enough information to allow forgeries of
  authenticators on other messages.

  $(BIG Selected primitive)

  crypto_onetimeauth is crypto_onetimeauth_poly1305, an authenticator specified
  in "Cryptography in NaCl", Section 9. This authenticator is proven to meet
  the standard notion of unforgeability after a single message.
*/
module tweednacl.poly1305;

import tweednacl.basics;


struct Poly1305 {
  enum Primitive = "poly1305";
  enum Version = "-";
  enum Implementation = "crypto_onetimeauth/poly1305/tweet";

  enum Bytes = 16;
  enum KeyBytes = 32;

  alias onetimeauth = crypto_onetimeauth;
  alias onetimeauthVerify = crypto_onetimeauth_verify;

  alias Value = ubyte[Bytes];
  alias Key = ubyte[KeyBytes];
}
/**

  The crypto_onetimeauth function authenticates a message m[0], m[1], ...,
  m[mlen-1] using a secret key k[0], k[1], ..., k[crypto_onetimeauth_KEYBYTES-1];
  puts the authenticator into a[0], a[1], ..., a[crypto_onetimeauth_BYTES-1]; and
  returns 0.
*/
pure nothrow @safe @nogc
int crypto_onetimeauth(
    ref Poly1305.Value output,
    const(ubyte)[] m,
    ref const Poly1305.Key k)
{
  uint s,u;
  uint[17] x,r,h,c,g;

  foreach(j;0..17) r[j]=h[j]=0;
  foreach(j;0..16) r[j]=k[j];
  r[3]&=15;
  r[4]&=252;
  r[7]&=15;
  r[8]&=252;
  r[11]&=15;
  r[12]&=252;
  r[15]&=15;

  size_t n = m.length;

  while (n > 0) {
    foreach(j;0..17) { c[j] = 0; }
    uint jj;
    for (jj = 0;(jj < 16) && (jj < n);++jj) c[jj] = m[jj];
    c[jj] = 1;
    m = m[jj..$]; n -= jj;
    add1305(h,c);
    foreach(i;0..17) {
      x[i] = 0;
      foreach(j;0..17) x[i] += h[j] * ((j <= i) ? r[i - j] : 320 * r[i + 17 - j]);
    }
    foreach(i;0..17) h[i] = x[i];
    u = 0;
    foreach(j;0..16) {
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }
    u += h[16]; h[16] = u & 3;
    u = 5 * (u >> 2);
    foreach(j;0..16) {
      u += h[j];
      h[j] = u & 255;
      u >>= 8;
    }
    u += h[16]; h[16] = u;
  }

  foreach(j;0..17) g[j] = h[j];
  add1305(h,minusp);
  s = -(h[16] >> 7);
  foreach(j;0..17) h[j] ^= s & (g[j] ^ h[j]);

  foreach(j;0..16) c[j] = k[j + 16];
  c[16] = 0;
  add1305(h,c);
  foreach(j;0..16) output[j] = cast(ubyte)(h[j]);
  return 0;
}

/**

  This function returns 0 if a[0], a[1], ..., a[crypto_onetimeauth_BYTES-1] is
  a correct authenticator of a message m[0], m[1], ..., m[mlen-1] under a
  secret key k[0], k[1], ..., k[crypto_onetimeauth_KEYBYTES-1]. Otherwise
  crypto_onetimeauth_verify returns -1.

*/
pure nothrow @safe @nogc
bool crypto_onetimeauth_verify(
    ref const Poly1305.Value h,
    const ubyte[] m,
    ref const Poly1305.Key k)
{
  ubyte x[16];
  crypto_onetimeauth(x,m,k);
  return (crypto_verify_16(h,x) == 0);
}

private:

pure nothrow @safe @nogc
void add1305(ref uint[17] h, ref const uint[17] c)
{
  uint u = 0;
  foreach(j;0..17) {
    u += h[j] + c[j];
    h[j] = u & 255;
    u >>= 8;
  }
}

const uint[17] minusp = [
  5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
];


unittest {
  ubyte rs[32]
    = [ 0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91, 0x6d, 0x11, 0xc2,
      0xcb, 0x21, 0x4d, 0x3c, 0x25, 0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23,
      0x4e, 0x65, 0x2d, 0x65, 0x1f, 0xa4, 0xc8, 0xcf, 0xf8, 0x80 ];
  ubyte c[131]
    = [ 0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73, 0xc2, 0x96, 0x50, 0xba,
      0x32, 0xfc, 0x76, 0xce, 0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4,
      0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a, 0xc0, 0xdf, 0xc1, 0x7c,
      0x98, 0xdc, 0xe8, 0x7b, 0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72,
      0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2, 0x27, 0x0d, 0x6f, 0xb8,
      0x63, 0xd5, 0x17, 0x38, 0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a,
      0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae, 0x90, 0x22, 0x43, 0x68,
      0x51, 0x7a, 0xcf, 0xea, 0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
      0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde, 0x56, 0x24, 0x4a, 0x9e,
      0x88, 0xd5, 0xf9, 0xb3, 0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
      0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74, 0xe3, 0x55, 0xa5 ];
  ubyte[16] sig = [ 0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5,
        0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9 ];
  ubyte a[16];

  crypto_onetimeauth(a, c, rs);
  assert( a == sig);
  assert( crypto_onetimeauth_verify(a, c, rs));
  assert( crypto_onetimeauth_verify( sig, c, rs));
}


unittest {
  import std.random;
  ubyte key[32];
  ubyte c[10000];
  ubyte a[16];
  int clen;
  for (clen = 0; clen < 10000; clen = (clen << 1) + 1) {
    auto currentC = c[0..clen];
    foreach(ref k;key) k = uniform(ubyte.min, ubyte.max);
    foreach(ref v;currentC) v = uniform(ubyte.min, ubyte.max);
    crypto_onetimeauth(a, currentC, key);
    assert (crypto_onetimeauth_verify(a, currentC, key));
    if (clen > 0) {
      currentC[uniform(0u, clen)] += 1 + (uniform(0u, 255u));
      assert( !crypto_onetimeauth_verify(a, currentC, key), "forgery");
      a[uniform(0u, a.length)] += 1 + (uniform(0u,255u));
      assert( !crypto_onetimeauth_verify(a, currentC, key), "forgery");
    }
  }
}

