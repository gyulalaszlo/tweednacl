module nacl.sign;

import nacl.constants;
import nacl.basics;
import nacl.math25519;
import nacl.hash;

/**
  The crypto_sign_keypair function randomly generates a secret key and a
  corresponding public key. It puts the secret key into sk[0], sk[1], ...,
  sk[crypto_sign_SECRETKEYBYTES-1] and puts the public key into pk[0], pk[1],
  ..., pk[crypto_sign_PUBLICKEYBYTES-1]. It then returns true.
    import nacl.basics : safeRandomBytes;

Params:
  safeRnd = a cryptographically safe random number generator like safeRandomBytes(ubyte[], size_t n)
  pk = the output for the public key
  sk = the output for the secret key
 */
bool crypto_sign_keypair(alias safeRnd)(ref ubyte[crypto_sign_PUBLICKEYBYTES] pk,
   ref ubyte[crypto_sign_SECRETKEYBYTES] sk)
{
  ubyte d[64];
  gf p[4];

  safeRnd(sk, 32);
  crypto_hash(d, sk[0..32]);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  scalarbase(p,d[0..32]);
  pack(pk,p);

  foreach(i;0..32) sk[32 + i] = pk[i];
  return true;
}


/*
  The crypto_sign function signs a message m[0], ..., m[mlen-1] using the
  signer's secret key sk[0], sk[1], ..., sk[crypto_sign_SECRETKEYBYTES-1], puts
  the length of the signed message into smlen and puts the signed message into
  sm[0], sm[1], ..., sm[smlen-1]. It then returns 0.

  The maximum possible length smlen is mlen+crypto_sign_BYTES. The caller must
  allocate at least mlen+crypto_sign_BYTES bytes for sm.
*/
pure nothrow @safe @nogc
bool crypto_sign(ubyte[] sm, out ulong smlen, const ubyte[] m,
    ref const ubyte[crypto_sign_SECRETKEYBYTES] sk)
in {
  assert( sm.length >= m.length + crypto_sign_BYTES,
      "crypto_sign() The caller must allocate at least mlen+crypto_sign_BYTES bytes for sm." );
}
body {
  size_t n = m.length;
  ubyte[64] d,h,r;
  //long i,j;
  long[64] x;
  gf p[4];

  crypto_hash(d, sk[0..32]);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  smlen = n+64;
  foreach(i;0..n) sm[64 + i] = m[i];
  foreach(i;0..32) sm[32 + i] = d[32 + i];

  crypto_hash(r, sm[32..32+n+32]); //, n+32);
  reduce(r);
  scalarbase(p,r[0..32]);
  pack(sm[0..32],p);

  foreach(i;0..32) sm[i+32] = sk[i+32];
  crypto_hash(h,sm[0..n+64]);
  reduce(h);

  foreach(i;0..64) x[i] = 0;
  foreach(i;0..32) x[i] = ulong(r[i]);
  foreach(i;0..32) foreach(j;0..32) x[i+j] += h[i] * ulong(d[j]);
  modL(sm[32..64],x);

  return true;
}

/*
  The crypto_sign_open function verifies the signature in sm[0], ..., sm[smlen-1]
  using the signer's public key pk[0], pk[1], ...,
  pk[crypto_sign_PUBLICKEYBYTES-1]. The crypto_sign_open function puts the length
  of the message into mlen and puts the message into m[0], m[1], ..., m[mlen-1].
  It then returns true.

  The maximum possible length mlen is smlen. The caller must allocate at least
  smlen bytes for m.

  If the signature fails verification, crypto_sign_open instead returns false,
  possibly after modifying m[0], m[1], etc.

   */
pure nothrow @safe @nogc
bool crypto_sign_open(ubyte[] m, ref ulong mlen, const ubyte[] sm,
    ref const ubyte[crypto_sign_PUBLICKEYBYTES] pk)
in {
  // The following unittest makes one of the test fail
  //assert( sm.length >= crypto_sign_BYTES );
  assert( m.length >= sm.length,
      "crypto_sign_open() The caller must allocate at least sm.length bytes for m." );
}
body {
  size_t n = sm.length;
  ubyte[32] t;
  ubyte[64] h;
  gf[4] p,q;

  mlen = -1;
  if (n < 64) return false;

  if (!unpackneg(q,pk[0..32])) return false;

  foreach(i;0..n) m[i] = sm[i];
  foreach(i;0..32) m[i+32] = pk[i];
  crypto_hash(h,m[0..n]);
  reduce(h);
  scalarmult(p,q,h[0..32]);

  scalarbase(q,sm[32..64]);
  add(p,q);
  pack(t,p);

  n -= 64;
  if (crypto_verify_32(sm[0..32], t)) {
    foreach(i;0..n) m[i] = 0;
    return false;
  }

  foreach(i;0..n) m[i] = sm[i + 64];
  mlen = n;
  return true;
}

private:

pure nothrow @safe @nogc void add(ref gf[4] p, ref gf[4] q)
{
  gf a,b,c,d,t,e,f,g,h;

  Z(a, p[1], p[0]);
  Z(t, q[1], q[0]);
  M(a, a, t);
  A(b, p[0], p[1]);
  A(t, q[0], q[1]);
  M(b, b, t);
  M(c, p[3], q[3]);
  M(c, c, D2);
  M(d, p[2], q[2]);
  A(d, d, d);
  Z(e, b, a);
  Z(f, d, c);
  A(g, d, c);
  A(h, b, a);

  M(p[0], e, f);
  M(p[1], h, g);
  M(p[2], g, f);
  M(p[3], e, h);
}

pure nothrow @safe @nogc void cswap(ref gf[4] p, ref gf[4] q, ubyte b)
{
  foreach(i;0..4)
    sel25519(p[i],q[i],b);
}

pure nothrow @safe @nogc void pack(ref ubyte[32] r, ref gf[4] p)
{
  gf tx, ty, zi;
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

pure nothrow @safe @nogc void scalarmult(ref gf[4] p, ref gf[4] q, ref const ubyte[32] s)
{
  int i;
  set25519(p[0],gf0);
  set25519(p[1],gf1);
  set25519(p[2],gf1);
  set25519(p[3],gf0);
  for (i = 255;i >= 0;--i) {
    ubyte b = (s[i/8]>>(i&7))&1;
    cswap(p,q,b);
    add(q,p);
    add(p,p);
    cswap(p,q,b);
  }
}

pure nothrow @safe @nogc void scalarbase(ref gf[4] p, ref const ubyte[32] s)
{
  gf q[4];
  set25519(q[0],X);
  set25519(q[1],Y);
  set25519(q[2],gf1);
  M(q[3],X,Y);
  scalarmult(p,q,s);
}

const ulong L[32] = [
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde,
    0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
  ];

pure nothrow @safe @nogc void modL(ref ubyte[32] r, ref long[64] x)
{
  long carry;
  for (long i = 63;i >= 32;--i) {
    carry = 0;
    long j;
    for (j = i - 32;j < i - 12;++j) {
      x[j] += carry - 16 * x[i] * L[j - (i - 32)];
      carry = (x[j] + 128) >> 8;
      x[j] -= carry << 8;
    }
    x[j] += carry;
    x[i] = 0;
  }
  carry = 0;
  foreach(j;0..32) {
    x[j] += carry - (x[31] >> 4) * L[j];
    carry = x[j] >> 8;
    x[j] &= 255;
  }
  foreach(j;0..32) x[j] -= carry * L[j];
  foreach(i;0..32) {
    x[i+1] += x[i] >> 8;
    r[i] = x[i] & 255;
  }
}

pure nothrow @safe @nogc void reduce(ref ubyte[64] r)
{
  long[64] x;
  foreach(i;0..64) x[i] = ulong(r[i]);
  foreach(i;0..64) r[i] = 0;
  modL(r[0..32],x);
}


pure nothrow @safe @nogc bool unpackneg(ref gf[4] r,ref const ubyte[32] p)
{
  gf t, chk, num, den, den2, den4, den6;
  set25519(r[2],gf1);
  unpack25519(r[1],p);
  S(num,r[1]);
  M(den,num,D);
  Z(num,num,r[2]);
  A(den,r[2],den);

  S(den2,den);
  S(den4,den2);
  M(den6,den4,den2);
  M(t,den6,num);
  M(t,t,den);

  pow2523(t,t);
  M(t,t,num);
  M(t,t,den);
  M(t,t,den);
  M(r[0],t,den);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) M(r[0],r[0],I);

  S(chk,r[0]);
  M(chk,chk,den);
  if (neq25519(chk, num)) return false;

  if (par25519(r[0]) == (p[31]>>7)) Z(r[0],gf0,r[0]);

  M(r[3],r[0],r[1]);
  return true;
}


unittest {

  import nacl.test_data_crypto_sign_open;

  const ubyte keypair_seed[]
    = [ 0x42, 0x11, 0x51, 0xa4, 0x59, 0xfa, 0xea, 0xde, 0x3d, 0x24, 0x71,
      0x15, 0xf9, 0x4a, 0xed, 0xae, 0x42, 0x31, 0x81, 0x24, 0x09, 0x5a,
      0xfa, 0xbe, 0x4d, 0x14, 0x51, 0xa5, 0x59, 0xfa, 0xed, 0xee ];


  void add_l(ref ubyte[32] S)
  {
    static const ubyte l[32] =
    [ 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
      0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 ];
    ubyte c = 0U;
    uint  i;
    uint  s;

    for (i = 0U; i < 32U; i++) {
      s = S[i] + l[i] + c;
      S[i] = cast(ubyte)(s);
      c = (s >> 8) & 1;
    }
  }

  ubyte extracted_seed[crypto_sign_SEEDBYTES];
  ubyte extracted_pk[crypto_sign_PUBLICKEYBYTES];
  ubyte sig[crypto_sign_BYTES];
  ubyte sm[1024 + crypto_sign_BYTES];
  ubyte m[1024];
  ubyte skpk[crypto_sign_SECRETKEYBYTES];
  ubyte pk[crypto_sign_PUBLICKEYBYTES];
  ubyte sk[crypto_sign_SECRETKEYBYTES];
  char          pk_hex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
  char          sk_hex[crypto_sign_SECRETKEYBYTES * 2 + 1];

  ulong siglen;
  ulong smlen;
  ulong mlen;
  uint i;
  uint j;

  sig[] = 0;
  import std.string;
  import std.digest.sha : toHexString;
  for (i = 0U; i < test_data.length; i++) {
    skpk[0..crypto_sign_SEEDBYTES] = test_data[i].sk[];
    skpk[crypto_sign_SEEDBYTES..crypto_sign_SEEDBYTES + crypto_sign_PUBLICKEYBYTES] =
      test_data[i].pk[0..crypto_sign_PUBLICKEYBYTES];

    auto signedMsgLen = crypto_sign_BYTES+i;
    auto inputMsg = toBytes(test_data[i].m);

    assert( crypto_sign(sm[0..signedMsgLen], smlen, inputMsg, skpk),
        format("crypto_sign() failure: [%s]", i) );

    assert(smlen == signedMsgLen, "signed message has incorrect lenght");
    auto signedMsg = sm[0..smlen];

    assert( test_data[i].sig[0..crypto_sign_BYTES] == sm[0..crypto_sign_BYTES],
        format("signature failure: [%s]", i ));

    assert( crypto_sign_open(m, mlen, signedMsg, test_data[i].pk),
        format("crypto_sign_open() failure: [%s]", i ));
    add_l(sm[32..64]);
    assert( crypto_sign_open(m, mlen, signedMsg, test_data[i].pk),
        format("crypto_sign_open(): signature [%s] is not malleable", i) );
    assert( toBytes(test_data[i].m) == m[0..mlen],
        format("message verification failure: [%s]", i) );

    sm[i + crypto_sign_BYTES - 1U]++;
    assert(!crypto_sign_open(m, mlen, signedMsg, test_data[i].pk),
        format("message can be forged: [%s]", i));
    assert( !crypto_sign_open(m, mlen, signedMsg[0..i % crypto_sign_BYTES], test_data[i].pk),
        format("short signed message verifies: [%s - %s]", i, i % crypto_sign_BYTES) );
  }
}


unittest
{
  import std.random;

  ubyte[crypto_sign_PUBLICKEYBYTES] pk;
  ubyte[crypto_sign_SECRETKEYBYTES] sk;


  ubyte[testMessageLengthsUpTo] msgBuf;
  ubyte[testMessageLengthsUpTo + crypto_sign_BYTES] decodedMsgBuf;
  ubyte[testMessageLengthsUpTo + crypto_sign_BYTES] signedMsgBuf;
  ulong msgLen, signedMsgLen;
  // generate a random message and test if it can be signed/opened
  // with a keypair.
  foreach(mlen;0..testMessageLengthsUpTo) {
    import nacl.basics : safeRandomBytes;
    auto msg = msgBuf[0..mlen];
    auto signedMsg = signedMsgBuf[0..mlen+crypto_sign_BYTES];
    assert(crypto_sign_keypair!safeRandomBytes(pk, sk) );
    randomBuffer(msg[0..mlen]);

    assert( crypto_sign( signedMsg, signedMsgLen, msg,  sk ));
    assert( signedMsg.length == signedMsgLen );
    assert( crypto_sign_open( decodedMsgBuf[0..signedMsgLen], msgLen, signedMsg,  pk ),
        "crypto_sign_keypair() key does not sign for public key");
    assert( msgLen == mlen );
    assert( decodedMsgBuf[0..msgLen] == msg[0..mlen] );

    if (mlen == 0) continue;
    foreach(j;0..10)
    {
      signedMsg[uniform(crypto_sign_BYTES, signedMsgLen)] = uniform(ubyte.min, ubyte.max);
      if (crypto_sign_open( decodedMsgBuf[0..signedMsgLen], msgLen, signedMsg,  pk ))
      {
        assert( msgLen == mlen );
        assert( decodedMsgBuf[0..msgLen] == msg[0..mlen], "crypto_sign_keypair() forgery" );
      }
    }
  }
}

