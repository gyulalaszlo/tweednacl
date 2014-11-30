module nacl;

public import nacl.constants;


/**
  A cryptograhically secure random source.

  Default versions are implemented in separate modules.
  */
extern (D) void safeRandomBytes( ubyte[] output, size_t count);

version(unittest) {
  /**
  For unittests that try to forge sign/crypt/forge random messages
  up to a given length  testMessageLengthsUpTo  is the maximum message
  length in bytes.

  For example specifying 64 here should try to forge message lengths
  up to 0..64 bytes. Upping this number makes the tests take much
  more time. The soundness of the encryption should make strong enough
  guarantees that the message lengths checked here should be checking
  for possible failts in the implementation.
  */
  private enum testMessageLengthsUpTo = 16;

  /**
    Helper to generate a pseudo-random buffer.
    The generated random numbers are from std.random, so they are not
    safe for generating keys. Use
    */
  void randomBuffer(T)( T[] m )
  {
    import std.random;
    foreach(ref e;m) e = uniform(T.min, T.max);
  }

}

/**
  Converts any array slice into a byte array slice.
  */
const(ubyte)[] toBytes(T)(T[] input)
{
  if (input.length == 0) return nullBytes;
  return (cast(const(ubyte)*)(&input[0]))[0..(input.length*T.sizeof)];
}

alias gf = long[16];


private immutable ubyte[16] _0 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
private immutable ubyte[32] _9 = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

private const gf gf0;
private const gf gf1 = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
private const gf _121665 = [0xDB41,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
private const gf D = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d,
        0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee,
        0x5203];

private const gf D2 = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a,
        0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc,
        0x2406];

private const gf X = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760,
        0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3,
        0x2169];

private const gf Y = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
        0x6666];

private const gf I = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806,
        0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480,
        0x2b83];

private uint L32(uint x,int c) { return (x << c) | ((x&0xffffffff) >> (32 - c)); }

private uint ld32(ref const ubyte[4] x)
{
  uint u = x[3];
  u = (u<<8)|x[2];
  u = (u<<8)|x[1];
  return (u<<8)|x[0];
}

private ulong dl64(ref const ubyte[8] x)
{
  ulong u=0;
  foreach(ulong i;0..8) u=(u<<8)|x[i];
  return u;
}

private void st32(ref ubyte[4] x,uint u)
{
  foreach(i;0..4) { x[i] = cast(ubyte)(u); u >>= 8; }
}

private void ts64(ref ubyte[8] x,ulong u)
{
  int i;
  for (i = 7;i >= 0;--i) { x[i] = cast(ubyte)(u); u >>= 8; }
}

private int vn(const ubyte[] x,const ubyte[] y,int n)
{
  uint d = 0;
  foreach(i;0..n) d |= x[i]^y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}

/**
  The crypto_verify_16 function returns 0 if x[0], x[1], ..., x[15] are the
  same as y[0], y[1], ..., y[15]. Otherwise it returns -1.

  This function is safe to use for secrets x[0], x[1], ..., x[15], y[0], y[1],
  ..., y[15]. The time taken by crypto_verify_16 is independent of the contents
  of x[0], x[1], ..., x[15], y[0], y[1], ..., y[15]. In contrast, the standard C
  comparison function memcmp(x,y,16) takes time that depends on the longest
  matching prefix of x and y, often allowing easy timing attacks.

 */
int crypto_verify_16(ref const ubyte[16] x, ref const ubyte[16] y)
{
  return vn(x,y,16);
}

/**
  Similar verification function as crypto_verify_16 , but operating on 32
  byte blocks.
 */
int crypto_verify_32(ref const ubyte[32] x, ref const ubyte[32] y)
{
  return vn(x,y,32);
}

// Should the core use Salsa or HSalsa
private enum UseHSalsa {No, Yes};

private void core(UseHSalsa useHSalsa)(
    ubyte[] output,const ubyte[] input,const ubyte[] k,const ubyte[] c)
{
  uint[16] w,x,y;
  uint[4] t;

  foreach(i;0..4) {
    x[5*i] = ld32(c[4*i..$][0..4]);
    x[1+i] = ld32(k[4*i..$][0..4]);
    x[6+i] = ld32(input[4*i..$][0..4]);
    x[11+i] = ld32(k[16+4*i..$][0..4]);
  }

  foreach(i;0..16) y[i] = x[i];

  foreach(i;0..20) {
    foreach(j;0..4) {
      foreach(m;0..4) t[m] = x[(5*j+4*m)%16];
      t[1] ^= L32(t[0]+t[3], 7);
      t[2] ^= L32(t[1]+t[0], 9);
      t[3] ^= L32(t[2]+t[1],13);
      t[0] ^= L32(t[3]+t[2],18);
      foreach(m;0..4) w[4*j+(j+m)%4] = t[m];
    }
    foreach(m;0..16) x[m] = w[m];
  }

  static if (useHSalsa == UseHSalsa.Yes) {
    foreach(i;0..16) x[i] += y[i];
    foreach(i;0..4) {
      x[5*i] -= ld32(c[4*i..$][0..4]);
      x[6+i] -= ld32(input[4*i..$][0..4]);
    }
    foreach(i;0..4) {
      st32(output[4 * i..$][0..4],x[5*i]);
      st32(output[16+ 4 * i..$][0..4],x[6+i]);
    }
  } else {
    foreach(i;0..16) st32(output[4*i..$][0..4],x[i] + y[i]);
  }
}

int crypto_core_salsa20(
    ref ubyte[crypto_core_salsa20_OUTPUTBYTES] output,
    ref const ubyte[crypto_core_salsa20_INPUTBYTES] input,
    ref const ubyte[crypto_core_salsa20_KEYBYTES] k,
    ref const ubyte[crypto_core_salsa20_CONSTBYTES] c)
{
  core!(UseHSalsa.No)(output,input,k,c);
  return 0;
}

int crypto_core_hsalsa20(
    ref ubyte[crypto_core_hsalsa20_OUTPUTBYTES] output,
    ref const ubyte[crypto_core_hsalsa20_INPUTBYTES] input,
    ref const ubyte[crypto_core_hsalsa20_KEYBYTES] k,
    ref const ubyte[crypto_core_hsalsa20_CONSTBYTES] c)
{
  core!(UseHSalsa.Yes)(output,input,k,c);
  return 0;
}

unittest {
  ubyte[32] shared_
    = [ 0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b,
      0xf4, 0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1,
      0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42 ];
  ubyte[16] zero;
  ubyte[16] c = [ 0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
    0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b ];
  ubyte firstkey[32];

  crypto_core_hsalsa20(firstkey, zero, shared_, c);

  assert( firstkey == [ 0x1b,0x27,0x55,0x64,0x73,0xe9,0x85,0xd4
      ,0x62,0xcd,0x51,0x19,0x7a,0x9a,0x46,0xc7
      ,0x60,0x09,0x54,0x9e,0xac,0x64,0x74,0xf2
      ,0x06,0xc4,0xee,0x08,0x44,0xf6,0x83,0x89]);
}


unittest {
  ubyte[32] firstkey
    = [ 0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51,
    0x19, 0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64,
    0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89 ];
  ubyte[32] nonceprefix
    = [ 0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
    0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
    ];
  ubyte[16] c = [ 0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
    0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b,
    ];
  ubyte[32] secondkey;
  crypto_core_hsalsa20(secondkey, nonceprefix[0..16], firstkey, c);

  assert( secondkey == [ 0xdc,0x90,0x8d,0xda,0x0b,0x93,0x44,0xa9
      ,0x53,0x62,0x9b,0x73,0x38,0x20,0x77,0x88
      ,0x80,0xf3,0xce,0xb4,0x21,0xbb,0x61,0xb9
      ,0x1c,0xbd,0x4c,0x3e,0x66,0x25,0x6c,0xe4]);
}

unittest {
  ubyte secondkey[32]
    = [ 0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9, 0x53, 0x62, 0x9b,
    0x73, 0x38, 0x20, 0x77, 0x88, 0x80, 0xf3, 0xce, 0xb4, 0x21, 0xbb,
    0x61, 0xb9, 0x1c, 0xbd, 0x4c, 0x3e, 0x66, 0x25, 0x6c, 0xe4 ];
  ubyte noncesuffix[8]
    = [ 0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37 ];
  ubyte c[16] = [ 0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
        0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b ];
  ubyte[16] input;
  ubyte[64 * 256 * 256] output;
  ubyte[64] h;

  int i;
  long pos = 0;
  for (i = 0; i < 8; ++i)
    input[i] = noncesuffix[i];
  do {
    do {
      crypto_core_salsa20(output[pos..$][0..64], input, secondkey, c);
      pos += 64;
    } while (++input[8]);
  } while (++input[9]);

  import std.digest.sha;

  assert( toHexString(sha256Of(output[])) ==
      "662B9D0E3463029156069B12F918691A98F7DFB2CA0393C96BBFC6B1FBD630A2"
      );

  crypto_hash(h, output);

  assert( toHexString(sha512Of(output[])) ==
      "2BD8E7DB6877539E4F2B295EE415CD378AE214AA3BEB3E08E911A5BD4A25E6AC16CA283C79C34C08C99F7BDB560111E8CAC1AE65EEA08AC384D7A591461AB6E3"
      );


  assert( h == sha512Of(output[]) );
  assert( h ==
      [0x2b, 0xd8, 0xe7, 0xdb, 0x68, 0x77, 0x53, 0x9e, 0x4f, 0x2b, 0x29,
      0x5e, 0xe4, 0x15, 0xcd, 0x37, 0x8a, 0xe2, 0x14, 0xaa, 0x3b, 0xeb, 0x3e,
      0x08, 0xe9, 0x11, 0xa5, 0xbd, 0x4a, 0x25, 0xe6, 0xac, 0x16, 0xca, 0x28,
      0x3c, 0x79, 0xc3, 0x4c, 0x08, 0xc9, 0x9f, 0x7b, 0xdb, 0x56, 0x01, 0x11,
      0xe8, 0xca, 0xc1, 0xae, 0x65, 0xee, 0xa0, 0x8a, 0xc3, 0x84, 0xd7, 0xa5,
      0x91, 0x46, 0x1a, 0xb6, 0xe3 ]
      );
}


unittest {
  //#define TEST_NAME "core4"
  ubyte k[32] = [ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
    12, 13, 14, 15, 16, 201, 202, 203, 204, 205, 206,
    207, 208, 209, 210, 211, 212, 213, 214, 215, 216 ];
  ubyte input[16] = [ 101, 102, 103, 104, 105, 106, 107, 108,
    109, 110, 111, 112, 113, 114, 115, 116 ];
  ubyte c[16] = [ 101, 120, 112, 97, 110, 100, 32, 51,
    50, 45, 98, 121, 116, 101, 32, 107 ];
  ubyte output[64];

  crypto_core_salsa20(output, input, k, c);

  assert( output == [
      69, 37, 68, 39, 41, 15,107,193
      ,255,139,122, 6,170,233,217, 98
      , 89,144,182,106, 21, 51,200, 65
      ,239, 49,222, 34,215,114, 40,126
      ,104,197, 7,225,197,153, 31, 2
      ,102, 78, 76,176, 84,245,246,184
      ,177,160,133,130, 6, 72,149,119
      ,192,195,132,236,234,103,246, 74
      ]);
}

unittest {

  //#define TEST_NAME "core5"
  ubyte k[32]
    = [ 0xee, 0x30, 0x4f, 0xca, 0x27, 0x00, 0x8d, 0x8c, 0x12, 0x6f, 0x90,
    0x02, 0x79, 0x01, 0xd8, 0x0f, 0x7f, 0x1d, 0x8b, 0x8d, 0xc9, 0x36,
    0xcf, 0x3b, 0x9f, 0x81, 0x96, 0x92, 0x82, 0x7e, 0x57, 0x77 ];
  ubyte input[16] = [ 0x81, 0x91, 0x8e, 0xf2, 0xa5, 0xe0, 0xda, 0x9b,
        0x3e, 0x90, 0x60, 0x52, 0x1e, 0x4b, 0xb3, 0x52 ];
  ubyte c[16] = [ 101, 120, 112, 97, 110, 100, 32, 51,
        50, 45, 98, 121, 116, 101, 32, 107 ];
  ubyte output[32];

  crypto_core_hsalsa20(output, input, k, c);

  assert( output == [
      0xbc,0x1b,0x30,0xfc,0x07,0x2c,0xc1,0x40
      ,0x75,0xe4,0xba,0xa7,0x31,0xb5,0xa8,0x45
      ,0xea,0x9b,0x11,0xe9,0xa5,0x19,0x1f,0x94
      ,0xe1,0x8c,0xba,0x8f,0xd8,0x21,0xa7,0xcd
      ]);
}


unittest {
  //#define TEST_NAME "core6"

  ubyte k[32]
    = [ 0xee, 0x30, 0x4f, 0xca, 0x27, 0x00, 0x8d, 0x8c, 0x12, 0x6f, 0x90,
      0x02, 0x79, 0x01, 0xd8, 0x0f, 0x7f, 0x1d, 0x8b, 0x8d, 0xc9, 0x36,
      0xcf, 0x3b, 0x9f, 0x81, 0x96, 0x92, 0x82, 0x7e, 0x57, 0x77 ];
  ubyte input[16] = [ 0x81, 0x91, 0x8e, 0xf2, 0xa5, 0xe0, 0xda, 0x9b,
    0x3e, 0x90, 0x60, 0x52, 0x1e, 0x4b, 0xb3, 0x52 ];
  ubyte c[16] = [ 101, 120, 112, 97, 110, 100, 32, 51,
    50, 45, 98, 121, 116, 101, 32, 107 ];
  ubyte output[64];

  void cat(Out)(ubyte[] x, ubyte[] y, Out o )
  {
    int i;
    uint borrow = 0;
    for (i = 0; i < 4; ++i) {
      uint xi = x[i];
      uint yi = y[i];
      o.put( ubyte( 255 & (xi - yi - borrow)));
      borrow = (xi < yi + borrow);
    }
  }
  import std.array;

  auto o = appender!(ubyte[])();
  crypto_core_salsa20(output, input, k, c);
  cat(output[0..4], c[0..4],o);
  cat(output[20..24], c[4..8],o);
  cat(output[40..44], c[8..12],o);
  cat(output[60..64], c[12..16],o);
  cat(output[24..28], input[0..4],o);
  cat(output[28..32], input[4..8],o);
  cat(output[32..36], input[8..12],o);
  cat(output[36..40], input[12..16],o);


  assert( o.data == [
      0xbc,0x1b,0x30,0xfc,0x07,0x2c,0xc1,0x40
      ,0x75,0xe4,0xba,0xa7,0x31,0xb5,0xa8,0x45
      ,0xea,0x9b,0x11,0xe9,0xa5,0x19,0x1f,0x94
      ,0xe1,0x8c,0xba,0x8f,0xd8,0x21,0xa7,0xcd
      ]);
}


private const ubyte[16] sigma = [ 'e','x','p','a','n','d',' ','3','2','-','b','y','t','e', ' ','k'];


// Implementations for crypto_stream_salsa20
// -----------------------------------------
// the nonce bytes
private enum salsaRoundNonceBytes = 8;

private int crypto_stream_salsa20_xor_impl(bool useMessage=true)(
    ubyte[] c,
    const(ubyte)[] m,
    ulong b,
    ref const(ubyte)[salsaRoundNonceBytes] n,
    ref const(ubyte)[crypto_stream_KEYBYTES] k
    )
{
  ubyte[16] z;
  ubyte[64] x;
  uint u;
  if (!b) return 0;
  foreach(i;0..16) z[i] = 0;
  foreach(i;0..8) z[i] = n[i];
  while (b >= 64) {
    crypto_core_salsa20(x,z,k,sigma);
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
    crypto_core_salsa20(x,z,k,sigma);
    static if (useMessage)
      foreach(i;0..b) {
        c[i] = m[i] ^ x[i];
      }
    else
      foreach(i;0..b) c[i] = 0 ^ x[i];
  }
  return 0;
}

private const(const(ubyte)[]) nullBytes = [];

private int crypto_stream_salsa20(ubyte[] c,ulong d,
    ref const(ubyte)[salsaRoundNonceBytes] n,
    ref const(ubyte)[crypto_stream_KEYBYTES] k)
{
  return crypto_stream_salsa20_xor_impl!false(c,nullBytes,d,n,k);
}

private int crypto_stream_salsa20_xor(ubyte[] c, const(ubyte)[] m,ulong b,
    ref const(ubyte)[salsaRoundNonceBytes] n,
    ref const(ubyte)[crypto_stream_KEYBYTES] k)
{
  return crypto_stream_salsa20_xor_impl!true(c,m,b,n,k);
}

/**
  Secret-key encryption: crypto_stream
  ====================================

  Security model
  --------------

  The crypto_stream function, viewed as a function of the nonce for a uniform
  random key, is designed to meet the standard notion of unpredictability
  ("PRF"). For a formal definition see, e.g., Section 2.3 of Bellare, Kilian, and
  Rogaway, "The security of the cipher block chaining message authentication
  code," Journal of Computer and System Sciences 61 (2000), 362–399;
  http://www-cse.ucsd.edu/~mihir/papers/cbc.html.

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

  Selected primitive
  ------------------

  crypto_stream is crypto_stream_xsalsa20, a particular cipher specified in
  "Cryptography in NaCl", Section 7. This cipher is conjectured to meet the
  standard notion of unpredictability. 

*/

/**


     const unsigned char k[crypto_stream_KEYBYTES];
     const unsigned char n[crypto_stream_NONCEBYTES];
     unsigned char c[...]; unsigned long long clen;

     crypto_stream(c,clen,n,k);

  The crypto_stream function produces a stream c[0], c[1], ..., c[clen-1] as a
  function of a secret key k[0], k[1], ..., k[crypto_stream_KEYBYTES-1] and a
  nonce n[0], n[1], ..., n[crypto_stream_NONCEBYTES-1]. The crypto_stream
  function then returns 0.

*/
int crypto_stream(ubyte[] c,ulong d,
    ref const ubyte[crypto_stream_NONCEBYTES] nonce,
    ref const ubyte[crypto_stream_KEYBYTES] k)
{
  ubyte s[32];
  crypto_core_hsalsa20(s,nonce[0..crypto_core_hsalsa20_INPUTBYTES],k,sigma);
  return crypto_stream_salsa20(c,d,nonce[crypto_core_hsalsa20_INPUTBYTES..$],s);
}

/**


     const unsigned char k[crypto_stream_KEYBYTES];
     const unsigned char n[crypto_stream_NONCEBYTES];
     unsigned char m[...]; unsigned long long mlen;
     unsigned char c[...];

     crypto_stream_xor(c,m,mlen,n,k);

  The crypto_stream_xor function encrypts a message m[0], m[1], ..., m[mlen-1]
  using a secret key k[0], k[1], ..., k[crypto_stream_KEYBYTES-1] and a nonce
  n[0], n[1], ..., n[crypto_stream_NONCEBYTES-1]. The crypto_stream_xor function
  puts the ciphertext into c[0], c[1], ..., c[mlen-1]. It then returns 0.

  The crypto_stream_xor function guarantees that the ciphertext is the plaintext
  xor the output of crypto_stream. Consequently crypto_stream_xor can also be
  used to decrypt.

*/
int crypto_stream_xor(ubyte[] c,const(ubyte)[] m,ulong d,
    ref const ubyte[crypto_stream_NONCEBYTES] nonce,
    ref const ubyte[crypto_stream_KEYBYTES] k)
{
  ubyte s[32];
  crypto_core_hsalsa20(s,nonce[0..crypto_core_hsalsa20_INPUTBYTES],k,sigma);
  return crypto_stream_salsa20_xor(c,m,d,nonce[crypto_core_hsalsa20_INPUTBYTES..$],s);
}

/*
   Sodium Stream tests
 */

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

private void add1305(ref uint[17] h, ref const uint[17] c)
{
  uint u = 0;
  foreach(j;0..17) {
    u += h[j] + c[j];
    h[j] = u & 255;
    u >>= 8;
  }
}

private const uint[17] minusp = [
  5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252
];



/**
  C interface
  -----------

  Security model
  --------------

  The crypto_onetimeauth function, viewed as a function of the message for a
  uniform random key, is designed to meet the standard notion of unforgeability
  after a single message. After the sender authenticates one message, an
  attacker cannot find authenticators for any other messages.

  The sender must not use crypto_onetimeauth to authenticate more than one
  message under the same key. Authenticators for two messages under the same
  key should be expected to reveal enough information to allow forgeries of
  authenticators on other messages.

  Selected primitive
  ------------------

  crypto_onetimeauth is crypto_onetimeauth_poly1305, an authenticator specified
  in "Cryptography in NaCl", Section 9. This authenticator is proven to meet
  the standard notion of unforgeability after a single message.
*/
/**


     #include "crypto_onetimeauth.h"

     const unsigned char k[crypto_onetimeauth_KEYBYTES];
     const unsigned char m[...]; unsigned long long mlen;
     unsigned char a[crypto_onetimeauth_BYTES];

     crypto_onetimeauth(a,m,mlen,k);

  The crypto_onetimeauth function authenticates a message m[0], m[1], ...,
  m[mlen-1] using a secret key k[0], k[1], ..., k[crypto_onetimeauth_KEYBYTES-1];
  puts the authenticator into a[0], a[1], ..., a[crypto_onetimeauth_BYTES-1]; and
  returns 0.
*/
int crypto_onetimeauth( ref ubyte[crypto_onetimeauth_BYTES] output,
    const(ubyte)[] m,
    ref const ubyte[crypto_onetimeauth_KEYBYTES] k)
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
  C NaCl also provides a crypto_onetimeauth_verify function callable as follows:

     #include "crypto_onetimeauth.h"

     const unsigned char k[crypto_onetimeauth_KEYBYTES];
     const unsigned char m[...]; unsigned long long mlen;
     const unsigned char a[crypto_onetimeauth_BYTES];

     crypto_onetimeauth_verify(a,m,mlen,k);

  This function returns 0 if a[0], a[1], ..., a[crypto_onetimeauth_BYTES-1] is
  a correct authenticator of a message m[0], m[1], ..., m[mlen-1] under a
  secret key k[0], k[1], ..., k[crypto_onetimeauth_KEYBYTES-1]. Otherwise
  crypto_onetimeauth_verify returns -1.

*/
bool crypto_onetimeauth_verify( ref const ubyte[crypto_onetimeauth_BYTES] h,
    const ubyte[] m,
    ref const ubyte[crypto_onetimeauth_KEYBYTES] k)
{
  ubyte x[16];
  crypto_onetimeauth(x,m,k);
  return (crypto_verify_16(h,x) == 0);
}


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

  import std.stdio;
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
    if (!crypto_onetimeauth_verify(a, currentC, key)) {
      writefln("fail %d", clen);
      assert(false);
    }
    if (clen > 0) {
      currentC[uniform(0u, clen)] += 1 + (uniform(0u, 255u));
      if (crypto_onetimeauth_verify(a, currentC, key)) {
        writefln("forgery %d", clen);
        assert(false);
      }
      a[uniform(0u, a.length)] += 1 + (uniform(0u,255u));
      if (crypto_onetimeauth_verify(a, currentC, key)) {
        writefln("forgery %d", clen);
        assert(false);
      }
    }
  }
}

/**
  Secret-key authenticated encryption: crypto_secretbox
  =====================================================

  Security model
  --------------

  The crypto_secretbox function is designed to meet the standard notions of
  privacy and authenticity for a secret-key authenticated-encryption scheme using
  nonces. For formal definitions see, e.g., Bellare and Namprempre,
  "Authenticated encryption: relations among notions and analysis of the generic
  composition paradigm," Lecture Notes in Computer Science 1976 (2000), 531–545,
  http://www-cse.ucsd.edu/~mihir/papers/oem.html.

  Note that the length is not hidden. Note also that it is the caller's
  responsibility to ensure the uniqueness of nonces—for example, by using nonce 1
  for the first message, nonce 2 for the second message, etc. Nonces are long
  enough that randomly generated nonces have negligible risk of collision.

  Selected primitive
  ------------------

  crypto_secretbox is crypto_secretbox_xsalsa20poly1305, a particular combination
  of Salsa20 and Poly1305 specified in "Cryptography in NaCl". This function is
  conjectured to meet the standard notions of privacy and authenticity.

*/

/**

  The crypto_secretbox function encrypts and authenticates a message m[0], m[1],
  ..., m[mlen-1] using a secret key k[0], ..., k[crypto_secretbox_KEYBYTES-1] and
  a nonce n[0], n[1], ..., n[crypto_secretbox_NONCEBYTES-1]. The crypto_secretbox
  function puts the ciphertext into c[0], c[1], ..., c[mlen-1]. It then returns
  0.

  WARNING: Messages in the C NaCl API are 0-padded versions of messages in the
  C++ NaCl API. Specifically: The caller must ensure, before calling the C NaCl
  crypto_secretbox function, that the first crypto_secretbox_ZEROBYTES bytes of
  the message m are all 0. Typical higher-level applications will work with the
  remaining bytes of the message; note, however, that mlen counts all of the
  bytes, including the bytes required to be 0.

  Similarly, ciphertexts in the C NaCl API are 0-padded versions of messages in
  the C++ NaCl API. Specifically: The crypto_secretbox function ensures that the
  first crypto_secretbox_BOXZEROBYTES bytes of the ciphertext c are all 0.

*/
bool crypto_secretbox(ubyte[] c,const ubyte[] m,
    ref const ubyte[crypto_secretbox_NONCEBYTES] n,
    ref const ubyte[crypto_secretbox_KEYBYTES] k)
{
  immutable d = m.length;
  if (d < 32) return false;
  crypto_stream_xor(c,m,d,n,k);
  crypto_onetimeauth(c[16..32],c[32..$],c[0..32]);
  foreach(i;0..16) c[i] = 0;
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
  The crypto_secretbox_open function ensures (in case of success) that the first
  crypto_secretbox_ZEROBYTES bytes of the plaintext m are all 0.

  */
bool crypto_secretbox_open(ubyte[] m, const ubyte[] c,
    ref const ubyte[crypto_secretbox_NONCEBYTES] n,
    ref const ubyte[crypto_secretbox_KEYBYTES] k)
in {
  foreach(i;0..crypto_secretbox_BOXZEROBYTES) assert( c[i] == 0 );
}
body {
  immutable d = c.length;
  if (d < 32) return false;
  ubyte x[32];
  crypto_stream(x,32,n,k);
  if (!crypto_onetimeauth_verify(c[16..32], c[32..d],x)) return false;
  crypto_stream_xor(m,c,d,n,k);
  foreach(i;0..32) m[i] = 0;
  return true;
}

unittest {
  //#define TEST_NAME "secretbox"

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

  crypto_secretbox(c, m, nonce, firstkey);
  assert( c[16..163] == cRes[16..163]);


  ubyte m2[163];

  assert( crypto_secretbox_open(m2, c, nonce, firstkey) );
  assert( m[32..163] == m2[32..163]);
  m2[] = 0;
  assert( crypto_secretbox_open(m2, cRes, nonce, firstkey) );
  assert( m[32..163] == m2[32..163]);
}

unittest
{
  import std.random;

  ubyte k[crypto_secretbox_KEYBYTES];
  ubyte n[crypto_secretbox_NONCEBYTES];
  ubyte m[10000];
  ubyte c[10000];
  ubyte m2[10000];


  size_t mlen;
  size_t i;
  for (mlen = 0; mlen < 1000 && mlen + crypto_secretbox_ZEROBYTES < m.length;
      mlen = (mlen << 1) + 1) {
    immutable msgBlockLen = mlen + crypto_secretbox_ZEROBYTES;
    randomBuffer(k);
    randomBuffer(n);
    m[0..crypto_secretbox_ZEROBYTES] = 0;
    randomBuffer(m[crypto_secretbox_ZEROBYTES..msgBlockLen]);

    auto currentC = c[0..msgBlockLen];
    currentC[] = 0;

    crypto_secretbox( currentC, m[0..msgBlockLen], n, k );
    assert(crypto_secretbox_open(m2[0..msgBlockLen], currentC[], n, k),
        "ciphertext fails verification");
    assert( m2[0..msgBlockLen] == m[0..msgBlockLen] );

    // Sodium test: Secretbox8
    auto caught = 0;
    while (caught < 10) {
      // change a random byte
      auto idx = uniform(0u, mlen + crypto_secretbox_ZEROBYTES);
      c[idx] = uniform(ubyte.min, ubyte.max);;
      // fix any errors that might trigger the first crypto_secretbox_ZEROBYTES
      // to be not 0, and thats invalid for the crypto_secretbox_open() interface
      // (it seems to work but the docs say they should not)
      c[0..crypto_secretbox_ZEROBYTES] = 0;

      if(crypto_secretbox_open(m2[0..msgBlockLen], currentC, n, k)) {
        assert( m2[0..msgBlockLen] == m[0..msgBlockLen], "foregery" );
      } else {
        ++caught;
      }
    }
  }
}

private void set25519(out gf r, ref const gf a)
{
  foreach(i;0..16) r[i]=a[i];
}

private void car25519(ref gf o)
{
  long c;
  foreach(i;0..16) {
    o[i]+=(long(1)<<16);
    c=o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=c<<16;
  }
}

private void sel25519(ref gf p, ref gf q,long b)
{
  long t,c=~(b-1);
  foreach(i;0..16) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

private void pack25519(ref ubyte[32] o, ref const gf n)
{
  int b;
  gf m,t;
  foreach(i;0..16) t[i]=n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  foreach(j;0..2) {
    m[0]=t[0]-0xffed;
    foreach(i;1..15) {
      m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(m[15]>>16)&1;
    m[14]&=0xffff;
    sel25519(t,m,1-b);
  }
  foreach(i;0..16) {
    o[2*i]=t[i]&0xff;
    o[2*i+1]=cast(ubyte)(t[i]>>8);
  }
}

private int neq25519(ref const gf a, ref const gf b)
{
  ubyte[32] c,d;
  pack25519(c,a);
  pack25519(d,b);
  return crypto_verify_32(c,d);
}

private ubyte par25519(ref const gf a)
{
  ubyte d[32];
  pack25519(d,a);
  return d[0]&1;
}

private void unpack25519(ref gf o, ref const ubyte[32] n)
{
  foreach(i;0..16) o[i]=n[2*i]+(long(n[2*i+1])<<8);
  o[15]&=0x7fff;
}

private void A(ref gf o,ref const gf a,ref const gf b)
{
  foreach(i;0..16) o[i]=a[i]+b[i];
}

private void Z(ref gf o,ref const gf a,ref const gf b)
{
  foreach(i;0..16) o[i]=a[i]-b[i];
}

private void M(ref gf o,ref const gf a,ref const gf b)
{
  long t[31];
  foreach(i;0..31) t[i]=0;
  foreach(i;0..16) foreach(j;0..16) t[i+j]+=a[i]*b[j];
  foreach(i;0..15) t[i]+=38*t[i+16];
  foreach(i;0..16) o[i]=t[i];
  car25519(o);
  car25519(o);
}

private void S(ref gf o,ref const gf a)
{
  M(o,a,a);
}

private void inv25519(ref gf o,ref const gf i)
{
  gf c;
  foreach(a;0..16) c[a]=i[a];
  for(int a=253;a>=0;a--) {
    S(c,c);
    if(a!=2&&a!=4) M(c,c,i);
  }
  foreach(a;0..16) o[a]=c[a];
}

private void pow2523(ref gf o,ref const gf i)
{
  gf c;
  foreach(a;0..16) c[a]=i[a];
  for(int a=250;a>=0;a--) {
    S(c,c);
    if(a!=1) M(c,c,i);
  }
  foreach(a;0..16) o[a]=c[a];
}

/**
  Scalar multiplication: crypto_scalarmult
  ========================================

  Security model
  --------------

  crypto_scalarmult is designed to be strong as a component of various well-known
  "hashed Diffie–Hellman" applications. In particular, it is designed to make the
  "computational Diffie–Hellman" problem (CDH) difficult with respect to the
  standard base.

  crypto_scalarmult is also designed to make CDH difficult with respect to other
  nontrivial bases. In particular, if a represented group element has small
  order, then it is annihilated by all represented scalars. This feature allows
  protocols to avoid validating membership in the subgroup generated by the
  standard base.

  NaCl does not make any promises regarding the "decisional Diffie–Hellman"
  problem (DDH), the "static Diffie–Hellman" problem (SDH), etc. Users are
  responsible for hashing group elements.

  Selected primitive
  ------------------

  crypto_scalarmult is the function crypto_scalarmult_curve25519 specified in
  "Cryptography in NaCl", Sections 2, 3, and 4. This function is conjectured to
  be strong. For background see Bernstein, "Curve25519: new Diffie-Hellman speed
  records," Lecture Notes in Computer Science 3958 (2006), 207–228,
  http://cr.yp.to/papers.html#curve25519.

*/
/**
  crypto_scalarmult(q,n,p);

  This function multiplies a group element p[0], ..., p[crypto_scalarmult_BYTES-1]
  by an integer n[0], ..., n[crypto_scalarmult_SCALARBYTES-1].

  It puts the resulting group element into
  q[0], ..., q[crypto_scalarmult_BYTES-1] and returns 0.
*/
int crypto_scalarmult(ref ubyte[crypto_scalarmult_BYTES] q,
    ref const ubyte[crypto_scalarmult_SCALARBYTES] n,
    ref const ubyte[crypto_scalarmult_BYTES] p)
{
  ubyte z[32];
  long[80] x;
  long r;
  gf a,b,c,d,e,f;
  foreach(i;0..31) z[i]=n[i];
  z[31]=(n[31]&127)|64;
  z[0]&=248;
  unpack25519(x[0..16],p);
  foreach(i;0..16) {
    b[i]=x[i];
    d[i]=a[i]=c[i]=0;
  }
  a[0]=d[0]=1;
  for(long i=254;i>=0;--i) {
    r=(z[i>>3]>>(i&7))&1;
    sel25519(a,b,r);
    sel25519(c,d,r);
    A(e,a,c);
    Z(a,a,c);
    A(c,b,d);
    Z(b,b,d);
    S(d,e);
    S(f,a);
    M(a,c,a);
    M(c,b,e);
    A(e,a,c);
    Z(a,a,c);
    S(b,a);
    Z(c,d,f);
    M(a,c,_121665);
    A(a,a,d);
    M(c,c,a);
    M(a,d,f);
    M(d,b,x[0..16]);
    S(b,e);
    sel25519(a,b,r);
    sel25519(c,d,r);
  }
  foreach(i;0..16) {
    x[i+16]=a[i];
    x[i+32]=c[i];
    x[i+48]=b[i];
    x[i+64]=d[i];
  }
  inv25519(x[32..48],x[32..48]);
  M(x[16..32],x[16..32],x[32..48]);
  pack25519(q, x[16..32]);
  return 0;
}

/**

  The crypto_scalarmult_base function computes the scalar product of a standard
  group element and an integer n[0], ..., n[crypto_scalarmult_SCALARBYTES-1]. It
  puts the resulting group element into q[0], ..., q[crypto_scalarmult_BYTES-1]
  and returns 0.

  */
int crypto_scalarmult_base(ref ubyte[crypto_scalarmult_BYTES] q,
    ref const ubyte[crypto_scalarmult_SCALARBYTES] n)
{
  return crypto_scalarmult(q,n,_9);
}

unittest {
  ubyte alicesk[32]
    = [ 0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
      0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
      0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a ];
  ubyte alicepk[32];

  crypto_scalarmult_base(alicepk, alicesk);
  assert( alicepk == [0x85,0x20,0xf0,0x09,0x89,0x30,0xa7,0x54
      ,0x74,0x8b,0x7d,0xdc,0xb4,0x3e,0xf7,0x5a
      ,0x0d,0xbf,0x3a,0x0d,0x26,0x38,0x1a,0xf4
      ,0xeb,0xa4,0xa9,0x8e,0xaa,0x9b,0x4e,0x6a]);
}

unittest {

  ubyte bobsk[32]
    = [ 0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f,
      0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18,
      0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb ];
  ubyte bobpk[32];

  crypto_scalarmult_base(bobpk, bobsk);
  assert( bobpk == [0xde,0x9e,0xdb,0x7d,0x7b,0x7d,0xc1,0xb4
      ,0xd3,0x5b,0x61,0xc2,0xec,0xe4,0x35,0x37
      ,0x3f,0x83,0x43,0xc8,0x5b,0x78,0x67,0x4d
      ,0xad,0xfc,0x7e,0x14,0x6f,0x88,0x2b,0x4f]);

}


unittest {
  ubyte alicesk[32]
    = [ 0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
      0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
      0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a ];
  ubyte bobpk[32]
    = [ 0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61,
      0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78,
      0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f ];
  ubyte k[32];

  crypto_scalarmult(k, alicesk, bobpk);

  assert( k == [
      0x4a,0x5d,0x9d,0x5b,0xa4,0xce,0x2d,0xe1
      ,0x72,0x8e,0x3b,0xf4,0x80,0x35,0x0f,0x25
      ,0xe0,0x7e,0x21,0xc9,0x47,0xd1,0x9e,0x33
      ,0x76,0xf0,0x9b,0x3c,0x1e,0x16,0x17,0x42
      ]);
}

unittest {

  ubyte p1[32] = [
    0x72, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
    0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
    0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0xea
  ];
  ubyte p2[32] = [
    0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
    0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
    0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
    0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a
  ];
  ubyte scalar[32];
  ubyte out1[32];
  ubyte out2[32];

  scalar[0] = 1;
  crypto_scalarmult(out1, scalar, p1);
  crypto_scalarmult(out2, scalar, p2);
  assert( out1[0..32] < out2[0..32] );
}


/**

  Public-key authenticated encryption: crypto_box
  ===============================================

  Security model
  --------------

  The crypto_box function is designed to meet the standard notions of privacy and
  third-party unforgeability for a public-key authenticated-encryption scheme
  using nonces. For formal definitions see, e.g., Jee Hea An, "Authenticated
  encryption in the public-key setting: security notions and analyses,"
  http://eprint.iacr.org/2001/079.

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

  The crypto_box function is not meant to provide non-repudiation. On the
  contrary: the crypto_box function guarantees repudiability. A receiver can
  freely modify a boxed message, and therefore cannot convince third parties that
  this particular message came from the sender. The sender and receiver are
  nevertheless protected against forgeries by other parties. In the terminology
  of http://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c, crypto_box
  uses "public-key authenticators" rather than "public-key signatures."

  Users who want public verifiability (or receiver-assisted public verifiability)
  should instead use signatures (or signcryption). Signature support is a high
  priority for NaCl; a signature API will be described in subsequent NaCl
  documentation.

  Selected primitive
  ------------------

  crypto_box is curve25519xsalsa20poly1305, a particular combination of
  Curve25519, Salsa20, and Poly1305 specified in "Cryptography in NaCl". This
  function is conjectured to meet the standard notions of privacy and third-party
  unforgeability.


  */

/**
  Key Generation
  --------------

  The crypto_box_keypair function randomly generates a secret key and a
  corresponding public key. It puts the secret key into sk[0], sk[1], ...,
  sk[crypto_box_SECRETKEYBYTES-1] and puts the public key into pk[0], pk[1], ...,
  pk[crypto_box_PUBLICKEYBYTES-1]. It then returns 0.

  */
int crypto_box_keypair(ref ubyte[crypto_box_PUBLICKEYBYTES] pk,
    ref ubyte[crypto_box_SECRETKEYBYTES] sk)
{
  safeRandomBytes(sk,32);
  return crypto_scalarmult_base(pk,sk);
}

/**

  Precomputation interface
  ------------------------

  Applications that send several messages to the same receiver can gain speed
  by splitting crypto_box into two steps, crypto_box_beforenm and
  crypto_box_afternm. Similarly, applications that receive several messages
  from the same sender can gain speed by splitting crypto_box_open into two
  steps, crypto_box_beforenm and crypto_box_open_afternm.

  The intermediate data computed by crypto_box_beforenm is suitable for both
  crypto_box_afternm and crypto_box_open_afternm, and can be reused for any
  number of messages.
  */
int crypto_box_beforenm( ref ubyte[crypto_box_BEFORENMBYTES] k,
    ref const ubyte[crypto_box_PUBLICKEYBYTES] pk,
    const ubyte[crypto_box_SECRETKEYBYTES] sk)
{
  ubyte s[32];
  crypto_scalarmult(s,sk,pk);
  return crypto_core_hsalsa20(k,_0,s,sigma);
}

/**
*/
bool crypto_box_afternm(ubyte[] cypherText, const ubyte[] m,
    ref const ubyte[crypto_box_NONCEBYTES] nonce,
    ref const ubyte[crypto_box_BEFORENMBYTES] k)
in {
  assert( m.length >= crypto_box_ZEROBYTES );
  assert( cypherText.length >= m.length );
  foreach(i;0..crypto_box_ZEROBYTES) assert( m[i] == 0 );
}
body {
  return crypto_secretbox(cypherText,m,nonce,k);
}

/**
  */
bool crypto_box_open_afternm(ubyte[] m, const ubyte[] cypherText,
    ref const ubyte[crypto_box_NONCEBYTES] nonce,
    ref const ubyte[crypto_box_BEFORENMBYTES] k)
in {
  foreach(i;0..crypto_box_BOXZEROBYTES)
    assert( cypherText[i] == 0,
        "The first crypto_box_BOXZEROBYTES bytes of the ciphertext c must be all 0." );
}
body {
  return crypto_secretbox_open(m,cypherText,nonce,k);
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
bool crypto_box(ubyte[] cypherText,const ubyte[] m,
    ref const ubyte[crypto_box_NONCEBYTES] nonce,
    ref const ubyte[crypto_box_PUBLICKEYBYTES] recvPk,
    ref const ubyte[crypto_box_SECRETKEYBYTES] senderSk)
in {
  assert( m.length >= crypto_box_ZEROBYTES );
  assert( cypherText.length >= m.length );
  foreach(i;0..crypto_box_ZEROBYTES) assert( m[i] == 0 );
}
body {
  ubyte k[32];
  crypto_box_beforenm(k,recvPk,senderSk);
  return crypto_box_afternm(cypherText,m,nonce,k);
}

/**

  crypto_box_open(m,c,clen,n,pk,sk);

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
bool crypto_box_open(ubyte[] m,const ubyte[] cypherText,
    ref const ubyte[crypto_box_NONCEBYTES] nonce,
    ref const ubyte[crypto_box_PUBLICKEYBYTES] senderPk,
    ref const ubyte[crypto_box_SECRETKEYBYTES] recvSk)
in {
  assert( cypherText.length >= crypto_box_BOXZEROBYTES);
  assert( m.length >= cypherText.length );
  foreach(i;0..crypto_box_BOXZEROBYTES)
    assert( cypherText[i] == 0 );
}
body {
  ubyte k[32];
  crypto_box_beforenm(k,senderPk,recvSk);
  return crypto_box_open_afternm(m,cypherText,nonce,k);
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

  ubyte k[crypto_box_BEFORENMBYTES];
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
  ubyte k[crypto_box_BEFORENMBYTES];
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

  ubyte alicesk[crypto_box_SECRETKEYBYTES];
  ubyte alicepk[crypto_box_PUBLICKEYBYTES];
  ubyte bobsk[crypto_box_SECRETKEYBYTES];
  ubyte bobpk[crypto_box_PUBLICKEYBYTES];
  ubyte n[crypto_box_NONCEBYTES];
  ubyte m[32000];
  ubyte c[32000];
  ubyte m2[32000];

  size_t mlen;
  // This test is reallly slow when incrementing 1-by-1
  for (mlen = 0; mlen < (2 << 16) && mlen + crypto_box_ZEROBYTES < m.length;
      mlen = (mlen << 1) + 1 )
  {
    immutable msgBlockLen = mlen + crypto_box_ZEROBYTES;

    crypto_box_keypair(alicepk, alicesk);
    crypto_box_keypair(bobpk, bobsk);
    foreach(ref e;n) n = uniform(ubyte.min, ubyte.max);
    foreach(ref e;m[crypto_box_ZEROBYTES..msgBlockLen]) e = uniform(ubyte.min, ubyte.max);
    crypto_box(c[0..msgBlockLen], m[0..msgBlockLen], n, bobpk, alicesk);
    assert( crypto_box_open(m2, c[0..msgBlockLen], n, alicepk, bobsk), "ciphertext fails verification");
    assert( m2[0..msgBlockLen] == m[0..msgBlockLen] );

    foreach(i;0..10) {
      c[uniform(0, msgBlockLen)] = uniform(ubyte.min,ubyte.max);
      c[0..crypto_box_ZEROBYTES] = 0;
      if (crypto_box_open(m2, c[0..msgBlockLen], n, alicepk, bobsk))
        assert( m2[0..msgBlockLen] == m[0..msgBlockLen], "forgery" );
    }
  }
}

// Hash helper functions
// ---------------------

private ulong R(ulong x,int c) { return (x >> c) | (x << (64 - c)); }
private ulong Ch(ulong x,ulong y,ulong z) { return (x & y) ^ (~x & z); }
private ulong Maj(ulong x,ulong y,ulong z) { return (x & y) ^ (x & z) ^ (y & z); }
private ulong Sigma0(ulong x) { return R(x,28) ^ R(x,34) ^ R(x,39); }
private ulong Sigma1(ulong x) { return R(x,14) ^ R(x,18) ^ R(x,41); }
private ulong sigma0(ulong x) { return R(x, 1) ^ R(x, 8) ^ (x >> 7); }
private ulong sigma1(ulong x) { return R(x,19) ^ R(x,61) ^ (x >> 6); }

private const ulong[80] K = [
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
  0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
  0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
  0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
  0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
  0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
  0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
  0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
  0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
  0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
  0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
];

/**
*/
size_t crypto_hashblocks(ref ubyte[crypto_hashblocks_STATEBYTES] x, const(ubyte)[] m)
{
  size_t n = m.length;
  ulong[8] z,b,a;
  ulong w[16];
  ulong t;

  foreach(i;0..8) z[i] = a[i] = dl64(x[8 * i..$][0..8]);

  while (n >= 128) {
    foreach(i;0..16) w[i] = dl64(m[8 * i..$][0..8]);

    foreach(i;0..80) {
      foreach(j;0..8) b[j] = a[j];
      t = a[7] + Sigma1(a[4]) + Ch(a[4],a[5],a[6]) + K[i] + w[i%16];
      b[7] = t + Sigma0(a[0]) + Maj(a[0],a[1],a[2]);
      b[3] += t;
      foreach(j;0..8) a[(j+1)%8] = b[j];
      if (i%16 == 15)
        foreach(j;0..16)
          w[j] += w[(j+9)%16] + sigma0(w[(j+1)%16]) + sigma1(w[(j+14)%16]);
    }

    foreach(i;0..8) { a[i] += z[i]; z[i] = a[i]; }

    m = m[128..$]; // += 128;
    n -= 128;
  }

  foreach(i;0..8) ts64(x[8*i..$][0..8],z[i]);

  return n;
}

private const ubyte[64] iv = [
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
];

/**
  Hashing: crypto_hash
  ====================

  Security model
  --------------

  The crypto_hash function is designed to be usable as a strong component of
  DSA, RSA-PSS, key derivation, hash-based message-authentication codes,
  hash-based ciphers, and various other common applications. "Strong" means
  that the security of these applications, when instantiated with crypto_hash,
  is the same as the security of the applications against generic attacks. In
  particular, the crypto_hash function is designed to make finding collisions
  difficult.

  Selected primitive
  ------------------

  crypto_hash is currently an implementation of SHA-512.

  There has been considerable degradation of public confidence in the security
  conjectures for many hash functions, including SHA-512. However, for the
  moment, there do not appear to be alternatives that inspire satisfactory
  levels of confidence. One can hope that NIST's SHA-3 competition will improve
  the situation.

*/
/**
  The crypto_hash function hashes a message m[0], m[1], ..., m[m.length-1]. It puts
  the hash into h[0], h[1], ..., h[crypto_hash_BYTES-1].
*/
void crypto_hash( ref ubyte[crypto_hash_BYTES] output,
    const(ubyte)[] m )
{
  size_t n = m.length;
  ubyte[64] h;
  ubyte[256] x;
  ulong b = n;

  foreach(i;0..64) h[i] = iv[i];

  //crypto_hashblocks(h,m[0..n],n);
  crypto_hashblocks(h,m[0..n]);
  m = m[n - (n & 127)..$];
  n &= 127;

  foreach(i;0..256) x[i] = 0;
  foreach(i;0..n) x[i] = m[i];
  x[n] = 128;

  n = 256-128*(n<112);
  x[n-9] = b >> 61;
  ts64(x[n-8..$][0..8],b<<3);
  crypto_hashblocks(h,x[0..n]);

  foreach(i;0..64) output[i] = h[i];

}


unittest {
  import std.stdio;
  auto x = "testing\n";
  auto x2 = "The Conscience of a Hacker is a small essay written January 8, 1986 by a computer security hacker who went by the handle of The Mentor, who belonged to the 2nd generation of Legion of Doom.";
  ubyte[crypto_hash_BYTES] h;

  size_t i;
  crypto_hash(h, toBytes(x));
  assert( h == [
      0x24, 0xf9, 0x50, 0xaa, 0xc7, 0xb9, 0xea, 0x9b, 0x3c, 0xb7, 0x28, 0x22,
      0x8a, 0x0c, 0x82, 0xb6, 0x7c, 0x39, 0xe9, 0x6b, 0x4b, 0x34, 0x47, 0x98,
      0x87, 0x0d, 0x5d, 0xae, 0xe9, 0x3e, 0x3a, 0xe5, 0x93, 0x1b, 0xaa, 0xe8,
      0xc7, 0xca, 0xcf, 0xea, 0x4b, 0x62, 0x94, 0x52, 0xc3, 0x80, 0x26, 0xa8,
      0x1d, 0x13, 0x8b, 0xc7, 0xaa, 0xd1, 0xaf, 0x3e, 0xf7, 0xbf, 0xd5, 0xec,
      0x64, 0x6d, 0x6c, 0x28
      ]);

  crypto_hash(h, toBytes(x2));
  assert( h == [
      0xa7, 0x7a, 0xbe, 0x1c, 0xcf, 0x8f, 0x54, 0x97, 0xe2, 0x28, 0xfb, 0xc0, 0xac,
      0xd7, 0x3a, 0x52, 0x1e, 0xde, 0xdb, 0x21, 0xb8, 0x97, 0x26, 0x68, 0x4a, 0x6e,
      0xbb, 0xc3, 0xba, 0xa3, 0x23, 0x61, 0xac, 0xa5, 0xa2, 0x44, 0xda, 0xa8, 0x4f,
      0x24, 0xbf, 0x19, 0xc6, 0x8b, 0xaf, 0x78, 0xe6, 0x90, 0x76, 0x25, 0xa6, 0x59,
      0xb1, 0x54, 0x79, 0xeb, 0x7b, 0xd4, 0x26, 0xfc, 0x62, 0xaa, 0xfa, 0x73,
      ]

      );
}




private void add(ref gf[4] p, ref gf[4] q)
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

private void cswap(ref gf[4] p, ref gf[4] q, ubyte b)
{
  foreach(i;0..4)
    sel25519(p[i],q[i],b);
}

private void pack(ref ubyte[32] r, ref gf[4] p)
{
  gf tx, ty, zi;
  inv25519(zi, p[2]);
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

private void scalarmult(ref gf[4] p, ref gf[4] q, ref const ubyte[32] s)
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

private void scalarbase(ref gf[4] p, ref const ubyte[32] s)
{
  gf q[4];
  set25519(q[0],X);
  set25519(q[1],Y);
  set25519(q[2],gf1);
  M(q[3],X,Y);
  scalarmult(p,q,s);
}

/**
  The crypto_sign_keypair function randomly generates a secret key and a
  corresponding public key. It puts the secret key into sk[0], sk[1], ...,
  sk[crypto_sign_SECRETKEYBYTES-1] and puts the public key into pk[0], pk[1],
  ..., pk[crypto_sign_PUBLICKEYBYTES-1]. It then returns true.
 */
bool crypto_sign_keypair(ref ubyte[crypto_sign_PUBLICKEYBYTES] pk,
   ref ubyte[crypto_sign_SECRETKEYBYTES] sk)
{
  ubyte d[64];
  gf p[4];

  safeRandomBytes(sk, 32);
  crypto_hash(d, sk[0..32]);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  scalarbase(p,d[0..32]);
  pack(pk,p);

  foreach(i;0..32) sk[32 + i] = pk[i];
  return true;
}

private const ulong L[32] = [
  0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde,
    0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10
  ];

private void modL(ref ubyte[32] r, ref long[64] x)
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

private void reduce(ref ubyte[64] r)
{
  long[64] x;
  foreach(i;0..64) x[i] = ulong(r[i]);
  foreach(i;0..64) r[i] = 0;
  modL(r[0..32],x);
}


/*
  The crypto_sign function signs a message m[0], ..., m[mlen-1] using the
  signer's secret key sk[0], sk[1], ..., sk[crypto_sign_SECRETKEYBYTES-1], puts
  the length of the signed message into smlen and puts the signed message into
  sm[0], sm[1], ..., sm[smlen-1]. It then returns 0.

  The maximum possible length smlen is mlen+crypto_sign_BYTES. The caller must
  allocate at least mlen+crypto_sign_BYTES bytes for sm.
*/
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

private bool unpackneg(ref gf[4] r,ref const ubyte[32] p)
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
bool crypto_sign_open(ubyte[] m, ref ulong mlen, const ubyte[] sm,
    ref const ubyte[crypto_sign_PUBLICKEYBYTES] pk)
in {
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
    auto msg = msgBuf[0..mlen];
    auto signedMsg = signedMsgBuf[0..mlen+crypto_sign_BYTES];
    assert(crypto_sign_keypair(pk, sk) );
    randomBuffer(msg[0..mlen]);

    assert( crypto_sign( signedMsg, signedMsgLen, msg,  sk ));
    assert( signedMsg.length == signedMsgLen );
    assert( crypto_sign_open( decodedMsgBuf[0..signedMsgLen], msgLen, signedMsg,  pk ),
        "crypto_sign_keypair() private key does not sign for public key");
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

version(OSX) {
  /**
    Cryptographically secure random bytes on OSX are sourced from /dev/random
    as suggested by Apple.
    */
  void safeRandomBytes( ubyte[] output, size_t count)
  {
    import core.stdc.stdio;
    import std.exception;
    FILE* fp = enforce(fopen("/dev/random", "r"));
    scope(exit) fclose(fp);
    foreach(i;0..count) {
      output[i] = cast(ubyte)(fgetc(fp));
    }
  }
}
