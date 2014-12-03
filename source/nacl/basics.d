module nacl.basics;

public:


/**
  The crypto_verify_16 function returns 0 if x[0], x[1], ..., x[15] are the
  same as y[0], y[1], ..., y[15]. Otherwise it returns -1.

  This function is safe to use for secrets x[0], x[1], ..., x[15], y[0], y[1],
  ..., y[15]. The time taken by crypto_verify_16 is independent of the contents
  of x[0], x[1], ..., x[15], y[0], y[1], ..., y[15]. In contrast, the standard C
  comparison function memcmp(x,y,16) takes time that depends on the longest
  matching prefix of x and y, often allowing easy timing attacks.

 */
pure nothrow @safe @nogc int crypto_verify_16(ref const ubyte[16] x, ref const ubyte[16] y)
{
  return vn(x,y,16);
}

/**
  Similar verification function as crypto_verify_16 , but operating on 32
  byte blocks.
 */
pure nothrow @safe @nogc int crypto_verify_32(ref const ubyte[32] x, ref const ubyte[32] y)
{
  return vn(x,y,32);
}

/**
  Converts any array slice into a byte array slice.
  */
pure nothrow @trusted @nogc const(ubyte)[] toBytes(T)(T[] input)
out(o) {
  if (input.length > 0)
    assert( cast(T*)(&o[0]) == &input[0] && cast(T*)(&o[$-1]) == &input[$-1] );
  else
    assert( o.length == 0 );
}
body {
  const(const(ubyte)[]) nullBytes = [];
  if (input.length == 0) return nullBytes;
  return (cast(const(ubyte)*)(&input[0]))[0..(input.length*T.sizeof)];
}


package:


alias gf = long[16];

const ubyte[16] sigma = [ 'e','x','p','a','n','d',' ','3','2','-','b','y','t','e', ' ','k'];

immutable ubyte[16] _0 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
immutable ubyte[32] _9 = [9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

const gf gf0;
const gf gf1 = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
const gf _121665 = [0xDB41,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
const gf D = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d,
        0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee,
        0x5203];

const gf D2 = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a,
        0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc,
        0x2406];

const gf X = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760,
        0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3,
        0x2169];

const gf Y = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
        0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
        0x6666];

const gf I = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806,
        0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480,
        0x2b83];

pure nothrow @safe @nogc uint L32(uint x,int c)
{
  return (x << c) | ((x&0xffffffff) >> (32 - c));
}

pure nothrow @safe @nogc uint ld32(ref const ubyte[4] x)
{
  uint u = x[3];
  u = (u<<8)|x[2];
  u = (u<<8)|x[1];
  return (u<<8)|x[0];
}

pure nothrow @safe @nogc ulong dl64(ref const ubyte[8] x)
{
  ulong u=0;
  foreach(ulong i;0..8) u=(u<<8)|x[i];
  return u;
}

pure nothrow @safe @nogc void st32(ref ubyte[4] x,uint u)
{
  foreach(i;0..4) { x[i] = cast(ubyte)(u); u >>= 8; }
}

pure nothrow @safe @nogc void ts64(ref ubyte[8] x,ulong u)
{
  int i;
  for (i = 7;i >= 0;--i) { x[i] = cast(ubyte)(u); u >>= 8; }
}

pure nothrow @safe @nogc int vn(const ubyte[] x,const ubyte[] y,int n)
{
  uint d = 0;
  foreach(i;0..n) d |= x[i]^y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}


version(unittest) {
  import std.random;
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
  enum testMessageLengthsUpTo = 16;

  /**
    Helper to generate a pseudo-random buffer.
    The generated random numbers are from std.random, so they are not
    safe for generating keys. Use
    */
  void randomBuffer(T)( T[] m )
  {
    foreach(ref e;m) e = uniform(T.min, T.max);
  }


  void forgeBuffer(T)( T[] m, size_t count )
  {
    foreach(i;0..count)
      m[uniform(0,m.length)] = uniform(T.min, T.max);
  }

  /** ditto */
  T[S] randomBuffer(size_t S, T=ubyte)()
  {
    T[S] buffer;
    randomBuffer(buffer);
    //foreach(ref e;buffer) e = uniform(T.min, T.max);
    return buffer;
  }

  /** ditto */
  T[] randomBuffer(T=ubyte)(size_t s)
  {
    T[] buffer;
    buffer.length = s;
    randomBuffer(buffer);
    //foreach(ref e;buffer) e = uniform(T.min, T.max);
    return buffer;
  }

}

version(OSX) {
  /**
    Cryptographically secure random bytes on OSX are sourced from /dev/random
    as suggested by Apple.
    */
  @system void safeRandomBytes( ubyte[] output, size_t count)
  {
    import core.stdc.stdio;
    import std.exception;
    FILE* fp = enforce(fopen("/dev/random", "r"));
    scope(exit) fclose(fp);
    foreach(i;0..count) {
      output[i] = cast(ubyte)(fgetc(fp));
    }
  }
} else {
  static assert( false, "void safeRandomBytes( ubyte[] output, size_t count) not implemented" );
}
