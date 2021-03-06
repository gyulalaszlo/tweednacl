module tweednacl.salsa20;

import std.experimental.crypto.nacl;

struct Salsa20 {
  enum Primitive = CryptoPrimitive( "salsa20",
      "crypto_core/salsa20/tweet"
      );

  alias Output = ubyte[64];
  alias Input = ubyte[16];
  alias Key = ubyte[32];
  alias Const = ubyte[16];

  pure nothrow @safe @nogc
  static int core(
      ref Output output,
      ref const Input input,
      ref const Key k,
      ref const Const c)
  {
    salsaCoreImpl!(UseHSalsa.No)(output,input,k,c);
    return 0;
  }

}

struct HSalsa20 {
  enum Primitive = CryptoPrimitive( "hsalsa20",
      "crypto_core/hsalsa20/tweet"
      );

  alias Output = ubyte[32];
  alias Input = ubyte[16];
  alias Key = ubyte[32];
  alias Const = ubyte[16];

  pure nothrow @safe @nogc
  static int core(
      ref Output output,
      ref const Input input,
      ref const Key k,
      ref const Const c)
  {
    salsaCoreImpl!(UseHSalsa.Yes)(output,input,k,c);
    return 0;
  }

}


alias crypto_core_salsa20 = Salsa20.core;
alias crypto_core_hsalsa20 = HSalsa20.core;

private:

import tweednacl.basics : ld32, L32, st32;

// Should the core use Salsa or HSalsa
enum UseHSalsa {No, Yes};

pure nothrow @safe @nogc void salsaCoreImpl(UseHSalsa useHSalsa)(
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
  size_t pos = 0;
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


    assert( toHexString(sha512Of(output[])) ==
        "2BD8E7DB6877539E4F2B295EE415CD378AE214AA3BEB3E08E911A5BD4A25E6AC16CA283C79C34C08C99F7BDB560111E8CAC1AE65EEA08AC384D7A591461AB6E3"
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
