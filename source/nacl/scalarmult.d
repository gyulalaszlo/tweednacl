/**
  $(BIG $(B Scalar multiplication: crypto_scalarmult))

  $(BIG Security model)

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

  $(BIG Selected primitive)

  crypto_scalarmult is the function crypto_scalarmult_curve25519 specified in
  "Cryptography in NaCl", Sections 2, 3, and 4. This function is conjectured to
  be strong. For background see Bernstein, $(I "Curve25519: new Diffie-Hellman speed
  records,") Lecture Notes in Computer Science 3958 (2006), 207–228,
  $(LINK http://cr.yp.to/papers.html#curve25519).

*/
module nacl.scalarmult;

import nacl.constants;
import nacl.basics;
import nacl.math25519;
/**
  This function multiplies a group element p[0], ..., p[crypto_scalarmult_BYTES-1]
  by an integer n[0], ..., n[crypto_scalarmult_SCALARBYTES-1].

  It puts the resulting group element into
  q[0], ..., q[crypto_scalarmult_BYTES-1] and returns 0.
*/
pure nothrow @safe @nogc int crypto_scalarmult(ref ubyte[crypto_scalarmult_BYTES] q,
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

  This function computes the scalar product of a standard
  group element and an integer n[0], ..., n[crypto_scalarmult_SCALARBYTES-1]. It
  puts the resulting group element into q[0], ..., q[crypto_scalarmult_BYTES-1]
  and returns 0.

  */
pure nothrow @safe @nogc int crypto_scalarmult_base(ref ubyte[crypto_scalarmult_BYTES] q,
    ref const ubyte[crypto_scalarmult_SCALARBYTES] n)
{
  return crypto_scalarmult(q,n,_9);
}

private:
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

