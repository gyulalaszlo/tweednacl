/**
  $(BIG $(B Hashing: crypto_hash))

  $(BIG Security model)

  The crypto_hash function is designed to be usable as a strong component of
  DSA, RSA-PSS, key derivation, hash-based message-authentication codes,
  hash-based ciphers, and various other common applications. "Strong" means
  that the security of these applications, when instantiated with crypto_hash,
  is the same as the security of the applications against generic attacks. In
  particular, the crypto_hash function is designed to make finding collisions
  difficult.

  $(BIG Selected primitive)

  crypto_hash is currently an implementation of SHA-512.

  There has been considerable degradation of public confidence in the security
  conjectures for many hash functions, including SHA-512. However, for the
  moment, there do not appear to be alternatives that inspire satisfactory
  levels of confidence. One can hope that NIST's SHA-3 competition will improve
  the situation.

*/
module nacl.hash;
import nacl.constants;

/**
  The crypto_hash function hashes a message m[0], m[1], ..., m[m.length-1]. It puts
  the hash into h[0], h[1], ..., h[crypto_hash_BYTES-1].
*/
pure nothrow @safe @nogc void crypto_hash( ref ubyte[crypto_hash_BYTES] output,
    const(ubyte)[] m )
{
  import nacl.basics : ts64;
  size_t n = m.length;
  ubyte[64] h;
  ubyte[256] x;
  ulong b = n;

  foreach(i;0..64) h[i] = iv[i];

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

/**
*/
pure nothrow @safe @nogc size_t crypto_hashblocks(ref ubyte[crypto_hashblocks_STATEBYTES] x, const(ubyte)[] m)
{
  import nacl.basics : dl64, ts64;
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

private:




// Hash helper functions
// ---------------------

pure nothrow @safe @nogc ulong R(ulong x,int c) { return (x >> c) | (x << (64 - c)); }
pure nothrow @safe @nogc ulong Ch(ulong x,ulong y,ulong z) { return (x & y) ^ (~x & z); }
pure nothrow @safe @nogc ulong Maj(ulong x,ulong y,ulong z) { return (x & y) ^ (x & z) ^ (y & z); }
pure nothrow @safe @nogc ulong Sigma0(ulong x) { return R(x,28) ^ R(x,34) ^ R(x,39); }
pure nothrow @safe @nogc ulong Sigma1(ulong x) { return R(x,14) ^ R(x,18) ^ R(x,41); }
pure nothrow @safe @nogc ulong sigma0(ulong x) { return R(x, 1) ^ R(x, 8) ^ (x >> 7); }
pure nothrow @safe @nogc ulong sigma1(ulong x) { return R(x,19) ^ R(x,61) ^ (x >> 6); }

const ulong[80] K = [
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

const ubyte[64] iv = [
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08,
  0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b,
  0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1,
  0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b,
  0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
];


unittest {
  import nacl.basics : toBytes;
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

