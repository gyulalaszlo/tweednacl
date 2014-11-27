module nacl;

/*
   Header
   */

enum crypto_auth_PRIMITIVE = "hmacsha512256";
alias crypto_auth = crypto_auth_hmacsha512256;
alias crypto_auth_verify = crypto_auth_hmacsha512256_verify;
alias crypto_auth_BYTES = crypto_auth_hmacsha512256_BYTES;
alias crypto_auth_KEYBYTES = crypto_auth_hmacsha512256_KEYBYTES;
alias crypto_auth_IMPLEMENTATION = crypto_auth_hmacsha512256_IMPLEMENTATION;
alias crypto_auth_VERSION = crypto_auth_hmacsha512256_VERSION;
enum crypto_auth_hmacsha512256_tweet_BYTES = 32;
enum crypto_auth_hmacsha512256_tweet_KEYBYTES = 32;
extern int crypto_auth_hmacsha512256_tweet(ubyte *,const ubyte *,ulong,const ubyte *);
extern int crypto_auth_hmacsha512256_tweet_verify(const ubyte *,const ubyte *,ulong,const ubyte *);
enum crypto_auth_hmacsha512256_tweet_VERSION = "-";
alias crypto_auth_hmacsha512256 = crypto_auth_hmacsha512256_tweet;
alias crypto_auth_hmacsha512256_verify = crypto_auth_hmacsha512256_tweet_verify;
alias crypto_auth_hmacsha512256_BYTES = crypto_auth_hmacsha512256_tweet_BYTES;
alias crypto_auth_hmacsha512256_KEYBYTES = crypto_auth_hmacsha512256_tweet_KEYBYTES;
alias crypto_auth_hmacsha512256_VERSION = crypto_auth_hmacsha512256_tweet_VERSION;
enum crypto_auth_hmacsha512256_IMPLEMENTATION = "crypto_auth/hmacsha512256/tweet";

enum crypto_box_PRIMITIVE = "curve25519xsalsa20poly1305";
alias crypto_box = crypto_box_curve25519xsalsa20poly1305;
alias crypto_box_open = crypto_box_curve25519xsalsa20poly1305_open;
alias crypto_box_keypair = crypto_box_curve25519xsalsa20poly1305_keypair;
alias crypto_box_beforenm = crypto_box_curve25519xsalsa20poly1305_beforenm;
alias crypto_box_afternm = crypto_box_curve25519xsalsa20poly1305_afternm;
alias crypto_box_open_afternm = crypto_box_curve25519xsalsa20poly1305_open_afternm;
alias crypto_box_PUBLICKEYBYTES = crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES;
alias crypto_box_SECRETKEYBYTES = crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES;
alias crypto_box_BEFORENMBYTES = crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES;
alias crypto_box_NONCEBYTES = crypto_box_curve25519xsalsa20poly1305_NONCEBYTES;
alias crypto_box_ZEROBYTES = crypto_box_curve25519xsalsa20poly1305_ZEROBYTES;
alias crypto_box_BOXZEROBYTES = crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES;
alias crypto_box_IMPLEMENTATION = crypto_box_curve25519xsalsa20poly1305_IMPLEMENTATION;
alias crypto_box_VERSION = crypto_box_curve25519xsalsa20poly1305_VERSION;
enum crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES = 32;
enum crypto_box_curve25519xsalsa20poly1305_tweet_SECRETKEYBYTES = 32;
enum crypto_box_curve25519xsalsa20poly1305_tweet_BEFORENMBYTES = 32;
enum crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES = 24;
enum crypto_box_curve25519xsalsa20poly1305_tweet_ZEROBYTES = 32;
enum crypto_box_curve25519xsalsa20poly1305_tweet_BOXZEROBYTES = 16;
extern int crypto_box_curve25519xsalsa20poly1305_tweet(ubyte *,const ubyte *,ulong,const ubyte *,const ubyte *,const ubyte *);
extern int crypto_box_curve25519xsalsa20poly1305_tweet_open(ubyte *,const ubyte *,ulong,const ubyte *,const ubyte *,const ubyte *);
extern int crypto_box_curve25519xsalsa20poly1305_tweet_keypair(ubyte *,ubyte *);
extern int crypto_box_curve25519xsalsa20poly1305_tweet_beforenm(ubyte *,const ubyte *,const ubyte *);
extern int crypto_box_curve25519xsalsa20poly1305_tweet_afternm(ubyte *,const ubyte *,ulong,const ubyte *,const ubyte *);
extern int crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm(ubyte *,const ubyte *,ulong,const ubyte *,const ubyte *);
enum crypto_box_curve25519xsalsa20poly1305_tweet_VERSION = "-";
alias crypto_box_curve25519xsalsa20poly1305 = crypto_box_curve25519xsalsa20poly1305_tweet;
alias crypto_box_curve25519xsalsa20poly1305_open = crypto_box_curve25519xsalsa20poly1305_tweet_open;
alias crypto_box_curve25519xsalsa20poly1305_keypair = crypto_box_curve25519xsalsa20poly1305_tweet_keypair;
alias crypto_box_curve25519xsalsa20poly1305_beforenm = crypto_box_curve25519xsalsa20poly1305_tweet_beforenm;
alias crypto_box_curve25519xsalsa20poly1305_afternm = crypto_box_curve25519xsalsa20poly1305_tweet_afternm;
alias crypto_box_curve25519xsalsa20poly1305_open_afternm = crypto_box_curve25519xsalsa20poly1305_tweet_open_afternm;
alias crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES = crypto_box_curve25519xsalsa20poly1305_tweet_PUBLICKEYBYTES;
alias crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES = crypto_box_curve25519xsalsa20poly1305_tweet_SECRETKEYBYTES;
alias crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES = crypto_box_curve25519xsalsa20poly1305_tweet_BEFORENMBYTES;
alias crypto_box_curve25519xsalsa20poly1305_NONCEBYTES = crypto_box_curve25519xsalsa20poly1305_tweet_NONCEBYTES;
alias crypto_box_curve25519xsalsa20poly1305_ZEROBYTES = crypto_box_curve25519xsalsa20poly1305_tweet_ZEROBYTES;
alias crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES = crypto_box_curve25519xsalsa20poly1305_tweet_BOXZEROBYTES;
alias crypto_box_curve25519xsalsa20poly1305_VERSION = crypto_box_curve25519xsalsa20poly1305_tweet_VERSION;
enum crypto_box_curve25519xsalsa20poly1305_IMPLEMENTATION = "crypto_box/curve25519xsalsa20poly1305/tweet";

enum crypto_core_PRIMITIVE = "salsa20";
alias crypto_core = crypto_core_salsa20;
alias crypto_core_OUTPUTBYTES = crypto_core_salsa20_OUTPUTBYTES;
alias crypto_core_INPUTBYTES = crypto_core_salsa20_INPUTBYTES;
alias crypto_core_KEYBYTES = crypto_core_salsa20_KEYBYTES;
alias crypto_core_CONSTBYTES = crypto_core_salsa20_CONSTBYTES;
alias crypto_core_IMPLEMENTATION = crypto_core_salsa20_IMPLEMENTATION;
alias crypto_core_VERSION = crypto_core_salsa20_VERSION;
enum crypto_core_salsa20_tweet_OUTPUTBYTES = 64;
enum crypto_core_salsa20_tweet_INPUTBYTES = 16;
enum crypto_core_salsa20_tweet_KEYBYTES = 32;
enum crypto_core_salsa20_tweet_CONSTBYTES = 16;
extern int crypto_core_salsa20_tweet(ubyte *,const ubyte *,const ubyte *,const ubyte *);
enum crypto_core_salsa20_tweet_VERSION = "-";
//alias crypto_core_salsa20 = crypto_core_salsa20_tweet;
alias crypto_core_salsa20_OUTPUTBYTES = crypto_core_salsa20_tweet_OUTPUTBYTES;
alias crypto_core_salsa20_INPUTBYTES = crypto_core_salsa20_tweet_INPUTBYTES;
alias crypto_core_salsa20_KEYBYTES = crypto_core_salsa20_tweet_KEYBYTES;
alias crypto_core_salsa20_CONSTBYTES = crypto_core_salsa20_tweet_CONSTBYTES;
alias crypto_core_salsa20_VERSION = crypto_core_salsa20_tweet_VERSION;
enum crypto_core_salsa20_IMPLEMENTATION = "crypto_core/salsa20/tweet";
enum crypto_core_hsalsa20_tweet_OUTPUTBYTES = 32;
enum crypto_core_hsalsa20_tweet_INPUTBYTES = 16;
enum crypto_core_hsalsa20_tweet_KEYBYTES = 32;
enum crypto_core_hsalsa20_tweet_CONSTBYTES = 16;
//extern int crypto_core_hsalsa20_tweet(ubyte *,const ubyte *,const ubyte *,const ubyte *);
enum crypto_core_hsalsa20_tweet_VERSION = "-";
//alias crypto_core_hsalsa20 = crypto_core_hsalsa20_tweet;
alias crypto_core_hsalsa20_OUTPUTBYTES = crypto_core_hsalsa20_tweet_OUTPUTBYTES;
alias crypto_core_hsalsa20_INPUTBYTES = crypto_core_hsalsa20_tweet_INPUTBYTES;
alias crypto_core_hsalsa20_KEYBYTES = crypto_core_hsalsa20_tweet_KEYBYTES;
alias crypto_core_hsalsa20_CONSTBYTES = crypto_core_hsalsa20_tweet_CONSTBYTES;
alias crypto_core_hsalsa20_VERSION = crypto_core_hsalsa20_tweet_VERSION;
enum crypto_core_hsalsa20_IMPLEMENTATION = "crypto_core/hsalsa20/tweet";

enum crypto_hashblocks_PRIMITIVE = "sha512";
//alias crypto_hashblocks = crypto_hashblocks_sha512;
alias crypto_hashblocks_STATEBYTES = crypto_hashblocks_sha512_STATEBYTES;
alias crypto_hashblocks_BLOCKBYTES = crypto_hashblocks_sha512_BLOCKBYTES;
alias crypto_hashblocks_IMPLEMENTATION = crypto_hashblocks_sha512_IMPLEMENTATION;
alias crypto_hashblocks_VERSION = crypto_hashblocks_sha512_VERSION;
enum crypto_hashblocks_sha512_tweet_STATEBYTES = 64;
enum crypto_hashblocks_sha512_tweet_BLOCKBYTES = 128;
//extern int crypto_hashblocks_sha512_tweet(ubyte *,const ubyte *,ulong);
enum crypto_hashblocks_sha512_tweet_VERSION = "-";
//alias crypto_hashblocks_sha512 = crypto_hashblocks_sha512_tweet;
alias crypto_hashblocks_sha512_STATEBYTES = crypto_hashblocks_sha512_tweet_STATEBYTES;
alias crypto_hashblocks_sha512_BLOCKBYTES = crypto_hashblocks_sha512_tweet_BLOCKBYTES;
alias crypto_hashblocks_sha512_VERSION = crypto_hashblocks_sha512_tweet_VERSION;
enum crypto_hashblocks_sha512_IMPLEMENTATION = "crypto_hashblocks/sha512/tweet";
enum crypto_hashblocks_sha256_tweet_STATEBYTES = 32;
enum crypto_hashblocks_sha256_tweet_BLOCKBYTES = 64;
extern int crypto_hashblocks_sha256_tweet(ubyte *,const ubyte *,ulong);
enum crypto_hashblocks_sha256_tweet_VERSION = "-";
alias crypto_hashblocks_sha256 = crypto_hashblocks_sha256_tweet;
alias crypto_hashblocks_sha256_STATEBYTES = crypto_hashblocks_sha256_tweet_STATEBYTES;
alias crypto_hashblocks_sha256_BLOCKBYTES = crypto_hashblocks_sha256_tweet_BLOCKBYTES;
alias crypto_hashblocks_sha256_VERSION = crypto_hashblocks_sha256_tweet_VERSION;
enum crypto_hashblocks_sha256_IMPLEMENTATION = "crypto_hashblocks/sha256/tweet";

enum crypto_hash_PRIMITIVE = "sha512";
//alias crypto_hash = crypto_hash_sha512;
alias crypto_hash_BYTES = crypto_hash_sha512_BYTES;
alias crypto_hash_IMPLEMENTATION = crypto_hash_sha512_IMPLEMENTATION;
alias crypto_hash_VERSION = crypto_hash_sha512_VERSION;
enum crypto_hash_sha512_tweet_BYTES = 64;
//extern int crypto_hash_sha512_tweet(ubyte *,const ubyte *,ulong);
enum crypto_hash_sha512_tweet_VERSION = "-";
//alias crypto_hash_sha512 = crypto_hash_sha512_tweet;
alias crypto_hash_sha512_BYTES = crypto_hash_sha512_tweet_BYTES;
alias crypto_hash_sha512_VERSION = crypto_hash_sha512_tweet_VERSION;
enum crypto_hash_sha512_IMPLEMENTATION = "crypto_hash/sha512/tweet";
enum crypto_hash_sha256_tweet_BYTES = 32;
extern int crypto_hash_sha256_tweet(ubyte *,const ubyte *,ulong);
enum crypto_hash_sha256_tweet_VERSION = "-";
alias crypto_hash_sha256 = crypto_hash_sha256_tweet;
alias crypto_hash_sha256_BYTES = crypto_hash_sha256_tweet_BYTES;
alias crypto_hash_sha256_VERSION = crypto_hash_sha256_tweet_VERSION;
enum crypto_hash_sha256_IMPLEMENTATION = "crypto_hash/sha256/tweet";

enum crypto_onetimeauth_PRIMITIVE = "poly1305";
//alias crypto_onetimeauth = crypto_onetimeauth_poly1305;
//alias crypto_onetimeauth_verify = crypto_onetimeauth_poly1305_verify;
alias crypto_onetimeauth_BYTES = crypto_onetimeauth_poly1305_BYTES;
alias crypto_onetimeauth_KEYBYTES = crypto_onetimeauth_poly1305_KEYBYTES;
alias crypto_onetimeauth_IMPLEMENTATION = crypto_onetimeauth_poly1305_IMPLEMENTATION;
alias crypto_onetimeauth_VERSION = crypto_onetimeauth_poly1305_VERSION;
enum crypto_onetimeauth_poly1305_tweet_BYTES = 16;
enum crypto_onetimeauth_poly1305_tweet_KEYBYTES = 32;
//extern int crypto_onetimeauth_poly1305_tweet(ubyte *,const ubyte *,ulong,const ubyte *);
//extern int crypto_onetimeauth_poly1305_tweet_verify(const ubyte *,const ubyte *,ulong,const ubyte *);
enum crypto_onetimeauth_poly1305_tweet_VERSION = "-";
//alias crypto_onetimeauth_poly1305 = crypto_onetimeauth_poly1305_tweet;
//alias crypto_onetimeauth_poly1305_verify = crypto_onetimeauth_poly1305_tweet_verify;
alias crypto_onetimeauth_poly1305_BYTES = crypto_onetimeauth_poly1305_tweet_BYTES;
alias crypto_onetimeauth_poly1305_KEYBYTES = crypto_onetimeauth_poly1305_tweet_KEYBYTES;
alias crypto_onetimeauth_poly1305_VERSION = crypto_onetimeauth_poly1305_tweet_VERSION;
enum crypto_onetimeauth_poly1305_IMPLEMENTATION = "crypto_onetimeauth/poly1305/tweet";

enum crypto_scalarmult_PRIMITIVE = "curve25519";
alias crypto_scalarmult = crypto_scalarmult_curve25519;
alias crypto_scalarmult_base = crypto_scalarmult_curve25519_base;
alias crypto_scalarmult_BYTES = crypto_scalarmult_curve25519_BYTES;
alias crypto_scalarmult_SCALARBYTES = crypto_scalarmult_curve25519_SCALARBYTES;
alias crypto_scalarmult_IMPLEMENTATION = crypto_scalarmult_curve25519_IMPLEMENTATION;
alias crypto_scalarmult_VERSION = crypto_scalarmult_curve25519_VERSION;
enum crypto_scalarmult_curve25519_tweet_BYTES = 32;
enum crypto_scalarmult_curve25519_tweet_SCALARBYTES = 32;
extern int crypto_scalarmult_curve25519_tweet(ubyte *,const ubyte *,const ubyte *);
extern int crypto_scalarmult_curve25519_tweet_base(ubyte *,const ubyte *);
enum crypto_scalarmult_curve25519_tweet_VERSION = "-";
alias crypto_scalarmult_curve25519 = crypto_scalarmult_curve25519_tweet;
alias crypto_scalarmult_curve25519_base = crypto_scalarmult_curve25519_tweet_base;
alias crypto_scalarmult_curve25519_BYTES = crypto_scalarmult_curve25519_tweet_BYTES;
alias crypto_scalarmult_curve25519_SCALARBYTES = crypto_scalarmult_curve25519_tweet_SCALARBYTES;
alias crypto_scalarmult_curve25519_VERSION = crypto_scalarmult_curve25519_tweet_VERSION;
enum crypto_scalarmult_curve25519_IMPLEMENTATION = "crypto_scalarmult/curve25519/tweet";

enum crypto_secretbox_PRIMITIVE = "xsalsa20poly1305";
alias crypto_secretbox = crypto_secretbox_xsalsa20poly1305;
alias crypto_secretbox_open = crypto_secretbox_xsalsa20poly1305_open;
alias crypto_secretbox_KEYBYTES = crypto_secretbox_xsalsa20poly1305_KEYBYTES;
alias crypto_secretbox_NONCEBYTES = crypto_secretbox_xsalsa20poly1305_NONCEBYTES;
alias crypto_secretbox_ZEROBYTES = crypto_secretbox_xsalsa20poly1305_ZEROBYTES;
alias crypto_secretbox_BOXZEROBYTES = crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES;
alias crypto_secretbox_IMPLEMENTATION = crypto_secretbox_xsalsa20poly1305_IMPLEMENTATION;
alias crypto_secretbox_VERSION = crypto_secretbox_xsalsa20poly1305_VERSION;
enum crypto_secretbox_xsalsa20poly1305_tweet_KEYBYTES = 32;
enum crypto_secretbox_xsalsa20poly1305_tweet_NONCEBYTES = 24;
enum crypto_secretbox_xsalsa20poly1305_tweet_ZEROBYTES = 32;
enum crypto_secretbox_xsalsa20poly1305_tweet_BOXZEROBYTES = 16;
extern int crypto_secretbox_xsalsa20poly1305_tweet(ubyte *,const ubyte *,ulong,const ubyte *,const ubyte *);
extern int crypto_secretbox_xsalsa20poly1305_tweet_open(ubyte *,const ubyte *,ulong,const ubyte *,const ubyte *);
enum crypto_secretbox_xsalsa20poly1305_tweet_VERSION = "-";
alias crypto_secretbox_xsalsa20poly1305 = crypto_secretbox_xsalsa20poly1305_tweet;
alias crypto_secretbox_xsalsa20poly1305_open = crypto_secretbox_xsalsa20poly1305_tweet_open;
alias crypto_secretbox_xsalsa20poly1305_KEYBYTES = crypto_secretbox_xsalsa20poly1305_tweet_KEYBYTES;
alias crypto_secretbox_xsalsa20poly1305_NONCEBYTES = crypto_secretbox_xsalsa20poly1305_tweet_NONCEBYTES;
alias crypto_secretbox_xsalsa20poly1305_ZEROBYTES = crypto_secretbox_xsalsa20poly1305_tweet_ZEROBYTES;
alias crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES = crypto_secretbox_xsalsa20poly1305_tweet_BOXZEROBYTES;
alias crypto_secretbox_xsalsa20poly1305_VERSION = crypto_secretbox_xsalsa20poly1305_tweet_VERSION;
enum crypto_secretbox_xsalsa20poly1305_IMPLEMENTATION = "crypto_secretbox/xsalsa20poly1305/tweet";

enum crypto_sign_PRIMITIVE = "ed25519";
alias crypto_sign = crypto_sign_ed25519;
alias crypto_sign_open = crypto_sign_ed25519_open;
alias crypto_sign_keypair = crypto_sign_ed25519_keypair;
alias crypto_sign_BYTES = crypto_sign_ed25519_BYTES;
alias crypto_sign_PUBLICKEYBYTES = crypto_sign_ed25519_PUBLICKEYBYTES;
alias crypto_sign_SECRETKEYBYTES = crypto_sign_ed25519_SECRETKEYBYTES;
alias crypto_sign_IMPLEMENTATION = crypto_sign_ed25519_IMPLEMENTATION;
alias crypto_sign_VERSION = crypto_sign_ed25519_VERSION;
enum crypto_sign_ed25519_tweet_BYTES = 64;
enum crypto_sign_ed25519_tweet_PUBLICKEYBYTES = 32;
enum crypto_sign_ed25519_tweet_SECRETKEYBYTES = 64;
extern int crypto_sign_ed25519_tweet(ubyte *,ulong *,const ubyte *,ulong,const ubyte *);
extern int crypto_sign_ed25519_tweet_open(ubyte *,ulong *,const ubyte *,ulong,const ubyte *);
extern int crypto_sign_ed25519_tweet_keypair(ubyte *,ubyte *);
enum crypto_sign_ed25519_tweet_VERSION = "-";
alias crypto_sign_ed25519 = crypto_sign_ed25519_tweet;
alias crypto_sign_ed25519_open = crypto_sign_ed25519_tweet_open;
alias crypto_sign_ed25519_keypair = crypto_sign_ed25519_tweet_keypair;
alias crypto_sign_ed25519_BYTES = crypto_sign_ed25519_tweet_BYTES;
alias crypto_sign_ed25519_PUBLICKEYBYTES = crypto_sign_ed25519_tweet_PUBLICKEYBYTES;
alias crypto_sign_ed25519_SECRETKEYBYTES = crypto_sign_ed25519_tweet_SECRETKEYBYTES;
alias crypto_sign_ed25519_VERSION = crypto_sign_ed25519_tweet_VERSION;
enum crypto_sign_ed25519_IMPLEMENTATION = "crypto_sign/ed25519/tweet";

enum crypto_stream_PRIMITIVE = "xsalsa20";
//alias crypto_stream = crypto_stream_xsalsa20;
//alias crypto_stream_xor = crypto_stream_xsalsa20_xor;
alias crypto_stream_KEYBYTES = crypto_stream_xsalsa20_KEYBYTES;
alias crypto_stream_NONCEBYTES = crypto_stream_xsalsa20_NONCEBYTES;
alias crypto_stream_IMPLEMENTATION = crypto_stream_xsalsa20_IMPLEMENTATION;
alias crypto_stream_VERSION = crypto_stream_xsalsa20_VERSION;
enum crypto_stream_xsalsa20_tweet_KEYBYTES = 32;
enum crypto_stream_xsalsa20_tweet_NONCEBYTES = 24;
extern int crypto_stream_xsalsa20_tweet(ubyte *,ulong,const ubyte *,const ubyte *);
extern int crypto_stream_xsalsa20_tweet_xor(ubyte *,const ubyte *,ulong,const ubyte *,const ubyte *);
enum crypto_stream_xsalsa20_tweet_VERSION = "-";
alias crypto_stream_xsalsa20 = crypto_stream_xsalsa20_tweet;
alias crypto_stream_xsalsa20_xor = crypto_stream_xsalsa20_tweet_xor;
alias crypto_stream_xsalsa20_KEYBYTES = crypto_stream_xsalsa20_tweet_KEYBYTES;
alias crypto_stream_xsalsa20_NONCEBYTES = crypto_stream_xsalsa20_tweet_NONCEBYTES;
alias crypto_stream_xsalsa20_VERSION = crypto_stream_xsalsa20_tweet_VERSION;
enum crypto_stream_xsalsa20_IMPLEMENTATION = "crypto_stream/xsalsa20/tweet";
enum crypto_stream_salsa20_tweet_KEYBYTES = 32;
enum crypto_stream_salsa20_tweet_NONCEBYTES = 8;
//extern int crypto_stream_salsa20_tweet(ubyte *,ulong,const ubyte *,const ubyte *);
//extern int crypto_stream_salsa20_tweet_xor(ubyte *,const ubyte *,ulong,const ubyte *,const ubyte *);
enum crypto_stream_salsa20_tweet_VERSION = "-";
//alias crypto_stream_salsa20 = crypto_stream_salsa20_tweet;
//alias crypto_stream_salsa20_xor = crypto_stream_salsa20_tweet_xor;
alias crypto_stream_salsa20_KEYBYTES = crypto_stream_salsa20_tweet_KEYBYTES;
alias crypto_stream_salsa20_NONCEBYTES = crypto_stream_salsa20_tweet_NONCEBYTES;
alias crypto_stream_salsa20_VERSION = crypto_stream_salsa20_tweet_VERSION;
enum crypto_stream_salsa20_IMPLEMENTATION = "crypto_stream/salsa20/tweet";

enum crypto_verify_PRIMITIVE = "16";
//alias crypto_verify = crypto_verify_16;
alias crypto_verify_BYTES = crypto_verify_16_BYTES;
alias crypto_verify_IMPLEMENTATION = crypto_verify_16_IMPLEMENTATION;
alias crypto_verify_VERSION = crypto_verify_16_VERSION;
enum crypto_verify_16_tweet_BYTES = 16;
//extern int crypto_verify_16_tweet(const ubyte *,const ubyte *);
enum crypto_verify_16_tweet_VERSION = "-";
//alias crypto_verify_16 = crypto_verify_16_tweet;
alias crypto_verify_16_BYTES = crypto_verify_16_tweet_BYTES;
alias crypto_verify_16_VERSION = crypto_verify_16_tweet_VERSION;
enum crypto_verify_16_IMPLEMENTATION = "crypto_verify/16/tweet";
enum crypto_verify_32_tweet_BYTES = 32;
//extern int crypto_verify_32_tweet(const ubyte *,const ubyte *);
enum crypto_verify_32_tweet_VERSION = "-";
//alias crypto_verify_32 = crypto_verify_32_tweet;
alias crypto_verify_32_BYTES = crypto_verify_32_tweet_BYTES;
alias crypto_verify_32_VERSION = crypto_verify_32_tweet_VERSION;
enum crypto_verify_32_IMPLEMENTATION = "crypto_verify/32/tweet";

/*
   internal types
   */
alias gf = long[16];

extern (C) void randombytes(ubyte *,ulong);

private immutable ubyte[16] _0 = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
private immutable ubyte[32] _9 = [9,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];

private const gf gf0;
private const gf gf1 = [1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
private const gf _121665 = [0xDB41,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
private const gf
  D = [0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203];
private const gf
  D2 = [0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406];
private const gf
  X = [0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169];
private const gf
  Y = [0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666];
private const gf
  I = [0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83];

private uint L32(uint x,int c) { return (x << c) | ((x&0xffffffff) >> (32 - c)); }

private uint ld32(const ubyte* x)
{
  uint u = x[3];
  u = (u<<8)|x[2];
  u = (u<<8)|x[1];
  return (u<<8)|x[0];
}

private ulong dl64(const ubyte *x)
{
  ulong u=0;
  foreach(ulong i;0..8) u=(u<<8)|x[i];
  return u;
}

private void st32(ubyte *x,uint u)
{
  foreach(i;0..4) { x[i] = cast(ubyte)(u); u >>= 8; }
}

private void ts64(ubyte *x,ulong u)
{
  int i;
  for (i = 7;i >= 0;--i) { x[i] = cast(ubyte)(u); u >>= 8; }
}

/** Compares byte arrays in constant time. */
private int vn(const ubyte[] x,const ubyte[] y,int n)
{
  uint d = 0;
  foreach(i;0..n) d |= x[i]^y[i];
  return (1 & ((d - 1) >> 8)) - 1;
}

int crypto_verify_16(const ubyte[] x,const ubyte[] y)
{
  return vn(x,y,16);
}

int crypto_verify_32(const ubyte[] x,const ubyte[] y)
{
  return vn(x,y,32);
}

private void core(ubyte[] output,const ubyte[] input,const ubyte[] k,const ubyte[] c,int h)
{
  uint[16] w,x,y;
  uint[4] t;

  foreach(i;0..4) {
    x[5*i] = ld32(&c[4*i]);
    x[1+i] = ld32(&k[4*i]);
    x[6+i] = ld32(&input[4*i]);
    x[11+i] = ld32(&k[16+4*i]);
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

  if (h) {
    foreach(i;0..16) x[i] += y[i];
    foreach(i;0..4) {
      x[5*i] -= ld32(&c[4*i]);
      x[6+i] -= ld32(&input[4*i]);
    }
    foreach(i;0..4) {
      st32(&output[4*i],x[5*i]);
      st32(&output[16+4*i],x[6+i]);
    }
  } else
    foreach(i;0..16) st32(&output[4*i],x[i] + y[i]);
}

int crypto_core_salsa20(ubyte[] output,const ubyte[] input,const ubyte[] k,const ubyte[] c)
{
  core(output,input,k,c,0);
  return 0;
}

int crypto_core_hsalsa20(ubyte[] output,const ubyte[] input,const ubyte[] k,const ubyte[] c)
{
  core(output,input,k,c,1);
  return 0;
}

/*
   Core tests from libSodium
 */

unittest {
  //#define TEST_NAME "core1"
  ubyte[32] shared_
    = [ 0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b,
      0xf4, 0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1,
      0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42 ];
  ubyte[32] zero;
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
  //#define TEST_NAME "core2"
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
  crypto_core_hsalsa20(secondkey, nonceprefix, firstkey, c);

  assert( secondkey == [ 0xdc,0x90,0x8d,0xda,0x0b,0x93,0x44,0xa9
      ,0x53,0x62,0x9b,0x73,0x38,0x20,0x77,0x88
      ,0x80,0xf3,0xce,0xb4,0x21,0xbb,0x61,0xb9
      ,0x1c,0xbd,0x4c,0x3e,0x66,0x25,0x6c,0xe4]);
}

unittest {
  //#define TEST_NAME "core3"
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
      crypto_core_salsa20(output[pos..pos+64], input, secondkey, c);
      pos += 64;
    } while (++input[8]);
  } while (++input[9]);

  import std.digest.sha;

  // The results of D's sha512_256 does not match Sodiums sha256
  // result here:
  // 662b9d0e3463029156069b12f918691a98f7dfb2ca0393c96bbfc6b1fbd630a2
  // vs
  // 72676E4246DDF2C5797DB1E3FA49FF335EF76C622F4C78FEEBEDAD67DE7FB447
  static if (false) {
    assert( toHexString(sha512_256Of(output[])) ==
        "662B9D0E3463029156069B12F918691A98F7DFB2CA0393C96BBFC6B1FBD630A2"
        );
  }

  crypto_hash(h, output);

  assert( toHexString(sha512Of(output[])) ==
      "2BD8E7DB6877539E4F2B295EE415CD378AE214AA3BEB3E08E911A5BD4A25E6AC16CA283C79C34C08C99F7BDB560111E8CAC1AE65EEA08AC384D7A591461AB6E3"
      );


  assert( h == sha512Of(output[]) );
  // TODO: check if this SHA512 is valid
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

int crypto_stream_salsa20_xor(ubyte[] c,const(ubyte)[] m,ulong b,const(ubyte)[] n,const(ubyte)[] k)
{
  return crypto_stream_salsa20_xor_impl!true(c,m,b,n,k);
}

private const(const(ubyte)[]) nullBytes = [];

int crypto_stream_salsa20_xor(ubyte[] c,ulong b,const(ubyte)[] n,const(ubyte)[] k)
{
  return crypto_stream_salsa20_xor_impl!false(c,nullBytes,b,n,k);
}

import std.stdio;
private int crypto_stream_salsa20_xor_impl(bool useMessage=true)(ubyte[] c,const(ubyte)[] m,ulong b,const(ubyte)[] n,const(ubyte)[] k)
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
      foreach(i;0..b) c[i] = (m?m[i]:0) ^ x[i];
    else
      foreach(i;0..b) c[i] = 0 ^ x[i];
  }
  return 0;
}

int crypto_stream_salsa20(ubyte[] c,ulong d,const(ubyte)[] n,const(ubyte)[] k)
{
  //return crypto_stream_salsa20_xor(c,null,d,n,k);
  return crypto_stream_salsa20_xor(c,d,n,k);
}

int crypto_stream(ubyte[] c,ulong d,const(ubyte)[] n,const(ubyte)[] k)
{
  ubyte s[32];
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20(c,d,n[16..$],s);
}

int crypto_stream_xor(ubyte[] c,const(ubyte)[] m,ulong d,const(ubyte)[] n,const(ubyte)[] k)
{
  ubyte s[32];
  crypto_core_hsalsa20(s,n,k,sigma);
  return crypto_stream_salsa20_xor(c,m,d,n[16..$],s);
}

/*
   Sodium Stream tests
 */

unittest {
  //#define TEST_NAME "stream"

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
  //#define TEST_NAME "stream2"
  ubyte output[4194304];
  ubyte h[32];

  crypto_stream_salsa20(output, 4194304,
      [0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
      [ 0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9, 0x53, 0x62, 0x9b,
      0x73, 0x38, 0x20, 0x77, 0x88, 0x80, 0xf3, 0xce, 0xb4, 0x21, 0xbb,
      0x61, 0xb9, 0x1c, 0xbd, 0x4c, 0x3e, 0x66, 0x25, 0x6c, 0xe4]);

  import std.digest.sha;
  assert( toHexString(sha256Of(output[])) == "662B9D0E3463029156069B12F918691A98F7DFB2CA0393C96BBFC6B1FBD630A2" );
}


unittest {
  //#define TEST_NAME "stream3"
  ubyte[32] rs;
  crypto_stream(rs, 32,
      // noonce
      [0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
      0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
      0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37],
      // firstkey
      [0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51,
      0x19, 0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64,
      0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89]);

  assert( rs == [
      0xee,0xa6,0xa7,0x25,0x1c,0x1e,0x72,0x91
      ,0x6d,0x11,0xc2,0xcb,0x21,0x4d,0x3c,0x25
      ,0x25,0x39,0x12,0x1d,0x8e,0x23,0x4e,0x65
      ,0x2d,0x65,0x1f,0xa4,0xc8,0xcf,0xf8,0x80
      ] );
}

unittest {
  //#define TEST_NAME "stream4"
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

private void add1305(uint[] h,const uint[] c)
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

  C NaCl provides a crypto_onetimeauth function callable as follows:

     #include "crypto_onetimeauth.h"

     const unsigned char k[crypto_onetimeauth_KEYBYTES];
     const unsigned char m[...]; unsigned long long mlen;
     unsigned char a[crypto_onetimeauth_BYTES];

     crypto_onetimeauth(a,m,mlen,k);

  The crypto_onetimeauth function authenticates a message m[0], m[1], ...,
  m[mlen-1] using a secret key k[0], k[1], ..., k[crypto_onetimeauth_KEYBYTES-1];
  puts the authenticator into a[0], a[1], ..., a[crypto_onetimeauth_BYTES-1]; and
  returns 0.

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
int crypto_onetimeauth(ubyte[] output,const(ubyte)[] m,const ubyte[] k)
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

bool crypto_onetimeauth_verify(const ubyte[] h,const ubyte[] m,const ubyte[] k)
{
  ubyte x[16];
  crypto_onetimeauth(x,m,k);
  return (crypto_verify_16(h,x) == 0);
}


unittest {
  //#define TEST_NAME "onetimeauth"

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
  ubyte[] sig = [ 0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5,
        0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9 ];
  ubyte a[16];

  crypto_onetimeauth(a, c, rs);
  assert( a == sig);
  assert( crypto_onetimeauth_verify(a, c, rs));
  assert( crypto_onetimeauth_verify( sig, c, rs));
}


unittest {
  // This test may eat a lot of cycles if clen is incremented one-at-a-time

  import std.stdio;
  import std.random;
  //#define TEST_NAME "onetimeauth7"
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

/*
int crypto_secretbox(ubyte *c,const ubyte *m,ulong d,const ubyte *n,const ubyte *k)
{
  int i;
  if (d < 32) return -1;
  crypto_stream_xor(c,m,d,n,k);
  crypto_onetimeauth(c + 16,c + 32,d - 32,c);
  foreach(i;0..16) c[i] = 0;
  return 0;
}

int crypto_secretbox_open(ubyte *m,const ubyte *c,ulong d,const ubyte *n,const ubyte *k)
{
  int i;
  ubyte x[32];
  if (d < 32) return -1;
  crypto_stream(x,32,n,k);
  if (crypto_onetimeauth_verify(c + 16,c + 32,d - 32,x) != 0) return -1;
  crypto_stream_xor(m,c,d,n,k);
  foreach(i;0..32) m[i] = 0;
  return 0;
}

private void set25519(gf r, const gf a)
{
  int i;
  foreach(i;0..16) r[i]=a[i];
}

private void car25519(gf o)
{
  int i;
  long c;
  foreach(i;0..16) {
    o[i]+=(long(1)<<16);
    c=o[i]>>16;
    o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
    o[i]-=c<<16;
  }
}

private void sel25519(gf p,gf q,int b)
{
  long t,i,c=~(b-1);
  foreach(i;0..16) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

private void pack25519(ubyte *o,const gf n)
{
  int i,j,b;
  gf m,t;
  foreach(i;0..16) t[i]=n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  foreach(j;0..2) {
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++) {
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
    o[2*i+1]=t[i]>>8;
  }
}

private int neq25519(const gf a, const gf b)
{
  ubyte[32] c,d;
  pack25519(c,a);
  pack25519(d,b);
  return crypto_verify_32(c,d);
}

private ubyte par25519(const gf a)
{
  ubyte d[32];
  pack25519(d,a);
  return d[0]&1;
}

private void unpack25519(gf o, const ubyte *n)
{
  int i;
  foreach(i;0..16) o[i]=n[2*i]+(long(n[2*i+1])<<8);
  o[15]&=0x7fff;
}

private void A(gf o,const gf a,const gf b)
{
  int i;
  foreach(i;0..16) o[i]=a[i]+b[i];
}

private void Z(gf o,const gf a,const gf b)
{
  int i;
  foreach(i;0..16) o[i]=a[i]-b[i];
}

private void M(gf o,const gf a,const gf b)
{
  long i,j;
  long t[31];
  foreach(i;0..31) t[i]=0;
  foreach(i;0..16) foreach(j;0..16) t[i+j]+=a[i]*b[j];
  foreach(i;0..15) t[i]+=38*t[i+16];
  foreach(i;0..16) o[i]=t[i];
  car25519(o);
  car25519(o);
}

private void S(gf o,const gf a)
{
  M(o,a,a);
}

private void inv25519(gf o,const gf i)
{
  gf c;
  int a;
  foreach(a;0..16) c[a]=i[a];
  for(a=253;a>=0;a--) {
    S(c,c);
    if(a!=2&&a!=4) M(c,c,i);
  }
  foreach(a;0..16) o[a]=c[a];
}

private void pow2523(gf o,const gf i)
{
  gf c;
  int a;
  foreach(a;0..16) c[a]=i[a];
  for(a=250;a>=0;a--) {
    S(c,c);
    if(a!=1) M(c,c,i);
  }
  foreach(a;0..16) o[a]=c[a];
}

int crypto_scalarmult(ubyte *q,const ubyte *n,const ubyte *p)
{
  ubyte z[32];
  long[80] x;
  long r,i;
  gf a,b,c,d,e,f;
  foreach(i;0..31) z[i]=n[i];
  z[31]=(n[31]&127)|64;
  z[0]&=248;
  unpack25519(x,p);
  foreach(i;0..16) {
    b[i]=x[i];
    d[i]=a[i]=c[i]=0;
  }
  a[0]=d[0]=1;
  for(i=254;i>=0;--i) {
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
    M(d,b,x);
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
  inv25519(x+32,x+32);
  M(x+16,x+16,x+32);
  pack25519(q,x+16);
  return 0;
}

int crypto_scalarmult_base(ubyte *q,const ubyte *n)
{ 
  return crypto_scalarmult(q,n,_9);
}

int crypto_box_keypair(ubyte *y,ubyte *x)
{
  randombytes(x,32);
  return crypto_scalarmult_base(y,x);
}

int crypto_box_beforenm(ubyte *k,const ubyte *y,const ubyte *x)
{
  ubyte s[32];
  crypto_scalarmult(s,x,y);
  return crypto_core_hsalsa20(k,_0,s,sigma);
}

int crypto_box_afternm(ubyte *c,const ubyte *m,ulong d,const ubyte *n,const ubyte *k)
{
  return crypto_secretbox(c,m,d,n,k);
}

int crypto_box_open_afternm(ubyte *m,const ubyte *c,ulong d,const ubyte *n,const ubyte *k)
{
  return crypto_secretbox_open(m,c,d,n,k);
}

int crypto_box(ubyte *c,const ubyte *m,ulong d,const ubyte *n,const ubyte *y,const ubyte *x)
{
  ubyte k[32];
  crypto_box_beforenm(k,y,x);
  return crypto_box_afternm(c,m,d,n,k);
}

int crypto_box_open(ubyte *m,const ubyte *c,ulong d,const ubyte *n,const ubyte *y,const ubyte *x)
{
  ubyte k[32];
  crypto_box_beforenm(k,y,x);
  return crypto_box_open_afternm(m,c,d,n,k);
}
*/

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

/*

   C Code
   ------

  int crypto_hashblocks(u8 *x,const u8 *m,u64 n)
  {
    u64 z[8],b[8],a[8],w[16],t;
    int i,j;

    FOR(i,8) z[i] = a[i] = dl64(x + 8 * i);

    while (n >= 128) {
      FOR(i,16) w[i] = dl64(m + 8 * i);

      FOR(i,80) {
        FOR(j,8) b[j] = a[j];
        t = a[7] + Sigma1(a[4]) + Ch(a[4],a[5],a[6]) + K[i] + w[i%16];
        b[7] = t + Sigma0(a[0]) + Maj(a[0],a[1],a[2]);
        b[3] += t;
        FOR(j,8) a[(j+1)%8] = b[j];
        if (i%16 == 15)
    FOR(j,16)
      w[j] += w[(j+9)%16] + sigma0(w[(j+1)%16]) + sigma1(w[(j+14)%16]);
      }

      FOR(i,8) { a[i] += z[i]; z[i] = a[i]; }

      m += 128;
      n -= 128;
    }

    FOR(i,8) ts64(x+8*i,z[i]);

    return n;
  }

*/

size_t crypto_hashblocks(ubyte[] x,const(ubyte)[] m,size_t n)
{
  ulong[8] z,b,a;
  ulong w[16];
  ulong t;

  foreach(i;0..8) z[i] = a[i] = dl64(&x[8 * i]);

  while (n >= 128) {
    foreach(i;0..16) w[i] = dl64(&m[8 * i]);

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

  foreach(i;0..8) ts64(&x[8*i],z[i]);

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

/*

  C Code:
  -------

  int crypto_hash(u8 *out,const u8 *m,u64 n)
  {
    u8 h[64],x[256];
    u64 i,b = n;

    FOR(i,64) h[i] = iv[i];

    crypto_hashblocks(h,m,n);
    m += n;
    n &= 127;
    m -= n;

    FOR(i,256) x[i] = 0;
    FOR(i,n) x[i] = m[i];
    x[n] = 128;

    n = 256-128*(n<112);
    x[n-9] = b >> 61;
    ts64(x+n-8,b<<3);
    crypto_hashblocks(h,x,n);

    FOR(i,64) out[i] = h[i];

    return 0;
  }

*/

int crypto_hash(ubyte[] output,const(ubyte)[] m )
{
  size_t n = m.length;
  ubyte[64] h;
  ubyte[256] x;
  ulong b = n;

  foreach(i;0..64) h[i] = iv[i];

  crypto_hashblocks(h,m,n);
  m = m[n - (n & 127)..$];
  n &= 127;

  foreach(i;0..256) x[i] = 0;
  foreach(i;0..n) x[i] = m[i];
  x[n] = 128;

  n = 256-128*(n<112);
  x[n-9] = b >> 61;
  ts64(&x[n-8],b<<3);
  crypto_hashblocks(h,x,n);

  foreach(i;0..64) output[i] = h[i];

  return 0;
}


/**
  Converts any array slice into a byte array slice.
  */
const(ubyte)[] toBytes(T)(T[] input)
{
  return (cast(const(ubyte)*)(&input[0]))[0..(input.length*T.sizeof)];
}

unittest {
  import std.stdio;
  //#define TEST_NAME "hash"
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


/*

private void add(gf p[4],gf q[4])
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

private void cswap(gf p[4],gf q[4],ubyte b)
{
  int i;
  foreach(i;0..4)
    sel25519(p[i],q[i],b);
}

private void pack(ubyte *r,gf p[4])
{
  gf tx, ty, zi;
  inv25519(zi, p[2]); 
  M(tx, p[0], zi);
  M(ty, p[1], zi);
  pack25519(r, ty);
  r[31] ^= par25519(tx) << 7;
}

private void scalarmult(gf p[4],gf q[4],const ubyte *s)
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

private void scalarbase(gf p[4],const ubyte *s)
{
  gf q[4];
  set25519(q[0],X);
  set25519(q[1],Y);
  set25519(q[2],gf1);
  M(q[3],X,Y);
  scalarmult(p,q,s);
}

int crypto_sign_keypair(ubyte *pk, ubyte *sk)
{
  ubyte d[64];
  gf p[4];
  int i;

  randombytes(sk, 32);
  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  scalarbase(p,d);
  pack(pk,p);

  foreach(i;0..32) sk[32 + i] = pk[i];
  return 0;
}

private const ulong L[32] = [0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10];

private void modL(ubyte *r,long x[64])
{
  long carry,i,j;
  for (i = 63;i >= 32;--i) {
    carry = 0;
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

private void reduce(ubyte *r)
{
  long[64] x;
  long i;
  foreach(i;0..64) x[i] = ulong(r[i]);
  foreach(i;0..64) r[i] = 0;
  modL(r,x);
}

int crypto_sign(ubyte *sm,ulong *smlen,const ubyte *m,ulong n,const ubyte *sk)
{
  ubyte[64] d,h,r;
  long i,j;
  long[64] x;
  gf p[4];

  crypto_hash(d, sk, 32);
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;

  *smlen = n+64;
  foreach(i;0..n) sm[64 + i] = m[i];
  foreach(i;0..32) sm[32 + i] = d[32 + i];

  crypto_hash(r, sm+32, n+32);
  reduce(r);
  scalarbase(p,r);
  pack(sm,p);

  foreach(i;0..32) sm[i+32] = sk[i+32];
  crypto_hash(h,sm,n + 64);
  reduce(h);

  foreach(i;0..64) x[i] = 0;
  foreach(i;0..32) x[i] = ulong(r[i]);
  foreach(i;0..32) foreach(j;0..32) x[i+j] += h[i] * ulong(d[j]);
  modL(sm + 32,x);

  return 0;
}

private int unpackneg(gf r[4],const ubyte p[32])
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
  if (neq25519(chk, num)) return -1;

  if (par25519(r[0]) == (p[31]>>7)) Z(r[0],gf0,r[0]);

  M(r[3],r[0],r[1]);
  return 0;
}

int crypto_sign_open(ubyte *m,ulong *mlen,const ubyte *sm,ulong n,const ubyte *pk)
{
  int i;
  ubyte[32] t;
  ubyte[64] h;
  gf[4] p,q;

  *mlen = -1;
  if (n < 64) return -1;

  if (unpackneg(q,pk)) return -1;

  foreach(i;0..n) m[i] = sm[i];
  foreach(i;0..32) m[i+32] = pk[i];
  crypto_hash(h,m,n);
  reduce(h);
  scalarmult(p,q,h);

  scalarbase(q,sm + 32);
  add(p,q);
  pack(t,p);

  n -= 64;
  if (crypto_verify_32(sm, t)) {
    foreach(i;0..n) m[i] = 0;
    return -1;
  }

  foreach(i;0..n) m[i] = sm[i + 64];
  *mlen = n;
  return 0;
}

*/
