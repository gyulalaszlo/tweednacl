module bench;

static import std.digest.sha;
import std.datetime;
import std.stdio;

import tweednacl;
import tweednacl.xsalsa20poly1305;
import tweednacl.sha512;
import tweednacl.basics;
import tweednacl.nacl;

enum DefaultC = 1024;

struct TestData {
  size_t repeats;
  size_t bufferSize;
}

// A wrapper for std.digest hash types
struct StdDigest(Digest)
{
  mixin SHA512Algorithm!("crypto_hashblocks/sha512/tweet");

  static pure nothrow @safe
  void hash( ref Value output, const(ubyte)[] m )
  {
    output = std.digest.digest.digest!Digest( m );
  }

}

//crypto_hash_sha512_tweet
extern (C) int crypto_hash_sha512(ubyte*,const ubyte*, ulong);
extern (C) int crypto_hash_sha512_tweet(ubyte*,const ubyte*, ulong);
extern (C) int crypto_secretbox_xsalsa20poly1305(ubyte *,const ubyte *,ulong,const ubyte *,const ubyte *);
extern (C) int crypto_secretbox_xsalsa20poly1305_open(ubyte *,const ubyte *,ulong,const ubyte *,const ubyte *);
extern (C) int crypto_secretbox_xsalsa20poly1305_tweet(ubyte *,const ubyte *,ulong,const ubyte *,const ubyte *);
extern (C) int crypto_secretbox_xsalsa20poly1305_tweet_open(ubyte *,const ubyte *,ulong,const ubyte *,const ubyte *);

struct NaCl512(alias crypto_hash)
{
  mixin SHA512Algorithm!("crypto_hashblocks/sha512/nacl");

  static @system
  void hash( ref Value output, const(ubyte)[] m )
  {
    crypto_hash( &output[0], &m[0], m.length );
  }
}


struct NaClXSalsa20Poly1305(alias crypto_box, alias crypto_box_open) {
  mixin XSalsa20Poly1305Implementation!"crypto_secretbox/xsalsa20poly1305/nacl";

  alias secretbox = crypto_secretbox;
  alias secretboxOpen = crypto_secretbox_open;


  static bool box(
      ubyte[] c,const ubyte[] m,
      ref const XSalsa20Poly1305.Nonce n,
      ref const XSalsa20Poly1305.Key k)
  {
    return crypto_box(
        &c[0], &m[0], m.length, &n[0], &k[0]
        ) == 0;
  }


  static bool boxOpen(
    ubyte[] m, const ubyte[] c,
    ref const XSalsa20Poly1305.Nonce n,
    ref const XSalsa20Poly1305.Key k)
  {
    return crypto_box_open(
        &m[0], &c[0], c.length, &n[0], &k[0]
        ) == 0;
  }

  alias afternm = box;
  alias openAfternm = boxOpen;

  alias Beforenm = Key;
}


//extern void randombytes(u8 *,u64);
extern (C) void randombytes(ubyte* b, ulong l)
{
  safeRandomBytes(b[0..l], l);
}


void testHash(H)( immutable TestData testData, string label="")
{
  ubyte[] d;
  d.length = testData.bufferSize;

  unSafeRandomBytes( d );
  auto sw = StopWatch(AutoStart.yes);

  H.Value h;
  foreach(i;0..testData.repeats)
  {
    H.hash(h,d);
  }

  auto a = sw.peek();
  auto perIteration = a / testData.repeats;
  auto perBytes = perIteration / testData.bufferSize;
  writefln("%s %s %s bytes\t%s",
      primitiveName!H,
      label,
      testData.bufferSize,
      perBytes.nsecs );
}



void testSecretBox(C)( immutable TestData testData, string label="")
{
  import tweednacl.nonce_generator;
  ubyte[] d, o;
  C.Key k;
  C.Nonce n;
  d.length = testData.bufferSize + C.ZeroBytes;
  unSafeRandomBytes( d );
  d[0..C.ZeroBytes] = 0;
  o.length = testData.bufferSize + C.ZeroBytes;

  // key
  unSafeRandomBytes( k );

  // nonce
  unSafeRandomBytes( n );

  void traceRound( ref StopWatch sw, TestData testData, string roundLabel )
  {
    auto a = sw.peek();
    auto perIteration = a / testData.repeats;
    auto perBytes = perIteration / testData.bufferSize;
    writefln("%s %s %s bytes %s\t%s",
        primitiveName!C,
        label,
        testData.bufferSize,
        roundLabel,
        perBytes.nsecs );
  }


  {
    auto sw = StopWatch(AutoStart.yes);
    foreach(i;0..testData.repeats)
    {
      C.box( o, d, n, k );
    }
    traceRound( sw, testData, "box" );
  }
  {
    auto sw = StopWatch(AutoStart.yes);
    foreach(i;0..testData.repeats)
    {
      C.boxOpen( d, o, n, k );
    }
    traceRound( sw, testData, "open" );
  }
}


void testHashes( size_t bufSize )
{
    immutable hashParams = TestData( 1024, bufSize );
    testHash!(StdDigest!(std.digest.sha.SHA512))( hashParams, "std");

    testHash!(SHA512)( hashParams, "D");
    testHash!(NaCl512!crypto_hash_sha512_tweet)( hashParams, "tweet");
    testHash!(NaCl512!crypto_hash_sha512)( hashParams, "sodium");

}

void testSecretbox( size_t bufSize )
{
    immutable hashParams = TestData( 1024, bufSize );
    testSecretBox!(XSalsa20Poly1305)( hashParams, "D");
    testSecretBox!(
        NaClXSalsa20Poly1305!(
          crypto_secretbox_xsalsa20poly1305_tweet,
          crypto_secretbox_xsalsa20poly1305_tweet_open,
          ))( hashParams, "tweet");
    testSecretBox!(
        NaClXSalsa20Poly1305!(
          crypto_secretbox_xsalsa20poly1305,
          crypto_secretbox_xsalsa20poly1305_open,
          ))( hashParams, "sodium");
    //testSecretBox!(NaClXSalsa20Poly1305!crypto_secretbox_xsalsa20poly1305)( hashParams, "sodium");
    //testHash!(StdDigest!(std.digest.sha.SHA512))( hashParams, "std");

    //testHash!(SHA512)( hashParams, "D");
    //testHash!(NaCl512!crypto_hash_sha512_tweet)( hashParams, "tweet");
    //testHash!(NaCl512!crypto_hash_sha512)( hashParams, "sodium");

}


void runBench(alias test)()
{

  foreach(i;2..12)
  {
    immutable bufSize = 2 << i;
    test( bufSize );
    writeln();
  }
}






void main(string[] args)
{
  runBench!( (b) => testHashes(b) );
  runBench!( (b) => testSecretbox(b) );
}
