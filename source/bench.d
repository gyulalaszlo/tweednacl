module bench;

static import std.digest.sha;
import std.datetime;
import std.stdio;
import std.string;

import tweednacl;
import tweednacl.xsalsa20poly1305;
import tweednacl.sha512;
import tweednacl.basics;
import tweednacl.nacl;

enum DefaultC = 1024;

struct TestData {
  size_t repeats;
  size_t bufferSize;
  size_t testDataSize = 1024 * 1024;
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



struct Round
{
  string label;
  TestData testData;
  StopWatch sw;

  this(TestData testData_, string label_="") {
    testData = testData_;
    label = label_;
    sw = StopWatch(AutoStart.yes);
  }

  ~this() {
    //sw.peek();
    traceRound( sw, testData, label );
  }

}

// pretty-print a round
void traceRound( ref StopWatch sw, TestData testData, string roundLabel )
{
  auto a = sw.peek();
  //const repeats = testData.testDataSize / testData.bufferSize;
  //auto perIteration = a / testData.repeats;
  auto perBytes = a / testData.testDataSize;
  writefln("%s %sb/%sKb bytes \t%s",
      roundLabel,
      testData.bufferSize,
      testData.testDataSize,
      perBytes.nsecs );
}


void testHash(H)( immutable TestData testData, string label="")
{
  ubyte[] d;
  d.length = testData.testDataSize;

  unSafeRandomBytes( d );
  //auto sw = StopWatch(AutoStart.yes);

  const bufSize = testData.bufferSize;
  const repeats = testData.testDataSize / testData.bufferSize;
  auto r = Round(testData, format("%s %s", primitiveName!H, label));
  H.Value h;
  foreach(i;0..repeats)
  {
    H.hash(h,d[i*bufSize..(i+1)*bufSize]);
  }

  //auto a = sw.peek();
  //auto perIteration = a / testData.repeats;
  //auto perBytes = perIteration / testData.bufferSize;
  //writefln("%s %s %s bytes\t%s",
      //primitiveName!H,
      //label,
      //testData.bufferSize,
      //perBytes.nsecs );
}



void testSecretBox(C)( immutable TestData testData, string label="")
{
  import tweednacl.nonce_generator;
  ubyte[] d, o;
  C.Key k;
  C.Nonce n;
  d.length = testData.testDataSize;// + C.ZeroBytes;
  unSafeRandomBytes( d );
  d[0..C.ZeroBytes] = 0;
  o.length = testData.testDataSize;// + C.ZeroBytes;

  // key
  unSafeRandomBytes( k );

  // nonce
  unSafeRandomBytes( n );


  const bufSize = testData.bufferSize + C.ZeroBytes;
  const repeats = testData.testDataSize / bufSize;
  {
    auto r = Round(testData, format("%s %s(box)", primitiveName!C, label));
    //auto r = Round(testData, format("%s(box)", label));
    //auto sw = StopWatch(AutoStart.yes);
    foreach(i;0..repeats)
    {
      C.box( o[i*bufSize..(i+1)*bufSize], d[i*bufSize..(i+1)*bufSize], n, k );
    }
    //traceRound( sw, testData, format("%s(box)", label) );
  }
  {
    auto r = Round(testData, format("%s %s(boxOpen)", primitiveName!C, label));
    //auto r = Round(testData, format("%s(boxOpen)", label));
    //auto sw = StopWatch(AutoStart.yes);
    foreach(i;0..repeats)
    {
      C.boxOpen( d[i*bufSize..(i+1)*bufSize], o[i*bufSize..(i+1)*bufSize], n, k );
    }
    //traceRound( sw, testData, format("%s(box)", label) );
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
