module bench;

import std.datetime;
import std.stdio;
import std.string;
import std.digest.digest;

import tweednacl;
import std.experimental.crypto;
import tweednacl.xsalsa20poly1305;
import tweednacl.sha512;
import tweednacl.basics;
import std.experimental.crypto.nacl;

enum DefaultC = 1024;

struct TestData {
  size_t repeats;
  size_t bufferSize;
  size_t testDataSize = 1024 * 1024;
}

bool gnuplotFormat = false;

enum HasRepeats { no=0, yes=1 };

struct Round(HasRepeats hasRepeats)
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
    static if (hasRepeats) {
      auto res = sw.peek() / testData.repeats;
      if (gnuplotFormat)
        writefln("%s %sreps \t%s", label, testData.repeats, res.nsecs );
      else
        writefln("%10s %s %sreps", res.nsecs, label, testData.repeats );
    } else {
      auto res = sw.peek() / (testData.testDataSize / 1024);
      if (gnuplotFormat)
        writefln("%s %sbytes \t%s", label, testData.bufferSize, res.nsecs / 1024 );
      else
        writefln("%10s %s %sbytes", res.nsecs / 1024, label, testData.bufferSize );
    }
  }

}


auto round(HasRepeats hasRepeats=HasRepeats.no, Args...)(Args args)
{
  return Round!hasRepeats(args);
}

void testHash(H)( immutable TestData testData, string label="")
{
  ubyte[] d;
  d.length = testData.testDataSize;

  unSafeRandomBytes( d );

  const bufSize = testData.bufferSize;
  const repeats = testData.testDataSize / testData.bufferSize;
  auto r = round(testData, format("%s %s", H.Implementation, label));
  H.Value h;
  foreach(i;0..repeats)
  {
    H.hash(h,d[i*bufSize..(i+1)*bufSize]);
  }
}



void testSecretBox(C)( immutable TestData testData, string label="")
{
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
    auto r = round(testData, format("%s %s(box)", C.Implementation, label));
    foreach(i;0..repeats)
    {
      C.box( o[i*bufSize..(i+1)*bufSize], d[i*bufSize..(i+1)*bufSize], n, k );
    }
  }
  {
    auto r = round(testData, format("%s %s(boxOpen)", C.Implementation, label));
    foreach(i;0..repeats)
    {
      C.open( d[i*bufSize..(i+1)*bufSize], o[i*bufSize..(i+1)*bufSize], n, k );
    }
  }
}


void testCryptoBox(C)( immutable TestData testData, string label="")
{
  const repeats = testData.repeats;
  C.PublicKey[] aPk, bPk;
  C.SecretKey[] aSk, bSk;
  C.Beforenm[] beforenm;
  C.Nonce n;
  unSafeRandomBytes( n );
  aPk.length = aSk.length = bPk.length = bSk.length = beforenm.length = repeats;
  const bufSize = testData.bufferSize + C.ZeroBytes;
  {
    auto r = round!(HasRepeats.yes)(testData, format("%s %s(keygen)", C.Implementation, label));
    foreach(i;0..repeats)
    {
      C.keypair!unSafeRandomBytes( aPk[i], aSk[i] );
      C.keypair!unSafeRandomBytes( bPk[i], bSk[i] );
    }
  }
  {
    auto r = round!(HasRepeats.yes)(testData, format("%s %s(beforenm)", C.Implementation, label));
    foreach(i;0..repeats)
    {
      C.beforenm( beforenm[i], aPk[i], bSk[i] );
    }
  }
}


void testSignature(C)( immutable TestData testData, 
    const ubyte[] d,
    const C.PublicKey[] aPk,
    const C.SecretKey[] aSk,
    C.Signature[] signatures,
    string label="",
   )
{
  const msgSize = testData.bufferSize;
  const bufSize = msgSize + C.Bytes;
  const repeats = testData.testDataSize / testData.bufferSize;

  ubyte[] o, od;
  od.length = o.length = repeats * bufSize;
  size_t[] smlen;
  smlen.length = repeats;

  {
    auto r = round(testData, format("%s:sign", C.Implementation));
    foreach(i;0..repeats)
    {
      const idx = i * bufSize;
      C.sign( o[idx..idx+bufSize], smlen[i], d[idx..idx+msgSize], aSk[i] );
    }
  }
  foreach(i;0..repeats)
  {
      const idx = i * bufSize;
      signatures[i] = o[idx..$][0..C.Bytes];
  }
  {
    auto r = round(testData, format("%s:open", C.Implementation));
    foreach(i;0..repeats)
    {
      const idx = i * bufSize;
      C.open( od[idx..idx+bufSize], smlen[i], o[idx..idx+bufSize], aPk[i] );
    }
  }
}




void testHashes( size_t bufSize )
{
    immutable params = TestData( 1024, bufSize );
    version (TweedNaClUseStdSHA512) testHash!StdSHA512( params );
    testHash!(SHA512)( params);
    version (TweedNaClUseTweetNaCl) testHash!TweetSHA512( params);
    version (TweedNaClUseNaCl) testHash!SodiumSHA512( params);
}

void runTestSignatures(ReferenceImplementation=Ed25519)( size_t bufSize )
{
    alias Algorithm = ReferenceImplementation;
    immutable hashParams = TestData( 256, bufSize );
    auto testData = hashParams;


    const msgSize = testData.bufferSize;
    const bufSizeWithZeroes = msgSize + Algorithm.Bytes;
    const repeats = testData.testDataSize / testData.bufferSize;

    ubyte[] d;
    d.length = repeats * bufSizeWithZeroes;
    unSafeRandomBytes( d );

    Algorithm.PublicKey[] aPk;
    Algorithm.SecretKey[] aSk;

    enum AlgCounts = 3;
    auto usedAlgs = 1;
    Algorithm.Signature[][AlgCounts] sigs;

    aPk.length = aSk.length = /*sigs.length = */ repeats;
    foreach(ref s;sigs) s.length = repeats;

    version (TweedNaClUseTweetNaCl) usedAlgs++;
    version (TweedNaClUseNaCl) usedAlgs++;
    // generate the keys using something most likely fast.
    {
      version (TweedNaClUseNaCl)
        alias GenAlgorithm = SodiumEd25519;
      else
        alias GenAlgorithm = Algorithm;

      foreach(i;0..repeats)
      {
        GenAlgorithm.keypair!unSafeRandomBytes( aPk[i], aSk[i] );
      }

      foreach(i;0..repeats)
      {
        const idx = i * bufSizeWithZeroes;
        d[idx..idx+GenAlgorithm.Bytes] = 0;
      }
    }
    testSignature!(Ed25519)( hashParams, d, aPk, aSk, sigs[0]  );
    version (TweedNaClUseTweetNaCl) testSignature!TweetEd25519( hashParams, d, aPk, aSk, sigs[1]);
    version (TweedNaClUseNaCl) testSignature!SodiumEd25519( hashParams, d, aPk, aSk, sigs[2]);

    auto failCount = 0;
    foreach(i;0..repeats)
    {
      foreach(a;0..usedAlgs)
      {
        foreach(b;a..usedAlgs)
        {
          if (sigs[a][i] != sigs[b][i]) {
            if (failCount < 3)
            writefln("Error i=%s a=%s b=%s '%s' != '%s'", i, a, b, 
                toHexString(sigs[0][i]), 
                toHexString(sigs[1][i])
                );
            failCount++;
          }
        }
      }
    }
}

void testSecretbox( size_t bufSize )
{
    immutable hashParams = TestData( 1024, bufSize );
    testSecretBox!(XSalsa20Poly1305)( hashParams );

    version (TweedNaClUseTweetNaCl)
      testSecretBox!( TweetXSalsa20Poly1305)( hashParams );

    version (TweedNaClUseNaCl)
      testSecretBox!SodiumXSalsa20Poly1305( hashParams );
}


void testCryptobox( size_t repeatCount )
{
    immutable hashParams = TestData( repeatCount );
    testCryptoBox!Curve25519XSalsa20Poly1305( hashParams );

    version (TweedNaClUseTweetNaCl)
      testCryptoBox!TweetCurve25519XSalsa20Poly1305( hashParams );

    version (TweedNaClUseNaCl)
      testCryptoBox!SodiumCurve25519XSalsa20Poly1305( hashParams );

}


struct BufSizeRange
{
  import std.range;

  size_t i;
  size_t stop = 12;
  size_t stepSize = 1;

  @property
  {
    auto front() { return 2 << i; }
    auto empty() { return i >= stop; }
  }
  void popFront() { i+=stepSize; }

}

void runBench(alias test, R)(R bufSize)
{
  foreach(bs;bufSize) test( bs );
}





void main(string[] args)
{
  import std.getopt;
  bool runHashes = true;
  bool runSecretbox = true;
  bool runCryptobox = true;
  bool runSignatures = true;

  getopt( args,
          "hash", &runHashes,
          "secretbox", &runSecretbox,
          "cryptobox", &runCryptobox,
          "signatures", &runSignatures,
          "gnuplot", &gnuplotFormat);

  auto s = BufSizeRange(2);
  if (runHashes) runBench!( (b) => testHashes(b) )(s);
  if (runSecretbox) runBench!( (b) => testSecretbox(b) )(s);
  if (runCryptobox) testCryptobox(256);
  if (runSignatures) runBench!( (b) => runTestSignatures(b) )( BufSizeRange(10,17, 3) );
}
