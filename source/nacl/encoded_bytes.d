module nacl.encoded_bytes;

import std.stdio;
import nacl.basics : toBytes;

/**
  Calculates the least common multiple using reducing it to a GCD problem.
  */
private T lcm(T)(T a, T b)
{
  import std.numeric;
  if (a == 0 && b == 0) return 0;
  static if (T.min < 0)
    return abs(a * b) / gcd(a,b);
  else
    return (a * b) / gcd(a,b);
}

/** Is the given number a power of 2? */
private bool isPowerOf2(T)(T x) { return x && !(x & (x - 1)); }


// Get the bit count for a given length
private size_t bitCount( size_t len ) {
  if (len == 0) return 0;
  auto bits = 0;
  while(len > 0) {
    len /= 2;
    bits++;
  }
  return bits-1;
}

unittest {
  size_t[size_t] a = [ 16:4, 15:3, 17:4, 0:0, 2:1, 4:2, 8:3, 256:8 ];
  foreach(len,bc;a) assert( bitCount(len) == bc );
}





/**
  Converts data to a string using characters from the passed alphabet.
  */
private string toByteStringImpl(string alphabet="0123456789abcdef")(const(ubyte)[] bytes)
{
  static assert( isPowerOf2( alphabet.length ) );
  import std.array;
  import std.math;
  import std.bitmanip;
  enum dataBits = ubyte.sizeof * 8;
  enum alphabetBits = bitCount(alphabet.length);
  enum bitsPerLetterGroup = lcm( alphabetBits, dataBits );

  enum lettersPerGroup = bitsPerLetterGroup / alphabetBits;
  enum bytesPerGroup = bitsPerLetterGroup / dataBits;

  enum Masks = [
    0b00000000,
    0b00000001,
    0b00000011,
    0b00000111,
    0b00001111,
    0b00011111,
    0b00111111,
    0b01111111,
    0b11111111,
    ];
  enum letterMask = Masks[alphabetBits];

  alias Buf = ulong;

  immutable bytesLen = bytes.length;
  if (bytesLen == 0) return "";

  auto byteCount = bytes.length;
  auto byteIdx = &bytes[0];
  auto o = appender!string;
  Buf buffer;

  while(byteCount > 0) {
    size_t padBytes = 0;
    size_t maxLetters = lettersPerGroup;

    if (byteCount >= bytesPerGroup) {
      buffer = bigEndianToNative!Buf(byteIdx[0..Buf.sizeof]);
      byteCount -= bytesPerGroup;
    } else {
      ubyte[Buf.sizeof] b;
      b[0..byteCount] = byteIdx[0..byteCount];
      buffer = bigEndianToNative!Buf(b);
      padBytes = bytesPerGroup - byteCount;
      // include the possibly padded last letter
      maxLetters = (byteCount * 8) / alphabetBits + 1;
      byteCount = 0;
    }

    foreach(i;0..maxLetters) {
      size_t idx = (buffer >> ( (Buf.sizeof * 8) - alphabetBits)) & letterMask;
      buffer = buffer << alphabetBits;
      o ~= alphabet[idx];
    }

    if (padBytes > 0)
      foreach(i;0..lettersPerGroup-maxLetters) o ~= "=";

    byteIdx += bytesPerGroup;
  }
  return o.data;
}

string bytesToBinary(T)(T[] data) {
  return toByteStringImpl!("01")( data );
}

string bytesToHex(T)(T[] data)
{
  return toByteStringImpl!("0123456789abcdef")( data );
}

string bytesToHexUpper(T)(auto ref T[] data)
{
  return toByteStringImpl!("0123456789ABCDEF")( toBytes(data) );
}

string bytesToBase64(T)(auto ref T[] data)
{
  return toByteStringImpl!("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")( toBytes(data) );
}



unittest {
  assert( bytesToHex( cast(ubyte[])([0x01,0x23,0x45,0x67,0x89,0xab, 0xcd, 0xef ])) == "0123456789abcdef" );
  assert( bytesToHex( cast(ubyte[])([0xff,0xfe])) == "fffe" );

  assert( bytesToBase64("Man is distinguished, not only by his reason, but by this singular passion from "
    "other animals, which is a lust of the mind, that by a perseverance of delight "
    "in the continued and indefatigable generation of knowledge, exceeds the short "
    "vehemence of any carnal pleasure.") ==
    "TWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcyByZWFzb24sIGJ1dCBieSB0aGlz"
    "IHNpbmd1bGFyIHBhc3Npb24gZnJvbSBvdGhlciBhbmltYWxzLCB3aGljaCBpcyBhIGx1c3Qgb2Yg"
    "dGhlIG1pbmQsIHRoYXQgYnkgYSBwZXJzZXZlcmFuY2Ugb2YgZGVsaWdodCBpbiB0aGUgY29udGlu"
    "dWVkIGFuZCBpbmRlZmF0aWdhYmxlIGdlbmVyYXRpb24gb2Yga25vd2xlZGdlLCBleGNlZWRzIHRo"
    "ZSBzaG9ydCB2ZWhlbWVuY2Ugb2YgYW55IGNhcm5hbCBwbGVhc3VyZS4=" );


  // padding
  assert( bytesToBase64("any carnal pleasure.") == "YW55IGNhcm5hbCBwbGVhc3VyZS4=" );
  assert( bytesToBase64("any carnal pleasure") == "YW55IGNhcm5hbCBwbGVhc3VyZQ==" );
  assert( bytesToBase64("any carnal pleasur") == "YW55IGNhcm5hbCBwbGVhc3Vy" );
  assert( bytesToBase64("any carnal pleasu") == "YW55IGNhcm5hbCBwbGVhc3U=" );
  assert( bytesToBase64("any carnal pleas") == "YW55IGNhcm5hbCBwbGVhcw==" );

  assert( bytesToBase64("pleasure.") == "cGxlYXN1cmUu" );
  assert( bytesToBase64("leasure.") == "bGVhc3VyZS4=" );
  assert( bytesToBase64("easure.") == "ZWFzdXJlLg==" );
  assert( bytesToBase64("asure.") == "YXN1cmUu" );
  assert( bytesToBase64("sure.") == "c3VyZS4=" );

  //writefln("%s",  bytesToBinary(cast(ubyte[])([0xf3])));
  assert( bytesToBinary(cast(ubyte[])([0xf3])) == "11110011");

  // check against toHexString
  foreach(mlen;0..1024) {
    import std.digest.digest;
    import nacl.basics : randomBuffer;
    auto msg = randomBuffer(mlen);
    assert( toHexString(msg) == bytesToHexUpper( msg ) );
  }


}



