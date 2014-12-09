module tweednacl.encoded_bytes;

import std.stdio;
import tweednacl.basics : toBytes;

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


/**
  Get the bit count for a given alphabet size
  */
private T bitCount(T)( T len ) {
  if (len == 0) return 0;
  auto bits = 0;
  while(len > 0) { len /= 2; bits++; }
  return bits-1;
}

unittest {
  size_t[size_t] a = [ 16:4, 15:3, 17:4, 0:0, 2:1, 4:2, 8:3, 256:8 ];
  foreach(len,bc;a) assert( bitCount(len) == bc );
}


/**
  Returns a bit mask to grab a number of bits from a ubytes end.
  ---
  0 -> 0b00000000,
  1 -> 0b00000001,
  2 -> 0b00000011,
  3 -> 0b00000111,
  4 -> 0b00001111,
  5 -> 0b00011111,
  6 -> 0b00111111,
  7 -> 0b01111111,
  8 -> 0b11111111,
  ---
Params:
  bits = the number of bits
  */
ubyte getBitMask(ubyte bits)
in {
  assert( bits <= 8 );
}
body {
  enum BitMasks = [
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
  return cast(ubyte)(BitMasks[bits]);
}


struct Alphabet
{
  string chars = "0123456789abcdef";
  char paddingChar = '=';
  ubyte bits;
  ubyte bitmask;
  ushort size;

  ubyte[char] mapping;


  this(string characters, char paddingC = '=')
  in {
    assert( isPowerOf2( characters.length ) );
  }
  body {
    bits = cast(ubyte)(bitCount(characters.length));
    bitmask = getBitMask( bits );
    size = cast(ubyte)(characters.length);
    chars = characters;
    paddingChar = paddingC;
    initMapping();
  }


  this( ubyte alphabetBits, char startC, char paddingC = '=' )
  in {
    assert( alphabetBits <= 8 );
  }
  body {
    const alphabetSize = 1 << alphabetBits;
    import std.array;
    auto c = appender!string;
    c.reserve(alphabetSize);
    foreach(ch;startC..startC+alphabetSize)
      c ~= cast(char)(ch);

    bits = alphabetBits;
    bitmask = getBitMask( alphabetBits );
    size = cast(ushort)(1u << alphabetBits);
    chars = c.data;
    paddingChar = paddingC;
    initMapping();
  }

  void initMapping()
  {
    foreach(i,c;chars) mapping[cast(char)(c)] = cast(ubyte)(i);
  }


  pure nothrow @nogc char opIndex( size_t i ) const
  in {
    assert( i < chars.length );
  }
  body {
    return chars[i];
  }



}

enum ByteAlphabet = Alphabet(8, 0x00 );
enum BinaryAlphabet = Alphabet("01");
enum HexAlphabet = Alphabet("0123456789abcdef");
enum HexAlphabetUpper = Alphabet("0123456789ABCDEF");
enum Base64Alphabet = Alphabet("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/");


/**
  Converts data to a string using characters from the passed alphabet.
  */
template toByteStringImpl(Alphabet A, Alphabet B=ByteAlphabet)
{
  import std.array;
  import std.math;
  import std.bitmanip;

  enum bitsPerLetterGroup = lcm!uint( A.bits, B.bits );
  enum outLettersPerGroup = bitsPerLetterGroup / A.bits;
  enum inLettersPerGroup = bitsPerLetterGroup / B.bits;


  alias Buf = ulong;

  string toByteStringImpl(const(ubyte)[] bytes)
  {
    immutable bytesLen = bytes.length;
    if (bytesLen == 0) return "";

    auto byteCount = bytes.length;
    auto byteIdx = &bytes[0];
    auto o = appender!string;
    o.reserve( byteCount / B.bits * A.bits );
    Buf buffer;

    while(byteCount > 0) {
      size_t padBytes = 0;
      size_t maxLetters = outLettersPerGroup;
      ubyte[Buf.sizeof] b;


      if (byteCount >= inLettersPerGroup) {
        // read into the buffer
        buffer = 0;
        foreach(i;0..inLettersPerGroup)
        {
          immutable offset = (inLettersPerGroup - i - 1) * B.bits;
          immutable idx = byteIdx[i];
          buffer += B.mapping[ idx ] << offset;
        }
        byteCount -= inLettersPerGroup;
      } else {

        buffer = 0;
        foreach(i;0..byteCount)
        {
          buffer += (B.mapping[ byteIdx[i] ] << ( (inLettersPerGroup - i - 1) * B.bits));
        }

        padBytes = inLettersPerGroup - byteCount;
        // include the possibly padded last letter
        maxLetters = (byteCount * B.bits) / A.bits + 1;
        byteCount = 0;
      }

      {
        const minLetterIdx = outLettersPerGroup - maxLetters;
        size_t i = outLettersPerGroup - 1;
        while (true)
        {
          size_t idx = (buffer >> (i * A.bits)) & A.bitmask;
          o ~= A[idx];
          if (i == minLetterIdx) break;
          i--;
        }

      }
      if (padBytes > 0)
        foreach(i;0..outLettersPerGroup-maxLetters) o ~= A.paddingChar;

      byteIdx += inLettersPerGroup;
    }
    return o.data;
  }
}

string bytesToBinary(T)(T[] data) {
  return toByteStringImpl!(BinaryAlphabet)( data );
}

string bytesToHex(T)(T[] data)
{
  return toByteStringImpl!(HexAlphabet)( data );
}

string parseHexBytes(T)(T[] data)
{
  return toByteStringImpl!(ByteAlphabet,HexAlphabet)( toBytes(data) );
}

string bytesToHexUpper(T)(auto ref T[] data)
{
  return toByteStringImpl!(HexAlphabetUpper)( toBytes(data) );
}

string parseHexBytesUpper(T)(T[] data)
{
  return toByteStringImpl!(ByteAlphabet,HexAlphabetUpper)( toBytes(data) );
}


string bytesToBase64(T)(T[] data)
{
  return toByteStringImpl!(Base64Alphabet)( toBytes(data) );
}

string parseBase64(T)(T[] data)
{
  return toByteStringImpl!(ByteAlphabet, Base64Alphabet)( toBytes(data) );
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

  assert( bytesToBinary(cast(ubyte[])([0xf3])) == "11110011");

   //check against toHexString
  foreach(i;0..14) {
    const mlen = (1 << i) + 1;
    import std.digest.digest;
    import tweednacl.basics : randomBuffer;
    auto msg = randomBuffer(mlen);
    assert( toHexString(msg) == bytesToHexUpper( msg ) );
  }


}


unittest {
  // check against toHexString
  foreach(i;0..14) {
    const mlen = (1 << i) + 1;
    import std.digest.digest;
    import tweednacl.basics : randomBuffer;
    auto msg = randomBuffer(mlen);
    auto hMsg = toHexString(msg);
    //writefln("src=%s\ndec=%s\n", hMsg, parseHexBytesUpper(hMsg) );
    assert( parseHexBytesUpper( hMsg ) == msg );
  }
}
