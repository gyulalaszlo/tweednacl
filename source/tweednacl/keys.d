module tweednacl.keys;

import tweednacl.basics;
import tweednacl.nacl;

enum KeyRole { Shared = 0, Public = 1, Secret = 2 }

struct Key(Impl, size_t bytes, KeyRole role)
{
  import std.base64;
  import std.array;

  alias Primitive = Impl;
  alias T = ubyte[bytes];
  alias Bytes = bytes;

  enum Role = role;


  /** The raw bytes of the key */
  T data;

  /**
    Randomizes the key data. Depending on the primitive this may or may not be
    a valid key.
   */
  void randomize(alias safeRnd=safeRandomBytes)()
  {
    safeRnd( data, Bytes );
  }

  string toBase64()
  {
    return Base64.encode(data);
  }

  /**
    Creates a string of the implementation name, the key type
    and the key data, to make this key recognizable and loadable
    using loadKeyString(), and adds an MD5 checksum to the end.
    */
  string keyString()
  {
    import std.digest.md;

    return [
      primitiveName!Impl, Base64.encode(data), Base64.encode( md5Of(primitiveName!Impl, data) )
      ].join("|");
  }

  /**
    Creates a package of the implementation name, the key type
    and the key data, to make this key recognizable and loadable
    using loadKey().
    */
  ubyte[] keyData()
  {
    auto o = appender!(ubyte[]);
    const name = primitiveName!Impl;
    o ~= cast(ubyte)name.length;
    o ~= cast(ubyte)role;
    o ~= cast(ubyte)(T.length >> 8);
    o ~= cast(ubyte)T.length;

    o ~= toBytes( name );
    o ~= data[];

    return o.data;
  }

}

alias sharedKey(Impl) = Key!(Impl, Impl.Key.length, KeyRole.Shared);
alias publicKey(Impl) = Key!(Impl, Impl.PublicKey.length, KeyRole.Public);
alias secretKey(Impl) = Key!(Impl, Impl.SecretKey.length, KeyRole.Secret);

unittest
{
  import std.stdio;
  //import tweednacl.xsalsa20;
  struct XSalsa20 {
  enum Primitive = "xsalsa20";
  enum Implementation = "crypto_stream/xsalsa20/tweet";
  enum Version = "-";

    alias Key = ubyte[32];
  }

  struct Curve25519XSalsa20Poly1305 {
    alias PublicKey = ubyte[32];
    alias SecretKey = ubyte[32];
  }

  struct Ed25519
  {
    enum Primitive = CryptoPrimitive("ed25519",
        "crypto_sign/ed25519/tweet" );

    alias PublicKey = ubyte[32];
    alias SecretKey = ubyte[64];
  }


  alias XSKey = sharedKey!XSalsa20;
  alias PKey = publicKey!Ed25519;
  alias SKey = secretKey!Ed25519;


  static void dumpKey(K)() {
    foreach(i;0..16)
    {
      auto k1 = K();
      k1.randomize();
      //writefln( "raw  = %s", k1.toBase64() );
      //writefln( "kstr = %s", k1.keyString() );
      //writefln( "key  = %s\n", k1.keyData() );
    }
  }

  dumpKey!XSKey();
  dumpKey!PKey();
  dumpKey!SKey();
}
