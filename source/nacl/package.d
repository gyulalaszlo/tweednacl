module nacl;

public import nacl.constants;


static import nacl.basics;
alias crypto_verify_16 = nacl.basics.crypto_verify_16;
alias crypto_verify_32 = nacl.basics.crypto_verify_32;

static import nacl.core;
alias crypto_core_salsa20 = nacl.core.crypto_core_salsa20;
alias crypto_core_hsalsa20 = nacl.core.crypto_core_hsalsa20;

static import nacl.stream;
alias crypto_stream = nacl.stream.crypto_stream;
alias crypto_stream_xor = nacl.stream.crypto_stream_xor;

static import nacl.onetimeauth;
alias crypto_onetimeauth = nacl.onetimeauth.crypto_onetimeauth;
alias crypto_onetimeauth_verify = nacl.onetimeauth.crypto_onetimeauth_verify;

static import nacl.secretbox;
alias crypto_secretbox = nacl.secretbox.crypto_secretbox;
alias crypto_secretbox_open = nacl.secretbox.crypto_secretbox_open;

static import nacl.scalarmult;
alias crypto_scalarmult = nacl.scalarmult.crypto_scalarmult;
alias crypto_scalarmult_base = nacl.scalarmult.crypto_scalarmult_base;

static import nacl.crypto_box;
alias crypto_box_keypair = nacl.crypto_box.crypto_box_keypair;
alias crypto_box_beforenm = nacl.crypto_box.crypto_box_beforenm;
alias crypto_box_afternm = nacl.crypto_box.crypto_box_afternm;
alias crypto_box_open_afternm = nacl.crypto_box.crypto_box_open_afternm;
alias crypto_box = nacl.crypto_box.crypto_box;
alias crypto_box_open = nacl.crypto_box.crypto_box_open;

static import nacl.hash;
alias crypto_hashblocks = nacl.hash.crypto_hashblocks;
alias crypto_hash = nacl.hash.crypto_hash;

static import nacl.sign;
alias crypto_sign_keypair = nacl.sign.crypto_sign_keypair;
alias crypto_sign = nacl.sign.crypto_sign;
alias crypto_sign_open = nacl.sign.crypto_sign_open;

unittest {
  // this import is here so RDMD -unittest runs without linker errors
  // when running with only package.d
  import nacl.test_data_crypto_sign_open;
}

/**
  A pair of secret and public keys for signing data.
  */
struct SignKeyPair {
  alias PublicKey = ubyte[crypto_sign_PUBLICKEYBYTES];
  alias SecretKey = ubyte[crypto_sign_SECRETKEYBYTES];
  /** The public key to validate signed data with. */
  PublicKey publicKey;
  /** The secret key to sign data with */
  SecretKey secretKey;
}

/** Generate a pair of keys for signing data.  */
SignKeyPair generateSignKeypair()
{
  import nacl.basics : safeRandomBytes;
  auto o = SignKeyPair();
  crypto_sign_keypair!safeRandomBytes( o.publicKey, o.secretKey );
  return o;
}


class BadSignatureError : Exception {
  this() {
    super("Bad signature!");
  }
}

/**
  Opens a signed message

Params:
  signedData =  the signed data with crypto_sign_BYTES of signature followed
                by the plaintext message
  pk         =  the public key to check the signature with

Returns: The plaintext message with the signature removed.

Throws: BadSignatureError if the signature does not match the message.
  */
ubyte[] openSigned( const ubyte[] signedData, ref SignKeyPair.PublicKey pk )
in {
  assert(signedData.length >= crypto_sign_BYTES);
}
body {
  import std.stdio;
  ubyte[] output;
  output.length = signedData.length;
  ulong outputLen;
  if (!crypto_sign_open( output, outputLen, signedData, pk ))
    throw new BadSignatureError();
  output.length = outputLen;
  return output;
}

/**
  Signs a message using the given secret key

Params:
  signedData =  the signed data with crypto_sign_BYTES of signature followed
                by the plaintext message
  pk         =  the public key to check the signature with

Returns: The signed data with crypto_sign_BYTES of signature followed by the
plaintext message

  Throws: BadSignatureError if the signature does not match the message.
  */
ubyte[] sign(E)( const E[] message, ref SignKeyPair.SecretKey sk )
{
  ulong smlen;
  auto msg = nacl.basics.toBytes( message );
  ubyte[] o;
  o.length = msg.length + crypto_sign_BYTES;
  crypto_sign( o, smlen, msg, sk  );
  return o;
}


unittest {
  import std.stdio;
  import std.exception;
  import std.random;
  import nacl.basics : randomBuffer;

  auto o = generateSignKeypair();

  foreach(mlen;0..32) {
    ubyte[] msg;
    msg.length = mlen;
    randomBuffer( msg );

    auto signedMsg = sign( msg, o.secretKey );

    assert( openSigned(signedMsg, o.publicKey) == msg );

    foreach(i;0..10) {
      signedMsg[ uniform(0, signedMsg.length)]++;
      try assert( openSigned(signedMsg, o.publicKey) == msg );
      catch (BadSignatureError) { }
    }
  }
}


/**

  The following example shows
  */
unittest
{
  string toDHexData( const ubyte[] data ) {
    import std.array;
    import std.string;
    auto o = appender!string;
    o ~= "[ ";
    foreach(d;data) { o ~= format("0x%02x, ", d); }
    o ~= " ]";
    return o.data;
  }

  // GENERATE THE AUTHENTICATION KEYS.
  // ---------------------------------

  auto keyPair = generateSignKeypair();

  import std.stdio;
  writefln("public key (embed this in your application):\n ubyte[%s] publicKey = %s;",
      keyPair.publicKey.length, toDHexData(keyPair.publicKey) );

  writefln("secret key (use this to sign your data): \n %s",
      toDHexData(keyPair.secretKey) );

  // SIGNING A FILE
  // -----------------------

  // An example function that signs a file with a secret key and writes the signed
  // data (the signature and the plaintext) to the output file
  void signFile( string inputFileName, string signedFileName,
      ref SignKeyPair.SecretKey secretKey )
  {
    import std.file;
    std.file.write( signedFileName, sign( read( inputFileName ), secretKey ) );
  }

  signFile("dub.json", "dub.json.signed", keyPair.secretKey );


  // LOADING THE SIGNED FILE
  // -----------------------

  // some function that operates on the trusted data
  void process( const ubyte[] data ) { /* .. */ }


  // An example function that verifies a file signed by signFile()
  void loadAndProcessSignedFile( string signedFileName,
      ref SignKeyPair.PublicKey publicKey )
  {
    // if the verification fails, an exception is thrown and
    // the processing function isnt reached
    //process( verify( read(signedFileName), publicKey ) );
  }

}
