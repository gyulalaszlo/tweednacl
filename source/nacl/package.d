/**

  $(BIG $(I "Where theres magic theres security problems"))

  DEF CON 20 - Charlie Miller
  $(I"Don't Stand So Close To Me: An Analysis of the NFC Attack Surface")
  $(BR)
  $(LINK https://www.youtube.com/watch?v=16FKOQ1gx68)


$(BIG Expert selection of default primitives)

Typical cryptographic libraries force the programmer to specify choices of
cryptographic primitives: e.g., "sign this message with 4096-bit RSA using PKCS
#1 v2.0 with SHA-256."

Most programmers using cryptographic libraries are not expert cryptographic
security evaluators. Often programmers pass the choice along to users—who
usually have even less information about the security of cryptographic
primitives. There is a long history of these programmers and users making poor
choices of cryptographic primitives, such as MD5 and 512-bit RSA, years after
cryptographers began issuing warnings about the security of those primitives.

NaCl allows, and encourages, the programmer to simply say "sign this message."
NaCl has a side mechanism through which a cryptographer can easily specify the
choice of signature system. Furthermore, NaCl is shipped with a preselected
choice, namely a state-of-the-art signature system suitable for worldwide use
in a wide range of applications.

$(BIG High-level primitives)

A typical cryptographic library requires several steps to authenticate and
encrypt a message. Consider, for example, the following typical combination of
RSA, AES, etc.:

$(OL
  $(LI Generate a random AES key.)
  $(LI Use the AES key to encrypt the message.)
  $(LI Hash the encrypted message using SHA-256.)
  $(LI Read the sender's RSA secret key from "wire format.")
  $(LI Use the sender's RSA secret key to sign the hash.)
  $(LI Read the recipient's RSA public key from wire format.)
  $(LI Use the recipient's public key to encrypt the AES key, hash, and signature.)
  $(LI Convert the encrypted key, hash, and signature to wire format.)
  $(LI Concatenate with the encrypted message. )
)

Sometimes even more steps are required for storage allocation, error handling,
etc.

NaCl provides a simple crypto_box function that does everything in one step.
The function takes the sender's secret key, the recipient's public key, and a
message, and produces an authenticated ciphertext. All objects are represented
in wire format, as sequences of bytes suitable for transmission; the crypto_box
function automatically handles all necessary conversions, initializations, etc.

Another virtue of NaCl's high-level API is that it is not tied to the
traditional hash-sign-encrypt-etc. hybrid structure. NaCl supports much faster
message-boxing solutions that reuse Diffie-Hellman shared secrets for any
number of messages between the same parties.

A multiple-step procedure can have important speed advantages when multiple
computations share precomputations. NaCl allows users to split crypto_box into
two steps, namely crypto_box_beforenm for message-independent precomputation
and crypto_box_afternm for message-dependent computation.

$(BIG No data-dependent branches)

The CPU's instruction pointer, branch predictor, etc. are not designed to keep
information secret. For performance reasons this situation is unlikely to
change. The literature has many examples of successful timing attacks that
extracted secret keys from these parts of the CPU.

NaCl systematically avoids all data flow from secret information to the
instruction pointer and the branch predictor. There are no conditional branches
with conditions based on secret information; in particular, all loop counts are
predictable in advance.

This protection appears to be compatible with extremely high speed, so there is
no reason to consider weaker protections.

$(BIG No data-dependent array indices)

The CPU's cache, TLB, etc. are not designed to keep addresses secret. For
performance reasons this situation is unlikely to change. The literature has
several examples of successful cache-timing attacks that used secret
information leaked through addresses.

NaCl systematically avoids all data flow from secret information to the
addresses used in load instructions and store instructions. There are no array
lookups with indices based on secret information; the pattern of memory access
is predictable in advance.

The conventional wisdom for many years was that achieving acceptable software
speed for AES required variable-index array lookups, exposing the AES key to
side-channel attacks, specifically cache-timing attacks. However, the paper
$(I "Faster and timing-attack resistant AES-GCM") by Emilia Käsper and Peter Schwabe
at CHES 2009 introduced a new implementation that set record-setting speeds for
AES on the popular Core 2 CPU despite being immune to cache-timing attacks.
NaCl reuses these results.

$(BIG No dynamic memory allocation)

The low level NaCl-like API is intended to be usable in environments that cannot
guarantee the availability of large amounts of heap storage but that
nevertheless rely on their cryptographic computations to continue working.

They do use small amounts of stack space; these amounts will eventually be
measured by separate benchmarks.

$(BIG No copyright restrictions)

All of the NaCl software is in the public domain.
*/
/*

  $(DD Provide strong and transparent encryption.)
    $(P Encryption and strong signatures are crucial for system level software.)

    $(P The size of the library should make it easy for anyone qualified to
     validate the correctness of the implementation in reasonable time.)


  $(DD Make it easy to use.)
    $(P Provide a minimal interface that can be parameterized to suit
      the programmers specific needs, with minimal amount of glue code.)

  $(DD Make it hard for the user to misuse.)
    $(P Make all input values valid input values. Make memory errors.)

  */
module nacl;

import nacl.encoded_bytes;

import nacl.curve25519xsalsa20poly1305 : Curve25519XSalsa20Poly1305;
import nacl.ed25519 : Ed25519;
import nacl.xsalsa20poly1305 : XSalsa20Poly1305;
import nacl.poly1305 : Poly1305;

unittest {
  // this import is here so RDMD -unittest runs without linker errors
  // when running with only package.d
  import nacl.test_data_crypto_sign_open;
}

/**
  A generic pair of secret and public keys for signing data and an algorithm.
  */
struct KeyPair(Impl) {
  /** Accessor for the implementation */
  alias Primitive = Impl;
  /** The memory representation of a public key */
  alias PublicKey = ubyte[Impl.PublicKeyBytes];
  /** The memory representation of a secret key */
  alias SecretKey = ubyte[Impl.SecretKeyBytes];
  /** The public key to validate signed data with. */
  PublicKey publicKey;
  /** The secret key to sign data with */
  SecretKey secretKey;
}

/**
  Generate a pair of public and private keys for an implementation.

Params:
  Impl = The implementation to use (defaults to Ed25519)
 */
auto generateKeypair(Impl, alias safeRnd=nacl.basics.safeRandomBytes)()
{
  auto o = KeyPair!Impl();
  Impl.keypair!safeRnd( o.publicKey, o.secretKey );
  return o;
}


/**
  Generates a keypair for the sign() and openSigned() functions.

  Examples:
  Generate a key:
  ---

  auto keyPair = generateSignKeypair();

  import std.stdio;
  writefln("// public key (embed this in your application):");
  writefln("ubyte[%s] publicKey = %s;", keyPair.publicKey.length, keyPair.publicKey );

  writefln("secret key (use this to sign your data): \n %s", keyPair.secretKey );

  ---
  */
alias generateSignKeypair(Impl=Ed25519, alias safeRnd=nacl.basics.safeRandomBytes)
  = generateKeypair!(Impl, safeRnd);


/**
  Gets thrown when a signature mismatches during the opening
  a signed message or box.
  */
class BadSignatureError : Exception
{
  this() { super("Bad signature!"); }
}

/**
  Opens a signed message

Params:
  Impl = The implementation to use. Defaults to Ed25519.
  signedData =  the signed data with crypto_sign_BYTES of signature followed
                by the plaintext message
  pk         =  the public key to check the signature with

Returns: The plaintext message with the signature removed.

Throws: BadSignatureError if the signature does not match the message.

  */
ubyte[] openSigned(Impl=Ed25519, E, size_t keySize)(
    const E[] signedData, ref const ubyte[keySize] pk )
  if ( keySize == Impl.PublicKeyBytes )
in {
  assert(signedData.length >= Impl.Bytes);
}
body {
  const sm = nacl.basics.toBytes( signedData );
  ubyte[] output;
  output.length = sm.length;
  ulong outputLen;
  if (!Impl.signOpen( output, outputLen, sm, pk ))
    throw new BadSignatureError();
  output.length = outputLen;
  return output;
}

/**
  Signs a message using the given secret key

Params:
  Impl = The implementation to use. Defaults to Ed25519.

  signedData =  the signed data with crypto_sign_BYTES of signature followed
                by the plaintext message
  pk         =  the public key to check the signature with

Returns: The signed data with crypto_sign_BYTES of signature followed by the
plaintext message

  Throws: BadSignatureError if the signature does not match the message.
  */
ubyte[] sign(Impl=Ed25519, E, size_t keySize)(
    const E[] message, ref const ubyte[keySize] sk )
  if ( keySize == Impl.SecretKeyBytes )
{
  ulong smlen;
  const msg = nacl.basics.toBytes( message );
  ubyte[] o;
  o.length = msg.length + Impl.Bytes;
  Impl.sign( o, smlen, msg, sk  );
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
  Signing and loading a file, and process it only if the signature is valid.
  */
unittest {

  auto keyPair = generateSignKeypair();
  // SIGNING A FILE
  // -----------------------

  // An example function that signs a file with a secret key and writes the signed
  // data (the signature and the plaintext) to the output file
  void signFile(K)( string inputFileName, string signedFileName,
      ref const K secretKey )
  {
    import std.file;
    std.file.write( signedFileName, sign( read( inputFileName ), secretKey ) );
  }

  signFile("dub.json", "dub.json.signed", keyPair.secretKey );


  // LOADING THE SIGNED FILE
  // -----------------------

  // some function that operates on the trusted data
  void process( const ubyte[] data ) { /* ... */ }


  // An example function that verifies a file signed by signFile()
  void loadAndProcessSignedFile(K)( string signedFileName,
      ref const K publicKey )
  {
    import std.file;
    // If the opening fails signature verification, BadSignatureError is thrown
    // and the process() isnt reached.
    try {
      process( openSigned( read(signedFileName), publicKey ) );
    }
    catch (BadSignatureError) {
      // ...
    }
  }

  loadAndProcessSignedFile( "dub.json.signed", keyPair.publicKey );
}



/**
  Generates a keypair for the sign() and openSigned() functions.
  */
alias generateBoxKeypair(Impl=Curve25519XSalsa20Poly1305, alias safeRnd=nacl.basics.safeRandomBytes)
  = generateKeypair!(Impl, safeRnd);

import nacl.nonce_generator : DoubleStriderNonce, NonceStream, generateNonce;
import std.stdio;

/**
  A communication helper that can box and unbox messages to and form a single other party.

  the encrypted box looks like this:

  */
struct Boxer(
    Impl=Curve25519XSalsa20Poly1305,
    NonceGenerator=DoubleStriderNonce!(Impl.NonceBytes)
    ) {

  enum ZeroBytes = Impl.ZeroBytes;
  enum BoxZeroBytes = Impl.BoxZeroBytes;

  NonceGenerator nonceGenerator;

  private Impl.Beforenm sharedSecret;

  /**
    Creates a new Boxer.

    Note: The keys passed are only used for generating a shared secret, they
    arent stored.

    It is up to the user to provide some kind of a handshake to exchange a starting
    nonce. The suggested way is to use the generateNonce() function.
    */
  this( ref const Impl.PublicKey myPk,
      ref const Impl.PublicKey oPk,
      ref const Impl.SecretKey mySk)
  {
    nonceGenerator = NonceGenerator( myPk, oPk );
    initNm(oPk, mySk);
  }

  /// ditto
  this( ref const Impl.PublicKey myPk,
      ref const Impl.PublicKey oPk,
      ref const Impl.SecretKey mySk,
      ref const Impl.Nonce startNonce)
  {
    nonceGenerator = NonceGenerator( myPk, oPk, startNonce, startNonce );
    initNm(oPk, mySk);
  }

  // Calculates the shared secret in the beforenm (only key-dependent) parts of the boxing.
  private void initNm(
      ref const Impl.PublicKey otherPartyPublicKey,
      ref const Impl.SecretKey mySecretKey)
  {
    Impl.beforenm( sharedSecret, otherPartyPublicKey, mySecretKey );
  }

  /**
    Packages a message from me to the other party.

    Packs the plainText into an encrypted and authenticated using my secret
    key, and the other partys public key.

    Note:
      Calling this function changes the nonce of my boxer so the other side
      must read this message then change his own nonce to match mine. This
      means that as soon as a message is skipped the following messages will be
      invalid, as there may be a replay attack.

    The open() function takes care of this incrementing.

    Params:
      plainText = the input plaintext to ecrypt and sign.
      autoAck   = automatically increment my nonce after encoding this message.
                  This means that I am sure, that the receiver will get this message
                  or otherwise the nonces will be out of sync and the any messages
                  coming from me will be considered invalid.
                  If you dont want this behaviour, use the ack() function after
                  confirmation from the other party that the message was received.


    Returns: the authenticated and ecrypted box as bytes.
  */
  ubyte[] box(const ubyte[] plainText, bool autoAck=true)
  {
    ubyte[] msg;
    ubyte[] o;
    // lay out the message in memory
    immutable msgLen = plainText.length + ZeroBytes;
    msg.length = msgLen;
    o.length = msgLen;
    o[0..ZeroBytes] = 0;
    msg[0..ZeroBytes] = 0;
    msg[ZeroBytes..msgLen] = plainText[0..plainText.length];

    Impl.afternm( o, msg, nonceGenerator.myNonce, sharedSecret );
    if (autoAck) nonceGenerator.nextMine();
    return o[BoxZeroBytes..msgLen];
  }

  /**
    Acknowkledges the reception of the last message sent by this boxer.

    This means incrementing the nonce, so any message sent to another boxer
    who hasnt received the last message will be invalid.
    */
  void ack() {
    nonceGenerator.nextMine();
  }

  /**
    Opens a box sent to me by the other party.

    Throws: BadSignatureError if the message doesnt authenticate.
    */
  ubyte[] open(const ubyte[] cypherText)
  in {
    assert( cypherText.length >=  (ZeroBytes - BoxZeroBytes) );
  }
  body {
    ubyte[] o, ct;

    immutable msgLen = cypherText.length + BoxZeroBytes;
    ct.length = msgLen;
    o.length = msgLen;
    ct[0..BoxZeroBytes] = 0;
    ct[BoxZeroBytes..msgLen] = cypherText[0..$];

    if (!Impl.openAfternm( o, ct, nonceGenerator.otherNonce, sharedSecret ))
      throw new BadSignatureError;

    // increment the nonce only on successful decoding
    nonceGenerator.nextOther();

    return o[ZeroBytes..msgLen];
  }

}


/**
  Creates a new Boxer.

  The parameter keys should of the lengths required by the used
  implementation.

  Params:
    myPublic = my public key (only used for initializing the nonce generator,
               not stored)
    mySecret = my secret key
    otherPublic = the other sides public key

  Returns: a new Boxer

  */
auto boxer(Impl=Curve25519XSalsa20Poly1305, MP, MS, OP)(
    ref const MP myPublic,
    ref const OP otherPublic,
    ref const MS mySecret,
    )
if ( is(MP == Impl.PublicKey) && is( MS == Impl.SecretKey)
    && is( OP == Impl.PublicKey))
{
  return Boxer!Impl( myPublic, otherPublic, mySecret);
}


unittest
{
  import std.random;
  import std.string;
  import nacl.basics : randomBuffer;
  auto aliceK = generateBoxKeypair();
  auto bobK = generateBoxKeypair();


  auto nonceFromHandshake = generateNonce!(aliceK.Primitive)();
  auto aliceBoxer = boxer(aliceK.publicKey, bobK.publicKey, aliceK.secretKey );
  auto bobBoxer = boxer(bobK.publicKey, aliceK.publicKey, bobK.secretKey );

  foreach(mlen;0..1024) {
    const msg = randomBuffer(mlen);
    auto cypherText = aliceBoxer.box(msg);
    auto plainText = bobBoxer.open(cypherText);
    assert( plainText == msg );

     //Try a replay attack
    auto cypherText2 = aliceBoxer.box(msg);
    auto plainText2 = bobBoxer.open(cypherText2);
    assert( cypherText2 != cypherText, "replayable message" );
    assert( plainText2 == msg );

    // Try forgery
    if (mlen == 0) continue;
    foreach(i;0..10) {
      cypherText = aliceBoxer.box(msg, false);
      cypherText[uniform(0,mlen)]++;
      try {
        assert( bobBoxer.open(cypherText) == msg, "forgery" );
        aliceBoxer.ack();
      }
      catch (BadSignatureError) { }
    }
  }
}


/**
  A secret-key authenticated encrypter.
  */
struct SecretBoxer(
    Impl=XSalsa20Poly1305,
    NonceGenerator=NonceStream!(Impl.NonceBytes, 1),
    ) {
  enum ZeroBytes = Impl.ZeroBytes;
  enum BoxZeroBytes = Impl.BoxZeroBytes;

  Impl.Key key;
  NonceGenerator nonces;

  this( ref Impl.Key k, ref Impl.Nonce startNonce ) {
    key = k;
    nonces.bytes = startNonce;
  }


  /**
    Packages the plainText into an authenticated and encrypted box.

    Params:
    autoAck   = automatically increment my nonce after encoding this message.
                This means that I am sure, that the receiver will get this message
                or otherwise the nonces will be out of sync and the any messages
                coming from me will be considered invalid.
                If you dont want this behaviour, use the ack() function after
                confirmation from the other party that the message was received.

    */
  ubyte[] box( const ubyte[] plainText, bool autoAck = true )
  {
    ubyte[] m,c;
    immutable mlen = plainText.length + ZeroBytes;
    m.length = mlen;
    c.length = mlen;
    m[ZeroBytes..mlen] = plainText;
    Impl.secretbox( c, m, nonces.front, key );

    if (autoAck) nonces.popFront();

    return c[BoxZeroBytes..mlen];
  }


  /**
    Acknowkledges the reception of the last message sent by this boxer.

    This means incrementing the nonce, so any message sent to another boxer
    who hasnt received the last message will be invalid.
    */
  void ack()
  {
    nonces.popFront();
  }

  /**
    Opens a box encrypted and signed by another boxer with
    the same key and the same nonce.
    */
  ubyte[] open( const ubyte[] cypherText )
  in {
    assert(cypherText.length >= (ZeroBytes - BoxZeroBytes));
  }
  body {
    ubyte[] m,c;
    immutable mlen = cypherText.length + BoxZeroBytes;
    m.length = mlen;
    c.length = mlen;
    c[BoxZeroBytes..mlen] = cypherText;
    if (!Impl.secretboxOpen( m, c, nonces.front, key ))
      throw new BadSignatureError();

    nonces.popFront();

    return m[ZeroBytes..mlen];
  }


}

/**
  Convinience function to create a new SecretBoxer
  */
auto secretBoxer(Impl=XSalsa20Poly1305, Args...)( Args args )
{
  return SecretBoxer!(Impl)(args);
}

unittest {
  import nacl.basics : randomBuffer, forgeBuffer;
  import std.random;
  import std.exception;
  alias Impl = XSalsa20Poly1305;
  Impl.Key k;
  Impl.Nonce n = generateNonce!XSalsa20Poly1305();
  nacl.basics.safeRandomBytes(k, Impl.KeyBytes );

  auto alice = secretBoxer(k, n);
  auto bob = secretBoxer(k, n);
  foreach(mlen;0..1024) {
    const msg = randomBuffer(mlen);

    auto cypherText = alice.box( msg );
    assert( msg != cypherText );
    auto plainText = bob.open( cypherText );
    assert( plainText == msg );

    if (mlen < 10) continue;
    // forgery
    foreach(i;0..10) {
      cypherText = alice.box( msg, false );
      forgeBuffer( cypherText, i );
      try {
        assert( bob.open(cypherText) == msg );
        alice.ack();
      }
      catch (BadSignatureError) {
      }
    }
  }
}



/**
  Authenticates a message with a secret key.

  Users willing to compromise both provability and speed can replace
  auth with std.digest.* primitives.

  The sender must not use auth to authenticate more than one
  message under the same key. Authenticators for two messages under the
  same key should be expected to reveal enough information to allow
  forgeries of authenticators on other messages.
  */
auto auth(Impl=Poly1305, Key)( const ubyte[] plainText, ref const Key k )
  if (is(Key == Impl.Key))
{
  Impl.Value o;
  Impl.onetimeauth( o, plainText, k );
  return o;
}

/**
  Authenticates the message in constant-time.

  Returns: true if the message is authentic or false if not.
  */
bool verifyAuth(Impl=Poly1305, Value, Key)(
    ref const Value v, const ubyte[] plainText, ref const Key k )
  if (is(Key == Impl.Key) && is(Value == Impl.Value))
{
  return Impl.onetimeauthVerify( v, plainText, k );
}

/**
  Authenticates the message in constant-time and throws an exception if the
  message fails authentication.

  Throws: BadSignatureError if the signature is invalid
*/
void openAuth(Impl=Poly1305, Value, Key)(
    ref const Value v, const ubyte[] plainText, ref const Key k )
  if (is(Key == Impl.Key) && is(Value == Impl.Value))
{
  if (!Impl.onetimeauthVerify( v, plainText, k ))
      throw new BadSignatureError();
}




unittest {
  import nacl.basics : randomBuffer, forgeBuffer;
  import std.random;
  import std.exception;
  alias Impl = Poly1305;
  Impl.Key k;
  nacl.basics.safeRandomBytes(k, Impl.KeyBytes );

  foreach(mlen;0..1024) {
    const msg = randomBuffer(mlen);
    const authVal = auth(msg, k);
    assert( verifyAuth(authVal, msg, k) );

    if (mlen < 1) continue;
    ubyte[] tmp;
    tmp.length = msg.length;
    // forgery
    foreach(i;1..10) {
      do {
        tmp[0..$] = msg;
        forgeBuffer( tmp, i );
      } while (tmp == msg);
      assert( !verifyAuth(authVal, tmp, k), bytesToHex(tmp) ~ "  ==  " ~ bytesToHex(msg) );
      assertThrown!BadSignatureError( openAuth( authVal, tmp, k) );
    }
  }
}

