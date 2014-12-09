/**

  $(BIG $(I "Where theres magic theres security problems"))

  DEF CON 20 - Charlie Miller
  $(I"Don't Stand So Close To Me: An Analysis of the NFC Attack Surface")
  $(BR)
  $(LINK https://www.youtube.com/watch?v=16FKOQ1gx68)

$(UL
  $(LI $(LINK2 nacl.html , Rationale / about to NaCl ))
  $(LI $(LINK2 handshake.html , Handshakes ))
  )

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

$(UL
  NaCl provides a simple crypto_box function that does everything in one step.
  The function takes the sender's secret key, the recipient's public key, and a
  message, and produces an authenticated ciphertext. All objects are represented
  in wire format, as sequences of bytes suitable for transmission; the crypto_box
  function automatically handles all necessary conversions, initializations, etc.

  $(LI Another virtue of NaCl's high-level API is that it is not tied to the
  traditional hash-sign-encrypt-etc. hybrid structure. NaCl supports much
  faster message-boxing solutions that reuse Diffie-Hellman shared secrets for
  any number of messages between the same parties.)
)

License:
TweetNaCl is public domain, tweedNaCl is available under the Boost Public License.

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
module tweednacl;

import tweednacl.encoded_bytes;
import tweednacl.basics;

import tweednacl.curve25519xsalsa20poly1305 : Curve25519XSalsa20Poly1305;
import tweednacl.ed25519 : Ed25519;
import tweednacl.xsalsa20poly1305 : XSalsa20Poly1305;
import tweednacl.poly1305 : Poly1305;
import tweednacl.nonce_generator;

/**
  A generic pair of secret and public keys for signing data and an algorithm.
  */
struct KeyPair(Impl)
{
  /** Accessor for the implementation */
  alias Primitive = Impl;

  /** The memory representation of a public key */
  alias PublicKey = Impl.PublicKey;

  /** The memory representation of a secret key */
  alias SecretKey = Impl.SecretKey;

  /** The public key to validate signed data with. */
  PublicKey publicKey;

  /** The secret key */
  SecretKey secretKey;

  ~this() { erase(); }

  /** Overwrite the keys with zeroes (call before freeing their memory) */
  void erase() { publicKey[] = 0; secretKey[] = 0; }
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
alias generateSignKeypair(Impl=Ed25519, alias safeRnd=tweednacl.basics.safeRandomBytes)
  = generateKeypair!(Impl, safeRnd);


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

Examples:
---
{

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
  void process( const ubyte[] data ) { /+ ... +/ }


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
---
  */
ubyte[] sign(Impl=Ed25519, E, Key)(
    const E[] message, ref const Key sk )
  if ( is( Key == Impl.SecretKey ) )
{
  size_t smlen;
  const msg = tweednacl.basics.toBytes( message );
  auto o = zeroOut( Impl.Bytes, msg );
  Impl.sign( o, smlen, msg, sk  );
  return o;
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
ubyte[] openSigned(Impl=Ed25519, E, Key)(
    const E[] signedData, ref const Key pk )
  if ( is( Key == Impl.PublicKey ) )
in {
  assert(signedData.length >= Impl.Bytes);
}
body {
  const sm = tweednacl.basics.toBytes( signedData );
  auto output = zeroOut( sm );
  //ubyte[] output;
  //output.length = sm.length;
  size_t outputLen;
  if (!Impl.signOpen( output, outputLen, sm, pk ))
    throw new BadSignatureError();
  //output.length = outputLen;
  return output[0..outputLen];
}


unittest {
  import std.random;
  import tweednacl.basics : randomBuffer;

  auto o = generateSignKeypair();

  foreach(mlen;0..16) {
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

A communication helper that can box and unbox messages to and form another party.

It is up to the user to provide some kind of a handshake to exchange a starting
nonce. The suggested way is to use the generateNonce() function.

Examples:
---
  // Alice and Bob both create a public-secret keypair.
  auto aliceK = generateBoxKeypair();
  auto bobK = generateBoxKeypair();

  // they exchange their public keys, but keep their secret keys private
  auto alicePublicKey = aliceK.publicKey;
  auto bobPublicKey = bobK.publicKey;


  // Alice and Bob agree in a nonce for the current session via some
  // kind of handshake.
  auto nonceFromHandshake = generateNonce!(aliceK.Primitive)();
  auto aliceNonce = nonceFromHandshake;
  auto bobNonce = nonceFromHandshake;

  // Alice creates her boxer
  auto aliceBoxer = boxer(alicePublicKey, bobPublicKey,
      aliceK.secretKey, nonceFromHandshake );

  // Bob creates his boxer
  auto bobBoxer = boxer(bobPublicKey, alicePublicKey,
      bobK.secretKey, nonceFromHandshake );

  // Alice packages and signs her message and sends it to
  // Bob.
  auto aliceSends = aliceBoxer.box( "Hello!" );

  // After Bob gets the message he opens it.
  // If the message fails to authenticate, Bob gets a BadSignatureError
  // signaling that the message has altered or isnt coming from Alice.
  try {
    auto bobReceives = bobBoxer.open( aliceSends );
    // ...
  }
  catch( BadSignatureError ) {
    // If there has been an error authenticating the message.
  }

---

Examples:
  If the channel transmitted on may be unreliable, the acknowledment that
  a message is received may be necessary.
---

  // Lets assume aliceBoxer from the previous example

  // As alice is sending her message, she signals that she will
  // know when Bob gets the message, and if one of her messages
  // gets lost she will be able to send Bob a message without
  // performing another handshake
  auto aliceSends = aliceBoxer.box( "Hello!", false );

  // Alice calls $(D Boxer.ack()) when she knows her message
  // has been delivered (like a TCP ACK).
  void onMessageDelivered() {
    aliceBoxer.ack();
  }

---
  */
struct Boxer( Impl, NonceGenerator )
{
  alias Primitive = Impl;

  enum ZeroBytes = Impl.ZeroBytes;
  enum BoxZeroBytes = Impl.BoxZeroBytes;

  private NonceGenerator nonceGenerator;
  private Impl.Beforenm beforenm;

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
    auto msg = zeroPadded( ZeroBytes, plainText );
    auto o = zeroOut( ZeroBytes, plainText );

    Impl.afternm( o, msg, nonceGenerator.mine.front, beforenm );
    if (autoAck) ack();
    return o[BoxZeroBytes..$];
  }

  /**
    Acknowkledges the reception of the last message sent by this boxer.

    This means incrementing the nonce, so any message sent to another boxer
    who hasnt received the last message will be invalid.
    */
  void ack() {
    nonceGenerator.mine.popFront();
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
    auto ct = zeroPadded( BoxZeroBytes, cypherText );
    auto o = zeroOut( BoxZeroBytes, cypherText );

    if (!Impl.openAfternm( o, ct, nonceGenerator.other.front, beforenm ))
      throw new BadSignatureError;

    // increment the nonce only on successful decoding
    nonceGenerator.other.popFront();

    return o[ZeroBytes..$];
  }

}


version(unittest) {
  enum TryToForgeMessagesUpTo = 512;

  void testBoxers(A,B)(A aliceBoxer, B bobBoxer)
  {
    import tweednacl.basics : randomBuffer, forgeBuffer;
    foreach(mlen;0..TryToForgeMessagesUpTo) {
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
        // Re-send the message, but dont increment our nonce, since
        // this message may get lost so alice may need to resend it, and
        // if alice increments her nonce without bob receiving that message,
        // she will be unable to talk to bob.
        cypherText = aliceBoxer.box(msg, false);
        forgeBuffer( cypherText, i );
        try {
          assert( bobBoxer.open(cypherText) == msg, "forgery" );
          // at this point the cyphertext is the same as the original (so the
          // message is also the original), so alice must acknowledges it by
          // incrementing her nonce.
          aliceBoxer.ack();
        }
        catch (BadSignatureError) { }
      }
    }
  }
}

/**
  Generates a keypair for the sign() and openSigned() functions.
  */
alias generateBoxKeypair(
    Impl=Curve25519XSalsa20Poly1305,
    alias safeRnd=safeRandomBytes)
  = generateKeypair!(Impl, safeRnd);


/**
  Shortcut to generate a nonce for the default implementation of SecretBoxes.
  */
alias generateBoxNonce(Impl=Curve25519XSalsa20Poly1305) = generateNonce!(Impl);

/**
  Creates a new Boxer for public-key authenticated encryption.

Note:
  The keys are only used to derive a shared secret and the
  nonce-offsets, they are not stored in the Boxer.

Params:
myPublic = my public key
not stored)
mySecret = my secret key
otherPublic = the other sides public key
nonce = the starting nonce.

Returns: a new Boxer

  */
auto boxer(Impl=Curve25519XSalsa20Poly1305, MP, MS, OP,Nonce)(
    ref const MP myPublic,
    ref const OP otherPublic,
    ref const MS mySecret,
    ref const Nonce nonce)
if ( is(MP == Impl.PublicKey)
    && is( MS == Impl.SecretKey)
    && is( OP == Impl.PublicKey)
    && is(Nonce == Impl.Nonce))
{
  alias NonceGenerator=DoubleStriderNonce!(Impl.Nonce.length);
  Impl.Beforenm beforenm;
  Impl.beforenm( beforenm, otherPublic, mySecret );
  return Boxer!(Impl, NonceGenerator)(
      NonceGenerator( myPublic, otherPublic, nonce, nonce ),
      beforenm,
      );
}



unittest
{
  auto aliceK = generateBoxKeypair();
  auto bobK = generateBoxKeypair();

  // This nonce should be exchanged via some kind of a handshake
  auto nonceFromHandshake = generateNonce!(aliceK.Primitive)();

  auto aliceBoxer = boxer(aliceK.publicKey, bobK.publicKey,
      aliceK.secretKey, nonceFromHandshake );
  auto bobBoxer = boxer(bobK.publicKey, aliceK.publicKey,
      bobK.secretKey, nonceFromHandshake );

  testBoxers( aliceBoxer, bobBoxer);
}



/**
  Shortcut that generates a secret key for the default implementation of SecretBoxes.
  */
alias generateSecretBoxKey(Impl=XSalsa20Poly1305, alias safeRnd=safeRandomBytes) =
  generateSecretKey!(Impl, safeRnd);

/**
  Shortcut to generate a nonce for the default implementation of SecretBoxes.
  */
alias generateSecretBoxNonce(Impl=XSalsa20Poly1305) = generateNonce!(Impl);

/**

  Creates a new Boxer for a secret-key authenticated encryption.

Params:
  k = the shared secret key
  nonce = the starting nonce.

Returns: A new secret-key boxer.

  */
auto secretBoxer(Impl=XSalsa20Poly1305, Key, Nonce)(
    ref const Key k,
    ref const Nonce n)
  if (is(Key == Impl.Key) && is(Nonce == Impl.Nonce))
{
  alias NonceGenerator=SingleNonce!(Impl.Nonce.length);
  return Boxer!(Impl, NonceGenerator)( NonceGenerator(n), k);
}

unittest {
  alias Impl = XSalsa20Poly1305;
  auto k = generateSecretBoxKey!Impl();
  auto n = generateSecretBoxNonce!Impl();

  auto aliceBoxer = secretBoxer(k, n);
  auto bobBoxer = secretBoxer(k, n);

  testBoxers( aliceBoxer, bobBoxer );
}


/**
  Shortcut that generates a secret key for the default implementation of Secret-Key Authentication.
  */
alias generateAuthKey(Impl=Poly1305, alias safeRnd=safeRandomBytes) =
  generateSecretKey!(Impl, safeRnd);


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
  import tweednacl.basics : randomBuffer, forgeBuffer;
  import std.random;
  import std.exception;
  alias Impl = Poly1305;
  auto k = generateAuthKey();

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


static if (false) {
  /**
    Mixes two nonces (from the initiator and the accepter) and mixes
    them in a deterministic way.

    The current implementation mixes the even-odd bytes from the nonces.
   */
  Nonce mixNonces(Nonce)( ref const Nonce initiator, ref const Nonce receiver )
  {
    Nonce o;
    foreach(i,ref oe;o) {
      oe = (i % 2) ? initiator[i] : receiver[i];
    }
    return o;
  }

  class HandshakeError : Exception {
    this(string msg) { super("Handshake error: " ~ msg); }
  }

  struct NoSignature {}
  struct NonceHandshakeSteps(
      Nonce,
      alias nonceGeneratorFn=generateNonce!(Nonce.length),
      )
  {
    void init(Msg)( ref Msg msg )
    {
      msg.nonce = nonceGeneratorFn();
    }

    void acceptInit(InitMsg, Msg)( ref const InitMsg initMsg , ref Msg msg )
    {
      msg.initNonce = initMsg.nonce;
      msg.accepterNonce = nonceGeneratorFn();
    }
  }

  /**
    A handshake is a simple message interface for exchanging
    two pieces of data and deriving a common piece for both parties
   */
  struct Handshake( Nonce,
      Steps = NonceHandshakeSteps!Nonce,
      SignPrimitive = Ed25519,
      alias nonceMixer = mixNonces
      )
  {
    public:
      Steps steps;

      enum isSigned = !is(SignPrimitive == NoSignature );
      static if(isSigned)
      {
        // Allow the initialization with keys.
        SignPrimitive.PublicKey otherPartyPublicKey;
        SignPrimitive.SecretKey mySecretKey;

        // Clean the key memory afterwards
        ~this() {
          mySecretKey[] = 0;
          otherPartyPublicKey[] = 0;
        }

        auto signIfNeeded(E)(E i) { return sign!SignPrimitive( i, mySecretKey ); }
        auto openIfNeeded(E)(E m) { return openSigned!SignPrimitive( m, otherPartyPublicKey); }
        enum SignatureSize = SignPrimitive.Signature.length;
      } else {
        auto signIfNeeded(E)(E m) { return m; }
        auto openIfNeeded(E)(E m) { return m; }
        enum SignatureSize = 0;
      }
    private:

      Nonce exchangedNonce;
      bool nonceExchanged = false;

      struct InitMsg { Nonce nonce; }

      /** The message sent on initialization */
      struct InitAcceptMsg {
        Nonce initNonce;
        Nonce accepterNonce;
      }

    public:
      /**
        Step 1. initialize the connection.
       */
      ubyte[] init()
      {
        // allocate buffer
        ubyte[] msg;
        msg.length = InitMsg.sizeof;
        auto initMsg = cast(InitMsg*)(&msg[0]);

        steps.init( initMsg );
        //initMsg.nonce = nonceGeneratorFn();
        nonceExchanged = false;

        return signIfNeeded( msg );
      }


      ubyte[] acceptInit( const ubyte[] initMsgBytes )
      {
        if (initMsgBytes.length != InitMsg.sizeof + SignatureSize)
          throw new HandshakeError("Invalid handshake Init length");

        auto openedMsg = openIfNeeded( initMsgBytes );
        auto initMsg = cast(InitMsg*)(&openedMsg[0]);

        // allocate buffer
        ubyte[] msg;
        msg.length = InitAcceptMsg.sizeof;
        auto initAcceptMsg = cast(InitAcceptMsg*)(&msg[0]);

        steps.acceptInit( initMsg, initAcceptMsg );
        //initAcceptMsg.initNonce = initMsg.nonce;
        //initAcceptMsg.accepterNonce = nonceGeneratorFn();

        exchangedNonce = nonceMixer( initAcceptMsg.initNonce,
            initAcceptMsg.accepterNonce );

        nonceExchanged = true;

        return signIfNeeded(msg);
      }


      void succeed(  const ubyte[] initAcceptMsgBytes )
      {
        if (initAcceptMsgBytes.length != InitAcceptMsg.sizeof + SignatureSize)
          throw new HandshakeError("Invalid handshake InitAccept length");

        auto openedMsg = openIfNeeded( initAcceptMsgBytes );
        auto initAcceptMsg = cast(InitAcceptMsg*)(&openedMsg[0]);

        exchangedNonce = nonceMixer( initAcceptMsg.initNonce,
            initAcceptMsg.accepterNonce );

        nonceExchanged = true;
      }


      void acceptSuccesd()
      {
      }


      /**
        Get the exchanged nonce.

Throws: HandshakeError if exchange was unsuceesful or finished.
       */
      Nonce open()
      {
        if (!nonceExchanged)
          throw new HandshakeError("Tried to open not completed handshake.");

        return exchangedNonce;
      }


      /** Is the handshake done? (Can this handshake be $(D open)ed?) */
      bool done() { return nonceExchanged; }

  }

  auto signedHandshake( Data,
      SignPrimitive = Ed25519,
      alias nonceGeneratorFn=generateNonce!(Data.length),
      alias nonceMixer = mixNonces,
      Pk, Sk
      )( Pk otherPk, Sk mySk)
  {
    alias H = NonceHandshakeSteps!(ubyte[Data.length]);
    return Handshake!(Data, H)( H(), otherPk, mySk);
  }



  auto notSignedHandshake( Data,
      alias nonceGeneratorFn=generateNonce!(Data.length),
      alias nonceMixer = mixNonces
      )()
  {
    alias H = NonceHandshakeSteps!(ubyte[Data.length]);
    return Handshake!(Data, H, NoSignature)( H() );
  }



  unittest {
    import std.stdio;
    import std.exception;
    alias Nonce = ubyte[24];

    void testHandShake(H)(H aliceH, H bobH)
    {
      foreach(i;0..16) {

        auto msg1 = aliceH.init();

        assert(!aliceH.done());
        assertThrown!HandshakeError( aliceH.open() );

        auto msg2 = bobH.acceptInit( msg1 );
        aliceH.succeed( msg2 );

        assert( aliceH.done() );
        assert( bobH.done() );
        assert( aliceH.open() == bobH.open() );


      }
    }

    testHandShake(
        notSignedHandshake!Nonce(), notSignedHandshake!Nonce()
        );

    auto aliceK = generateSignKeypair();
    auto bobK = generateSignKeypair();


    testHandShake(
        signedHandshake!Nonce( bobK.publicKey, aliceK.secretKey ),
        signedHandshake!Nonce( aliceK.publicKey, bobK.secretKey )
        );
  }
}

import tweednacl.handshake;





auto session(Impl=Curve25519XSalsa20Poly1305)()
{
  return Session!(Impl)( generateKeypair!Impl() );
}

/*
   Creates and uses a session
*/
unittest {
  foreach (i;0..16)
  {
    // Generates a new keypair.
    // the .sessionRequest contains the public key.
    auto aliceSession = session();
    auto bobSession = session();

    auto nonceFromHandshake = generateBoxNonce();

    // Alice and Bob exchange their session public keys, and now they have
    // a secure session that cannot be decoded. When bobSession goes out of scope
    // the public and private keys for this session are forgotten and the only
    // way to communicate in this session is via the boxers
    auto bobBoxer = bobSession.open( aliceSession.request[0..32], nonceFromHandshake );
    auto aliceBoxer = aliceSession.open( bobSession.request[0..32], nonceFromHandshake );

    ubyte[8192] msgBuf;

    foreach(j;0..64)
    {
      auto mlen1 = uniform(0,4096u);
      auto mlen2 = uniform(0,4096u);

      auto rawMsg1 = msgBuf[0..mlen1];
      auto rawMsg2 = msgBuf[mlen1..(mlen1+mlen2)];
      unSafeRandomBytes( rawMsg1 );
      unSafeRandomBytes( rawMsg2 );

      auto msg1 = aliceBoxer.box( rawMsg1 );
      auto msg2 = bobBoxer.box( rawMsg2 );

      assert( bobBoxer.open( msg1 ) == rawMsg1 );
      assert( aliceBoxer.open( msg2 ) == rawMsg2 );

    }
  }
}


unittest {
  foreach (i;0..16)
  {
    // Generates a new keypair.
    // the .sessionRequest contains the public key.
    auto aliceSession = session();
    auto bobSession = session();


    auto aliceH = aliceSession.handshake();
    auto bobH = bobSession.handshake();

    // Alice and Bob exchange their session public keys.
    bobH.succeed( aliceH.sync( bobH.response( aliceH.challenge() )));

    // Alice and Bob exchange their session public keys, and now they have
    // a secure session that cannot be decoded. When bobSession goes out of scope
    // the public and private keys for this session are forgotten and the only
    // way to communicate in this session is via the boxers
    auto bobBoxer = bobSession.open( bobH.open() );
    auto aliceBoxer = aliceSession.open( aliceH.open() );



    ubyte[8192] msgBuf;

    foreach(j;0..64)
    {
      auto mlen1 = uniform(0,4096u);
      auto mlen2 = uniform(0,4096u);

      auto rawMsg1 = msgBuf[0..mlen1];
      auto rawMsg2 = msgBuf[mlen1..(mlen1+mlen2)];
      unSafeRandomBytes( rawMsg1 );
      unSafeRandomBytes( rawMsg2 );

      auto msg1 = aliceBoxer.box( rawMsg1 );
      auto msg2 = bobBoxer.box( rawMsg2 );

      assert( bobBoxer.open( msg1 ) == rawMsg1 );
      assert( aliceBoxer.open( msg2 ) == rawMsg2 );

    }
  }
}

struct Session(Impl)
{
  import std.typecons;

  KeyPair!Impl sessionKeyPair;


  ~this() {
    sessionKeyPair.secretKey[] = 0;
  }

  /** Contains the public key for this session */
  @property ubyte[] request()
  {
    return sessionKeyPair.publicKey;
  }

  /**
    Returns a new Boxer for the session keypair and the public key received from
    the other party.
    */
  auto open( ref const Impl.PublicKey pk, ref const Impl.Nonce nonce )
  {
    return boxer!Impl( sessionKeyPair.publicKey, pk, sessionKeyPair.secretKey, nonce );
  }

  /** ditto */
  auto open(HandshakeResult)( HandshakeResult fromHandshake )
    if (__traits(compiles, open( fromHandshake.expand )))
  {
    return open( fromHandshake[0], fromHandshake[1] );
  }


  /**
    Create a new $(RED unsigned) handshake to agree on public keys for this session.
    */
  auto handshake()
  {
    return unsignedPublicKeyNonceHandshake!Impl(sessionKeyPair.publicKey);
  }
}

/**
  Gets thrown when a signature mismatches during the opening
  a signed message or box.
  */
class BadSignatureError : Exception
{
  this() { super("Bad signature!"); }
}

/**
  Generates a pair of public and private keys for an implementation.

Params:
  Impl = The implementation to use (defaults to Ed25519)
 */
auto generateKeypair(Impl, alias safeRnd=tweednacl.basics.safeRandomBytes)()
{
  auto o = KeyPair!Impl();
  Impl.keypair!safeRnd( o.publicKey, o.secretKey );
  return o;
}

/**
  Generates a secret key.
  */
auto generateSecretKey(Impl, alias safeRnd=tweednacl.basics.safeRandomBytes)()
{
  Impl.Key k;
  safeRnd( k, Impl.Key.length );
  return k;
}

