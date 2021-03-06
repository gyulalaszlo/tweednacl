/**
$(STD_CRYPTO_HEAD)

$(H2 Boxes)

Most of the functionnality provided by std.experimental.crypto revolves around the
concept of boxes: instead of separate signing/encrypting/etc. steps, this library
tries to represent the simple human concepts of "I want to send this data. ENCRYPTED."
or 

"Encrypt with a public key" usually means:

$(UL
  $(LI derive a shared key from my secret key and the other partys public key)
  $(LI "Encrypt this data" using the derived key)
)

"Encrypt this data" usually means:

$(UL
  $(LI pad the data to suit the algorithm used)
  $(LI encrypt the data using the proper key and nonce/initialization vector)
  $(LI add an integrity checksum)
  $(LI add authenticity information)
)

"Decrypt with a secret key" usually means:

$(UL
  $(LI derive the same shared key from my secret key and the other partys public key)
  $(LI "Decrypt this data" using the derived key)
)

"Decrypt this data" usually means:

$(UL
  $(LI check the authenticity of the data)
  $(LI check the integrity of the data)
  $(LI decrypt the data using the proper key and nonce/initialization vector)
  $(LI remove any padding required by any of the previous algorithms)
)


These layers of modifications are as:  Both NaCl and std.experimental.crypto 

$(UL
  $(LI checksum + authenticity = authenticator (Poly1305))
  $(LI padding + encryption + authenticator = secret box (XSalsa20Poly1305))
  $(LI derive a shared secret + secret box = box (Curve25519XSalsa20Poly1305))
)

std.experimental.crypto adds the following abstractions:

$(UL
  $(LI key storage / serializatin / conversion = Key)
  $(LI exchange public keys and/or nonces = handshake())
  $(LI Handshake + public key authentication + replay & forgery protection = signedHandshake())
  $(LI keeping nonces/initialization vectors in sync: nonce generators )
    (DoubleStrided, SingleStrided, InMessage, NonceStream)
  $(LI Perfect Forward Secrecy using ephemeral keys = session())
)

<hr/>
$(COMM_TABLE_CSS)

$(H2 Signing messages / Public Key Authentication)

$(COMM_TABLE
  $(COMM_ROW_AB
    $(COMM_LABEL Scenario)
    Bob wants to transfer Alice 1 Million dollars, and needs Alice to send
    her account number over the wire. Bob has to make sure that he is in fact
    transfering to Alices account.
  )

  $(COMM_ROW_A
    $(COMM_LABEL Generate key)
    Alice generates a keypair for signing the data.

    ---
    auto aliceKeys = signKeypair();
    // deliver the keys to Bob
    ---

    And signs some data with it.

    ---
    // send some important banking data
    auto msg = sign( aliceAccountNumber, aliceKeys.secretKey );
    sendToBob(msg);
    ---
  )

  $(COMM_ROW_B
    $(COMM_LABEL Verify the authenticity)

    Bob verifies the authenticity of the message:
    ---
    // If the message isnt authentic, openSigned throws a BadSignatureError
    // and the money isnt transferred.
    transferOneMillionDollars( openSigned( msg, alicePublicKey ) );
    ---
  )
)


$(H2 Public-key Encrypted Communication)

$(COMM_TABLE
  $(COMM_ROW_AB
    $(COMM_LABEL Scenario)
    Bob wants to transfer Alice 1 Million dollars, and needs Alice to send
    her account number over the wire. Bob has to make sure that he is in fact
    transfering to Alices account.
  )

  $(COMM_ROW
    $(COMM_TD_A
      $(COMM_LABEL Generate key)
      Alice generates a keypair for signing the data.

      ---
      auto aliceKeys = boxKeypair();
      // deliver the public key to Bob
      ---

      $(COMM_LABEL Create a boxer)
      ---
      // exchangedNonce is somehow agreed before starting the communication
      auto aliceBoxer = boxer( bobPublicKey, aliceKeys.secretKey, exchangedNonce);
      ---

    )

    $(COMM_TD_B
      $(COMM_LABEL Generate key)
      Bob generates a keypair
      ---
      auto aliceKeys = boxKeypair();
      // deliver the public key to Alice
      ---

      $(COMM_LABEL Create a boxer)
      ---
      // exchangedNonce is somehow agreed upon starting the communication
      auto bobBoxer = boxer( alicePublicKey, bobKeys.secretKey, exchangedNonce);
      ---

    )
  )


  $(COMM_ROW_A
    $(COMM_LABEL Encrypt the message)

    Alice uses
    ---
    auto msg1 = aliceBoxer.box( aliceBillingData );
    // send msg1 to Bob
    ---
  )

  $(COMM_ROW_B
    $(COMM_LABEL Decrypt the message and encrypt a reply)

    Bob verifies the authenticity of the message and decrypts it:
    ---
    // if the message isnt authentic or damaged, a BadSignatureError
    // is thrown and the subscription isnt billed.
    auto billingData = bobBoxer.open( msg1 );
    ---
    Bob bills the subscription and creates the subscription, then replies to
    Alice with her subscription data.
    ---
    auto msg2 = bobBoxer.box( subscriptionData );
    ---
  )

  $(COMM_ROW_A
    $(COMM_LABEL Decrypt a message)

    Alice decrypts and verifies her subscription data
    ---
    auto subscriptionData = aliceBoxer.open( msg2 );
    ---
  )
)

$(H2 Shared-key Encrypted Communication)

$(COMM_TABLE
  $(COMM_ROW_AB
    $(COMM_LABEL Scenario)
    Bob wants to transfer Alice 1 Million dollars, and needs Alice to send
    her account number over the wire. Bob has to make sure that he is in fact
    transfering to Alices account.

    They both agree on a key.
    ---
    auto key = secretBoxKey();
    ---
  )

  $(COMM_ROW
    $(COMM_TD_A
      $(COMM_LABEL Create a boxer)

      ---
      // exchangedNonce is somehow agreed before starting the communication
      auto aliceBoxer = secretBoxer( key, exchangedNonce);
      ---

    )

    $(COMM_TD_B
      $(COMM_LABEL Create a boxer)
      ---
      // exchangedNonce is somehow agreed upon starting the communication
      auto bobBoxer = secretBoxer( key, exchangedNonce);
      ---

    )
  )


  $(COMM_ROW_A
    $(COMM_LABEL Encrypt the message)

    Alice uses
    ---
    auto msg1 = aliceBoxer.box( aliceBillingData );
    // send msg1 to Bob
    ---
  )

  $(COMM_ROW_B
    $(COMM_LABEL Decrypt the message and encrypt a reply)

    Bob verifies the authenticity of the message and decrypts it:
    ---
    // if the message isnt authentic or damaged, a BadSignatureError
    // is thrown and the subscription isnt billed.
    auto billingData = bobBoxer.open( msg1 );
    ---
    Bob bills the subscription and creates the subscription, then replies to
    Alice with her subscription data.
    ---
    auto msg2 = bobBoxer.box( subscriptionData );
    ---
  )

  $(COMM_ROW_A
    $(COMM_LABEL Decrypt a message)

    Alice decrypts and verifies her subscription data
    ---
    auto subscriptionData = aliceBoxer.open( msg2 );
    ---
  )
)
License:
TweetNaCl is public domain, TweeDNaCl and std.experimental.crypto is available
under the Boost Public License.

*/
module std.experimental.crypto;

import tweednacl;
import tweednacl.basics;

import std.experimental.crypto.nonce_generator;

import std.experimental.crypto.keys;
import std.experimental.crypto.handshake;

alias boxPublicKey(Impl=Curve25519XSalsa20Poly1305) = publicKeyT!Impl;
alias boxSecretKey(Impl=Curve25519XSalsa20Poly1305) = secretKeyT!Impl;

alias signPublicKey(Impl=Ed25519) = publicKeyT!Impl;
alias signSecretKey(Impl=Ed25519) = secretKeyT!Impl;


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
alias generateSignKeypair(Impl=Ed25519, alias safeRnd=safeRandomBytes)
  = generateKeypair!(Impl, safeRnd);

unittest
{
  import std.stdio;

  assert(signPublicKey!Ed25519.fromKeyString("BwEAIMS6a3Cz9mqIn8zvSBwQxgAM+F5iJgIZBUn2SX5O83o9LqcUY9NM/R4=").data
         == [179, 246, 106, 136, 159, 204, 239, 72, 28, 16, 198, 0, 12, 248, 94, 98, 38, 2, 25, 5, 73, 246, 73, 126, 78, 243, 122, 61, 46, 167, 20, 99]);
  assert(signSecretKey!Ed25519.fromKeyString("BwIAQMS6a3BZyu+Cx9JKZ4LyhrCrYi3houVPhRsSR/nlS71R3P655bP2aoifzO9IHBDGAAz4XmImAhkFSfZJfk7zej0upxRjJyE3Rw==").data
         == [89, 202, 239, 130, 199, 210, 74, 103, 130, 242, 134, 176, 171, 98, 45, 225, 162, 229, 79, 133, 27, 18, 71, 249, 229, 75, 189, 81, 220, 254, 185, 229, 179, 246, 106, 136, 159, 204, 239, 72, 28, 16, 198, 0, 12, 248, 94, 98, 38, 2, 25, 5, 73, 246, 73, 126, 78, 243, 122, 61, 46, 167, 20, 99]);
  
  auto a = generateSignKeypair();

  assert( signPublicKey!Ed25519.fromKeyString(a.pub.keyString).data == a.publicKey );
  assert( signSecretKey!Ed25519.fromKeyString(a.sec.keyString).data == a.secretKey );
}

/**
  Signs a message using the given secret key

Params:
  Impl = The implementation to use. Defaults to Ed25519.

  message =  the signed data with crypto_sign_BYTES of signature followed
                by the plaintext message
  sk         =  the secret key to sign the message with

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
ubyte[] sign(Impl=Ed25519, E, Key)( const E[] message, ref const Key sk )
  if ( is( Key == Impl.SecretKey ) )
{
  size_t smlen;
  const msg = toBytes( message );
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
  const sm = toBytes( signedData );
  auto output = zeroOut( sm );
  size_t outputLen;
  if (!Impl.open( output, outputLen, sm, pk ))
    throw new BadSignatureError();
  return output[0..outputLen];
}


unittest {
  import std.random;
  import tweednacl.random : randomBuffer;

  auto o = generateSignKeypair();

  foreach(mlenMagn;0..12) {
    const mlen = (2 << mlenMagn) - 1;
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


struct Authenticator(Impl)
{
    Impl.PublicKey otherPartyPublicKey;
    Impl.SecretKey mySecretKey;
    
    ubyte[] box(E, Key)( const E[] message )
    {
      size_t smlen;
      const msg = tweednacl.basics.toBytes( message );
      auto o = zeroOut( Impl.Bytes, msg );
      Impl.sign( o, smlen, msg, mySecretKey  );
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
    ubyte[] open(E)(const E[] signedData)
    in {
      assert(signedData.length >= Impl.Bytes);
    }
    body {
      const sm = tweednacl.basics.toBytes( signedData );
      auto output = zeroOut( sm );
      size_t outputLen;
      if (!Impl.open( output, outputLen, sm, otherPartyPublicKey ))
        throw new BadSignatureError();
      return output[0..outputLen];
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
  enum TryToForgeMessagesUpTo = 16;

  void testBoxers(size_t testCount=TryToForgeMessagesUpTo, A,B)(A aliceBoxer, B bobBoxer)
  {
    import tweednacl.random : randomBuffer, forgeBuffer;
    foreach(mlenMagn;0..testCount) {
      const mlen = mlenMagn == 0 ? 0 : (2 << mlenMagn - 1);
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
/** ditto */
alias secretBoxKey(Impl=XSalsa20Poly1305, alias safeRnd=safeRandomBytes) =
  generateSecretKey!(Impl, safeRnd);

/**
  Shortcut to generate a nonce for the default implementation of SecretBoxes.
  */
alias generateSecretBoxNonce(Impl=XSalsa20Poly1305) = generateNonce!(Impl);

/**

  Creates a new Boxer for a secret-key authenticated encryption.

Params:
  k = the shared secret key
  n = the starting nonce.

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
  import tweednacl.random: randomBuffer, forgeBuffer;
  import std.random;
  import std.exception;
  import std.digest.digest;
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
      assert( !verifyAuth(authVal, tmp, k), toHexString(tmp) ~ "  ==  " ~ toHexString(msg) );
      assertThrown!BadSignatureError( openAuth( authVal, tmp, k) );
    }
  }
}




/**
  Implements a forward-secret session with an ephemeral key usin Impl.
  
 */
auto session(Impl=Curve25519XSalsa20Poly1305)()
{
  return Session!(Impl)( generateKeypair!Impl() );
}

unittest
{
  import std.random;
  import tweednacl.random: randomBuffer;
  // Generates a new keypair.
  auto aliceSession = session();
  auto bobSession = session();

  auto nonceFromHandshake = generateBoxNonce();

  // Alice and Bob exchange their session public keys, and now they have
  // a secure session that cannot be decoded. When bobSession goes out of scope
  // the public and private keys for this session are forgotten and the only
  // way to communicate in this session is via the boxers
  auto bobBoxer = bobSession.open( aliceSession.request[0..32], nonceFromHandshake );
  auto aliceBoxer = aliceSession.open( bobSession.request[0..32], nonceFromHandshake );

  auto rawMsg1 = randomBuffer( uniform(0,4096u) );
  auto rawMsg2 = randomBuffer( uniform(0,4096u) );

  auto msg1 = aliceBoxer.box( rawMsg1 );
  auto msg2 = bobBoxer.box( rawMsg2 );

  assert( bobBoxer.open( msg1 ) == rawMsg1 );
  assert( aliceBoxer.open( msg2 ) == rawMsg2 );

}

/** Establish a session without authenticating the parties. */
unittest
{
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

    testBoxers!4(bobBoxer, aliceBoxer);
}

/** Establish a session with public-key singing used to authenticating the parties. */
unittest
{

    auto aliceSignKeys = generateSignKeypair();
    auto bobSignKeys = generateSignKeypair();

    auto aliceSession = session();
    auto bobSession = session();

    auto aliceH = aliceSession.signedHandshake( bobSignKeys.publicKey, aliceSignKeys.secretKey );
    auto bobH = bobSession.signedHandshake( aliceSignKeys.publicKey, bobSignKeys.secretKey );

    // Alice and Bob exchange their session public keys.
    bobH.succeed( aliceH.sync( bobH.response( aliceH.challenge() )));

    auto bobBoxer = bobSession.open( bobH.open() );
    auto aliceBoxer = aliceSession.open( aliceH.open() );

    testBoxers!4(bobBoxer, aliceBoxer);
}

/**
  Helper to set up a forward-secret session with an ephemeral key
  usin Impl.
  */
struct Session(Impl)
{
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
    return boxHandshake!Impl(sessionKeyPair.publicKey);
  }

  /**
    Create a new $(RED unsigned) handshake to agree on public keys for this session.
    */
  auto signedHandshake( SignPrimitive=Ed25519, PublicKey, SecretKey)
    (
      PublicKey otherPartyPublicKey,
      SecretKey mySecretKey
      )
    if (is(PublicKey == SignPrimitive.PublicKey ) && is(SecretKey == SignPrimitive.SecretKey))
  {
    return signedBoxHandshake!Impl(sessionKeyPair.publicKey, otherPartyPublicKey, mySecretKey);
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

