module tweednacl.handshake;
import tweednacl.basics;
import tweednacl.nonce_generator;
import tweednacl.ed25519;
import tweednacl.curve25519xsalsa20poly1305;

import std.stdio;
import tweednacl.encoded_bytes;

/** Gets thrown in case there are errors */
class HandshakeError : Exception {
  this(string msg) { super("Handshake error: " ~ msg); }
}

enum isHandshakeSigner(T) =
  __traits( hasMember, T, "sign" )
  && __traits( hasMember, T, "open" )
  && __traits( hasMember, T, "restart" )
  && __traits( hasMember, T, "initRandom" )
  ;

unittest
{
  struct Fake {}
  static assert( isHandshakeSigner!NoSignature );
  static assert( !isHandshakeSigner!Fake );
}



/**
  A handshake is a simple message interface for exchanging
  two pieces of data and deriving a common piece for both parties

Params:
  Signer = The Signer to use to sign the messages. use NoSigner to not sign
  messages (if the channel is considered safe).

  Steps = A list of parts to exchange in the handshake. See $(D
  PublicKeyHandshake) and $(D NonceHandshake)

Examples:

Exchanging public keys
---
  auto aliceH = unsignedPublicKeyHandshake( alicePublicKey );
  auto bobH = unsignedPublicKeyHandshake( bobPublicKey );

  auto msg1 = aliceH.challenge();
  auto msg2 = bobH.response( msg1 );
  auto msg3 = aliceH.sync( msg2 );

  assert( aliceH.done() );

  bobH.succeed( msg3 );
  assert( bobH.done() );

  // at this point the public keys are exchanged
  assert( aliceH.open() == bobPublicKey );
  assert( bobH.open()  == alicePublicKey );
---

  */
template Handshake( Signer, Steps... )
  if (isHandshakeSigner!Signer)
{
  import std.array;
  import std.algorithm;
  import std.string;
  import std.typecons;
  import std.typetuple;

  // code generator for the steps
  static string makeStep( string[string] opts )
  {
    string input, inputName, output, outputName, methodBody;
    string[] returnStr, prelude, args, stepCalls;
    const string stepName = opts["name"];

    if (("body" in opts) != null) methodBody = opts["body"];

    methodBody ~= format("isDone = %s;", opts["done"]);


    if (("input" in opts) != null) {
      input = opts["input"];
      inputName = opts["inputName"];

      prelude ~= format( q"{
          if (input.length != %s.sizeof + Signer.Bytes )
            throw new HandshakeError("Invalid handshake message length in '%s'.");

          auto inputBuf = inputBuffer[0..(%s.sizeof + Signer.Bytes)];
          inputBuf[] = input[];
          }",
          input, stepName, input);

      prelude ~= "signer.open( inputBuf );";
      prelude ~= "auto inputMsg = " ~ "(cast(" ~ input ~ "*)(&inputBuf[Signer.Bytes]));";

      foreach(n;inputName.split(','))
        args ~= "inputMsg." ~ n;
    }

    if (("output" in opts) != null)
    {
      output = opts["output"];
      outputName = opts["outputName"];

      prelude ~= format(q"{
          immutable outLen = %s.sizeof+Signer.Bytes;
          auto outBuf = outputBuffer[0..outLen];
          outBuf[0..Signer.Bytes] = 0;
          auto outputMsg = cast(%s*)(&outBuf[Signer.Bytes]);
          }",
          output, output);

      args ~= "outputMsg." ~ outputName;

      returnStr ~= format("return signer.sign( outBuf );" );
    }

    foreach(i;0..Steps.length)
    {
      auto argList = args.map!( a => format("%s[%s]", a, i ));
      stepCalls ~= format("steps[%s].%s( %s );", i, stepName, join(argList, ", "));
    }

    return join( ["// ", join(prelude, "\n"), join(stepCalls,"\n"),
        methodBody, join(returnStr, "\n") ], "\n");
  }


  // Code generator for the opening function
  string generateOpen(size_t count)
  {
    if (count == 1) return "return steps[0].open();";
    string[] o;

    foreach(i;0..count)
      o ~= format(" steps[%s].open()",i);

    return "return tuple( " ~ join(o, ", ") ~ " );";
  }


  struct Handshake
  {

    Signer signer;
    Steps steps;

    private:

    // keep the state
    bool isDone = false;

    alias ChallengeFor(T) = T.Challenge;
    alias ResponseFor(T) = T.Response;
    alias ConsensusFor(T) = T.Consensus;

    alias Challenge = staticMap!( ChallengeFor, Steps );
    alias Response = staticMap!( ResponseFor, Steps );
    alias Consensus = staticMap!( ConsensusFor, Steps );


    struct ChallengeMsg {
      Challenge challenge;
    }

    /** The message sent on initialization */
    struct ResponseMsg {
      Challenge challenge;
      Response response;
    }

    struct SyncMsg {
      Consensus consensus;
    }

    enum BufferSize = Signer.Bytes +
      ((ResponseMsg.sizeof > SyncMsg.sizeof) ? ResponseMsg.sizeof : SyncMsg.sizeof);

    ubyte[BufferSize] inputBuffer, outputBuffer;

    public:
    /**
      Step 1. Initialize the connection and offer a Challenge.
     */
    ubyte[] challenge()
    {
      enum stepOptions = ["name":"challenge", "done": "false",
                       "output":"ChallengeMsg", "outputName":"challenge",
                       "body":"signer.initRandom();"];
      mixin( makeStep( stepOptions  ) );
    }


    /**
      Step 2. Accept the Challenge and provide a Response.
     */
    ubyte[] response( const ubyte[] input )
    {
      enum stepOptions = [ "name":"response", "done": "false",
                       "input":"ChallengeMsg", "inputName": "challenge",
                       "output":"ResponseMsg", "outputName": "response",
                       "body": q"{
                         signer.initRandom();
                         outputMsg.challenge = inputMsg.challenge;
                         isDone = false;
      }" ];
      mixin(makeStep( stepOptions ));
    }

    /**
      Step 3. Figure a Consensus from the Challenge and Response
     */
    ubyte[] sync(  const ubyte[] input )
    {
      enum stepOptions = ["name":"sync", "done": "true",
                       "input":"ResponseMsg", "inputName": "challenge,response",
                       "output":"SyncMsg", "outputName":"consensus"];
      //debug(ShowHandshakeMacros)
        //pragma(msg, makeStep( stepOptions ));
      mixin(makeStep( stepOptions ));
    }


    /**
      Step 4. Check if the consensus is the same.

      The last step of the handshake, this steps purpose is to make
      sure that Alice has to sign a message which contains the random
      bytes from Bob, so Bob can be sure that the messages arent replayed.
     */
    void succeed( const ubyte[] input )
    {
      enum stepOptions = [ "name": "succeed", "done": "true",
                       "input":"SyncMsg", "inputName":"consensus" ];
      mixin(makeStep(stepOptions));
    }


    /**
      Gets the exchanged consensus or throws a $(D HandshakeError) if a
      Consensus was not reached (either because failiure or incompletition.

Throws: HandshakeError if exchange was unsuceesful or finished.
     */
    auto open()
    {
      if (!isDone)
        throw new HandshakeError("Tried to open a not yet completed handshake.");

      mixin(generateOpen(Steps.length));
    }


    /** Is the handshake done? (Can this handshake be $(D open)ed?) */
    @property bool done() const { return isDone; }


    /** Restarts the handshake process. */
    void restart()
    {
      foreach(s;steps) s.restart();
      signer.restart();
      isDone = false;
    }

  }
}

version(unittest)
{
  void testHandshake(H)(H aliceH, H bobH)
  {
    import std.stdio;
    import std.exception;
    import tweednacl.encoded_bytes;

    foreach(i;0..16) {

      auto msg1 = aliceH.challenge();

      assert(!aliceH.done());
      assertThrown!HandshakeError( aliceH.open() );

      auto msg2 = bobH.response( msg1 );
      assert( !bobH.done() );

      auto msg3 = aliceH.sync( msg2 );
      assert( aliceH.done() );

      bobH.succeed( msg3 );
      assert( bobH.done() );
      assert( aliceH.open() == bobH.open() );

      aliceH.restart();
      bobH.restart();
    }
  }

  // test if the signed handshakes can be forged
  void testSignedHandshake(H)(H aliceH, H bobH)
  {
    import std.stdio;
    import std.exception;
    import tweednacl.encoded_bytes;
    foreach(i;0..16) {

      auto msg1 = aliceH.challenge();
      forgeBuffer( msg1, i+1);
      assertThrown!HandshakeError( bobH.response( msg1 ) );

      aliceH.restart();
      bobH.restart();
      msg1 = aliceH.challenge();
      auto msg2 = bobH.response( msg1 );
      forgeBuffer( msg2, i+1 );
      assertThrown!HandshakeError( aliceH.sync( msg2 ) );

      aliceH.restart();
      bobH.restart();
      msg1 = aliceH.challenge();
      msg2 = bobH.response( msg1 );
      auto msg3 = aliceH.sync( msg2 );
      forgeBuffer( msg3, i+1 );
      assertThrown!HandshakeError( bobH.succeed( msg3 ) );

      aliceH.restart();
      bobH.restart();
    }

    // try a replay
    foreach(i;0..16) {
      auto msg1 = aliceH.challenge();
      auto msg2 = bobH.response( msg1 );

      aliceH.restart();
      bobH.restart();

      auto msg3 = aliceH.challenge();
      assertThrown!HandshakeError( aliceH.sync( msg2 ) );

      aliceH.restart();
      bobH.restart();
    }
  }


}

/**

  Implements the exchange of random Nonces between two parties.

  The resulting Nonce is a bit-mixture of the nonces offered by both
  by the challenger and the responder. (see the $(D mixNonces) function)

  */
struct NonceHandshakeSteps(
    Nonce,
    alias nonceGeneratorFn=generateNonce!(Nonce.length),
    alias nonceMixerFn=bitmixNonces!(Nonce)
    )
{
  alias Challenge = Nonce;
  alias Response = Nonce;
  alias Consensus = Nonce;


  private Consensus agreedNonce = void;
  private bool hasConsensus = false;


  void challenge( ref Challenge c )
  {
    c = nonceGeneratorFn();
    hasConsensus = false;
  }


  void response( const ref Challenge c , ref Response r )
  {
    r = nonceGeneratorFn();
    agreedNonce = nonceMixerFn( c, r );
    hasConsensus = false;
  }


  void sync( const ref Challenge c , ref const Response r, ref Consensus cons )
  {
    agreedNonce = nonceMixerFn( c, r );
    cons = agreedNonce;
    // TODO: figure out if having consensus here is a strong enough guarantee
    hasConsensus = true;
  }


  void succeed( ref Consensus c )
  {
    if (agreedNonce != c)
      throw new HandshakeError("Disagreement on exchanged data.");

    hasConsensus = true;
  }


  auto open() const
  {
    if (!hasConsensus)
      throw new HandshakeError("Tried to open not completed handshake.");

    return agreedNonce;
  }


  @nogc nothrow bool done() const  { return hasConsensus; }
  @nogc nothrow void restart() { hasConsensus = false; }

}


/**
  Creates a handshake for exchanging nonces. See $(SEE NonceHandshakeSteps) 

  The resulting Nonce is a bit-mixture of the nonces offered by both
  by the challenger and the responder. (see the $(D mixNonces) function)

  */
auto nonceHandshake( Nonce,
    alias nonceGeneratorFn=generateNonce!(Nonce.length)
    )()
{
  alias H = NonceHandshakeSteps!(ubyte[Nonce.length], nonceGeneratorFn);
  return Handshake!(NoSignature, H)( NoSignature(), H() );
}


unittest
{
  alias Nonce = ubyte[24];
  testHandshake( nonceHandshake!Nonce(), nonceHandshake!Nonce());
}



/** ditto */
auto signedNonceHandshake( Data,
    SignPrimitive = Ed25519,
    alias nonceGeneratorFn=generateNonce!(Data.length),
    alias nonceMixerFn=bitmixNonces!Data,
    Pk, Sk
    )( Pk otherPk, Sk mySk)
{
  alias H = NonceHandshakeSteps!(ubyte[Data.length], nonceGeneratorFn);
  alias Signer = HandshakeSigner!SignPrimitive;
  return Handshake!(Signer,H)( Signer(otherPk, mySk), H() );
}


unittest
{
  alias Nonce = ubyte[24];

  Ed25519.PublicKey alicePk, bobPk;
  Ed25519.SecretKey aliceSk, bobSk;

  Ed25519.keypair!safeRandomBytes( alicePk, aliceSk );
  Ed25519.keypair!safeRandomBytes( bobPk, bobSk );


  testHandshake(
      signedNonceHandshake!Nonce( bobPk, aliceSk ),
      signedNonceHandshake!Nonce( alicePk, bobSk )
      );

  testSignedHandshake(
      signedNonceHandshake!Nonce( bobPk, aliceSk ),
      signedNonceHandshake!Nonce( alicePk, bobSk )
      );
}




/**
  Implements the exchange of Public keys between two parties.

  The resulting Nonce is a bit-mixture of the nonces offered by both
  by the challenger and the responder. (see the $(D mixNonces) function)

  */
struct PublicKeyExchangeHandshakeSteps(
    PublicKey
    )
{
  alias Challenge = PublicKey;
  alias Response = PublicKey;;
  struct Consensus {
    PublicKey challengerPublicKey;
    PublicKey responderPublicKey;
  }

  PublicKey myPublicKey;
  PublicKey otherPartyPublicKey;
  private bool hasConsensus = false;


  void challenge( ref Challenge challenge )
  {
    challenge = myPublicKey;
    hasConsensus = false;
  }


  void response( const ref Challenge challenge, ref Response response )
  {
    otherPartyPublicKey = challenge;
    response = myPublicKey;
    hasConsensus = false;
  }


  void sync( const ref Challenge challenge , ref const Response response, ref Consensus cons )
  {
    if (myPublicKey != challenge)
      throw new HandshakeError("Challenge and Sync show different public keys.");

    otherPartyPublicKey = response;

    cons.challengerPublicKey = myPublicKey;
    cons.responderPublicKey = otherPartyPublicKey;
    // TODO: figure out if having consensus here is a strong enough guarantee
    hasConsensus = true;
  }


  void succeed( ref Consensus cons )
  {
    if (myPublicKey != cons.responderPublicKey
        || otherPartyPublicKey != cons.challengerPublicKey)
      throw new HandshakeError("Response and Succeed show different public keys.");

    hasConsensus = true;
  }


  auto open()
  {
    if (!hasConsensus)
      throw new HandshakeError("Tried to open not completed handshake.");

    return otherPartyPublicKey;
  }


  @nogc nothrow bool done() const  { return hasConsensus; }


  @nogc void restart()
  {
    hasConsensus = false;
  }

}


/**
  Creates a new handshake for exchanging public keys that simply proposes the
  provided public key.
  */
auto publicKeyHandshake(
    Primitive=Curve25519XSalsa20Poly1305,
    ExchangePk
    )( ref const ExchangePk myPk)
  if (is(ExchangePk == Primitive.PublicKey))
{
  alias H = PublicKeyExchangeHandshakeSteps!(Primitive.PublicKey);
  return Handshake!(NoSignature,H)( NoSignature(), H( myPk ));
}

/** ditto */
auto signedPublicKeyHandshake(
    Primitive=Curve25519XSalsa20Poly1305,
    SignPrimitive = Ed25519,
    ExchangePk, SignPk, SignSk
    )( ref const ExchangePk myPk, ref const SignPk otherSignPk, ref const SignSk mySignSk)
  if (is(ExchangePk == Primitive.PublicKey)
      && is(SignPk == SignPrimitive.PublicKey)
      && is(SignSk == SignPrimitive.SecretKey))
{
  alias H = PublicKeyExchangeHandshakeSteps!(Primitive.PublicKey);
  alias Signer = HandshakeSigner!SignPrimitive;
  return Handshake!(Signer,H)( Signer( otherSignPk, mySignSk ), H( myPk ) );
}


unittest
{

  static void testPublicKeyHandshake(A, B, APK, BPK)(A aliceH, B bobH, APK alicePk, BPK bobPk)
  {
    auto msg1 = aliceH.challenge();
    auto msg2 = bobH.response( msg1 );
    auto msg3 = aliceH.sync( msg2 );
    bobH.succeed( msg3 );

    assert( aliceH.open() == bobPk );
    assert( bobH.open() == alicePk );

    aliceH.restart();
    bobH.restart();
  }


  {
    alias Pk = Curve25519XSalsa20Poly1305.PublicKey;

    Pk alicePk = randomBuffer(Pk.length);
    Pk bobPk = randomBuffer(Pk.length);

    auto aliceH = publicKeyHandshake( alicePk );
    auto bobH = publicKeyHandshake( bobPk );

    testPublicKeyHandshake( aliceH, bobH, alicePk, bobPk );
  }

  {
    alias Pk = Curve25519XSalsa20Poly1305.PublicKey;

    Ed25519.PublicKey aliceSPk, bobSPk;
    Ed25519.SecretKey aliceSSk, bobSSk;

    Ed25519.keypair!safeRandomBytes( aliceSPk, aliceSSk );
    Ed25519.keypair!safeRandomBytes( bobSPk, bobSSk );


    Pk alicePk = randomBuffer(Pk.length);
    Pk bobPk = randomBuffer(Pk.length);

    auto aliceH = signedPublicKeyHandshake( alicePk, bobSPk, aliceSSk );
    auto bobH = signedPublicKeyHandshake( bobPk, aliceSPk, bobSSk );

    testPublicKeyHandshake( aliceH, bobH, alicePk, bobPk );
  }
}

/**
  Creates a new handshake for exchanging public keys and a nonce to create a
  Boxer.
  */
auto boxHandshake(
    Primitive=Curve25519XSalsa20Poly1305,
    alias nonceGeneratorFn=generateNonce!Primitive,
    alias nonceMixerFn=bitmixNonces!(Primitive.Nonce),
    ExchangePk
    )( ref const ExchangePk myPk)
  if (is(ExchangePk == Primitive.PublicKey))
{
  alias NonH = NonceHandshakeSteps!(Primitive.Nonce, nonceGeneratorFn, nonceMixerFn);
  alias PkH = PublicKeyExchangeHandshakeSteps!(Primitive.PublicKey);
  return Handshake!(NoSignature,PkH,NonH)( NoSignature(), PkH( myPk ), NonH());
}

/** ditto */
auto signedBoxHandshake(
    Primitive=Curve25519XSalsa20Poly1305,
    SignPrimitive = Ed25519,
    alias nonceGeneratorFn=generateNonce!Primitive,
    alias nonceMixerFn=bitmixNonces!(Primitive.Nonce),
    ExchangePk, SignPk, SignSk
    )( ref const ExchangePk myPk, ref const SignPk otherSignPk, ref const SignSk mySignSk)
  if (is(ExchangePk == Primitive.PublicKey)
      && is(SignPk == SignPrimitive.PublicKey)
      && is(SignSk == SignPrimitive.SecretKey))
{
  alias NonH = NonceHandshakeSteps!(Primitive.Nonce, nonceGeneratorFn, nonceMixerFn);
  alias PkH = PublicKeyExchangeHandshakeSteps!(Primitive.PublicKey);
  alias Signer = HandshakeSigner!SignPrimitive;
  return Handshake!(Signer,PkH,NonH)( Signer( otherSignPk, mySignSk ),  PkH( myPk ), NonH() );
}

unittest
{

  static void testBoxHandshake(A, B, APK, BPK)(A aliceH, B bobH, APK alicePk, BPK bobPk)
  {
    auto msg1 = aliceH.challenge();
    auto msg2 = bobH.response( msg1 );
    auto msg3 = aliceH.sync( msg2 );
    bobH.succeed( msg3 );

    auto ao = aliceH.open();
    auto bo = bobH.open();

    assert( ao[1] == bo[1] );
    assert( bo[0]  == alicePk );
    assert( ao[0] == bobPk );

    aliceH.restart();
    bobH.restart();
  }

  {
    alias Pk = Curve25519XSalsa20Poly1305.PublicKey;

    Pk alicePk = randomBuffer(Pk.length);
    Pk bobPk = randomBuffer(Pk.length);

    auto aliceH = boxHandshake( alicePk );
    auto bobH = boxHandshake( bobPk );

    testBoxHandshake( aliceH, bobH, alicePk, bobPk );
  }

  {
    alias Pk = Curve25519XSalsa20Poly1305.PublicKey;

    Ed25519.PublicKey aliceSPk, bobSPk;
    Ed25519.SecretKey aliceSSk, bobSSk;

    Ed25519.keypair!safeRandomBytes( aliceSPk, aliceSSk );
    Ed25519.keypair!safeRandomBytes( bobSPk, bobSSk );

    Pk alicePk = randomBuffer(Pk.length);
    Pk bobPk = randomBuffer(Pk.length);

    auto aliceH = signedBoxHandshake( alicePk, bobSPk, aliceSSk );
    auto bobH = signedBoxHandshake( bobPk, aliceSPk, bobSSk );

    testBoxHandshake( aliceH, bobH, alicePk, bobPk );
  }
}


/**
  Mixes two nonces (from the initiator and the accepter) and mixes
  them in a deterministic way.

  The current implementation mixes the even-odd bits from the nonces.
 */
pure @nogc nothrow Nonce bitmixNonces(Nonce)( ref const Nonce initiator, ref const Nonce receiver )
{
  Nonce o;
  foreach(i,ref oe;o) {
    oe = cast(ubyte)((initiator[i] ^ 0b01010101u) + (receiver[i] ^ 0b10101010u));
  }
  return o;
}

/**
  A signer that does not sign anything. Useful if the communication
  channel is already secure (like an already established Box).

  Also implements the interface required by the signature mechanism.
  */
struct NoSignature
{
  alias RandomData = ubyte[0];
  struct Data { RandomData challenge; RandomData response; } //RandomBlock!(RandomData, true);

  enum SignatureSize = 0;
  enum Bytes = 0;

  auto sign(ubyte[] m) { return m; }
  auto open(ubyte[] m) { return m; }
  void restart() {}

  void initRandom() {}
}

/**
  A signer takes a SignPrimitive and sign each message in the handshake.

  It also adds random bytes to make replay attacks harder.
  */
template HandshakeSigner(SignPrimitive, alias safeRnd=safeRandomBytes)
{
  enum isSigned = !is(SignPrimitive == NoSignature );

  struct RandomBlock(RandomData, bool hasResponse)
  {
    RandomData challenge;
    static if (hasResponse)
      RandomData response;
  }

  // The one that actually signes things
  struct HandshakeSigner
  {
    alias RandomData = ubyte[8];
    alias Data = RandomBlock!(RandomData, true);

    //enum SignatureSize = SignPrimitive.Signature.sizeof;
    enum Bytes = SignPrimitive.Bytes + Data.sizeof;

    // Allow the initialization with keys.
    SignPrimitive.PublicKey otherPartyPublicKey;
    SignPrimitive.SecretKey mySecretKey;



    RandomData myRandom;
    private RandomData otherRandom;

    // We use the random from the other party sent the first
    // time in this handshake
    bool seenOtherRandom = false;

    // Clean the key memory afterwards
    ~this() {
      mySecretKey[] = 0;
      otherPartyPublicKey[] = 0;
    }

    /**
      Signs an outgoing message and adds the random bits.
     */
    auto sign(ubyte[] i)
    in {
      assert( i.length >= Bytes );
    }
    body {
      auto signRandomData = cast(Data*)(&i[SignPrimitive.Bytes]);
      signRandomData.challenge = myRandom;
      signRandomData.response = otherRandom;

      size_t smlen;
      SignPrimitive.sign( i, smlen, i[64..$], mySecretKey );

      return i[0..smlen];
    }


    /**
      Opens a signed message and checks the length, the randoms and the signature.
     */
    void open(ubyte[] m)
    in {
      assert( m.length >= Bytes );
    }
    body
    {
      //auto o = zeroOut(m);
      size_t mlen;
      //if (!SignPrimitive.signOpenInPlace( o, mlen, m, otherPartyPublicKey ))
      if (!SignPrimitive.signOpenInPlace( m, mlen, otherPartyPublicKey ))
        throw new HandshakeError("Handshake signature mismatch");

      auto signRandomData = cast(Data*)(&m[SignPrimitive.Bytes]);
      if (signRandomData.response != myRandom)
        throw new HandshakeError("Error in handshake");

      // store the outher partys random.
      if (!seenOtherRandom) {
        otherRandom = signRandomData.challenge;
        seenOtherRandom = true;
      }
    }


    /**
      Restart the signature process and cleans the random bytes. This
      is needed to restart a handshake.
     */
    void restart()
    {
      myRandom[] = 0;
      otherRandom[] = 0;
      seenOtherRandom = false;
    }


    void initRandom()
    {
      safeRnd( myRandom );
    }

  }

}
