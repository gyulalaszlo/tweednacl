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

  auto sign(E)(E m) { return m; }
  auto open(N, E)(E m) { return m; }
  void restart() {}

  void initRandom() {}
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

    enum SignatureSize = SignPrimitive.Signature.length;

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
    auto sign(E)(E i)
    {
      auto msgBuf = zeroPadded( Data.sizeof, i );
      auto signedBuf = zeroOut( SignPrimitive.Bytes + Data.sizeof, i );

      auto signRandomData = cast(Data*)(&msgBuf[0]);
      signRandomData.challenge = myRandom;
      signRandomData.response = otherRandom;

      size_t smlen;
      SignPrimitive.sign( signedBuf, smlen, msgBuf, mySecretKey );

      return signedBuf[0..smlen];
    }


    /**
      Opens a signed message and checks the length, the randoms and the signature.
     */
    auto open(E, T)(T m)
    {
      if (m.length != E.sizeof + Data.sizeof + SignPrimitive.Bytes )
        throw new HandshakeError("Invalid handshake message length ");

      auto o = zeroOut(m);
      size_t mlen;
      if (!SignPrimitive.signOpen( o, mlen, m, otherPartyPublicKey ))
        throw new HandshakeError("Handshake signature mismatch");

      auto signRandomData = cast(Data*)(&o[0]);
      if (signRandomData.response != myRandom)
        throw new HandshakeError("Error in handshake");

      // store the outher partys random.
      if (!seenOtherRandom) {
        otherRandom = signRandomData.challenge;
        seenOtherRandom = true;
      }

      return o[(Data.sizeof)..mlen];
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


/**
  A handshake is a simple message interface for exchanging
  two pieces of data and deriving a common piece for both parties


Examples:

---
  auto Val = ubyte[24];

  auto aliceH = signedHandshake!Val( bobPubKey, aliceSecretKey );
  auto bobH = signedHandshake!Val( alicePubKey, bobSecretKey);

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
    const string stepName = opts["name"];

    const hasInput = ("input" in opts) != null;
    const hasOutput = ("output" in opts) != null;
    const hasBody = ("body" in opts) != null;

    string input, inputName, output, outputName, methodBody;
    if (hasInput) { input = opts["input"]; inputName = opts["inputName"]; }
    if (hasOutput) { output = opts["output"]; outputName = opts["outputName"]; }
    if (hasBody) methodBody = opts["body"];

    methodBody ~= format("isDone = %s;", opts["done"]);

    string[] returnStr;
    string[] prelude;
    string[] args;

    debug(DebugHandshakeSteps)
      prelude ~= "writefln(\"---- " ~ stepName ~ " ----\");";

    if (hasInput) {
      prelude ~= "auto openedMsg = signer.open!" ~ input ~ "( input );";
      prelude ~= "if (openedMsg.length != " ~ input ~ ".sizeof)";
      prelude ~= "  throw new HandshakeError(\"Invalid handshake input message length in " ~ stepName  ~ ".\");";
      prelude ~= "auto inputMsg = " ~ "(cast(" ~ input ~ "*)(&openedMsg[0]));";

      debug(DebugHandshakeSteps)
        prelude ~= "writefln(\"openedMsg = %s\", bytesToHex(openedMsg));";

      foreach(n;inputName.split(','))
      {
        args ~= "inputMsg." ~ n;
      }
    }

    if (hasOutput) {
      prelude ~= "ubyte[] msg = zeroOut(" ~ output ~ ".sizeof);";
      prelude ~= "auto outputMsg = " ~ "(cast(" ~ output ~ "*)(&msg[0]));";
      args ~= "outputMsg." ~ outputName;

      debug(DebugHandshakeSteps)
        returnStr ~= "writefln(\"output    = %s\", bytesToHex(msg));";

      returnStr ~= "return signer.sign( msg );";
    }

    string[] stepCalls;

    foreach(i;0..Steps.length)
    {
      auto argList = args.map!( a => format("%s[%s]", a, i ));
      stepCalls ~= format("steps[%s].%s( %s );", i, stepName, join(argList, ", "));
    }


    return join( ["// ", join(prelude, "\n"),
        join(stepCalls,"\n"),
        //"steps." ~ stepName ~ "( " ~ join(args, ", ") ~ " );",
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

    enum BufferSize = ResponseMsg.sizeof > SyncMsg.sizeof ? ResponseMsg.sizeof : SyncMsg.sizeof;
    ubyte buffer[BufferSize];

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
      debug(ShowHandshakeMacros)
        pragma(msg, makeStep( stepOptions ));
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
                       "input":"SyncMsg", "inputName":"consensus"
                         ];
      mixin(makeStep(stepOptions));
    }


    /**
      Gets the exchanged consensus or throws a $(D HandshakeError) if a
      Consensus was not reached (either because failiure or incompletition.

Throws: HandshakeError if exchange was unsuceesful or finished.
     */
    auto open() {

      if (!isDone)
        throw new HandshakeError("Tried to open a not yet completed handshake.");

      debug(ShowHandshakeMacros)
        pragma(msg, generateOpen(Steps.length));
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

/** Creates an unsigned handshake for exchanging nonces */
auto unsignedNonceHandshake( Nonce,
    alias nonceGeneratorFn=generateNonce!(Nonce.length)
    )()
{
  alias H = NonceHandshakeSteps!(ubyte[Nonce.length], nonceGeneratorFn);
  return Handshake!(NoSignature, H)( NoSignature(), H() );
}


unittest {
  alias Nonce = ubyte[24];
  testHandshake(
      unsignedNonceHandshake!Nonce(), unsignedNonceHandshake!Nonce()
      );

}



/**
  Creates a new $(RED unsigned) handshake for exchanging public keys.

  This handshake simply proposes the provided public key.
  */
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


unittest {
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
  Implements the exchange of random Nonces between two parties.

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
  Creates a new $(RED unsigned) handshake for exchanging public keys.

  This handshake simply proposes the provided public key.
  */
auto unsignedPublicKeyHandshake(
    Primitive=Curve25519XSalsa20Poly1305,
    ExchangePk
    )( ref const ExchangePk myPk)
  if (is(ExchangePk == Primitive.PublicKey))
{
  alias H = PublicKeyExchangeHandshakeSteps!(Primitive.PublicKey);
  return Handshake!(NoSignature,H)( NoSignature(), H( myPk ));
}

/**
  Creates a new $(GREEN signed) handshake for exchanging public keys.

  This handshake simply proposes the provided public key.
  */
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


version(unittest) {

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
}


unittest
{
  alias Pk = Curve25519XSalsa20Poly1305.PublicKey;

  Pk alicePk = randomBuffer(Pk.length);
  Pk bobPk = randomBuffer(Pk.length);

  auto aliceH = unsignedPublicKeyHandshake( alicePk );
  auto bobH = unsignedPublicKeyHandshake( bobPk );

  testPublicKeyHandshake( aliceH, bobH, alicePk, bobPk );
}

unittest
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


/**
  Creates a new $(RED unsigned) handshake for exchanging public keys.

  This handshake simply proposes the provided public key.
  */
auto unsignedPublicKeyNonceHandshake(
    Primitive=Curve25519XSalsa20Poly1305,
    Nonce=Primitive.Nonce,
    alias nonceGeneratorFn=generateNonce!(Nonce.length),
    ExchangePk
    )( ref const ExchangePk myPk)
  if (is(ExchangePk == Primitive.PublicKey)
      && is(Nonce == Primitive.Nonce))
{
  alias NonH = NonceHandshakeSteps!(ubyte[Nonce.length], nonceGeneratorFn);
  alias PkH = PublicKeyExchangeHandshakeSteps!(Primitive.PublicKey);
  return Handshake!(NoSignature,PkH,NonH)( NoSignature(), PkH( myPk ), NonH());
}

unittest
{

  static void dump( string name, const ubyte[] b )
  {
    writefln("%s = %s",name, bytesToHex(b));
  }

  static void testPublicKeyNonceHandshake(A, B, APK, BPK)(A aliceH, B bobH, APK alicePk, BPK bobPk)
  {
    auto msg1 = aliceH.challenge();
    auto msg2 = bobH.response( msg1 );
    auto msg3 = aliceH.sync( msg2 );
    bobH.succeed( msg3 );

    //dump("msg1", msg1);
    //dump("msg2", msg2);
    //dump("msg3", msg3);

    auto ao = aliceH.open();
    auto bo = bobH.open();

    //dump("aliceH[0]", ao[0]);
    //dump("aliceH[1]", ao[1]);

    //dump("bobH[0]", bo[0]);
    //dump("bobH[1]", bo[1]);

    assert( ao[1] == bo[1] );
    assert( bo[0]  == alicePk );
    assert( ao[0] == bobPk );

    aliceH.restart();
    bobH.restart();
  }

  alias Pk = Curve25519XSalsa20Poly1305.PublicKey;

  Pk alicePk = randomBuffer(Pk.length);
  Pk bobPk = randomBuffer(Pk.length);

  auto aliceH = unsignedPublicKeyNonceHandshake( alicePk );
  auto bobH = unsignedPublicKeyNonceHandshake( bobPk );

  testPublicKeyNonceHandshake( aliceH, bobH, alicePk, bobPk );
}

