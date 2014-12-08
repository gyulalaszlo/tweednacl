module tweednacl.handshake;
import tweednacl.basics;
import tweednacl.nonce_generator;

import std.stdio;
import tweednacl.encoded_bytes;


/**
  Mixes two nonces (from the initiator and the accepter) and mixes
  them in a deterministic way.

  The current implementation mixes the even-odd bytes from the nonces.
  */
Nonce mixNonces(Nonce)( ref const Nonce initiator, ref const Nonce receiver )
{
  Nonce o;
  foreach(i,ref oe;o) {
    oe = cast(ubyte)((initiator[i] ^ 0b01010101u) + (receiver[i] ^ 0b10101010u));
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
    alias nonceMixer = mixNonces
    )
{
  alias Challenge = Nonce;
  alias Response = Nonce;

  alias Consensus = Nonce;


  private Consensus consensus = void;
  private bool hasConsensus = false;


  void challenge(Msg)( Msg msg )
  {
    msg.challenge = nonceGeneratorFn();
    hasConsensus = false;
  }


  void response(InitMsg, Msg)( InitMsg initMsg , Msg msg )
  {
    msg.challenge = initMsg.challenge;
    msg.response = nonceGeneratorFn();
    consensus = mixNonces( msg.challenge, msg.response );
    hasConsensus = false;
  }


  void sync(RM, CM)( RM responseMsg , CM syncMsg )
  {
    consensus = mixNonces( responseMsg.challenge, responseMsg.response );
    syncMsg.consensus = consensus;
    // TODO: figure out if having consensus here is a strong enough guarantee
    hasConsensus = true;
  }


  void succeed(CM)( CM  syncMsg )
  {
    if (consensus != syncMsg.consensus)
      throw new HandshakeError("Disagreement on exchanged data.");

    hasConsensus = true;
  }


  auto open()
  {
    if (!hasConsensus)
      throw new HandshakeError("Tried to open not completed handshake.");

    return consensus;
  }


  @nogc nothrow bool done() const  { return hasConsensus; }


  @nogc void restart()
  {
    hasConsensus = false;
  }
}

/**
  A signer takes a SignPrimitive and sign each message in the handshake.

  It also adds random bytes to make replay attacks harder
  */
template HandshakeSigner(SignPrimitive)
{
  enum isSigned = !is(SignPrimitive == NoSignature );

  struct RandomBlock(RandomData, bool hasResponse)
  {
    RandomData challenge;
    static if (hasResponse)
      RandomData response;
  }

  static if (isSigned) {
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

        // Signs an outgoing message and adds the random bits
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


        // Opens a signed message and checks the length, the randoms and the signature.
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


        void restart()
        {
          myRandom[] = 0;
          otherRandom[] = 0;
          seenOtherRandom = false;
        }


    }
  } else {
    // The one that does not sign anything
    struct HandshakeSigner
    {
        alias RandomData = ubyte[0];
        alias Data = RandomBlock!(RandomData, true);

        enum SignatureSize = 0;

        auto sign(E)(E m) { return m; }
        auto open(N, E)(E m) { return m; }
        void restart() {}
    }
  }
}


/**
  A handshake is a simple message interface for exchanging
  two pieces of data and deriving a common piece for both parties
  */
struct Handshake( Nonce,
    Steps = NonceHandshakeSteps!Nonce,
    SignPrimitive = NoSignature,
    alias safeRnd=safeRandomBytes,
    )
{
public:
  enum isSigned = !is(SignPrimitive == NoSignature );
  alias Signer = HandshakeSigner!SignPrimitive;
  enum SignatureSize = Signer.SignatureSize;

  Steps steps;
  Signer signer;

private:

  Steps.Consensus consensus;
  bool nonceExchanged = false;


  // The random sent by me (whether im a sender or a receiver)
  Signer.RandomData myRandom;


  struct InitMsg {
    Steps.Challenge challenge;
  }

  /** The message sent on initialization */
  struct InitAcceptMsg {
    Steps.Challenge challenge;
    Steps.Response response;
  }

  struct SyncMsg {
    Steps.Consensus consensus;
  }



public:
  /**
    Step 1. initialize the connection.
   */
  ubyte[] challenge()
  {
    // allocate buffer
    ubyte[] msg = zeroOut(InitMsg.sizeof);
    steps.challenge( cast(InitMsg*)(&msg[0]) );

    // generate a random for us at this point for signing
    static if (isSigned) safeRnd( signer.myRandom );

    return signer.sign( msg );
  }


  ubyte[] response( const ubyte[] initMsgBytes )
  {
    auto openedMsg = signer.open!InitMsg( initMsgBytes );
    auto msg = zeroOut( InitAcceptMsg.sizeof );
    steps.response( cast(InitMsg*)(&openedMsg[0]), cast(InitAcceptMsg*)(&msg[0]) );
    // generate a random for us at this point for signing
    static if (isSigned) safeRnd( signer.myRandom );
    return signer.sign(msg);
  }

  auto sync(  const ubyte[] initAcceptMsgBytes )
  {
    auto openedMsg = signer.open!InitAcceptMsg( initAcceptMsgBytes );
    auto oBuf = zeroOut( SyncMsg.sizeof );
    steps.sync( cast(InitAcceptMsg*)(&openedMsg[0]), cast(SyncMsg*)(&oBuf[0]) );
    return signer.sign( oBuf );
  }


  /**
    The last step of the handshake, this steps purpose is to make
    sure that Alice has to sign a message which contains the random
    bytes from Bob, so Bob can be sure that the messages arent replayed.
    */
  void succeed( const ubyte[] syncMsg )
  {
    auto openedMsg = signer.open!SyncMsg( syncMsg );
    steps.succeed( cast(SyncMsg*)(&openedMsg[0]) );
  }


  /**
    Get the exchanged consensus.

Throws: HandshakeError if exchange was unsuceesful or finished.
   */
  Steps.Consensus open() { return steps.open(); }


  /** Is the handshake done? (Can this handshake be $(D open)ed?) */
  @property bool done() const { return steps.done(); }


  /** Restarts the handshake process */
  void restart()
  {
    nonceExchanged = false;
    myRandom[] = 0;
    consensus = Steps.Consensus.init;
    steps.restart();
    signer.restart();
  }

}



auto notSignedHandshake( Data,
    alias nonceGeneratorFn=generateNonce!(Data.length),
    alias nonceMixer = mixNonces
    )()
{
  alias H = NonceHandshakeSteps!(ubyte[Data.length], nonceGeneratorFn, nonceMixer);
  return Handshake!(Data, H, NoSignature)( H() );
}


version(unittest)
{
  void testHandShake(H)(H aliceH, H bobH)
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


}

unittest {
  alias Nonce = ubyte[24];
  testHandShake(
      notSignedHandshake!Nonce(), notSignedHandshake!Nonce()
      );

}

version(SignedHandshakeTest) {

  import tweednacl.ed25519;
  auto signedHandshake( Data,
      SignPrimitive = Ed25519,
      alias nonceGeneratorFn=generateNonce!(Data.length),
      alias nonceMixer = mixNonces,
      Pk, Sk
      )( Pk otherPk, Sk mySk)
  {
    alias H = NonceHandshakeSteps!(ubyte[Data.length], nonceGeneratorFn, nonceMixer);
    alias Signer = HandshakeSigner!SignPrimitive;
    return Handshake!(Data, H, SignPrimitive)( H(), Signer(otherPk, mySk) );
  }


  unittest {
    alias Nonce = ubyte[24];

    Ed25519.PublicKey alicePk, bobPk;
    Ed25519.SecretKey aliceSk, bobSk;

    Ed25519.keypair!safeRandomBytes( alicePk, aliceSk );
    Ed25519.keypair!safeRandomBytes( bobPk, bobSk );


    testHandShake(
        signedHandshake!Nonce( bobPk, aliceSk ),
        signedHandshake!Nonce( alicePk, bobSk )
        );
  }

}


