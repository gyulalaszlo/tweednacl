module tweednacl.nonce_generator;
import tweednacl.basics;
//import tweednacl.sha512;

/**
  Implments a simple nonce-generator.

  Distinct messages between the same {sender, receiver} set are required to
  have distinct nonces.

  In this generator, the lexicographically smaller public key
  uses nonce 1 for its first message to the other key, nonce 3 for its
  second message, nonce 5 for its third message, etc., while the
  lexicographically larger public key uses nonce 2 for its first message to the
  other key, nonce 4 for its second message, nonce 6 for its third message,
  etc. Nonces are long enough that randomly generated nonces have negligible
  risk of collision.
 */
struct DoubleStriderNonce(size_t nonceSize) {
  alias Nonce = ubyte[nonceSize];

  alias NonceS = NonceStream!(nonceSize, 2, 0xfe);

  /// The nonce stream that I use to encrypt packages sent by me.
  NonceS mine;
  /// The nonce that mirrors the other partys $(D mine) stream, which
  /// he or she uses to encrypt packages sent to me.
  NonceS other;

  /** Initializes the nonce generator to 0  */
  this(Pk)(ref const Pk myPk, ref const Pk otherPk)
  {
    initOffsetsAndNonces(myPk > otherPk);
  }

  /** Initializes the nonce generator to 0  */
  this(Pk)(ref const Pk myPk, ref const Pk otherPk,
      ref const Nonce myStartNonce, ref const Nonce otherStartNonce )
  {
    mine.bytes = myStartNonce;
    other.bytes = otherStartNonce;
    initOffsetsAndNonces(myPk > otherPk);
  }

  // Helper to initialize the offsets depending on if my public key is bigger
  // then the other partys.
  // Also makes sure that the nonces are in their lockstep state. Call after
  // setting the nonces
  private void initOffsetsAndNonces( bool isMyPkBigger )
  {
    mine.offset = isMyPkBigger ? 0 : 1;
    other.offset = isMyPkBigger ? 1 : 0;

    mine.popFront();
    other.popFront();
  }

}

unittest {
  import std.stdio;
  import std.string;
  import std.digest.digest : toHexString;

  enum NonceLen = 24;

  alias NonceT = ubyte[NonceLen];
  // The keys just need to be compareable
  auto alicePk = 42;
  auto bobPk = 44;

  auto aliceN = DoubleStriderNonce!NonceLen( alicePk, bobPk );
  auto bobN = DoubleStriderNonce!NonceLen( bobPk, alicePk );

  enum CheckCount = 1024 * 16;

  bool[typeof(aliceN).Nonce] usedNonces;

  // Helper that checks if the nonces generated by from.nextMine()
  // are the same as to.nextMine() and dont reappear.
  void sendMsg(NonceGen)( ref NonceGen from, ref NonceGen to )
  {
    from.mine.popFront();
    to.other.popFront();
    assert( from.mine.front == to.other.front );
    assert( (from.mine.front in usedNonces) is null );
    usedNonces[from.mine.front] = true;
  }

  // one-way
  foreach(i;0..CheckCount) sendMsg( aliceN, bobN );

  // other way
  foreach(i;0..CheckCount) sendMsg( bobN, aliceN );

  // stride
  foreach(i;0..CheckCount) {
    sendMsg( aliceN, bobN);
    sendMsg( bobN, aliceN);
  }

  // random
  foreach(i;0..CheckCount) {
    import std.random;
    switch(uniform(0,2)) {
      case 0: sendMsg( aliceN, bobN); break;
      case 1: sendMsg( bobN, aliceN); break;
      default: assert(0);
    }
  }

}


/**
  Implments a single nonce-generator.

  This simply enables for secret-key encryption primitives to have the same
  nonce on both sides of a communication.
 */
struct SingleNonce(size_t nonceSize) {
  alias Nonce = ubyte[nonceSize];

  alias NonceS = NonceStream!(nonceSize, 1);

  NonceS nonces;

  @property ref auto mine() { return nonces; }
  @property ref auto other() { return nonces; }

  ///// The nonce I use to encrypt packages sent by me and the other party uses 
  ///// to encrypt packages sent to me.
  //@property ref Nonce myNonce() { return nonces.front; }
  ///// ditto
  //@property ref Nonce otherNonce() { return nonces.front; }

  /** Initializes the nonce generator to 0  */
  this( ref const Nonce startNonce )
  {
    nonces.bytes = startNonce;
  }

  //[>* Sets the next nonce for the next <]
  //void nextMine() { nonces.popFront(); }

  //[>* Sets the next nonce for the next <]
  //void nextOther() { nonces.popFront(); }
}

/**
  A single, always incrementing infinite range of nonces.
Params:
  byteCount = the number of bytes in the nonce
  incrementAmt = the distance between two nonces
  mask = when 
  */
template NonceStream(size_t byteCount, ubyte incrementAmt=1, ubyte mask=0) {
  alias Nonce = ubyte[byteCount];
  enum useOffset = (incrementAmt != 1);

  struct NonceStream {
    Nonce bytes;

    static if (useOffset) {
      /** The offset of this specific nonce range */
      ubyte offset;
    }

    // this is an inifinite range
    enum empty = false;

    /** The current nonce. */
    @property ref Nonce front() { return bytes; }

    /** Get the next nonce for this counter */
    void popFront() {
      increment( bytes, incrementAmt );
      static if (useOffset) {
        bytes[0] = cast(ubyte)( (bytes[0] & mask) + offset );
      }
    }
  }
}

// Calulcates the next nonce in the stream
private void increment(size_t n)( ref ubyte[n] nonce, ubyte amount = 1 )
{
  uint carry = amount;
  foreach(i;0..n) {
    uint tmp = nonce[i] + carry;
    carry = (tmp & 0xff00) >> 8;
    nonce[i] = cast(ubyte)(tmp & 0xff);
  }
}

unittest {
  import std.string;
  ubyte[4] n = [0,0,0,0];
  increment(n);
  assert( n == [1,0,0,0] );
  increment(n,2);
  assert( n == [3,0,0,0] );
  increment(n,0xff);
  assert( n == [2,1,0,0] );
}

/**
  Generates a nonce that is based on the current clock value.

  The output of the function is as follows:
  ---

  | Hash of current time           | Current time (Little Endian)
  +---+---+---+-----+--------------+---+---+---+---+---+---+---+---+
  | 0 | 1 | 2 | ... | Hash.Bytes-8 | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 |
  +---+---+---+-----+--------------+---+---+---+---+---+---+---+---+
  | 0                              | Hash.Bytes-8

  ---
  */
auto generateNonce(size_t byteCount, alias safeRnd=safeRandomBytes)()
{
  import tweednacl.basics;

  ubyte[byteCount] nonce;
  safeRnd(nonce, byteCount);

  return nonce;
}

unittest {
  enum nonceSize = 24;
  bool[ubyte[nonceSize]] usedNonces;

  foreach(i;0..1024) {
    auto nonceFromHandshake = generateNonce!nonceSize();
    assert( (nonceFromHandshake in usedNonces) is  null );
    usedNonces[nonceFromHandshake] = true;
  }

}


/** ditto */
auto generateNonce(Impl, alias safeRnd=safeRandomBytes)()
{
  return generateNonce!(Impl.Nonce.length, safeRnd);
}

unittest {
  enum nonceSize = 64;
  alias NonceT = ubyte[nonceSize];
  bool[NonceT] usedNonces;
  struct TestPrimitive {
    alias Nonce = NonceT;

  }

  foreach(i;0..1024) {
    auto nonceFromHandshake = generateNonce!TestPrimitive();
    assert( (nonceFromHandshake in usedNonces) is  null );
    usedNonces[nonceFromHandshake] = true;
  }

}

