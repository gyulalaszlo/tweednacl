module nacl.nonce_generator;

import std.stdio;

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

  NonceS myNonces;
  NonceS otherNonces;

  /// The nonce I use to encrypt packages sent by me.
  @property ref Nonce myNonce() { return myNonces.front; }
  /// The nonce the other party uses to encrypt packages sent to me.
  @property ref Nonce otherNonce() { return otherNonces.front; }

  /** Initializes the nonce generator to 0  */
  this(Pk)(ref const Pk myPk, ref const Pk otherPk)
  {
    initOffsetsAndNonces(myPk > otherPk);
  }

  /** Initializes the nonce generator to 0  */
  this(Pk)(ref const Pk myPk, ref const Pk otherPk,
      ref const Nonce myStartNonce, ref const Nonce otherStartNonce )
  {
    myNonces.bytes = myStartNonce;
    otherNonces.bytes = otherStartNonce;
    initOffsetsAndNonces(myPk > otherPk);
  }

  /** Sets the next nonce for the next */
  void nextMine() { myNonces.popFront(); }

  /** Sets the next nonce for the next */
  void nextOther() { otherNonces.popFront(); }

  // Helper to initialize the offsets depending on if my public key is bigger
  // then the other partys.
  // Also makes sure that the nonces are in their lockstep state. Call after
  // setting the nonces
  private void initOffsetsAndNonces( bool isMyPkBigger )
  {
    myNonces.offset = isMyPkBigger ? 0 : 1;
    otherNonces.offset = isMyPkBigger ? 1 : 0;

    nextMine();
    nextOther();
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
    from.nextMine();
    to.nextOther();
    assert( from.myNonce == to.otherNonce );
    assert( (from.myNonce in usedNonces) is null );
    usedNonces[from.myNonce] = true;
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

struct NonceStream(size_t byteCount, ubyte incrementAmt=1, ubyte mask=0) {
  alias Nonce = ubyte[byteCount];
  enum useOffset = (incrementAmt != 1);

  Nonce bytes;

  static if (useOffset) {
    ubyte offset;
  }

  @property ref Nonce front() { return bytes; }

  void popFront() {
    increment( bytes, incrementAmt );
    static if (useOffset) {
      bytes[0] = cast(ubyte)( (bytes[0] & mask) + offset );
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

import nacl.hash : SHA512;
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
auto generateNonce(size_t byteCount, alias Hash=nacl.hash.SHA512)()
  if (byteCount >= long.sizeof && (Hash.Bytes + long.sizeof) >= byteCount)
{
  import std.datetime;
  import std.bitmanip;
  import nacl.basics;


  enum timeBytes = typeof(Clock.currStdTime()).sizeof;
  enum firstTimeByte = byteCount - timeBytes;

  ubyte[byteCount] nonce;
  Hash.HashValue hsh;
  immutable ubyte[timeBytes] timeAsBytes = nativeToLittleEndian(Clock.currStdTime());

  Hash.hash( hsh, timeAsBytes );
  nonce[0..firstTimeByte] = hsh[0..firstTimeByte];
  nonce[firstTimeByte..byteCount] = timeAsBytes;

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
auto generateNonce(Impl, alias Hash=nacl.hash.SHA512)()
{
  return generateNonce!(Impl.NonceBytes, Hash);
}

unittest {
  enum nonceSize = 64;
  bool[ubyte[nonceSize]] usedNonces;
  struct SomePrimitive {
    enum NonceBytes = nonceSize;
  }

  foreach(i;0..1024) {
    auto nonceFromHandshake = generateNonce!SomePrimitive();
    assert( (nonceFromHandshake in usedNonces) is  null );
    usedNonces[nonceFromHandshake] = true;
  }

}
