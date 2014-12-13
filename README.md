# Cryptography in D

* Tour de force
* Importance of crypto / Why D needs built-in crypto in std
* How-to
* About NaCl and TweetNaCl
* The high-level interface: std.experimental.crypto
* The low-level interface: std.experimental.crypto.nacl
* The default D implementation: std.experimental.crypto.tweednacl
* A high-performance implementation of the low level primitives: sodiumed
* Performance comparisons


# Tour de force


# Importance of crypto / Why D needs built-in crypto in std

## Threats:

Exploiting systems has been a financially worhtwile activty for years,
yet every year there are more and more reports of data breaches stealing
sensitive information that was only protected by network security.

There is a strong myth that when an attacker has control of a machine
any data on that machine is compromised. This myth is powered by the
lazyness of developers implementing insufficient countermeasures to
guard their data: real attacks against encrypted data come from a
limited number of directions:

## Privacy:

Most of the data used by todays application are in a ownership and
privacy limbo: the application handles data of the clients, and this
application is reponsible for the safe keeping of this data.

Without strong cryptograohy the strongest guarantee a developer
can give about the safety and integrity of the system is the guarantee
given by the network and operations securty providers (which is a kind
of balanced losing game of evolving offense vs defense).

Distortion: the channel of communication may distort messages

Forgery: provide a valid looking message that is in fact not the
original message

Fuzzing: flood the target with large amounts of random data that may
trigger undefined / unintended behaviour either from the cryptographycal
stack or the application receiving the data (buffer overflows due to not
validated input, etc.).



* The Target did not implement any encryption (no attack necessary)
* The Target uses homebrew cryptography (hard to do properly, most of
  them are easy to break)

#### Signing messages

* The Target Protocol does not sign its messages (forgery, fuzzing, distortion)
* The Target Protocol does sign its messages but the Target does not
  verify them (this has been a source of bugs in a number of open source
  projects where implementation details like return value vs errno led
  to code not really verifying incoming messages)

#### Encryption

* The target does not use initialization vectors properly:
  * Each message is encrypted with the same IV / the same sequence of
    IVs (after a number of messages the attacker can figure out the
    secret due to the key leaking)

* The Target uses improper cyptographic primitives:
  * Hashes already proven to be weak: MD5, ...
  * Cyphers already proven to be weak: DES, ...
  * Improper key sizes: 1024 bit RSA, ...
  * Using public-key encryption instead of key-exchange

* The Target uses proper cyptographic primitives but an improper
  implementation:
  * Implementations valueable to timing attacks
  * Implementations valueable to memory attacks (buffer overflows)
  * Black box implementations: cryptography as a whole may be useless if the
    implementation itself cannot be validated by anyone willing to do so.

### Entropy

* Using non-secure random numbers: the C rand(), the D library of
  std.random all all designed for generating numbers that are NOT random
  numbers but a reproducible sequence of numbers.

* The sources for true entropy on a computing device are scarce:
    * input devices: mouse / keyboard / etc...
    * hard disk rotation (spin is influenced by air thus it varies by small
      amounts)
    * hardware Random Number Generators

Sometimes (like on a server with an SSD or a virtual device) the
device has none of these. In this case the security may be compromised
when using improper implementation.


__This means the library needs to be easy to use and hard to misuse.__



# How-to

## Authentication:

You want to verify that a message really comes the owner of a public key and
check that its contents hasnt bee altered.

### Generating a keypair

```D

```

### Sign a message
### Authenticate a message using a public key



## Public-key authenticated encryption:

The crypto library provides the Box primitive to enclose your messages in a encrypted
and authenticates envelope that can be transmitted over an unsecure channel.

### Generating a keypair

```D
  // Alice and Bob both create a public-secret keypair.
  auto aliceK = generateBoxKeypair();
  auto bobK = generateBoxKeypair();

  // they exchange their public keys, but keep their secret keys private
  auto alicePublicKey = aliceK.publicKey;
  auto bobPublicKey = bobK.publicKey;
```

### Exchanging public keys and nonces


### Encrypting a message

### Decrypting and authenticating a message



## Shared-key authenticated encryption:

The crypto library provides the SecretBox primitive to enclose your messages in a encrypted
and authenticates envelope that can be transmitted over an unsecure channel.

### Generating a keypair
### Exchanging public keys and nonces
### Encrypting a message
### Decrypting and authenticating a message







## Appendix 1: Why reimplement SHA-512?

While the default D library provides a really good implementation of SHA-512,
tweednacl uses its own implementation that is depending on the compiler slower
or sometimes faster. However at the time of writing std.digest does not provide
any @nogc interface.

