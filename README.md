Cryptography

* Tour de force
* Importance of crypto
* Why D needs built-in crypto in std
* How-to
* About NaCl and TweetNaCl
* The high-level interface: std.experimental.crypto
* The low-level interface: std.experimental.crypto.nacl
* The default D implementation: std.experimental.crypto.tweednacl
* A high-performance implementation of the low level primitives: sodiumed
* Performance comparisons



* Appendix 1: Why reimplement SHA-512?

While the default D library provides a really good implementation of SHA-512,
tweednacl uses its own implementation that is depending on the compiler slower
or sometimes faster. However at the time of writing std.digest does not provide
any @nogc interface.



# How-to

## Authentication:

You want to verify that a message really comes the owner of a public key and
check that its contents hasnt bee altered.

* Generating a keypair
* Sign a message
* Authenticate a message using a public key



## Public-key authenticated encryption:

The crypto library provides the Box primitive to enclose your messages in a encrypted
and authenticates envelope that can be transmitted over an unsecure channel.

* Generating a keypair
* Exchanging public keys and nonces
* Encrypting a message
* Decrypting and authenticating a message



## Shared-key authenticated encryption:

The crypto library provides the SecretBox primitive to enclose your messages in a encrypted
and authenticates envelope that can be transmitted over an unsecure channel.

* Generating a keypair
* Exchanging public keys and nonces
* Encrypting a message
* Decrypting and authenticating a message








How good libraries are built


By stealing good concepts from other places and packaging them up.
