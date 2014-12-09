/**

$(BIG Introduction)

NaCl (pronounced "salt") is a new easy-to-use high-speed software library for
network communication, encryption, decryption, signatures, etc. NaCl's goal is
to provide all of the core operations needed to build higher-level
cryptographic tools.

Of course, other libraries already exist for these core operations. NaCl
advances the state of the art by improving security, by improving usability,
and by improving speed.

The following report contrasts NaCl with other libraries from a security
perspective: (PDF) Daniel J. Bernstein, Tanja Lange, Peter Schwabe, "The
security impact of a new cryptographic library". Pages 159–176 in Proceedings
of LatinCrypt 2012, edited by Alejandro Hevia and Gregory Neven, Lecture Notes
in Computer Science 7533, Springer, 2012. ISBN 978-3-642-33480-1.

The following report was created for Research Plaza and gives an introduction
to NaCl for a wider audience: (PDF)


$(BIG Contributors)

The core NaCl development team consists of Daniel J. Bernstein (University of
Illinois at Chicago and Technische Universiteit Eindhoven), Tanja Lange
(Technische Universiteit Eindhoven), and Peter Schwabe (Radboud Universiteit
Nijmegen).

NaCl was initiated under the CACE (Computer Aided Cryptography Engineering)
project funded by the European Commission's Seventh Framework Programme (FP7),
contract number ICT-2008-216499, running from 2008 through 2010. CACE
activities were organized into several Work Packages (WPs); NaCl was the main
task of WP2, "Accelerating Secure Networking". Work on NaCl at Technische
Universiteit Eindhoven between 2008 and 2010 was sponsored by CACE.

NaCl benefits from close collaboration with two other projects. The NaCl API is
based on, and has influenced, the SUPERCOP (System for Unified Performance
Evaluation Related to Cryptographic Operations and Primitives) API developed
for the eBACS (ECRYPT Benchmarking of Cryptographic Systems) project. Many of
the algorithms and implementations used in NaCl were developed as part of
Daniel J. Bernstein's High-Speed Cryptography project funded by the U.S.
National Science Foundation, grant number 0716498, and the followup
Higher-Speed Cryptography project funded by the U.S. National Science
Foundation, grant number 1018836. Work on NaCl at the University of Illinois at
Chicago was sponsored by these grants. "Any opinions, findings, and conclusions
or recommendations expressed in this material are those of the author(s) and do
not necessarily reflect the views of the National Science Foundation."

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
module tweednacl.nacl;

struct CryptoPrimitive
{
  string primitive;
  string implementation;
  string versionStr = "-";
}

struct BasicBoxInfo {
  size_t KeyBytes;

  size_t NonceBytes;
  /** The number of 0 bytes in front of the plaintext */
  size_t ZeroBytes;
  /** The number of 0 bytes in front of the encrypted box. */
  size_t BoxZeroBytes;
}
