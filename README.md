# Strong-OpenPGP Message Format

## Abstract

This is a strong subset of OpenPGP.

OpenPGP keys and messages are sequences of packets.

### How to use this profile

??? `GnuPG: --compress-level 0 --disable-signer-uid`

## 1. Data Formats

A _scalar_ number is an unsigned big-endian.  Example: `0x01 0x00` = 256.

A _multiprecision integer_ (MPI) is a two-byte scalar with the
length in bits, followed by a scalar with the actual integer.
Unused bits of an MPI MUST be zero.  Example: `0x00 0x09 0x01 0x00` = 256.

A _text_ is an UTF-8 string.

A _time_ is a four-byte scalar with the number of seconds since
midnight, 1 January 1970 UTC.

## 2. Packet Syntax

A _packet_ consists of a packet tag, followed by one or more packet
data blocks containing length information and the packet body.

### 2.1. Packet Tag

A _packet tag_ is a byte:

    packet tag = 0xc0 || tag

The defined tags are:

|       Tag | Packet Type                                         |
| --------- | ----------------------------------------------------|
|      0x0b | Literal Data                                        |
|      0x01 | Public-Key Encrypted Session Key                    |
|      0x14 | AEAD Encrypted Data                                 |
|      0x04 | One-Pass Signature                                  |
|      0x02 | Signature                                           |
|      0x06 | Public-Key                                          |
|      0x0e | Public-Subkey                                       |
|      0x0d | User ID                                             |

### 2.2. Packet Data Blocks

The _packet data_ depends on the packet type.

#### 2.2.1. Regular Packets

All packets except "Literal Data" and "AEAD Encrypted Data" use exactly
one fixed length data block.

A _fixed length data block_ consists of:

* `0xff`,
* a four-byte scalar with the length of the following body data,
* followed by the packet body data.

#### 2.2.2. Literal Data Packets

Literal data packets have a body that consists of:

* zero or more partial length data blocks,
* finished by exactly one fixed length data block.

A _partial length data block_ consists of the byte `0xf0`, followed by
exactly 2^16 = 65536 bytes of packet body data.

#### 2.2.3. AEAD Encrypted Data Packets

AEAD-encrypted data packets have a body that consists of:

* an AEAD header block,
* an AEAD initialization block,
* zero or more repetitions of:
  * a partial length data block
  * an AEAD tag block
* finished by exactly one fixed length data block that includes a final AEAD tag at the end (without the block header).

An _AEAD header block_ consists of the byte `0xe2`, followed by the
4 byte AEAD header:
* `0x01` (version)
* `0x09` (AES-256)
* `0x01` (EAX)
* `0x0a` (64 KB chunk size)

An _AEAD initialization block_ consists followed by the byte `0xe4`,
followed by the 16 byte EAX initialization vector.

An _AEAD tag block_ consists of the byte `0xe4`, followed by the EAX
authentication tag for the previous data block.

## 3. Packet Composition

These are the rules for how packets should be put into sequences.

### 3.1. Encrypted and/or Signed Message

A message is a sequence of packets according to this grammar (see
RFC5234):

    message = encrypted-message / signed-message

    encrypted-message = 1*64"Public-Key Encrypted Session Key Packet" "AEAD Encrypted Data Packet"

    signed-message = "One-Pass Signature Packet" (signed-message / "Literal Data Packet") "Signature Packet"

In addition, decrypting an AEAD Encrypted Data packet must yield a
signed-message or a Literal Data packet.

If a message contains more than one signature, the signature
packets bracket the message; that is, the first Signature packet
after the message corresponds to the last One-Pass Signature packet
and the final Signature packet corresponds to the first One-Pass
signature packet.

The maximum number of signatures is 64. If you need more, use
detached signatures instead which do not require nesting.

### 3.2. Detached Signatures

Detached signatures consist of exactly one Signature Packet.

### 3.3. Transfering Public Key

   Primary-Key
      [Revocation Self Signature]
      [Direct Key Signature...]
      [User ID [Signature ...] ...]
      [[Subkey [Binding-Signature-Revocation]
              Primary-Key-Binding-Signature] ...]

   A subkey always has a single signature after it that is issued using
   the primary key to tie the two keys together.  Subkeys that can
   issue signatures MUST have a V4 binding signature due to the REQUIRED
   embedded primary key binding signature.

   In the above diagram, if the binding signature of a subkey has been
   revoked, the revoked key may be removed, leaving only one key.

   In a V4 key, the primary key SHOULD be a key capable of
   certification.  There are cases, such as device certificates, where
   the primary key may not be capable of certification.  A primary key
   capable of making signatures SHOULD be accompanied by either a
   certification signature (on a User ID) or a signature directly on
   the key.

   Implementations SHOULD accept encryption-only primary keys without a
   signature.  It also SHOULD allow importing any key accompanied either
   by a certification signature or a signature on itself.  It MAY accept
   signature-capable primary keys without an accompanying signature.

   It is also possible to have a signature-only subkey.  This permits a
   primary key that collects certifications (key signatures), but is
   used only for certifying subkeys that are used for encryption and
   signatures.

   o  One Public-Key packet

   o  Zero or more revocation signatures

   o  Zero or more User ID packets

   o  After each User ID packet, zero or more Signature packets
      (certifications)

   o  Zero or more Subkey packets

   o  After each Subkey packet, one Signature packet, plus optionally a
      revocation

   The Public-Key packet occurs first.  Each of the following User ID
   packets provides the identity of the owner of this public key.  If
   there are multiple User ID packets, this corresponds to multiple
   means of identifying the same unique individual user; for example, a
   user may have more than one email address, and construct a User ID
   for each one.

   Immediately following each User ID packet, there are zero or more
   Signature packets.  Each Signature packet is calculated on the
   immediately preceding User ID packet and the initial Public-Key
   packet.  The signature serves to certify the corresponding public key
   and User ID.  In effect, the signer is testifying to his or her
   belief that this public key belongs to the user identified by this
   User ID.

   After the User ID packets, there may be zero or more Subkey
   packets.  In general, subkeys are provided in cases where the
   top-level public key is a signature-only key.  However, any V4 key
   may have subkeys, and the subkeys may be encryption-only keys,
   signature-only keys, or general-purpose keys.

   Each Subkey packet MUST be followed by one Signature packet, which
   should be a subkey binding signature issued by the top-level key.
   For subkeys that can issue signatures, the subkey binding signature
   MUST contain an Embedded Signature subpacket with a primary key
   binding signature (0x19) issued by the subkey on the top-level key.

   Subkey and Key packets may each be followed by a revocation Signature
   packet to indicate that the key is revoked.  Revocation signatures
   are only accepted if they are issued by the key itself, or by a key
   that is authorized to issue revocations via a Revocation Key
   subpacket in a self-signature by the top-level key.


4. Packet Types

4.1. Literal Data Packet (Tag 11)

   A Literal Data packet contains the actual plaintext of an encrypted
   and/or signed message.

   Format:

   * 0x62 (binary)
   * 0x00 (empty filename)
   * 0x00 0x00 0x00 0x00 (no creation time)
   * the actual plaintext message

4.2. One-Pass Signature Packets (Tag 4)

   A One-Pass Signature packet comes before the signed data and allows
   the signer to output the signed message in one pass.

   Format:

   * 0x03 (version)
   * 0x00 (binary document)
   * 0x08 (SHA2-256)
   * 0x01 (RSA) or 0x16 (EdDSA)
   * Key ID of signing key (8 bytes)
   * 0x00 (not nested)

4.3. Signature Packets for File Signatures (Tag 2)

   Format:

   Hashed part:

   * 0x04 (version)
   * 0x00 (binary document)
   * 0x01 (RSA) or 0x16 (EdDSA)
   * 0x08 (SHA2-256)
   * 0x00 0x28 (length of hashed subpacket data)
   * 0x21 0x21 followed by 32-byte fingerprint (issuer fingerprint version 5)
   * 0x05 0x02 followed by 4-byte signature creation time

   Unhashed part:

   * 0x00 0x00 (length of unhashed subpacket data)
   * 0x00 0x00 (quick check bytes, could also be random)

   For RSA:

   * MPI of RSA signature value m**d mod n

   For EdDSA:

   * MPI of EdDSA compressed value r
   * MPI of EdDSA compressed value s

   The compressed version of R and S for use with EdDSA is described in
   [I-D.irtf-cfrg-eddsa].

   The concatenation of the data being signed and the signature data
   from the version number through the hashed subpacket data (inclusive)
   is hashed.  The resulting hash value is what is signed.

4.4. Public-Key Encrypted Session Key Packets (Tag 1)

   A Public-Key Encrypted Session Key packet holds the session key
   used to encrypt a message. The AEAD Encrypted Data Packet is
   preceded by one Public-Key Encrypted Session Key packet for each
   OpenPGP key to which the message is encrypted.

   The body of this packet consists of:

   o  The byte 0x03.

   o  The eight-byte key ID of the public (sub-)key to
      which the session key is encrypted.

   o  A one-byte number giving the public-key algorithm used.

   o  A string of bytes that is the encrypted session key.  This string
      takes up the remainder of the packet, and its contents are
      dependent on the public-key algorithm used.

      Algorithm Specific Fields for RSA encryption:

      *  Multiprecision integer (MPI) of RSA encrypted value m**e mod n.

      Algorithm-Specific Fields for ECDH encryption:

      *  MPI of an EC point representing an ephemeral public key.

      *  a one-byte size, followed by a symmetric key encoded using the
         method described in Section 13.5.

   The value "m" in the above formulas is derived from the session key
   as follows.  First, the session key is prefixed with a one-byte
   0x09.  Then a two-byte checksum is appended, which is equal to the
   sum of the preceding session key bytes, not including 0x09, modulo
   65536.  This value is then encoded as described in PKCS#1 block
   encoding EME-PKCS1-v1_5 in Section 7.2.1 of [RFC3447] to form the
   "m" value used in the formulas above.  See Section 13.1 of this
   document for notes on OpenPGP's use of PKCS#1.

   Note that when an implementation forms several PKESKs with one
   session key, forming a message that can be decrypted by several keys,
   the implementation MUST make a new PKCS#1 encoding for each key.

   An implementation MAY accept or use a Key ID of zero as a "wild
   card" or "speculative" Key ID.  In this case, the receiving
   implementation may try all available private keys, checking for a
   valid decrypted session key.

5.16.  AEAD Encrypted Data Packet (Tag 20)

   This packet contains data encrypted with an authenticated encryption
   and additional data (AEAD) construction.  When it has been decrypted,
   it will typically contain other packets (often a Literal Data packet
   or Compressed Data packet).

   The body of this packet consists of:

   o  The bytes 0x01 0x09 0x01

   o  A one-byte chunk size

   o  A starting initialization vector (16 bytes)

   o  Encrypted data, the output of the selected symmetric-key cipher
      operating in the given AEAD mode.

   o  A final, summary authentication tag for the AEAD mode.

   An AEAD encrypted data packet consists of one or more chunks of data.
   The plaintext of each chunk is of a size specified using the chunk
   size byte using the method specified below.

   The encrypted data consists of the encryption of each chunk of
   plaintext, followed immediately by the relevant authentication tag.
   If the last chunk of plaintext is smaller than the chunk size, the
   ciphertext for that data may be shorter; it is nevertheless followed
   by a full authentication tag.

   For each chunk, the AEAD construction is given the Packet Tag in new
   format encoding (bits 7 and 6 set, bits 5-0 carry the packet tag),
   version number, cipher algorithm byte, AEAD algorithm byte, chunk
   size byte, and an eight-byte, big-endian chunk index as additional
   data.  The index of the first chunk is zero.  For example, the
   additional data of the first chunk using EAX and AES-128 with a chunk
   size of 64 kiByte consists of the bytes 0xD4, 0x01, 0x07, 0x01,
   0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, and 0x00.

   After the final chunk, the AEAD algorithm is used to produce a final
   authentication tag encrypting the empty string.  This AEAD instance
   is given the additional data specified above, plus an eight-byte,
   big-endian value specifying the total number of plaintext bytes
   encrypted.  This allows detection of a truncated ciphertext.

   The chunk size byte specifies the size of chunks using the following
   formula (in C), where c is the chunk size byte:

       chunk_size = ((uint64_t)1 << (c + 6))

   An implementation MUST support chunk size bytes with values from 0
   to 56.  Chunk size bytes with other values are reserved for future
   extensions.

   A new random initialization vector MUST be used for each message.

   The starting initialization vector and authentication tag are both 16
   bytes long.

   The starting initialization vector for this mode MUST be unique and
   unpredictable.

   The nonce for EAX mode is computed by treating the starting
   initialization vector as a 16-byte, big-endian value and exclusive-
   oring the low eight bytes of it with the chunk index.

5.2. Signature Packet (Tag 2)

   A Signature packet describes a binding between some public key and
   some data.  The most common signatures are a signature of a file or a
   block of text, and a signature that is a certification of a User ID.

5.2.1.  {5.2.1} Signature Types

   0x00  Signature of a binary document.  This means the signer owns it,
      created it, or certifies that it has not been modified.

   0x10  Generic certification of a User ID and Public-Key packet.  The
      issuer of this certification does not make any particular
      assertion as to how well the certifier has checked that the owner
      of the key is in fact the person described by the User ID.

   0x11  Persona certification of a User ID and Public-Key packet.  The
      issuer of this certification has not done any verification of the
      claim that the owner of this key is the User ID specified.

   0x12  Casual certification of a User ID and Public-Key packet.  The
      issuer of this certification has done some casual verification of
      the claim of identity.

   0x13  Positive certification of a User ID and Public-Key packet.  The
      issuer of this certification has done substantial verification of
      the claim of identity.

      Most OpenPGP implementations make their "key signatures" as 0x10
      certifications.  Some implementations can issue 0x11-0x13
      certifications, but few differentiate between the types.

   0x18  Subkey Binding Signature This signature is a statement by the
      top-level signing key that indicates that it owns the subkey.
      This signature is calculated directly on the primary key and
      subkey, and not on any User ID or other packets.  A signature that
      binds a signing subkey MUST have an Embedded Signature subpacket
      in this binding signature that contains a 0x19 signature made by
      the signing subkey on the primary key and subkey.

   0x19  Primary Key Binding Signature This signature is a statement by
      a signing subkey, indicating that it is owned by the primary key
      and subkey.  This signature is calculated the same way as a 0x18
      signature: directly on the primary key and subkey, and not on any
      User ID or other packets.

   0x1F  Signature directly on a key This signature is calculated
      directly on a key.  It binds the information in the Signature
      subpackets to the key, and is appropriate to be used for
      subpackets that provide information about the key, such as the
      Revocation Key subpacket.  It is also appropriate for statements
      that non-self certifiers want to make about the key itself, rather
      than the binding between a key and a name.

5.2.2.  {5.2.2} Version 3 Signature Packet Format

      The concatenation of the data to be signed, the signature type,
      and creation time from the Signature packet (5 additional bytes)
      is hashed.  The resulting hash value is used in the signature
      algorithm.  The high 16 bits (first two bytes) of the hash are
      included in the Signature packet to provide a quick test to reject
      some invalid signatures.

      Algorithm-Specific Fields for RSA signatures:

      *  Multiprecision integer (MPI) of RSA signature value m**d mod n.

      Algorithm-Specific Fields for DSA and ECDSA signatures:

      *  MPI of DSA or ECDSA value r.

      *  MPI of DSA or ECDSA value s.

   The signature calculation is based on a hash of the signed data, as
   described above.  The details of the calculation are different for
   DSA signatures than for RSA signatures.

   With RSA signatures, the hash value is encoded using PKCS#1 encoding
   type EMSA-PKCS1-v1_5 as described in Section 9.2 of RFC 3447.  This
   requires inserting the hash value as an byte string into an ASN.1
   structure.  The object identifier for the type of hash being used is
   included in the structure.  The hexadecimal representations for the
   currently defined hash algorithms are as follows:

    - SHA2-256:   0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01

   The ASN.1 Object Identifiers (OIDs) are as follows:

    - SHA2-256:   2.16.840.1.101.3.4.2.1

   The full hash prefixes for these are as follows:

    - SHA2-224:   0x30, 0x2D, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
                  0x00, 0x04, 0x1C

    - SHA2-256:   0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
                  0x00, 0x04, 0x20

    - SHA2-384:   0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
                  0x00, 0x04, 0x30

    - SHA2-512:   0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
                  0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
                  0x00, 0x04, 0x40

   If the output size of the chosen hash is larger than the number of
   bits of q, the hash result is truncated to fit by taking the number
   of leftmost bits equal to the number of bits of q.  This (possibly
   truncated) hash function result is treated as a number and used
   directly in the DSA signature algorithm.

5.2.3.  {5.2.3} Version 4 Signature Packet Format

   The body of a version 4 Signature packet contains:

   o  One-byte version number (4).

   o  One-byte signature type.

   o  One-byte public-key algorithm.

   o  One-byte hash algorithm.

   o  Two-byte scalar byte count for following hashed subpacket data.
      Note that this is the length in bytes of all of the hashed
      subpackets; a pointer incremented by this number will skip over
      the hashed subpackets.

   o  Hashed subpacket data set (zero or more subpackets).

   o  Two-byte scalar byte count for the following unhashed subpacket
      data.  Note that this is the length in bytes of all of the
      unhashed subpackets; a pointer incremented by this number will
      skip over the unhashed subpackets.

   o  Unhashed subpacket data set (zero or more subpackets).

   o  Two-byte field holding the left 16 bits of the signed hash value.

   o  One or more multiprecision integers comprising the signature.
      This portion is algorithm specific:

      Algorithm-Specific Fields for RSA signatures:

      *  Multiprecision integer (MPI) of RSA signature value m**d mod n.

      Algorithm-Specific Fields for DSA or ECDSA signatures:

      *  MPI of DSA or ECDSA value r.

      *  MPI of DSA or ECDSA value s.

      Algorithm-Specific Fields for EdDSA signatures:

      *  MPI of EdDSA compressed value r.

      *  MPI of EdDSA compressed value s.

   The compressed version of R and S for use with EdDSA is described in
   [I-D.irtf-cfrg-eddsa].  The version 3 signature format MUST NOT be
   used with EdDSA.

   The concatenation of the data being signed and the signature data
   from the version number through the hashed subpacket data (inclusive)
   is hashed.  The resulting hash value is what is signed.  The left 16
   bits of the hash are included in the Signature packet to provide a
   quick test to reject some invalid signatures.

   There are two fields consisting of Signature subpackets.  The first
   field is hashed with the rest of the signature data, while the second
   is unhashed.  The second set of subpackets is not cryptographically
   protected by the signature and should include only advisory
   information.

   The algorithms for converting the hash function result to a signature
   are described in a section below.

5.2.3.1.  {5.2.3.1} Signature Subpacket Specification

   A subpacket data set consists of zero or more Signature subpackets.
   In Signature packets, the subpacket data set is preceded by a two-
   byte scalar count of the length in bytes of all the subpackets.  A
   pointer incremented by this number will skip over the subpacket data
   set.

   Each subpacket consists of a subpacket header and a body.  The header
   consists of:

   o  the subpacket length (1, 2, or 5 bytes),

   o  the subpacket type (1 byte),

   and is followed by the subpacket-specific data.

   The length includes the type byte but not this length.  Its format
   is similar to the "new" format packet header lengths, but cannot have
   Partial Body Lengths.  That is:

      if the 1st byte <  192, then
          lengthOfLength = 1
          subpacketLen = 1st_byte

      if the 1st byte >= 192 and < 255, then
          lengthOfLength = 2
          subpacketLen = ((1st_byte - 192) << 8) + (2nd_byte) + 192

      if the 1st byte = 255, then
          lengthOfLength = 5
          subpacket length = [four-byte scalar starting at 2nd_byte]

   The value of the subpacket type byte may be:

         +-------------+-----------------------------------------+
         |        Type | Description                             |
         +-------------+-----------------------------------------+
         |           2 | Signature Creation Time                 |
         |           3 | Signature Expiration Time               |
         |           5 | Trust Signature                         |
         |           6 | Regular Expression                      |
         |           7 | Revocable                               |
         |           9 | Key Expiration Time                     |
         |          12 | Revocation Key                          |
         |          16 | Issuer                                  |
         |          25 | Primary User ID                         |
         |          29 | Reason for Revocation                   |
         |          33 | Issuer Fingerprint                      |
         +-------------+-----------------------------------------+

   An implementation SHOULD ignore any subpacket of a type that it does
   not recognize.

   Bit 7 of the subpacket type is the "critical" bit.  If set, it
   denotes that the subpacket is one that is critical for the evaluator
   of the signature to recognize.  If a subpacket is encountered that is
   marked critical but is unknown to the evaluating software, the
   evaluator SHOULD consider the signature to be in error.

   An evaluator may "recognize" a subpacket, but not implement it.  The
   purpose of the critical bit is to allow the signer to tell an
   evaluator that it would prefer a new, unknown feature to generate an
   error than be ignored.

   Implementations SHOULD implement the four preferred algorithm
   subpackets (11, 21, 22, and 34), as well as the "Reason for
   Revocation" subpacket.  Note, however, that if an implementation
   chooses not to implement some of the preferences, it is required to
   behave in a polite manner to respect the wishes of those users who do
   implement these preferences.

5.2.3.2.  {5.2.3.2} Signature Subpacket Types

   A number of subpackets are currently defined.  Some subpackets apply
   to the signature itself and some are attributes of the key.
   Subpackets that are found on a self-signature are placed on a
   certification made by the key itself.  Note that a key may have more
   than one User ID, and thus may have more than one self-signature, and
   differing subpackets.

   A subpacket may be found either in the hashed or unhashed subpacket
   sections of a signature.  If a subpacket is not hashed, then the
   information in it cannot be considered definitive because it is not
   part of the signature proper.

5.2.3.3.  {5.2.3.3} Notes on Self-Signatures

   A self-signature is a binding signature made by the key to which the
   signature refers.  There are three types of self-signatures, the
   certification signatures (types 0x10-0x13), the direct-key signature
   (type 0x1F), and the subkey binding signature (type 0x18).  For
   certification self-signatures, each User ID may have a self-
   signature, and thus different subpackets in those self-signatures.
   For subkey binding signatures, each subkey in fact has a self-
   signature.  Subpackets that appear in a certification self-signature
   apply to the user name, and subpackets that appear in the subkey
   self-signature apply to the subkey.  Lastly, subpackets on the
   direct-key signature apply to the entire key.

   Revoking a self-signature or allowing it to expire has a semantic
   meaning that varies with the signature type.  Revoking the self-
   signature on a User ID effectively retires that user name.  The self-
   signature is a statement, "My name X is tied to my signing key K" and
   is corroborated by other users' certifications.  If another user
   revokes their certification, they are effectively saying that they no
   longer believe that name and that key are tied together.  Similarly,
   if the users themselves revoke their self-signature, then the users
   no longer go by that name, no longer have that email address, etc.
   Revoking a binding signature effectively retires that subkey.
   Revoking a direct-key signature cancels that signature.  Please see
   the "Reason for Revocation" subpacket (Section 5.2.3.23) for more
   relevant detail.

   Since a self-signature contains important information about the key's
   use, an implementation SHOULD allow the user to rewrite the self-
   signature, and important information in it, such as key expiration.

   It is good practice to verify that a self-signature imported into an
   implementation doesn't advertise features that the implementation
   doesn't support, rewriting the signature as appropriate.

   An implementation that encounters multiple self-signatures on the
   same object may resolve the ambiguity in any way it sees fit, but it
   is RECOMMENDED that priority be given to the most recent self-
   signature.

5.2.3.4.  {5.2.3.4} Signature Creation Time

   (4-byte time field)

   The time the signature was made.

   MUST be present in the hashed area.

5.2.3.5.  {5.2.3.5} Issuer

   (8-byte Key ID)

   The OpenPGP Key ID of the key issuing the signature.  If the version
   of that key is greater than 4, this subpacket MUST NOT be included in
   the signature.

5.2.3.6.  {5.2.3.6} Key Expiration Time

   (4-byte time field)

   The validity period of the key.  This is the number of seconds after
   the key creation time that the key expires.  If this is not present
   or has a value of zero, the key never expires.  This is found only on
   a self-signature.

5.2.3.11.  {5.2.3.10} Signature Expiration Time

   (4-byte time field)

   The validity period of the signature.  This is the number of seconds
   after the signature creation time that the signature expires.  If
   this is not present or has a value of zero, it never expires.

5.2.3.13. (Removed intentionally)  {5.2.3.12} Revocable

   FIXME: Make sur this is present on non-revocation signatures.

   (1 byte of revocability, 0 for not, 1 for revocable)

   Signature's revocability status.  The packet body contains a Boolean
   flag indicating whether the signature is revocable.  Signatures that

   are not revocable have any later revocation signatures ignored.  They
   represent a commitment by the signer that he cannot revoke his
   signature for the life of his key.  If this packet is not present,
   the signature is revocable.

5.2.3.16.  {5.2.3.15} Revocation Key

   (1 byte of class, 1 byte of public-key algorithm ID, 20 or 32
   bytes of fingerprint)

   V4 keys use the full 20 byte fingerprint; V5 keys use the full 32
   byte fingerprint

   Authorizes the specified key to issue revocation signatures for this
   key.  Class byte must have bit 0x80 set.  If the bit 0x40 is set,
   then this means that the revocation information is sensitive.  Other
   bits are for future expansion to other kinds of authorizations.  This
   is found on a self-signature.

   If the "sensitive" flag is set, the keyholder feels this subpacket
   contains private trust information that describes a real-world
   sensitive relationship.  If this flag is set, implementations SHOULD
   NOT export this signature to other users except in cases where the
   data needs to be available: when the signature is being sent to the
   designated revoker, or when it is accompanied by a revocation
   signature from that revoker.  Note that it may be appropriate to
   isolate this subpacket within a separate signature so that it is not
   combined with other subpackets that need to be exported.

5.2.3.22.  {5.2.3.21} Key Flags

   (N bytes of flags)

   This subpacket contains a list of binary flags that hold information
   about a key.  It is a string of bytes, and an implementation MUST
   NOT assume a fixed size.  This is so it can grow over time.  If a
   list is shorter than an implementation expects, the unstated flags
   are considered to be zero.  The defined flags are as follows:

   0x01  This key may be used to certify other keys.

   0x02  This key may be used to sign data.

   0x04  This key may be used to encrypt communications.

   0x08  This key may be used to encrypt storage.

   0x10  The private component of this key may have been split by a
      secret-sharing mechanism.

   0x20  This key may be used for authentication.

   0x80  The private component of this key may be in the possession of
      more than one person.

   Usage notes:

   The flags in this packet may appear in self-signatures or in
   certification signatures.  They mean different things depending on
   who is making the statement --- for example, a certification
   signature that has the "sign data" flag is stating that the
   certification is for that use.  On the other hand, the
   "communications encryption" flag in a self-signature is stating a
   preference that a given key be used for communications.  Note
   however, that it is a thorny issue to determine what is
   "communications" and what is "storage".  This decision is left wholly
   up to the implementation; the authors of this document do not claim
   any special wisdom on the issue and realize that accepted opinion may
   change.

   The "split key" (0x10) and "group key" (0x80) flags are placed on a
   self-signature only; they are meaningless on a certification
   signature.  They SHOULD be placed only on a direct-key signature
   (type 0x1F) or a subkey signature (type 0x18), one that refers to the
   key the flag applies to.


5.2.3.24.  {5.2.3.23} Reason for Revocation

   (1 byte of revocation code, N bytes of reason string)

   This subpacket is used only in key revocation and certification
   revocation signatures.  It describes the reason why the key or
   certificate was revoked.

   The first byte contains a machine-readable code that denotes the
   reason for the revocation:

   +----------+--------------------------------------------------------+
   |     Code | Reason                                                 |
   +----------+--------------------------------------------------------+
   |        0 | No reason specified (key revocations or cert           |
   |          | revocations)                                           |
   |        1 | Key is superseded (key revocations)                    |
   |        2 | Key material has been compromised (key revocations)    |
   |        3 | Key is retired and no longer used (key revocations)    |
   |       32 | User ID information is no longer valid (cert           |
   |          | revocations)                                           |
   |  100-110 | Private Use                                            |
   +----------+--------------------------------------------------------+

   Following the revocation code is a string of bytes that gives
   information about the Reason for Revocation in human-readable form
   (UTF-8).  The string may be null, that is, of zero length.  The
   length of the subpacket is the length of the reason string plus one.
   An implementation SHOULD implement this subpacket, include it in all
   revocation signatures, and interpret revocations appropriately.
   There are important semantic differences between the reasons, and
   there are thus important reasons for revoking signatures.

   If a key has been revoked because of a compromise, all signatures
   created by that key are suspect.  However, if it was merely
   superseded or retired, old signatures are still valid.  If the
   revoked signature is the self-signature for certifying a User ID, a
   revocation denotes that that user name is no longer in use.  Such a
   revocation SHOULD include a 0x20 code.

   Note that any signature may be revoked, including a certification on
   some other person's key.  There are many good reasons for revoking a
   certification signature, such as the case where the keyholder leaves
   the employ of a business with an email address.  A revoked
   certification is no longer a part of validity calculations.

5.2.3.26.  {5.2.3.25} Signature Target

   (1 byte public-key algorithm, 1 byte hash algorithm, N bytes hash)

   This subpacket identifies a specific target signature to which a
   signature refers.  For revocation signatures, this subpacket provides
   explicit designation of which signature is being revoked.  For a
   third-party or timestamp signature, this designates what signature is
   signed.  All arguments are an identifier of that target signature.

   The N bytes of hash data MUST be the size of the hash of the
   signature.  For example, a target signature with a SHA-1 hash MUST
   have 20 bytes of hash data.


5.2.3.28.  Issuer Fingerprint

   (1 byte key version number, N bytes of fingerprint)

   The OpenPGP Key fingerprint of the key issuing the signature.  This
   subpacket SHOULD be included in all signatures.  If the version of
   the issuing key is 4 and an Issuer subpacket is also included in the
   signature, the key ID of the Issuer subpacket MUST match the low 64
   bits of the fingerprint.

   Note that the length N of the fingerprint is 32.

5.2.4.  {5.2.4} Computing Signatures

   All signatures are formed by producing a hash over the signature
   data, and then using the resulting hash in the signature algorithm.

   For binary document signatures (type 0x00), the document data is
   hashed directly.  For text document signatures (type 0x01), the
   document is canonicalized by converting line endings to <CR><LF>, and
   the resulting data is hashed.

   When a signature is made over a key, the hash data starts with the
   byte 0x99, followed by a two-byte length of the key, and then body
   of the key packet.  (Note that this is an old-style packet header for
   a key packet with two-byte length.)  A subkey binding signature
   (type 0x18) or primary key binding signature (type 0x19) then hashes
   the subkey using the same format as the main key (also using 0x99 as
   the first byte).  Primary key revocation signatures (type 0x20) hash
   only the key being revoked.  Subkey revocation signature (type 0x28)
   hash first the primary key and then the subkey being revoked.

   A certification signature (type 0x10 through 0x13) hashes the User
   ID being bound to the key into the hash context after the above
   data.  A V5 certification hashes the constant 0xB4 for User
   ID certifications or the constant 0xD1 for User Attribute
   certifications, followed by a four-byte number giving the length of
   the User ID or User Attribute data, and then the User ID or User
   Attribute data.

   When a signature is made over a Signature packet (type 0x50), the
   hash data starts with the byte 0x88, followed by the four-byte
   length of the signature, and then the body of the Signature packet.
   (Note that this is an old-style packet header for a Signature packet
   with the length-of-length set to zero.)  The unhashed subpacket data
   of the Signature packet being hashed is not included in the hash, and
   the unhashed subpacket data length value is set to zero.

   Once the data body is hashed, then a trailer is hashed. A V5
   signature hashes the packet body starting from its first field, the
   version number, through the end of the hashed subpacket data.
   Thus, the fields hashed are the signature version, the signature
   type, the public-key algorithm, the hash algorithm, the hashed
   subpacket length, and the hashed subpacket body.

   V4 signatures also hash in a final trailer of six bytes: the version
   of the Signature packet, i.e., 0x04; 0xFF; and a four-byte, big-
   endian number that is the length of the hashed data from the
   Signature packet (note that this number does not include these final
   six bytes). {FIXME: truncated or wrap that number on overflow}

   V5 signatures instead hash in a ten-byte trailer: the version of the
   Signature packet, i.e., 0x05; 0xFF; and an eight-byte, big-endian
   number that is the length of the hashed data from the Signature
   packet (note that this number does not include these final ten
   bytes).

   After all this has been hashed in a single hash context, the
   resulting hash field is used in the signature algorithm and placed at
   the end of the Signature packet.

5.5.  {5.5} Key Material Packet

   A key material packet contains all the information about a public or
   private key.  There are four variants of this packet type, and two
   major versions.  Consequently, this section is complex.

5.5.1.  {5.5.1} Key Packet Variants

5.5.1.1.  {5.5.1.1} Public-Key Packet (Tag 6)

   A Public-Key packet starts a series of packets that forms an OpenPGP
   key (sometimes called an OpenPGP certificate).

5.5.1.2.  {5.5.1.2} Public-Subkey Packet (Tag 14)

   A Public-Subkey packet (tag 14) has exactly the same format as a
   Public-Key packet, but denotes a subkey.  One or more subkeys may be
   associated with a top-level key.  By convention, the top-level key
   provides signature services, and the subkeys provide encryption
   services.

5.5.2.  {5.5.2} Public-Key Packet Formats

   o  A series of multiprecision integers comprising the key material:

      *  a multiprecision integer (MPI) of RSA public modulus n;

      *  an MPI of RSA public encryption exponent e.

   A version 5 packet contains:

   o  A one-byte version number (5).

   o  A four-byte number denoting the time that the key was created.

   o  A one-byte number denoting the public-key algorithm of this key.

   o  A four-byte scalar byte count for the following key material.

   o  A series of values comprising the key material.  This is
      algorithm-specific and described in section XXXX.


5.6.  Algorithm-specific Parts of Keys

   The public and secret key format specifies algorithm-specific parts
   of a key.  The following sections describe them in detail.

5.6.1.  Algorithm-Specific Part for RSA Keys

   The public key is this series of multiprecision integers:

   o  MPI of RSA public modulus n;

   o  MPI of RSA public encryption exponent e.

   The secret key is this series of multiprecision integers:

   o  MPI of RSA secret exponent d;

   o  MPI of RSA secret prime value p;

   o  MPI of RSA secret prime value q (p < q);

   o  MPI of u, the multiplicative inverse of p, mod q.

5.6.5.  Algorithm-Specific Part for EdDSA Keys

   The public key is this series of values:

   o  a variable-length field containing a curve OID, formatted as
      follows:

      *  a one-byte size of the following field; values 0 and 0xFF are
         reserved for future extensions,

      *  the bytes representing a curve OID, defined in section
         NN{FIXME};

   o  a MPI of an EC point representing a public key Q as described
      under EdDSA Point Format below.

   The secret key is this single multiprecision integer:

   o  MPI of an integer representing the secret key, which is a scalar
      of the public EC point.

5.6.6.  Algorithm-Specific Part for ECDH Keys

   The public key is this series of values:

   o  a variable-length field containing a curve OID, formatted as
      follows:

      *  a one-byte size of the following field; values 0 and 0xFF are
         reserved for future extensions,

      *  the bytes representing a curve OID, defined in
         Section 11{FIXME};

   o  a MPI of an EC point representing a public key;

   o  a variable-length field containing KDF parameters, formatted as
      follows:

      *  a one-byte size of the following fields; values 0 and 0xff are
         reserved for future extensions;

      *  a one-byte value 1, reserved for future extensions;

      *  a one-byte hash function ID used with a KDF;

      *  a one-byte algorithm ID for the symmetric algorithm used to
         wrap the symmetric key used for the message encryption; see
         Section 8 for details.

   Observe that an ECDH public key is composed of the same sequence of
   fields that define an ECDSA key, plus the KDF parameters field.

   The secret key is this single multiprecision integer:

   o  MPI of an integer representing the secret key, which is a scalar
      of the public EC point.


5.12.  {5.11} User ID Packet (Tag 13)

   A User ID packet consists of UTF-8 text that is intended to represent
   the name and email address of the key holder.  By convention, it
   includes an RFC 2822 [RFC2822] mail name-addr, but there are no



   restrictions on its content.  The packet length in the header
   specifies the length of the User ID.


9.  {9} Constants

   This section describes the constants used in OpenPGP.

   Note that these tables are not exhaustive lists; an implementation
   MAY implement an algorithm not on these lists, so long as the
   algorithm numbers are chosen from the private or experimental
   algorithm range.

   See the section "Notes on Algorithms" below for more discussion of
   the algorithms.

9.1.  {9.1} Public-Key Algorithms

    +-----------+----------------------------------------------------+
    |        ID | Algorithm                                          |
    +-----------+----------------------------------------------------+
    |         1 | RSA (Encrypt or Sign) [HAC]                        |
    |        18 | ECDH public key algorithm                          |
    |        19 | ECDSA public key algorithm [FIPS186]               |
    |        22 | EdDSA [I-D.irtf-cfrg-eddsa]                        |
    |        23 | Reserved for AEDH                                  |
    |        24 | Reserved for AEDSA                                 |
    +-----------+----------------------------------------------------+

   Implementations MUST implement RSA (1) and ECDSA (19) for signatures,
   and RSA (1) and ECDH (18) for encryption.  Implementations SHOULD
   implement EdDSA (22) keys.

   A compatible specification of ECDSA is given in [RFC6090] as "KT-I
   Signatures" and in [SEC1]; ECDH is defined in Section 13.5 this
   document.

9.2.  ECC Curve OID

   The parameter curve OID is an array of bytes that define a named
   curve.  The table below specifies the exact sequence of bytes for
   each named curve referenced in this document:





   +------------------------+-----+------------------+-----------------+
   | ASN.1 Object           | OID | Curve OID bytes  | Curve name      |
   | Identifier             | len | in hexadecimal   |                 |
   |                        |     | representation   |                 |
   +------------------------+-----+------------------+-----------------+
   | 1.2.840.10045.3.1.7    | 8   | 2A 86 48 CE 3D   | NIST P-256      |
   |                        |     | 03 01 07         |                 |
   | 1.3.132.0.34           | 5   | 2B 81 04 00 22   | NIST P-384      |
   | 1.3.132.0.35           | 5   | 2B 81 04 00 23   | NIST P-521      |
   | 1.3.36.3.3.2.8.1.1.7   | 9   | 2B 24 03 03 02   | brainpoolP256r1 |
   |                        |     | 08 01 01 07      |                 |
   | 1.3.36.3.3.2.8.1.1.13  | 9   | 2B 24 03 03 02   | brainpoolP512r1 |
   |                        |     | 08 01 01 0D      |                 |
   | 1.3.6.1.4.1.11591.15.1 | 9   | 2B 06 01 04 01   | Ed25519         |
   |                        |     | DA 47 0F 01      |                 |
   | 1.3.6.1.4.1.3029.1.5.1 | 10  | 2B 06 01 04 01   | Curve25519      |
   |                        |     | 97 55 01 05 01   |                 |
   +------------------------+-----+------------------+-----------------+

   The sequence of bytes in the third column is the result of applying
   the Distinguished Encoding Rules (DER) to the ASN.1 Object Identifier
   with subsequent truncation.  The truncation removes the two fields of
   encoded Object Identifier.  The first omitted field is one byte
   representing the Object Identifier tag, and the second omitted field
   is the length of the Object Identifier body.  For example, the
   complete ASN.1 DER encoding for the NIST P-256 curve OID is "06 08 2A
   86 48 CE 3D 03 01 07", from which the first entry in the table above
   is constructed by omitting the first two bytes.  Only the truncated
   sequence of bytes is the valid representation of a curve OID.

9.3.  {9.2} Symmetric-Key Algorithms

       +-----------+-----------------------------------------------+
       |        ID | Algorithm                                     |
       +-----------+-----------------------------------------------+
       |         9 | AES with 256-bit key                          |
       +-----------+-----------------------------------------------+

   Implementations MUST use AES-256.

9.5.  {9.4} Hash Algorithms

      +-----------+---------------------------------+--------------+
      |        ID | Algorithm                       | Text Name    |
      +-----------+---------------------------------+--------------+
      |         8 | SHA2-256 [FIPS180]              | "SHA256"     |
      +-----------+---------------------------------+--------------+

9.6.  AEAD Algorithms

              +-----------+---------------------------------+
              |        ID | Algorithm                       |
              +-----------+---------------------------------+
              |         1 | EAX [EAX]                       |
              +-----------+---------------------------------+

10.2.3.  {10.2.2} New Signature Subpackets

   OpenPGP signatures contain a mechanism for signed (or unsigned) data
   to be added to them for a variety of purposes in the Signature
   subpackets as discussed in Section 5.2.3.1.  This specification
   creates a registry of Signature subpacket types.  The registry
   includes the Signature subpacket type, the name of the subpacket, and
   a reference to the defining specification.  The initial values for
   this registry can be found in Section 5.2.3.1.  Adding a new
   Signature subpacket MUST be done through the IETF CONSENSUS method,
   as described in [RFC2434].

10.2.3.1.  {10.2.2.1} Signature Notation Data Subpackets

   OpenPGP signatures further contain a mechanism for extensions in
   signatures.  These are the Notation Data subpackets, which contain a
   key/value pair.  Notations contain a user space that is completely
   unmanaged and an IETF space.

   This specification creates a registry of Signature Notation Data
   types.  The registry includes the Signature Notation Data type, the
   name of the Signature Notation Data, its allowed values, and a
   reference to the defining specification.  The initial values for this
   registry can be found in Section 5.2.3.16.  Adding a new Signature
   Notation Data subpacket MUST be done through the EXPERT REVIEW
   method, as described in [RFC2434].

   This document requests IANA register the following Signature Notation
   Data types:















10.3.1.  {10.3.1} Public-Key Algorithms

   OpenPGP specifies a number of public-key algorithms.  This
   specification creates a registry of public-key algorithm identifiers.
   The registry includes the algorithm name, its key sizes and
   parameters, and a reference to the defining specification.  The
   initial values for this registry can be found in Section 9.  Adding a
   new public-key algorithm MUST be done through the IETF CONSENSUS
   method, as described in [RFC2434].

   This document requests IANA register the following public-key
   algorithm:

            +-----+-----------------------------+------------+
            | ID  | Algorithm                   | Reference  |
            +-----+-----------------------------+------------+
            | 22  | EdDSA public key algorithm  | This doc   |
            | 23  | Reserved for AEDH           | This doc   |
            | 24  | Reserved for AEDSA          | This doc   |
            +-----+-----------------------------+------------+

   [Notes to RFC-Editor: Please remove the table above on publication.
   It is desirable not to reuse old or reserved algorithms because some
   existing tools might print a wrong description.  A higher number is
   also an indication for a newer algorithm.  As of now 22 is the next
   free number.]

10.3.3.  {10.3.3} Hash Algorithms

   OpenPGP specifies a number of hash algorithms.  This specification
   creates a registry of hash algorithm identifiers.  The registry
   includes the algorithm name, a text representation of that name, its
   block size, an OID hash prefix, and a reference to the defining
   specification.  The initial values for this registry can be found in
   Section 9 for the algorithm identifiers and text names, and



   Section 5.2.2 for the OIDs and expanded signature prefixes.  Adding a
   new hash algorithm MUST be done through the IETF CONSENSUS method, as
   described in [RFC2434].

   This document requests IANA register the following hash algorithms:

                     +-----+------------+------------+
                     | ID  | Algorithm  | Reference  |
                     +-----+------------+------------+
                     | 12  | SHA3-256   | This doc   |
                     | 13  | Reserved   |            |
                     | 14  | SHA3-512   | This doc   |
                     +-----+------------+------------+

   [Notes to RFC-Editor: Please remove the table above on publication.
   It is desirable not to reuse old or reserved algorithms because some
   existing tools might print a wrong description.  The ID 13 has been
   reserved so that the SHA3 algorithm IDs align nicely with their SHA2
   counterparts.]

11.  {11} Packet Composition

   OpenPGP packets are assembled into sequences in order to create
   messages and to transfer keys.  Not all possible packet sequences are
   meaningful and correct.  This section describes the rules for how
   packets should be placed into sequences.

11.1.  {11.1} Transferable Public Keys

   OpenPGP users may transfer public keys.  The essential elements of a
   transferable public key are as follows:

   o  One Public-Key packet

   o  Zero or more revocation signatures

   o  Zero or more User ID packets




   o  After each User ID packet, zero or more Signature packets
      (certifications)

   o  Zero or more User Attribute packets

   o  After each User Attribute packet, zero or more Signature packets
      (certifications)

   o  Zero or more Subkey packets

   o  After each Subkey packet, one Signature packet, plus optionally a
      revocation

   The Public-Key packet occurs first.  Each of the following User ID
   packets provides the identity of the owner of this public key.  If
   there are multiple User ID packets, this corresponds to multiple
   means of identifying the same unique individual user; for example, a
   user may have more than one email address, and construct a User ID
   for each one.

   Immediately following each User ID packet, there are zero or more
   Signature packets.  Each Signature packet is calculated on the
   immediately preceding User ID packet and the initial Public-Key
   packet.  The signature serves to certify the corresponding public key
   and User ID.  In effect, the signer is testifying to his or her
   belief that this public key belongs to the user identified by this
   User ID.

   Within the same section as the User ID packets, there are zero or
   more User Attribute packets.  Like the User ID packets, a User
   Attribute packet is followed by zero or more Signature packets
   calculated on the immediately preceding User Attribute packet and the
   initial Public-Key packet.

   User Attribute packets and User ID packets may be freely intermixed
   in this section, so long as the signatures that follow them are
   maintained on the proper User Attribute or User ID packet.

   After the User ID packet or Attribute packet, there may be zero or
   more Subkey packets.  In general, subkeys are provided in cases where
   the top-level public key is a signature-only key.  However, any V4
   key may have subkeys, and the subkeys may be encryption-only keys,
   signature-only keys, or general-purpose keys.

   Each Subkey packet MUST be followed by one Signature packet, which
   should be a subkey binding signature issued by the top-level key.
   For subkeys that can issue signatures, the subkey binding signature



   MUST contain an Embedded Signature subpacket with a primary key
   binding signature (0x19) issued by the subkey on the top-level key.

   Subkey and Key packets may each be followed by a revocation Signature
   packet to indicate that the key is revoked.  Revocation signatures
   are only accepted if they are issued by the key itself, or by a key
   that is authorized to issue revocations via a Revocation Key
   subpacket in a self-signature by the top-level key.

   Transferable public-key packet sequences may be concatenated to allow
   transferring multiple public keys in one operation.

12.  {12} Enhanced Key Formats

12.1.  {12.1} Key Structures

   The format of an OpenPGP V4 key that uses multiple public keys is
   similar except that the other keys are added to the end as "subkeys"
   of the primary key.

   Primary-Key
      [Revocation Self Signature]
      [Direct Key Signature...]
      [User ID [Signature ...] ...]
      [User Attribute [Signature ...] ...]
      [[Subkey [Binding-Signature-Revocation]
              Primary-Key-Binding-Signature] ...]

   A subkey always has a single signature after it that is issued using
   the primary key to tie the two keys together.  Subkeys that can
   issue signatures MUST have a V4 binding signature due to the REQUIRED
   embedded primary key binding signature.

   In the above diagram, if the binding signature of a subkey has been
   revoked, the revoked key may be removed, leaving only one key.

   In a V4 key, the primary key SHOULD be a key capable of
   certification.  There are cases, such as device certificates, where
   the primary key may not be capable of certification.  A primary key
   capable of making signatures SHOULD be accompanied by either a
   certification signature (on a User ID or User Attribute) or a
   signature directly on the key.

   Implementations SHOULD accept encryption-only primary keys without a
   signature.  It also SHOULD allow importing any key accompanied either
   by a certification signature or a signature on itself.  It MAY accept
   signature-capable primary keys without an accompanying signature.

   It is also possible to have a signature-only subkey.  This permits a
   primary key that collects certifications (key signatures), but is
   used only for certifying subkeys that are used for encryption and
   signatures.




12.2.  {12.2} Key IDs and Fingerprints

   A V5 fingerprint is the 256-bit SHA2-256 hash of the byte 0x9A,
   followed by the four-byte packet length, followed by the entire
   Public-Key packet starting with the version field.  The Key ID is the
   high-order 64 bits of the fingerprint.  Here are the fields of the
   hash material, with the example of a DSA key:








  a.1) 0x9A (1 byte)

  a.2) four-byte scalar byte count of (b)-(f)

  b) version number = 5 (1 byte);

  c) timestamp of key creation (4 bytes);

  d) algorithm (1 byte): 17 = DSA (example);

  e) four-byte scalar byte count for the following key material;

  f) algorithm-specific fields.

  Algorithm-Specific Fields for DSA keys (example):

  f.1) MPI of DSA prime p;

  f.2) MPI of DSA group order q (q is a prime divisor of p-1);

  f.3) MPI of DSA group generator g;

  f.4) MPI of DSA public-key value y (= g\*\*x mod p where x is secret).

   Note that it is possible for there to be collisions of Key IDs -- two
   different keys with the same Key ID.  Note that there is a much
   smaller, but still non-zero, probability that two different keys have
   the same fingerprint.

   Finally, the Key ID and fingerprint of a subkey are calculated in
   the same way as for a primary key, including the 0x9A (V5 key) as
   the first byte.

13.  Elliptic Curve Cryptography

   This section descripes algorithms and parameters used with Elliptic
   Curve Cryptography (ECC) keys.  A thorough introduction to ECC can be
   found in [KOBLITZ].








13.1.  Supported ECC Curves

   This document references five named prime field curves, defined in
   [FIPS186] as "Curve P-256", "Curve P-384", and "Curve P-521"; and
   defined in [RFC5639] as "brainpoolP256r1", and "brainpoolP512r1".
   Further curve "Curve25519", defined in [RFC7748] is referenced for
   use with Ed25519 (EdDSA signing) and X25519 (encryption).

   The named curves are referenced as a sequence of bytes in this
   document, called throughout, curve OID.  Section 9.2 describes in
   detail how this sequence of bytes is formed.

13.2.  ECDSA and ECDH Conversion Primitives

   This document defines the uncompressed point format for ECDSA and
   ECDH and a custom compression format for certain curves.  The point
   is encoded in the Multiprecision Integer (MPI) format.

   For an uncompressed point the content of the MPI is:

   B = 04 || x || y

   where x and y are coordinates of the point P = (x, y), each encoded
   in the big-endian format and zero-padded to the adjusted underlying
   field size.  The adjusted underlying field size is the underlying
   field size that is rounded up to the nearest 8-bit boundary.  This
   encoding is compatible with the definition given in [SEC1].

   For a custom compressed point the content of the MPI is:

   B = 40 || x

   where x is the x coordinate of the point P encoded to the rules
   defined for the specified curve.  This format is used for ECDH keys
   based on curves expressed in Montgomery form.

   Therefore, the exact size of the MPI payload is 515 bits for "Curve
   P-256", 771 for "Curve P-384", 1059 for "Curve P-521", and 263 for
   Curve25519.

   Even though the zero point, also called the point at infinity, may
   occur as a result of arithmetic operations on points of an elliptic
   curve, it SHALL NOT appear in data structures defined in this
   document.

   If other conversion methods are defined in the future, a compliant
   application MUST NOT use a new format when in doubt that any
   recipient can support it.  Consider, for example, that while both the



   public key and the per-recipient ECDH data structure, respectively
   defined in Sections 9{FIXME} and 10{FIXME}, contain an encoded point
   field, the format changes to the field in Section 10{FIXME} only
   affect a given recipient of a given message.

13.3.  EdDSA Point Format

   The EdDSA algorithm defines a specific point compression format.  To
   indicate the use of this compression format and to make sure that the
   key can be represented in the Multiprecision Integer (MPI) format the
   byte string specifying the point is prefixed with the byte 0x40.
   This encoding is an extension of the encoding given in [SEC1] which
   uses 0x04 to indicate an uncompressed point.

   For example, the length of a public key for the curve Ed25519 is 263
   bit: 7 bit to represent the 0x40 prefix byte and 32 bytes for the
   native value of the public key.

13.4.  Key Derivation Function

   A key derivation function (KDF) is necessary to implement the EC
   encryption.  The Concatenation Key Derivation Function (Approved
   Alternative 1) [SP800-56A] with the KDF hash function that is
   SHA2-256 [FIPS180] or stronger is REQUIRED.  See Section 12{FIXME}
   for the details regarding the choice of the hash function.

   For convenience, the synopsis of the encoding method is given below
   with significant simplifications attributable to the restricted
   choice of hash functions in this document.  However, [SP800-56A] is
   the normative source of the definition.

   //   Implements KDF( X, oBits, Param );
   //   Input: point X = (x,y)
   //   oBits - the desired size of output
   //   hBits - the size of output of hash function Hash
   //   Param - bytes representing the parameters
   //   Assumes that oBits <= hBits
   // Convert the point X to the byte string, see section 6{FIXME}:
   //   ZB' = 04 || x || y
   // and extract the x portion from ZB'
   ZB = x;
   MB = Hash ( 00 || 00 || 00 || 01 || ZB || Param );
   return oBits leftmost bits of MB.

   Note that ZB in the KDF description above is the compact
   representation of X, defined in Section 4.2 of [RFC6090].





13.5.  EC DH Algorithm (ECDH)

   The method is a combination of an ECC Diffie-Hellman method to
   establish a shared secret, a key derivation method to process the
   shared secret into a derived key, and a key wrapping method that uses
   the derived key to protect a session key used to encrypt a message.

   The One-Pass Diffie-Hellman method C(1, 1, ECC CDH) [SP800-56A] MUST
   be implemented with the following restrictions: the ECC CDH primitive
   employed by this method is modified to always assume the cofactor as
   1, the KDF specified in Section 7 is used, and the KDF parameters
   specified below are used.

   The KDF parameters are encoded as a concatenation of the following 5
   variable-length and fixed-length fields, compatible with the
   definition of the OtherInfo bitstring [SP800-56A]:

   o  a variable-length field containing a curve OID, formatted as
      follows:

      *  a one-byte size of the following field

      *  the bytes representing a curve OID, defined in Section 11

   o  a one-byte public key algorithm ID defined in Section 5

   o  a variable-length field containing KDF parameters, identical to
      the corresponding field in the ECDH public key, formatted as
      follows:

      *  a one-byte size of the following fields; values 0 and 0xff are
         reserved for future extensions

      *  a one-byte value 01, reserved for future extensions

      *  a one-byte hash function ID used with the KDF

      *  a one-byte algorithm ID for the symmetric algorithm used to
         wrap the symmetric key for message encryption; see Section 8
         for details

   o  20 bytes representing the UTF-8 encoding of the string "Anonymous
      Sender ", which is the byte sequence 41 6E 6F 6E 79 6D 6F 75 73
      20 53 65 6E 64 65 72 20 20 20 20

   o  20 bytes representing a recipient encryption subkey or a master
      key fingerprint, identifying the key material that is needed for




      the decryption.  For version 5 keys the 20 leftmost bytes of the
      fingerprint are used.

   The size of the KDF parameters sequence, defined above, is either 54
   for the NIST curve P-256, 51 for the curves P-384 and P-521, or 56
   for Curve25519.

   The key wrapping method is described in [RFC3394].  KDF produces a
   symmetric key that is used as a key-encryption key (KEK) as specified
   in [RFC3394].  Refer to Section 13{FIXME} for the details regarding
   the choice of the KEK algorithm, which SHOULD be one of three AES
   algorithms.  Key wrapping and unwrapping is performed with the
   default initial value of [RFC3394].

   The input to the key wrapping method is the value "m" derived from
   the session key, as described in Section 5.1{FIXME}, "Public-Key
   Encrypted Session Key Packets (Tag 1)", except that the PKCS #1.5
   padding step is omitted.  The result is padded using the method
   described in [PKCS5] to the 8-byte granularity.  For example, the
   following AES-256 session key, in which 32 bytes are denoted from k0
   to k31, is composed to form the following 40 byte sequence:

   09 k0 k1 ... k31 c0 c1 05 05 05 05 05

   The bytes c0 and c1 above denote the checksum.  This encoding allows
   the sender to obfuscate the size of the symmetric encryption key used
   to encrypt the data.  For example, assuming that an AES algorithm is
   used for the session key, the sender MAY use 21, 13, and 5 bytes of
   padding for AES-128, AES-192, and AES-256, respectively, to provide
   the same number of bytes, 40 total, as an input to the key wrapping
   method.

   The output of the method consists of two fields.  The first field is
   the MPI containing the ephemeral key used to establish the shared
   secret.  The second field is composed of the following two fields:

   o  a one-byte encoding the size in bytes of the result of the key
      wrapping method; the value 255 is reserved for future extensions;

   o  up to 254 bytes representing the result of the key wrapping
      method, applied to the 8-byte padded session key, as described
      above.

   Note that for session key sizes 128, 192, and 256 bits, the size of
   the result of the key wrapping method is, respectively, 32, 40, and
   48 bytes, unless the size obfuscation is used.





   For convenience, the synopsis of the encoding method is given below;
   however, this section, [SP800-56A], and [RFC3394] are the normative
   sources of the definition.

   Obtain the authenticated recipient public key R
   Generate an ephemeral key pair {v, V=vG}
   Compute the shared point S = vR;
   m = symm_alg_ID || session key || checksum || pkcs5_padding;
   curve_OID_len = (byte)len(curve_OID);
   Param = curve_OID_len || curve_OID || public_key_alg_ID || 03
   || 01 || KDF_hash_ID || KEK_alg_ID for AESKeyWrap || "Anonymous
   Sender    " || recipient_fingerprint;
   Z_len = the key size for the KEK_alg_ID used with AESKeyWrap
   Compute Z = KDF( S, Z_len, Param );
   Compute C = AESKeyWrap( Z, m ) as per [RFC3394]
   VB = convert point V to the byte string
   Output (MPI(VB) || len(C) || C).

   The decryption is the inverse of the method given.  Note that the
   recipient obtains the shared secret by calculating

   S = rV = rvG, where (r,R) is the recipient's key pair.

   Consistent with Section 5.13{FIXME}, "Sym.  Encrypted Integrity
   Protected Data Packet (Tag 18)", a Modification Detection Code (MDC)
   MUST be used anytime the symmetric key is protected by ECDH.

14.  {13} Notes on Algorithms

14.1.  {13.1} PKCS#1 Encoding in OpenPGP

   This standard makes use of the PKCS#1 functions EME-PKCS1-v1_5 and
   EMSA-PKCS1-v1_5.  However, the calling conventions of these functions
   has changed in the past.  To avoid potential confusion and
   interoperability problems, we are including local copies in this
   document, adapted from those in PKCS#1 v2.1 [RFC3447].  RFC 3447
   should be treated as the ultimate authority on PKCS#1 for OpenPGP.
   Nonetheless, we believe that there is value in having a self-
   contained document that avoids problems in the future with needed
   changes in the conventions.

14.1.1.  {13.1.1} EME-PKCS1-v1_5-ENCODE

   Input:

   k = the length in bytes of the key modulus

   M = message to be encoded, an byte string of length mLen, where mLen
   \<= k - 11

   Output:

   EM = encoded message, an byte string of length k

   Error: "message too long"

    1. Length checking: If mLen > k - 11, output "message too long"
       and stop.

    2. Generate an byte string PS of length k - mLen - 3 consisting
       of pseudo-randomly generated nonzero bytes.  The length of PS
       will be at least eight bytes.

    3. Concatenate PS, the message M, and other padding to form an
       encoded message EM of length k bytes as

       EM = 0x00 || 0x02 || PS || 0x00 || M.

    4. Output EM.

14.1.2.  {13.1.2} EME-PKCS1-v1_5-DECODE

   Input:

   EM = encoded message, an byte string

   Output:

   M = message, an byte string

   Error: "decryption error"

   To decode an EME-PKCS1_v1_5 message, separate the encoded message EM
   into an byte string PS consisting of nonzero bytes and a message M
   as follows

    EM = 0x00 || 0x02 || PS || 0x00 || M.

   If the first byte of EM does not have hexadecimal value 0x00, if the
   second byte of EM does not have hexadecimal value 0x02, if there is
   no byte with hexadecimal value 0x00 to separate PS from M, or if the
   length of PS is less than 8 bytes, output "decryption error" and
   stop.  See also the security note in Section 14 regarding differences
   in reporting between a decryption error and a padding error.

14.1.3.  {13.1.3} EMSA-PKCS1-v1_5

   This encoding method is deterministic and only has an encoding
   operation.

   Option:

   Hash - a hash function in which hLen denotes the length in bytes
          of the hash function output

   Input:

   M = message to be encoded

   emLen = intended length in bytes of the encoded message, at least
        tLen + 11, where tLen is the byte length of the DER encoding
        T of a certain value computed during the encoding operation

   Output:

   EM = encoded message, an byte string of length emLen

   Errors: "message too long";
           "intended encoded message length too short"

   Steps:

    1. Apply the hash function to the message M to produce a hash
       value H:

       H = Hash(M).

       If the hash function outputs "message too long," output
       "message too long" and stop.

    2. Using the list in Section 5.2.2, produce an ASN.1 DER value
       for the hash function used.  Let T be the full hash prefix
       from Section 5.2.2, and let tLen be the length in bytes of T.

    3. If emLen < tLen + 11, output "intended encoded message length
       too short" and stop.

    4. Generate an byte string PS consisting of emLen - tLen - 3
       bytes with hexadecimal value 0xFF.  The length of PS will be
       at least 8 bytes.

    5. Concatenate PS, the hash prefix T, and other padding to form
       the encoded message EM as

           EM = 0x00 || 0x01 || PS || 0x00 || T.

    6. Output EM.

14.8.  EdDSA

   Although the EdDSA algorithm allows arbitrary data as input, its use
   with OpenPGP requires that a digest of the message is used as input
   (pre-hashed).  See section XXXXX, "Computing Signatures" for details.
   Truncation of the resulting digest is never applied; the resulting
   digest value is used verbatim as input to the EdDSA algorithm.

Appendix B.  ECC Point compression flag bytes

   This specification introduces the new flag byte 0x40 to indicate the
   point compression format.  The value has been chosen so that the high
   bit is not cleared and thus to avoid accidental sign extension.  Two
   other values might also be interesting for other ECC specifications:

     Flag  Description
     ----  -----------
     0x04  Standard flag for uncompressed format
     0x40  Native point format of the curve follows
     0x41  Only X coordinate follows.
     0x42  Only Y coordinate follows.



Key signature subpackets:

   0x02 0x0b 0x09 (AES256)
   0x02 0x15 0x08 (SHA2-256)
   0x02 0x16 0x00 (no compression)

   0x02 0x09 0x01 (for primary user id)
