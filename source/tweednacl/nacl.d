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
