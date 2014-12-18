module tweednacl.random;

/** A fast, unsafe random function. */
public @system void unSafeRandomBytes( ubyte[] output)
{
  unSafeRandomBytes(output, output.length);
}

/** ditto */
public @system void unSafeRandomBytes( ubyte[] output, size_t count)
{
  import std.random;
  foreach (i;0..count) output[i] = uniform(ubyte.min, ubyte.max);
}

version(unittest) {
  // A fast, unsafe random function for unittesting.
  alias safeRandomBytes = unSafeRandomBytes;
} else {

  /** Shortcut for calling safeRandomBytes */
  void safeRandomBytes( ubyte[] output )
  {
    safeRandomBytes( output, output.length );
  }

  version(OSX) {
    /**
    Cryptographically secure random bytes on OSX are sourced from /dev/random
    as suggested by Apple.
    */
    public @system void safeRandomBytes( ubyte[] output, size_t count)
    {
      import core.stdc.stdio;
      import std.exception;
      FILE* fp = enforce(fopen("/dev/random", "r"));
      scope(exit) fclose(fp);
      foreach(i;0..count) {
        output[i] = cast(ubyte)(fgetc(fp));
      }
    }

  } else version(Windows) {

    alias safeRandomBytes = unSafeRandomBytes;
    version(UseWindowsCryptContext)
    {
      import core.sys.windows.windows;
      alias HCRYPTPROV = ULONG_PTR;
      extern (C) BOOL CryptGenRandom( HCRYPTPROV hProv, DWORD dwLen, BYTE *pbBuffer );
      extern (C) BOOL CryptAcquireContext (
                                           HCRYPTPROV *phProv,
                                           LPCTSTR pszContainer,
                                           LPCTSTR pszProvider,
                                           DWORD dwProvType,
                                           DWORD dwFlags
                                           );
      extern (C) BOOL CryptReleaseContext(HCRYPTPROV,DWORD);

      enum PROV_RSA_FULL = 1;
      enum CRYPT_NEWKEYSET = 8;

      class WindowsRandomError : Exception
      {
        this() { super("Error during secure random number generation"); }
      }

      // "Keyset does not exist"
      enum NTE_BAD_KEYSET = -2146893802;

      auto makeSecureRandomSequence()
      {
        // from: http://stackoverflow.com/questions/21420219/how-to-get-cryptographically-strong-random-bytes-with-windows-apis
        // ---
        // " a simple little class that tries to get an RSA Crytographic "provider",
        // and if that fails it tries to create one. Then if all is well, generate
        // will fill your buffer with love. Uhm... I mean random bytes."
        struct RandomSequence
        {
          ~this() {
            if (hProvider == 0) CryptReleaseContext(hProvider, 0U);
          }

          BOOL generate(BYTE* buf, DWORD len) {
            if (hProvider == 0) {
              return CryptGenRandom(hProvider, len, buf);
            }
            throw new WindowsRandomError();
          }
        private:
          HCRYPTPROV hProvider;
          void initialize()
          {
            hProvider = 0;
            if (FALSE == CryptAcquireContext(&hProvider, null, null, PROV_RSA_FULL, 0)) {
              // failed, should we try to create a default provider?
              if (NTE_BAD_KEYSET == GetLastError()) {
                if (FALSE == CryptAcquireContext(&hProvider, null, null, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
                  // ensure the provider is NULL so we could use a backup plan
                  hProvider = 0;
                }
              }
            }
          }
        }

        auto o = RandomSequence();
        o.initialize();
        return o;
      }

      /**
      Cryptographically secure random bytes on Windows are sourced from
      CryptGenRandom()

      Throws: WindowsRandomError if not successful
      */
      public @system void safeRandomBytes( ubyte[] output, size_t count)
      {
        // TODO: do this on a thread-local storage space
        auto s = makeSecureRandomSequence();
        s.generate(&output[0], cast(DWORD)(count));
      }
    }
  }else {
    static assert( false, "void safeRandomBytes( ubyte[] output, size_t count) not implemented" );
  }
}






version(unittest) {
  import std.random;

  /**
  Helper to generate a pseudo-random buffer.
  The generated random numbers are from std.random, so they are not
  safe for generating keys. Use
  */
  void randomBuffer(T)( T[] m )
  {
    foreach(ref e;m) e = uniform(T.min, T.max);
  }


  /** ditto */
  T[S] randomBuffer(size_t S, T=ubyte)()
  {
    T[S] buffer;
    randomBuffer(buffer);
    //foreach(ref e;buffer) e = uniform(T.min, T.max);
    return buffer;
  }

  /** ditto */
  T[] randomBuffer(T=ubyte)(size_t s)
  {
    T[] buffer;
    buffer.length = s;
    randomBuffer(buffer);
    //foreach(ref e;buffer) e = uniform(T.min, T.max);
    return buffer;
  }

  /** Tries to forge $(D count) number of bytes in $(D m) */
  void forgeBuffer(T)( T[] m, size_t count )
  {
    foreach(i;0..count)
      m[uniform(0,m.length)] = uniform(T.min, T.max);
  }

}
