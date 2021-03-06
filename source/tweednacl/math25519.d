module tweednacl.math25519;

package:

import tweednacl.basics : gf,crypto_verify_32;


pure nothrow @safe @nogc void set25519(out gf r, ref const gf a)
{
  foreach(i;0..16) r[i]=a[i];
}

pure nothrow @safe @nogc void sel25519(ref gf p, ref gf q,long b)
{
  long t,c=~(b-1);
  foreach(i;0..16) {
    t= c&(p[i]^q[i]);
    p[i]^=t;
    q[i]^=t;
  }
}

pure nothrow @safe @nogc void pack25519(ref ubyte[32] o, ref const gf n)
{
  int b;
  gf m,t;
  foreach(i;0..16) t[i]=n[i];
  car25519(t);
  car25519(t);
  car25519(t);
  foreach(j;0..2) {
    m[0]=t[0]-0xffed;
    foreach(i;1..15) {
      m[i]=t[i]-0xffff-((m[i-1]>>16)&1);
      m[i-1]&=0xffff;
    }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(m[15]>>16)&1;
    m[14]&=0xffff;
    sel25519(t,m,1-b);
  }
  foreach(i;0..16) {
    o[2*i]=t[i]&0xff;
    o[2*i+1]=cast(ubyte)(t[i]>>8);
  }
}

pure nothrow @safe @nogc int neq25519(ref const gf a, ref const gf b)
{
  ubyte[32] c,d;
  pack25519(c,a);
  pack25519(d,b);
  return crypto_verify_32(c,d);
}

pure nothrow @safe @nogc ubyte par25519(ref const gf a)
{
  ubyte d[32];
  pack25519(d,a);
  return d[0]&1;
}

pure nothrow @safe @nogc void unpack25519(ref gf o, ref const ubyte[32] n)
{
  foreach(i;0..16) o[i]=n[2*i]+(long(n[2*i+1])<<8);
  o[15]&=0x7fff;
}

pure nothrow @safe @nogc void A(ref gf o,ref const gf a,ref const gf b)
{
  foreach(i;0..16) o[i]=a[i]+b[i];
}

pure nothrow @safe @nogc void Z(ref gf o,ref const gf a,ref const gf b)
{
  foreach(i;0..16) o[i]=a[i]-b[i];
}

version(TweedNaClUseFastMath25519)
{
  // The M function itself is responsible for most of the workload during
  // public-key signing and encryption.
  //
  // This version simply expands the loops of the Tweet version to use
  // local variables (registers) instead of accessing the input array directly,
  // so the compiler can do its magic.
  //
  // This gives a little speed boost in DMD and about halves the execution time
  // of the complete Ed25519 sigining process in LDC.

  private string genCar25519Body()
  {
    import std.string;
    string[] o;

    foreach(i;0..16)
    {
      o ~= format( "t%s += long(1) << 16;", i,);
      o ~= format( "c = t%s >> 16;", i,);
      o ~= format( "t%s += c - 1 + 37 * (c-1) * (%s == 15);", ((i+1) * (i < 15)), i,);
      o ~= format( "t%s -= c << 16;" , i);
    }
    return o.join("\n");
  }

  private string genCar25519()
  {
    import std.string;
    string[] o;

    foreach(i;0..16) o ~= format("long t%s = o[%s];", i,i);
    o ~= "long c;";
    o ~= genCar25519Body();
    foreach(i;0..16) o ~= format("o[%s]=t%s;", i,i);
    return o.join("\n");
  }

  private string genM()
  {
    import std.string;
    string[] o;

    foreach(i;0..16) o ~= format("long a%s = a[%s];", i,i );
    foreach(i;0..16) o ~= format("long b%s = b[%s];", i,i );

    string[][31] addParts;
    foreach(i;0..16) foreach(j;0..16) addParts[i+j] ~= format( "a[%s] * b[%s]", i,j);
    foreach(i,p;addParts) o ~= format("long t%s = %s;", i, p.join(" + ") );

    foreach(i;0..15) o ~= format("t%s += 38 * t%s;", i, i+16);

    o ~= "long c;";
    foreach(rep;0..2) o ~= genCar25519Body();
    foreach(i;0..16) o ~= format("o[%s]=t%s;", i,i);

    return o.join("\n");
  }

  pure nothrow @safe @nogc void car25519(ref gf o)
  {
    debug(TweedNaClDebugFastMath25519)
      pragma(msg, genCar25519());
    mixin(genCar25519());
  }

  pure nothrow @safe @nogc void M(ref gf o,ref const gf a,ref const gf b)
  {
    debug(TweedNaClDebugFastMath25519)
      pragma(msg, genM());
    mixin(genM());
  }

}
else  // version(TweedNaClUseFastMath25519)
{

  pure nothrow @safe @nogc void car25519(ref gf o)
  {
    long c;
    foreach(i;0..16) {
      o[i]+=(long(1)<<16);
      c=o[i]>>16;
      o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15);
      o[i]-=c<<16;
    }
  }

  /*
     Additions and subtractions do not have to worry about carries or modular
     reduction; they simply turn into a loop that performs 16 cofficient
     additions or subtractions.  Multiplication performs simple "operand
     scanning" schoolbook multiplication in two nested loops. We then reduce
     modulo 2 ^ 256 - 38
  */
  pure nothrow @safe @nogc void M(ref gf o,ref const gf a,ref const gf b)
  {
    long t[31];
    foreach(i;0..16) foreach(j;0..16) t[i+j]+=a[i]*b[j];
    foreach(i;0..15) t[i]+=38*t[i+16];
    foreach(i;0..16) o[i]=t[i];
    car25519(o);
    car25519(o);
  }

}


pure nothrow @safe @nogc void S(ref gf o,ref const gf a)
{
  M(o,a,a);
}

pure nothrow @safe @nogc void inv25519(ref gf o,ref const gf i)
{
  gf c;
  foreach(a;0..16) c[a]=i[a];
  for(int a=253;a>=0;a--) {
    S(c,c);
    if(a!=2&&a!=4) M(c,c,i);
  }
  foreach(a;0..16) o[a]=c[a];
}

pure nothrow @safe @nogc void pow2523(ref gf o,ref const gf i)
{
  gf c;
  foreach(a;0..16) c[a]=i[a];
  for(int a=250;a>=0;a--) {
    S(c,c);
    if(a!=1) M(c,c,i);
  }
  foreach(a;0..16) o[a]=c[a];
}

