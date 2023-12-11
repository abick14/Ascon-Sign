using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Pqc.Crypto.SphincsPlus;
using Org.BouncyCastle.Utilities;


namespace Org.BouncyCastle.Pqc.Crypto.AsconSign
{
    internal abstract class AsconSignEngine
    {
        internal bool robust;

        internal int N;

        internal uint WOTS_W;
        internal int WOTS_LOGW;
        internal int WOTS_LEN;
        internal int WOTS_LEN1;
        internal int WOTS_LEN2;

        internal uint D;
        internal int A; // FORS_HEIGHT
        internal int K; // FORS_TREES
        internal uint FH; // FULL_HEIGHT
        internal uint H_PRIME; // H / D

        internal uint T; // T = 1 << A

        internal AsconSignEngine(bool robust, int n, uint w, uint d, int a, int k, uint h)
        {
            this.N = n;

            /* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
            if (w == 16)
            {
                WOTS_LOGW = 4;
                WOTS_LEN1 = (8 * N / WOTS_LOGW);
                if (N <= 8)
                {
                    WOTS_LEN2 = 2;
                }
                else if (N <= 136)
                {
                    WOTS_LEN2 = 3;
                }
                else if (N <= 256)
                {
                    WOTS_LEN2 = 4;
                }
                else
                {
                    throw new ArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
                }
            }
            else if (w == 256)
            {
                WOTS_LOGW = 8;
                WOTS_LEN1 = (8 * N / WOTS_LOGW);
                if (N <= 1)
                {
                    WOTS_LEN2 = 1;
                }
                else if (N <= 256)
                {
                    WOTS_LEN2 = 2;
                }
                else
                {
                    throw new ArgumentException("cannot precompute SPX_WOTS_LEN2 for n outside {2, .., 256}");
                }
            }
            else
            {
                throw new ArgumentException("wots_w assumed 16 or 256");
            }

            this.WOTS_W = w;
            this.WOTS_LEN = WOTS_LEN1 + WOTS_LEN2;

            this.robust = robust;
            this.D = d;
            this.A = a;
            this.K = k;
            this.FH = h;
            this.H_PRIME = (h / d);
            this.T = 1U << a;
        }

        public abstract void Init(byte[] pkSeed);

        public abstract byte[] F(byte[] pkSeed, Adrs adrs, byte[] m1);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public abstract void F(byte[] pkSeed, Adrs adrs, Span<byte> m1);
#endif

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public abstract void H(byte[] pkSeed, Adrs adrs, byte[] m1, byte[] m2, Span<byte> output);
#else
        public abstract void H(byte[] pkSeed, Adrs adrs, byte[] m1, byte[] m2, byte[] output);
#endif

        public abstract IndexedDigest H_msg(byte[] prf, byte[] pkSeed, byte[] pkRoot, byte[] message);

#if NETCOREAPP2_1_OR_GREATER || NETSTANDARD2_1_OR_GREATER
        public abstract void T_l(byte[] pkSeed, Adrs adrs, byte[] m, Span<byte> output);
#else
        public abstract void T_l(byte[] pkSeed, Adrs adrs, byte[] m, byte[] output);
#endif

        public abstract void PRF(byte[] skSeed, Adrs adrs, byte[] prf, int prfOff);

        public abstract byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message);




        internal class AsconSign : AsconSignEngine
        {
            private AsconDigest treeDigest;
            private AsconDigest maskDigest;
            private AsconXof asconXof;
            private AsconDigest.AsconParameters asconParameters;
            private AsconXof.AsconParameters asconParametersXof;
            public AsconSign(bool robust, int n, uint w, uint d, int a, int k, uint h) : base(robust, n, w, d, a, k, h)
            {

                //how would we actually pass values for the parameters? or get them to say the least
                //I probably need two differnt ones, one for Ascon and AsconXof and then a separate for the A's
                this.treeDigest = new AsconDigest(asconParameters);
                this.maskDigest = new AsconDigest(asconParameters);
                this.asconXof = new AsconXof(asconParametersXof);
            }

            public override byte[] F(byte[] pkSeed, Adrs adrs, byte[] m1)
            {

                byte[] mTheta = m1;
                //if (robust)
                //{
                //    mTheta = Bitmask(pkSeed, adrs, m1);
                //}

                byte[] rv = new byte[N];
                treeDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                treeDigest.BlockUpdate(adrs.value, 0, adrs.value.Length);
                treeDigest.BlockUpdate(mTheta, 0, mTheta.Length);
                treeDigest.DoFinal(rv, 0);
                return rv;
            }

            public override void H(byte[] pkSeed, Adrs adrs, byte[] m1, byte[] m2, byte[] output)
            {
                treeDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                treeDigest.BlockUpdate(adrs.value, 0, adrs.value.Length);
                treeDigest.BlockUpdate(m1, 0, m1.Length);
                treeDigest.BlockUpdate(m2, 0, m2.Length);

                //this currently doesn't include the robust version with bitmasks

                treeDigest.DoFinal(output, 0);

            }

            public override IndexedDigest H_msg(byte[] R, byte[] pkSeed, byte[] pkRoot, byte[] message)
            {

                int forsMsgBytes = ((A * K) + 7) / 8;
                uint leafBits = FH / D;
                uint treeBits = FH - leafBits;
                uint leafBytes = (leafBits + 7) / 8;
                uint treeBytes = (treeBits + 7) / 8;
                uint m = (uint)(forsMsgBytes + treeBytes + leafBytes);
                uint m2 = 8 * m;
                byte[] output = new byte[m2];



                asconXof.BlockUpdate(R, 0, R.Length);
                asconXof.BlockUpdate(pkSeed, 0, pkSeed.Length);
                asconXof.BlockUpdate(pkRoot, 0, pkRoot.Length);
                asconXof.BlockUpdate(message, 0, message.Length);
                asconXof.OutputFinal(output, 0, output.Length);

                // tree index
                // currently, only indexes up to 64 bits are supported
                ulong treeIndex = Pack.BE_To_UInt64_Low(output, forsMsgBytes, (int)treeBytes)
                                & ulong.MaxValue >> (64 - (int)treeBits);

                uint leafIndex = Pack.BE_To_UInt32_Low(output, forsMsgBytes + (int)treeBytes, (int)leafBytes)
                               & uint.MaxValue >> (32 - (int)leafBits);

                return new IndexedDigest(treeIndex, leafIndex, Arrays.CopyOfRange(output, 0, forsMsgBytes));
            }

            public override void Init(byte[] pkSeed)
            {
                throw new NotImplementedException();
            }

            public override void PRF(byte[] skSeed, Adrs adrs, byte[] prf, int prfOff)
            {

                //I removed the pkseed input since it doesn't seem to need it from the papers
                treeDigest.BlockUpdate(skSeed, 0, skSeed.Length);
                treeDigest.BlockUpdate(adrs.value, 0, adrs.value.Length);
                //not sure if prf byte is needed
                treeDigest.DoFinal(prf, prfOff);
            }

            public override byte[] PRF_msg(byte[] prf, byte[] randomiser, byte[] message)
            {
                treeDigest.BlockUpdate(prf, 0, prf.Length);
                treeDigest.BlockUpdate(randomiser, 0, randomiser.Length);
                treeDigest.BlockUpdate(message, 0, message.Length);


                //probably don't need N but what do I replace it with?
                byte[] output = new byte[N];
                treeDigest.DoFinal(output, 0);
                return output;
            }

            public override void T_l(byte[] pkSeed, Adrs adrs, byte[] m, byte[] output)
            {
                treeDigest.BlockUpdate(pkSeed, 0, pkSeed.Length);
                treeDigest.BlockUpdate(adrs.value, 0, adrs.value.Length);
                treeDigest.BlockUpdate(m, 0, m.Length);

                treeDigest.DoFinal(output, 0);
            }
        }


    }
}