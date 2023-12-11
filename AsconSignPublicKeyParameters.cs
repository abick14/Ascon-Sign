using System;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Pqc.Crypto.AsconSign
{
    public sealed class AsconSignPublicKeyParameters
        : AsconSignKeyParameters
    {
        private readonly PK m_pk;

        public AsconSignPublicKeyParameters(AsconSignParameters parameters, byte[] pkEncoded)
            : base(false, parameters)
        {
            int n = parameters.N;
            if (pkEncoded.Length != 2 * n)
                throw new ArgumentException("public key encoding does not match parameters", nameof(pkEncoded));

            m_pk = new PK(Arrays.CopyOfRange(pkEncoded, 0, n), Arrays.CopyOfRange(pkEncoded, n, 2 * n));
        }

        internal AsconSignPublicKeyParameters(AsconSignParameters parameters, PK pk)
            : base(false, parameters)
        {
            m_pk = pk;
        }

        public byte[] GetEncoded()
        {
            return Arrays.ConcatenateAll(m_pk.seed, m_pk.root);
        }

        public byte[] GetRoot()
        {
            return Arrays.Clone(m_pk.root);
        }

        public byte[] GetSeed()
        {
            return Arrays.Clone(m_pk.seed);
        }
    }
}
