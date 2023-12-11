using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Pqc.Crypto.AsconSign
{
    public abstract class AsconSignKeyParameters
        : AsymmetricKeyParameter
    {
        private readonly AsconSignParameters m_parameters;

        internal AsconSignKeyParameters(bool isPrivate, AsconSignParameters parameters)
            : base(isPrivate)
        {
            m_parameters = parameters;
        }

        public AsconSignParameters Parameters => m_parameters;
    }
}
