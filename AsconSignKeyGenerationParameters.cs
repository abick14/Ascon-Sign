using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.AsconSign
{
    public sealed class AsconSignKeyGenerationParameters
        : KeyGenerationParameters
    {
        private readonly AsconSignParameters m_parameters;

        public AsconSignKeyGenerationParameters(SecureRandom random, AsconSignParameters parameters)
            : base(random, 256)
        {
            m_parameters = parameters;
        }

        public AsconSignParameters Parameters => m_parameters;
    }
}
