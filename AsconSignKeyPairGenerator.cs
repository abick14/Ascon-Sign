
using System;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Pqc.Crypto.AsconSign
{
    public sealed class AsconSignKeyPairGenerator
        : IAsymmetricCipherKeyPairGenerator
    {
        private SecureRandom random;
        private AsconSignParameters parameters;

        public void Init(KeyGenerationParameters param)
        {
            random = param.Random;
            parameters = ((AsconSignKeyGenerationParameters)param).Parameters;
        }

        public AsymmetricCipherKeyPair GenerateKeyPair()
        {
            AsconSignEngine engine = parameters.GetEngine();
            byte[] pkSeed;
            SK sk;

        
                sk = new SK(SecRand(engine.N), SecRand(engine.N));
                pkSeed = SecRand(engine.N);
            
            engine.Init(pkSeed);
            // TODO
            PK pk = new PK(pkSeed, new HT(engine, sk.seed, pkSeed).HTPubKey);

            return new AsymmetricCipherKeyPair(new AsconSignPublicKeyParameters(parameters, pk),
                new AsconSignPrivateKeyParameters(parameters, sk, pk));
        }

        private byte[] SecRand(int n)
        {
            return SecureRandom.GetNextBytes(random, n);
        }
    }
}
