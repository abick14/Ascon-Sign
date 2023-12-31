﻿using System;
using System.Collections.Generic;

using Org.BouncyCastle.Crypto.Utilities;
using Org.BouncyCastle.Utilities.Collections;
using static Org.BouncyCastle.Pqc.Crypto.AsconSign.AsconSignEngine;

namespace Org.BouncyCastle.Pqc.Crypto.AsconSign
{
    internal interface IAsconSignEngineProvider
    {
        int N { get; }

        AsconSignEngine Get();
    }



    //bool robust, int n, uint w, uint d, int a, int k, uint h
    public sealed class AsconSignParameters
    {
        public static readonly AsconSignParameters ascon_128s = new AsconSignParameters(
           0x010101, "ascon-128s-robust", new AsconEngineProvider(true, 16, 16, 7, 12, 14, 63));
        public static readonly AsconSignParameters ascon_128f = new AsconSignParameters(
           0x010102, "ascon-128f-robust", new AsconEngineProvider(true, 16, 16, 22, 6, 33, 66));
        public static readonly AsconSignParameters ascon_192s = new AsconSignParameters(
           0x010103, "ascon-192s-robust", new AsconEngineProvider(true, 24, 16, 7, 12, 14, 63));
        public static readonly AsconSignParameters ascon_192f = new AsconSignParameters(
           0x010104, "ascon-192f-robust", new AsconEngineProvider(true, 246, 16, 22, 8, 33, 66));

        public static readonly AsconSignParameters ascon_128s_simple = new AsconSignParameters(
           0x010101, "ascon-128s-simple", new AsconEngineProvider(false, 16, 16, 7, 12, 14, 63));
        public static readonly AsconSignParameters ascon_128f_simple = new AsconSignParameters(
           0x010102, "ascon-128f-simple", new AsconEngineProvider(false, 16, 16, 22, 6, 33, 66));
        public static readonly AsconSignParameters ascon_192s_simple = new AsconSignParameters(
           0x010103, "ascon-192s-simple", new AsconEngineProvider(false, 24, 16, 7, 12, 14, 63));
        public static readonly AsconSignParameters ascon_192f_simple = new AsconSignParameters(
           0x010104, "ascon-192f-simple", new AsconEngineProvider(false, 246, 16, 22, 8, 33, 66));

        private static readonly Dictionary<int, AsconSignParameters> IdToParams =
           new Dictionary<int, AsconSignParameters>();

        static AsconSignParameters()
        {
            AsconSignParameters[] all = new AsconSignParameters[]{
                AsconSignParameters.ascon_128f, AsconSignParameters.ascon_128s,AsconSignParameters.ascon_192f,
                AsconSignParameters.ascon_192s, AsconSignParameters.ascon_128s_simple, AsconSignParameters.ascon_128f_simple,
                AsconSignParameters.ascon_192f_simple, AsconSignParameters.ascon_192s_simple

            };

            for (int i = 0; i < all.Length; ++i)
            {
                AsconSignParameters parameters = all[i];
                IdToParams.Add(parameters.ID, parameters);
            }
        }

        private readonly int m_id;
        private readonly string m_name;
        private readonly IAsconSignEngineProvider m_engineProvider;

        private AsconSignParameters(int id, string name, IAsconSignEngineProvider engineProvider)
        {
            m_id = id;
            m_name = name;
            m_engineProvider = engineProvider;
        }

        public int ID => m_id;

        public string Name => m_name;

        internal int N => m_engineProvider.N;

        internal AsconSignEngine GetEngine() => m_engineProvider.Get();

        /**
         * Return the SPHINCS+ parameters that map to the passed in parameter ID.
         * 
         * @param id the oid of interest.
         * @return the parameter set.
         */
        public static AsconSignParameters GetParams(int id) => CollectionUtilities.GetValueOrNull(IdToParams, id);

        /**
         * Return the OID that maps to the passed in SPHINCS+ parameters.
         *
         * @param params the parameters of interest.
         * @return the OID for the parameter set.
         */
        [Obsolete("Use 'ID' property instead")]
        public static int GetID(AsconSignParameters parameters) => parameters.ID;

        public byte[] GetEncoded() => Pack.UInt32_To_BE((uint)ID);
    }

    internal sealed class AsconEngineProvider
        : IAsconSignEngineProvider
    {
        private readonly bool robust;
        private readonly int n;
        private readonly uint w;
        private readonly uint d;
        private readonly int a;
        private readonly int k;
        private readonly uint h;

        internal AsconEngineProvider(bool robust, int n, uint w, uint d, int a, int k, uint h)
        {
            this.robust = robust;
            this.n = n;
            this.w = w;
            this.d = d;
            this.a = a;
            this.k = k;
            this.h = h;
        }

        public int N => this.n;

        public AsconSignEngine Get()
        {
            return new AsconSignEngine.AsconSign(robust, n, w, d, a, k, h);
        }
    }
}
