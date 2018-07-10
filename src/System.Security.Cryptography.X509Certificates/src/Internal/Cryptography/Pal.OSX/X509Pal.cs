// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Security.Cryptography;
using System.Security.Cryptography.Apple;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Win32.SafeHandles;

namespace Internal.Cryptography.Pal
{
    internal sealed partial class X509Pal
    {
        public static IX509Pal Instance = new AppleX509Pal();

        private X509Pal()
        {
        }

        private partial class AppleX509Pal : ManagedX509ExtensionProcessor, IX509Pal
        {
            public AsymmetricAlgorithm DecodePublicKey(Oid oid, byte[] encodedKeyValue, byte[] encodedParameters,
                ICertificatePal certificatePal)
            {
                AppleCertificatePal applePal = certificatePal as AppleCertificatePal;

                if (applePal != null)
                {
                    SafeSecKeyRefHandle key = Interop.AppleCrypto.X509GetPublicKey(applePal.CertificateHandle);

                    switch (oid.Value)
                    {
                        case Oids.RsaRsa:
                            return new RSAImplementation.RSASecurityTransforms(key);
                        case Oids.DsaDsa:
                            return new DSAImplementation.DSASecurityTransforms(key);
                        case Oids.Ecc:
                            return new ECDsaImplementation.ECDsaSecurityTransforms(key);
                    }

                    key.Dispose();
                }
                else
                {
                    switch (oid.Value)
                    {
                        case Oids.RsaRsa:
                            return DecodeRsaPublicKey(encodedKeyValue);
                        case Oids.DsaDsa:
                            return DecodeDsaPublicKey(encodedKeyValue, encodedParameters);
                    }
                }

                throw new NotSupportedException(SR.NotSupported_KeyAlgorithm);
            }

            private static AsymmetricAlgorithm DecodeRsaPublicKey(byte[] encodedKeyValue)
            {
                DerSequenceReader reader = new DerSequenceReader(encodedKeyValue);
                RSAParameters rsaParameters = new RSAParameters();
                reader.ReadPkcs1PublicBlob(ref rsaParameters);

                RSA rsa = RSA.Create();
                try
                {
                    rsa.ImportParameters(rsaParameters);
                    return rsa;
                }
                catch (Exception)
                {
                    rsa.Dispose();
                    throw;
                }
            }

            private static AsymmetricAlgorithm DecodeDsaPublicKey(byte[] encodedKeyValue, byte[] encodedParameters)
            {
                DSAParameters dsaParameters = new DSAParameters();
                DerSequenceReader parameterReader = new DerSequenceReader(encodedParameters);

                parameterReader.ReadSubjectPublicKeyInfo(encodedKeyValue, ref dsaParameters);

                DSA dsa = DSA.Create();
                try
                {
                    dsa.ImportParameters(dsaParameters);
                    return dsa;
                }
                catch (Exception)
                {
                    dsa.Dispose();
                    throw;
                }
            }

            public string X500DistinguishedNameDecode(byte[] encodedDistinguishedName, X500DistinguishedNameFlags flag)
            {
                return X500NameEncoder.X500DistinguishedNameDecode(encodedDistinguishedName, true, flag);
            }

            public byte[] X500DistinguishedNameEncode(string distinguishedName, X500DistinguishedNameFlags flag)
            {
                return X500NameEncoder.X500DistinguishedNameEncode(distinguishedName, flag);
            }

            public string X500DistinguishedNameFormat(byte[] encodedDistinguishedName, bool multiLine)
            {
                return X500NameEncoder.X500DistinguishedNameDecode(
                    encodedDistinguishedName,
                    true,
                    multiLine ? X500DistinguishedNameFlags.UseNewLines : X500DistinguishedNameFlags.None,
                    multiLine);
            }

            public X509ContentType GetCertContentType(byte[] rawData)
            {
                if (rawData == null || rawData.Length == 0)
                {
                    return X509ContentType.Unknown;
                }
                
                return Interop.AppleCrypto.X509GetContentType(rawData, rawData.Length);
            }

            public X509ContentType GetCertContentType(string fileName)
            {
                return GetCertContentType(System.IO.File.ReadAllBytes(fileName));
            }

            public ICertificatePal CertificateFromHandle(IntPtr handle)
                => AppleCertificatePal.FromHandle(handle);

            public ICertificatePal CertificateFromOtherCert(X509Certificate cert)
                => AppleCertificatePal.FromOtherCert(cert);

            public  ICertificatePal CertificateFromBlob(byte[] rawData, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
                => AppleCertificatePal.FromBlob(rawData,  password, keyStorageFlags);

            public ICertificatePal CertificateFromFile(string fileName, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
                => AppleCertificatePal.FromFile(fileName, password, keyStorageFlags);

            public IChainPal ChainFromHandle(IntPtr chainContext)
                => SecTrustChainPal.FromHandle(chainContext);

            public bool ReleaseSafeX509ChainHandle(IntPtr handle)
                => SecTrustChainPal.ReleaseSafeX509ChainHandle(handle);

            public IChainPal BuildChain(
                bool useMachineContext,
                ICertificatePal cert,
                X509Certificate2Collection extraStore,
                OidCollection applicationPolicy,
                OidCollection certificatePolicy,
                X509RevocationMode revocationMode,
                X509RevocationFlag revocationFlag,
                DateTime verificationTime,
                TimeSpan timeout)
                => SecTrustChainPal.BuildChain(
                    useMachineContext,
                    cert,
                    extraStore,
                    applicationPolicy,
                    certificatePolicy,
                    revocationMode,
                    revocationFlag,
                    verificationTime,
                    timeout);

            public IFindPal OpenFindPal(X509Certificate2Collection findFrom, X509Certificate2Collection copyTo, bool validOnly)
                => new AppleCertificateFinder(findFrom, copyTo, validOnly);

            public IStorePal StoreFromHandle(IntPtr storeHandle)
                => AppleStorePal.FromHandle(storeHandle);

            public ILoaderPal LoaderFromBlob(byte[] rawData, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
                => AppleStorePal.FromBlob(rawData, password, keyStorageFlags);

            public ILoaderPal LoaderFromFile(string fileName, SafePasswordHandle password, X509KeyStorageFlags keyStorageFlags)
                => AppleStorePal.FromFile(fileName, password, keyStorageFlags);

            public IExportPal ExportFromCertificate(ICertificatePal cert)
                => AppleStorePal.FromCertificate(cert);

            public IExportPal ExportLinkFromCertificateCollection(X509Certificate2Collection certificates)
                => AppleStorePal.LinkFromCertificateCollection(certificates);

            public IStorePal StoreFromSystemStore(string storeName, StoreLocation storeLocation, OpenFlags openFlags)
                => AppleStorePal.FromSystemStore(storeName, storeLocation, openFlags);
        }
    }
}
