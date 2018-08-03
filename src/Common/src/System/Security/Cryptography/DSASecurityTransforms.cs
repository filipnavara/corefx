// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.IO;
using System.Numerics;
using System.Security.Cryptography.Apple;
using System.Security.Cryptography.Asn1;
using Internal.Cryptography;

namespace System.Security.Cryptography
{
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS

    public partial class DSA : AsymmetricAlgorithm
    {
        public static new DSA Create()
        {
            return new DSAImplementation.DSASecurityTransforms();
        }
#endif

        internal static partial class DSAImplementation
        {
            public sealed partial class DSASecurityTransforms : DSA
            {
                private SecKeyPair _keys;

                public DSASecurityTransforms()
                    : this(1024)
                {
                }

                public DSASecurityTransforms(int keySize)
                {
                    KeySize = keySize;
                }

                internal DSASecurityTransforms(SafeSecKeyRefHandle publicKey)
                {
                    SetKey(SecKeyPair.PublicOnly(publicKey));
                }

                internal DSASecurityTransforms(SafeSecKeyRefHandle publicKey, SafeSecKeyRefHandle privateKey)
                {
                    SetKey(SecKeyPair.PublicPrivatePair(publicKey, privateKey));
                }

                public override KeySizes[] LegalKeySizes
                {
                    get
                    {
                        return new[] { new KeySizes(minSize: 512, maxSize: 1024, skipSize: 64) };
                    }
                }

                public override int KeySize
                {
                    get
                    {
                        return base.KeySize;
                    }
                    set
                    {
                        if (KeySize == value)
                            return;

                        // Set the KeySize before freeing the key so that an invalid value doesn't throw away the key
                        base.KeySize = value;

                        if (_keys != null)
                        {
                            _keys.Dispose();
                            _keys = null;
                        }
                    }
                }

                public override DSAParameters ExportParameters(bool includePrivateParameters)
                {
                    SecKeyPair keys = GetKeys();

                    if (keys.PublicKey == null ||
                        (includePrivateParameters && keys.PrivateKey == null))
                    { 
                        throw new CryptographicException(SR.Cryptography_OpenInvalidHandle);
                    }

                    if (!includePrivateParameters)
                    {
                        byte[] publicKey = Interop.AppleCrypto.SecKeyExport(keys.PublicKey, exportPrivate: false, password: null);
                        DSAKeyFormatHelper.ReadSubjectPublicKeyInfo(
                            publicKey,
                            out int localRead,
                            out DSAParameters key);
                        return key;
                    }
                    else
                    {
                        // Apple requires all private keys to be exported encrypted, but since we're trying to export
                        // as parsed structures we will need to decrypt it for the user.
                        const string ExportPassword = "DotnetExportPassphrase";

                        byte[] privateKey = Interop.AppleCrypto.SecKeyExport(keys.PrivateKey, exportPrivate: true, password: ExportPassword);
                        DSAKeyFormatHelper.ReadEncryptedPkcs8(
                            privateKey,
                            ExportPassword,
                            out int localRead,
                            out DSAParameters key);
                        return key;
                    }
                }

                public override void ImportParameters(DSAParameters parameters)
                {
                    if (parameters.P == null || parameters.Q == null || parameters.G == null || parameters.Y == null)
                        throw new ArgumentException(SR.Cryptography_InvalidDsaParameters_MissingFields);

                    // J is not required and is not even used on CNG blobs.
                    // It should, however, be less than P (J == (P-1) / Q).
                    // This validation check is just to maintain parity with DSACng and DSACryptoServiceProvider,
                    // which also perform this check.
                    if (parameters.J != null && parameters.J.Length >= parameters.P.Length)
                        throw new ArgumentException(SR.Cryptography_InvalidDsaParameters_MismatchedPJ);

                    int keySize = parameters.P.Length;
                    bool hasPrivateKey = parameters.X != null;

                    if (parameters.G.Length != keySize || parameters.Y.Length != keySize)
                        throw new ArgumentException(SR.Cryptography_InvalidDsaParameters_MismatchedPGY);

                    if (hasPrivateKey && parameters.X.Length != parameters.Q.Length)
                        throw new ArgumentException(SR.Cryptography_InvalidDsaParameters_MismatchedQX);

                    if (!(8 * parameters.P.Length).IsLegalSize(LegalKeySizes))
                        throw new CryptographicException(SR.Cryptography_InvalidKeySize);

                    if (parameters.Q.Length != 20)
                        throw new CryptographicException(SR.Cryptography_InvalidDsaParameters_QRestriction_ShortKey);

                    if (hasPrivateKey)
                    {
                        SafeSecKeyRefHandle privateKey = ImportKey(parameters);

                        DSAParameters publicOnly = parameters;
                        publicOnly.X = null;

                        SafeSecKeyRefHandle publicKey;
                        try
                        {
                            publicKey = ImportKey(publicOnly);
                        }
                        catch
                        {
                            privateKey.Dispose();
                            throw;
                        }

                        SetKey(SecKeyPair.PublicPrivatePair(publicKey, privateKey));
                    }
                    else
                    {
                        SafeSecKeyRefHandle publicKey = ImportKey(parameters);
                        SetKey(SecKeyPair.PublicOnly(publicKey));
                    }
                }

                private static SafeSecKeyRefHandle ImportKey(DSAParameters parameters)
                {
                    bool hasPrivateKey = parameters.X != null;
                    byte[] blob;
                    
                    if (hasPrivateKey)
                    {
                        Debug.Assert(parameters.X != null);

                        // DSAPrivateKey ::= SEQUENCE(
                        //   version INTEGER,
                        //   p INTEGER,
                        //   q INTEGER,
                        //   g INTEGER,
                        //   y INTEGER,
                        //   x INTEGER,
                        // )

                        using (AsnWriter privateKeyWriter = new AsnWriter(AsnEncodingRules.DER))
                        {
                            privateKeyWriter.PushSequence();
                            privateKeyWriter.WriteInteger(0);
                            privateKeyWriter.WriteKeyParameterInteger(parameters.P);
                            privateKeyWriter.WriteKeyParameterInteger(parameters.Q);
                            privateKeyWriter.WriteKeyParameterInteger(parameters.G);
                            privateKeyWriter.WriteKeyParameterInteger(parameters.Y);
                            privateKeyWriter.WriteKeyParameterInteger(parameters.X);
                            privateKeyWriter.PopSequence();
                            blob = privateKeyWriter.Encode();
                        }
                    }
                    else
                    {
                        using (AsnWriter writer = DSAKeyFormatHelper.WriteSubjectPublicKeyInfo(parameters))
                        {
                            blob = writer.Encode();
                        }
                    }

                    return Interop.AppleCrypto.ImportEphemeralKey(blob, hasPrivateKey);
                }

                public override byte[] CreateSignature(byte[] rgbHash)
                {
                    if (rgbHash == null)
                        throw new ArgumentNullException(nameof(rgbHash));

                    SecKeyPair keys = GetKeys();

                    if (keys.PrivateKey == null)
                    {
                        throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);
                    }

                    byte[] derFormatSignature = Interop.AppleCrypto.GenerateSignature(keys.PrivateKey, rgbHash);

                    // Since the AppleCrypto implementation is limited to FIPS 186-2, signature field sizes
                    // are always 160 bits / 20 bytes (the size of SHA-1, and the only legal length for Q).
                    byte[] ieeeFormatSignature = AsymmetricAlgorithmHelpers.ConvertDerToIeee1363(
                        derFormatSignature,
                        0,
                        derFormatSignature.Length,
                        fieldSizeBits: 160);

                    return ieeeFormatSignature;
                }

                public override bool VerifySignature(byte[] hash, byte[] signature)
                {
                    if (hash == null)
                        throw new ArgumentNullException(nameof(hash));
                    if (signature == null)
                        throw new ArgumentNullException(nameof(signature));

                    return VerifySignature((ReadOnlySpan<byte>)hash, (ReadOnlySpan<byte>)signature);
                }

                public override bool VerifySignature(ReadOnlySpan<byte> hash, ReadOnlySpan<byte> signature)
                {
                    byte[] derFormatSignature = AsymmetricAlgorithmHelpers.ConvertIeee1363ToDer(signature);

                    return Interop.AppleCrypto.VerifySignature(
                        GetKeys().PublicKey,
                        hash,
                        derFormatSignature);
                }

                protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
                {
                    if (hashAlgorithm != HashAlgorithmName.SHA1)
                    {
                        // Matching DSACryptoServiceProvider's "I only understand SHA-1/FIPS 186-2" exception
                        throw new CryptographicException(SR.Cryptography_UnknownHashAlgorithm, hashAlgorithm.Name);
                    }

                    return AsymmetricAlgorithmHelpers.HashData(data, offset, count, hashAlgorithm);
                }

                protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm) =>
                    AsymmetricAlgorithmHelpers.HashData(data, hashAlgorithm);

                protected override bool TryHashData(ReadOnlySpan<byte> data, Span<byte> destination, HashAlgorithmName hashAlgorithm, out int bytesWritten) =>
                    AsymmetricAlgorithmHelpers.TryHashData(data, destination, hashAlgorithm, out bytesWritten);

                protected override void Dispose(bool disposing)
                {
                    if (disposing)
                    {
                        if (_keys != null)
                        {
                            _keys.Dispose();
                            _keys = null;
                        }
                    }

                    base.Dispose(disposing);
                }

                internal SecKeyPair GetKeys()
                {
                    SecKeyPair current = _keys;

                    if (current != null)
                    {
                        return current;
                    }

                    // macOS 10.11 and macOS 10.12 declare DSA invalid for key generation.
                    // Rather than write code which might or might not work, returning
                    // (OSStatus)-4 (errSecUnimplemented), just make the exception occur here.
                    //
                    // When the native code can be verified, then it can be added.
                    throw new PlatformNotSupportedException(SR.Cryptography_DSA_KeyGenNotSupported);
                }

                private void SetKey(SecKeyPair newKeyPair)
                {
                    SecKeyPair current = _keys;
                    _keys = newKeyPair;
                    current?.Dispose();

                    if (newKeyPair != null)
                    {
                        int size = Interop.AppleCrypto.GetSimpleKeySizeInBits(newKeyPair.PublicKey);
                        KeySizeValue = size;
                    }
                }
            }
        }
#if INTERNAL_ASYMMETRIC_IMPLEMENTATIONS
    }
#else
    internal static class KeySizeHelpers
    {

        public static bool IsLegalSize(this int size, KeySizes[] legalSizes)
        {
            for (int i = 0; i < legalSizes.Length; i++)
            {
                KeySizes currentSizes = legalSizes[i];

                // If a cipher has only one valid key size, MinSize == MaxSize and SkipSize will be 0
                if (currentSizes.SkipSize == 0)
                {
                    if (currentSizes.MinSize == size)
                        return true;
                }
                else if (size >= currentSizes.MinSize && size <= currentSizes.MaxSize)
                {
                    // If the number is in range, check to see if it's a legal increment above MinSize
                    int delta = size - currentSizes.MinSize;

                    // While it would be unusual to see KeySizes { 10, 20, 5 } and { 11, 14, 1 }, it could happen.
                    // So don't return false just because this one doesn't match.
                    if (delta % currentSizes.SkipSize == 0)
                    {
                        return true;
                    }
                }
            }
            return false;
        }
    }
#endif
}
