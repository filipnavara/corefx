﻿using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography.X509Certificates.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct TimeAsn
    {
        internal DateTimeOffset? UtcTime;
        internal DateTimeOffset? GeneralTime;

#if DEBUG
        static TimeAsn()
        {
            var usedTags = new System.Collections.Generic.Dictionary<Asn1Tag, string>();
            Action<Asn1Tag, string> ensureUniqueTag = (tag, fieldName) =>
            {
                if (usedTags.TryGetValue(tag, out string existing))
                {
                    throw new InvalidOperationException($"Tag '{tag}' is in use by both '{existing}' and '{fieldName}'");
                }

                usedTags.Add(tag, fieldName);
            };
            
            ensureUniqueTag(Asn1Tag.UtcTime, "UtcTime");
            ensureUniqueTag(Asn1Tag.GeneralizedTime, "GeneralTime");
        }
#endif

        internal void Encode(AsnWriter writer)
        {
            bool wroteValue = false; 
            
            if (UtcTime.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                writer.WriteUtcTime(UtcTime.Value);
                wroteValue = true;
            }

            if (GeneralTime.HasValue)
            {
                if (wroteValue)
                    throw new CryptographicException();
                
                writer.WriteGeneralizedTime(GeneralTime.Value);
                wroteValue = true;
            }

            if (!wroteValue)
            {
                throw new CryptographicException();
            }
        }

        internal static void Decode(AsnReader reader, out TimeAsn decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = default;
            Asn1Tag tag = reader.PeekTag();
            
            if (tag.HasSameClassAndValue(Asn1Tag.UtcTime))
            {
                decoded.UtcTime = reader.GetUtcTime();
            }
            else if (tag.HasSameClassAndValue(Asn1Tag.GeneralizedTime))
            {
                decoded.GeneralTime = reader.GetGeneralizedTime();
            }
            else
            {
                throw new CryptographicException();
            }
        }
    }
}
