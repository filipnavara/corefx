﻿using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography.X509Certificates.Asn1
{
    [StructLayout(LayoutKind.Sequential)]
    internal partial struct CertificationRequestInfoAsn
    {
        internal System.Numerics.BigInteger Version;
        internal ReadOnlyMemory<byte> Subject;
        internal System.Security.Cryptography.Asn1.SubjectPublicKeyInfoAsn SubjectPublicKeyInfo;
        internal System.Security.Cryptography.X509Certificates.Asn1.X501AttributeAsn[] Attributes;
      
        internal void Encode(AsnWriter writer)
        {
            Encode(writer, Asn1Tag.Sequence);
        }
    
        internal void Encode(AsnWriter writer, Asn1Tag tag)
        {
            writer.PushSequence(tag);
            
            writer.WriteInteger(Version);
            // Validator for tag constraint for Subject
            {
                if (!Asn1Tag.TryParse(Subject.Span, out Asn1Tag validateTag, out _) ||
                    !validateTag.HasSameClassAndValue(new Asn1Tag((UniversalTagNumber)16)))
                {
                    throw new CryptographicException();
                }
            }

            writer.WriteEncodedValue(Subject);
            SubjectPublicKeyInfo.Encode(writer);

            writer.PushSetOf(new Asn1Tag(TagClass.ContextSpecific, 0));
            for (int i = 0; i < Attributes.Length; i++)
            {
                Attributes[i].Encode(writer); 
            }
            writer.PopSetOf(new Asn1Tag(TagClass.ContextSpecific, 0));

            writer.PopSequence(tag);
        }

        internal static void Decode(AsnReader reader, out CertificationRequestInfoAsn decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            Decode(reader, Asn1Tag.Sequence, out decoded);
        }

        internal static void Decode(AsnReader reader, Asn1Tag expectedTag, out CertificationRequestInfoAsn decoded)
        {
            if (reader == null)
                throw new ArgumentNullException(nameof(reader));

            decoded = default;
            AsnReader sequenceReader = reader.ReadSequence(expectedTag);
            AsnReader collectionReader;
            
            decoded.Version = sequenceReader.GetInteger();
            if (!sequenceReader.PeekTag().HasSameClassAndValue(new Asn1Tag((UniversalTagNumber)16)))
            {
                throw new CryptographicException();
            }

            decoded.Subject = sequenceReader.GetEncodedValue();
            System.Security.Cryptography.Asn1.SubjectPublicKeyInfoAsn.Decode(sequenceReader, out decoded.SubjectPublicKeyInfo);

            // Decode SEQUENCE OF for Attributes
            {
                collectionReader = sequenceReader.ReadSetOf(new Asn1Tag(TagClass.ContextSpecific, 0));
                var tmpList = new List<System.Security.Cryptography.X509Certificates.Asn1.X501AttributeAsn>();
                System.Security.Cryptography.X509Certificates.Asn1.X501AttributeAsn tmpItem;

                while (collectionReader.HasData)
                {
                    System.Security.Cryptography.X509Certificates.Asn1.X501AttributeAsn.Decode(collectionReader, out tmpItem); 
                    tmpList.Add(tmpItem);
                }

                decoded.Attributes = tmpList.ToArray();
            }


            sequenceReader.ThrowIfNotEmpty();
        }
    }
}
