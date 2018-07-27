// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Runtime.InteropServices;
using System.Security.Cryptography.Asn1;

namespace System.Security.Cryptography.X509Certificates.Asn1
{
    // Validity ::= SEQUENCE {
    //     notBefore      Time,
    //     notAfter       Time
    // }
    [StructLayout(LayoutKind.Sequential)]
    internal struct ValidityAsn
    {
        public ValidityAsn(DateTimeOffset notBefore, DateTimeOffset notAfter)
        {
            NotBefore = new TimeAsn(notBefore);
            NotAfter = new TimeAsn(notAfter);
        }

        public TimeAsn NotBefore;
        public TimeAsn NotAfter;
    }
}
