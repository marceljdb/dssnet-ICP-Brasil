/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas BovÃ© 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Esf;
using Org.BouncyCastle.Asn1.Ess;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Security.Certificates;
using Sharpen;
using System.Collections;
using System.Collections.Generic;
using BcX509 = Org.BouncyCastle.Asn1.X509;

namespace EU.Europa.EC.Markt.Dss.Signature.Cades
{
    /// <summary>
    /// This class holds the CAdES-BES signature profile; it supports the inclusion of the mandatory signed
    /// id_aa_signingCertificate[V2] attribute as specified in ETSI TS 101 733 V1.8.1, clause 5.7.3.
    /// </summary>
    /// <remarks>
    /// This class holds the CAdES-BES signature profile; it supports the inclusion of the mandatory signed
    /// id_aa_signingCertificate[V2] attribute as specified in ETSI TS 101 733 V1.8.1, clause 5.7.3.
    /// </remarks>
    /// <version>$Revision: 1887 $ - $Date: 2013-04-23 14:56:09 +0200 (mar., 23 avr. 2013) $
    /// 	</version>
    public class CAdESProfileBES
    {
        private bool padesUsage;

        /// <summary>The default constructor for CAdESProfileBES.</summary>
        /// <remarks>The default constructor for CAdESProfileBES.</remarks>
        public CAdESProfileBES() : this(false)
        {
        }

        /// <summary>The default constructor for CAdESProfileBES.</summary>
        /// <remarks>The default constructor for CAdESProfileBES.</remarks>
        public CAdESProfileBES(bool padesUsage)
        {
            this.padesUsage = padesUsage;
        }

        private Attribute MakeSigningCertificateAttribute(SignatureParameters parameters)
        {
            try
            {
                byte[] certHash = DigestUtilities.CalculateDigest
                    (parameters.DigestAlgorithm.GetName(),
                    parameters.SigningCertificate.GetEncoded());

                    EssCertIDv2 essCert = new EssCertIDv2(new AlgorithmIdentifier(parameters.DigestAlgorithm
                        .GetOid()), certHash);
                    SigningCertificateV2 scv2 = new SigningCertificateV2(new EssCertIDv2[] { essCert }
                        );
                    return new Attribute(PkcsObjectIdentifiers.IdAASigningCertificateV2, new DerSet
                        (scv2));
                //}
            }
            catch (NoSuchAlgorithmException e)
            {
                throw new RuntimeException(e);
            }
            catch (CertificateException e)
            {
                throw new RuntimeException(e);
            }
        }

        private Attribute MakeSigningTimeAttribute(SignatureParameters parameters)
        {
            var data = new Attribute(PkcsObjectIdentifiers.Pkcs9AtSigningTime, new DerSet(new
                BcX509.Time(parameters.SigningDate)));
            return data; 
        }

        private Attribute MakeSignerAttrAttribute(SignatureParameters parameters)
        {
            DerOctetString[] roles = new DerOctetString[1];
            roles[0] = new DerOctetString(Sharpen.Runtime.GetBytesForString(parameters.ClaimedSignerRole));
            return new Attribute(PkcsObjectIdentifiers.IdAAEtsSignerAttr, new DerSet(new SignerAttribute
                (new DerSequence(roles))));
        }

        private Attribute MakeSignerIdSpqEtsUriAttrAttribute(string teste)
        {
           return new Attribute(PkcsObjectIdentifiers.IdSpqEtsUri, new DerSet(new PolicyQualifierInfo("http://www.iti.gov.br/images/twiki/URL/pub/Certificacao/DocIcp/docs13082012/DOC-ICP-15.03_-_Versao_6.1.pdf")));
        }


        internal virtual IDictionary GetSignedAttributes
            (SignatureParameters parameters)
        {
            IDictionary signedAttrs = new Dictionary<DerObjectIdentifier
                , Asn1Encodable>();
            Attribute signingCertificateReference = MakeSigningCertificateAttribute(parameters
                );
            signedAttrs.Add((DerObjectIdentifier)signingCertificateReference.AttrType,
                signingCertificateReference);
            if (!padesUsage)
            {
                signedAttrs.Add(PkcsObjectIdentifiers.Pkcs9AtSigningTime, MakeSigningTimeAttribute
                    (parameters));
            }
            if (!padesUsage && parameters.ClaimedSignerRole != null)
            {
                signedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsSignerAttr, MakeSignerAttrAttribute
                    (parameters));
            }

            List<SigPolicyQualifierInfo> url = new List<SigPolicyQualifierInfo>();
            var sigQualifieer = new SigPolicyQualifierInfo(PkcsObjectIdentifiers.IdSpqEtsUri, new DerSet(new PolicyQualifierInfo("http://www.iti.gov.br/images/twiki/URL/pub/Certificacao/DocIcp/docs13082012/DOC-ICP-15.03_-_Versao_6.1.pdf")));
            url.Add(sigQualifieer);


            var sigPolicy = new SignaturePolicyIdentifier(
                new SignaturePolicyId(new DerObjectIdentifier(parameters.SignaturePolicyID), new OtherHashAlgAndValue(new AlgorithmIdentifier
                (DigestAlgorithm.GetByName(parameters.SignaturePolicyHashAlgo).GetOid()), new
                DerOctetString(parameters.SignaturePolicyHashValue))));

            var policy = new Attribute(PkcsObjectIdentifiers.IdAAEtsSigPolicyID, new DerSet(sigPolicy
                ));
            signedAttrs.Add(PkcsObjectIdentifiers.IdAAEtsSigPolicyID, policy);

            //signedAttrs.Add(PkcsObjectIdentifiers.IdSpqEtsUri, MakeSignerIdSpqEtsUriAttrAttribute("http://www.iti.gov.br/images/twiki/URL/pub/Certificacao/DocIcp/docs13082012/DOC-ICP-15.03_-_Versao_6.1.pdf"));

            return signedAttrs;
        }

        /// <summary>Return the table of unsigned properties.</summary>
        /// <remarks>Return the table of unsigned properties.</remarks>
        /// <param name="parameters"></param>
        /// <returns></returns>
        //public virtual IDictionary<DerObjectIdentifier, Asn1Encodable> GetUnsignedAttributes
        public virtual IDictionary GetUnsignedAttributes
            (SignatureParameters parameters)
        {
            return new Dictionary<DerObjectIdentifier, Asn1Encodable>();
        }
    }
}
