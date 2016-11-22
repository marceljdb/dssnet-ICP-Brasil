using System;
using System.Collections.Generic;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

namespace iTextSharp.text.pdf.security {
    /// <summary>
    /// Creates a signature using a X509Certificate2. It supports smartcards without 
    /// exportable private keys.
    /// </summary>
    public class X509Certificate2Signature : IExternalSignature {
        /// <summary>
        /// The certificate with the private key
        /// </summary>
        private X509Certificate2 certificate;
        /** The hash algorithm. */
        private String hashAlgorithm;
        /** The encryption algorithm (obtained from the private key) */
        private String encryptionAlgorithm;
        
        /// <summary>
        /// Creates a signature using a X509Certificate2. It supports smartcards without 
        /// exportable private keys.
        /// </summary>
        /// <param name="certificate">The certificate with the private key</param>
        /// <param name="hashAlgorithm">The hash algorithm for the signature. As the Windows CAPI is used
        /// to do the signature the only hash guaranteed to exist is SHA-1</param>
        public X509Certificate2Signature(X509Certificate2 certificate, String hashAlgorithm) {
            if (!certificate.HasPrivateKey)
                throw new ArgumentException("No private key.");
            this.certificate = certificate;
            this.hashAlgorithm = DigestAlgorithms.GetDigest(DigestAlgorithms.GetAllowedDigests(hashAlgorithm));
            if (certificate.PrivateKey is RSACryptoServiceProvider)
                encryptionAlgorithm = "RSA";
            else if (certificate.PrivateKey is DSACryptoServiceProvider)
                encryptionAlgorithm = "DSA";
            else
                throw new ArgumentException("Unknown encryption algorithm " + certificate.PrivateKey);
        }

        public virtual byte[] Sign(byte[] message) {
            if (certificate.PrivateKey is RSACryptoServiceProvider) {
                RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)certificate.PrivateKey;
                //TODO jbonilla-No siempre funciona con SHA-256
                //return rsa.SignData(message, CryptoConfig.CreateFromName("SHA-256"));

                
                var rsa2 = certificate.PrivateKey as RSACryptoServiceProvider;
                // Create a new RSACryptoServiceProvider
                RSACryptoServiceProvider rsaClear = new RSACryptoServiceProvider();
                                
                // Export RSA parameters from 'rsa' and import them into 'rsaClear'
                //rsaClear.ImportParameters(rsa.ExportParameters(true));
                //var teste = CryptoConfig.MapNameToOID("SHA256");                
                return rsa.SignData(message, CryptoConfig.CreateFromName("SHA256"));
            }
            else {
                DSACryptoServiceProvider dsa = (DSACryptoServiceProvider)certificate.PrivateKey;
                return dsa.SignData(message);
            }
        }

        /**
         * Returns the hash algorithm.
         * @return  the hash algorithm (e.g. "SHA-1", "SHA-256,...")
         * @see com.itextpdf.text.pdf.security.ExternalSignature#getHashAlgorithm()
         */
        public virtual String GetHashAlgorithm() {
            return hashAlgorithm;
        }
        
        /**
         * Returns the encryption algorithm used for signing.
         * @return the encryption algorithm ("RSA" or "DSA")
         * @see com.itextpdf.text.pdf.security.ExternalSignature#getEncryptionAlgorithm()
         */
        public virtual String GetEncryptionAlgorithm() {
            return encryptionAlgorithm;
        }
    }
}
