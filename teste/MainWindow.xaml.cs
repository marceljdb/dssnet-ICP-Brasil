using EU.Europa.EC.Markt.Dss;
using EU.Europa.EC.Markt.Dss.Signature;
using EU.Europa.EC.Markt.Dss.Signature.Cades;
using EU.Europa.EC.Markt.Dss.Signature.Token;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace teste
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private X509Certificate2 GetCertificate(string certID)
        {
            // Access Personal (MY) certificate store of current user
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadWrite);

            // Find the certificate we'll use to sign            
            X509Certificate2 certificate = null;
            foreach (X509Certificate2 cert in store.Certificates)
                if (cert.Subject.Contains(certID))
                {
                    certificate = cert;
                    break;
                }

            if (certificate == null)
                throw new Exception("Nenhum certificado válido foi encontrado.");

            return certificate;
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            var service = new CAdESService();

            // Creation of MS CAPI signature token
            var cert = new X509Certificate2(); //GetCertificate("47199695004");
            cert.Import(@"Resources\Certificado DEMOLINER E CIA LTDA.p12","renan2", System.Security.Cryptography.X509Certificates.X509KeyStorageFlags.Exportable);
            var token = new MSCAPISignatureToken { Cert = cert };


            var certBouncy = DotNetUtilities.FromX509Certificate(token.Cert);


            byte[] hash = DigestUtilities.CalculateDigest("SHA256", cert.Extensions[1].RawData); // File.ReadAllBytes(@"Resources\PA_AD_RB_v2_1.der")); //:\ certBouncy.CertificateStructure.SubjectPublicKeyInfo.GetDerEncoded());
            //URL Verificador - https://verificador.iti.gov.br/verificador.xhtml
            var parameters = new SignatureParameters
            {
                SignatureAlgorithm = SignatureAlgorithm.RSA,
                SignatureFormat = SignatureFormat.CAdES_EPES,
                DigestAlgorithm = DigestAlgorithm.SHA256,
                SignaturePackaging = SignaturePackaging.ENVELOPING,
                SigningCertificate = certBouncy,
                SigningDate = DateTime.UtcNow,
                SignaturePolicy = SignaturePolicy.EXPLICIT,
                SignaturePolicyHashValue = cert.Extensions[1].RawData,
                SignaturePolicyID = "2.16.76.1.7.1.1.2.1",
                SignaturePolicyHashAlgo = "SHA-256"              
                         
            };
            

            var toBeSigned = new FileDocument(@"Resources\teste.pdf");

            var iStream = service.ToBeSigned(toBeSigned, parameters);

            var signatureValue = token.Sign(iStream, parameters.DigestAlgorithm, token.GetKeys()[0]);
            var dest = @"Resources\teste.p7s";

            var signedDocument = service.SignDocument(toBeSigned, parameters, signatureValue);            

            if (File.Exists(dest)) File.Delete(dest);
            var fout = File.OpenWrite(dest);
            signedDocument.OpenStream().CopyTo(fout);
            fout.Close();
        }
    }
    
}
