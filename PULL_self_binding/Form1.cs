using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.ServiceModel;
using System.ServiceModel.Channels;
using System.ServiceModel.Description;
using System.ServiceModel.Security;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Xml;

namespace PULL_self_binding
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void button1_Click(object sender, EventArgs e)
        {
            string txtDestinationFolder = @"c:\pobrane_z_ePUAP";
            string txtAdresSkrytki = "/zsisigidspzoo/skrytkaKD";
            string txtNazwaSkrytki = "test KD";
            string txtPodmiot = "zsisigidspzoo";


            //parametry do zapytania
            ZapytaniePullOczekujaceTyp zapBody = new ZapytaniePullOczekujaceTyp();
            zapBody.adresSkrytki = txtAdresSkrytki;
            zapBody.nazwaSkrytki = txtNazwaSkrytki;
            zapBody.podmiot = txtPodmiot;

            textBox1.AppendText("Adres skrytki: " + zapBody.adresSkrytki + Environment.NewLine);
            textBox1.AppendText("Nazwa skrytki: " + zapBody.nazwaSkrytki + Environment.NewLine);
            textBox1.AppendText("Podmiot: " + zapBody.podmiot + Environment.NewLine);

            CustomBinding pullBinding = CreatePullBinding();
            EndpointAddress pullEndpoint = CreatePullEndpoint();

            //klient pull
            pullClient _client = new pullClient(pullBinding,pullEndpoint);
            
            X509Certificate2 certyfikatKlienta = GetClientCert();
            X509Certificate2 certyfikatSerwisu = GetServiceCert();

            _client.ClientCredentials.ClientCertificate.Certificate = certyfikatKlienta;
            _client.ClientCredentials.ServiceCertificate.DefaultCertificate = certyfikatSerwisu;

            //certyfikat dostarczony przez ePUAP do podpisywanie nie daje się zwalidować pod względem nadrzędnych instytucji
            //tzn. chyba sami go sobie wystawiają
            _client.ClientCredentials.ServiceCertificate.Authentication.CertificateValidationMode = X509CertificateValidationMode.None;

            try
            {
                //sprawdź oczekujące dokumenty
                OdpowiedzPullOczekujaceTyp odp = _client.oczekujaceDokumenty(zapBody);

                textBox1.AppendText("Oczekujące dokumenty: " + odp.oczekujace.ToString());
            }
            catch (MessageSecurityException ex)
            {
                try
                {
                    System.ServiceModel.FaultException exInner = (FaultException)ex.InnerException;
                    textBox1.AppendText("Wyjątek 1: " + ex.Message);
                    if (ex.InnerException == null)
                        throw new Exception("Brak szczegółowych informacji o błędzie.");
                    FaultException fe = ex.InnerException as FaultException;
                    textBox1.AppendText("Wyjątek 2: " + fe.Message);
                    if (fe == null)
                        throw new Exception("Szczegółowe informacje zapisane zostały w nieprzewidzianym formacie.");
                    MessageFault mf = fe.CreateMessageFault();
                    if (mf == null)
                        throw new Exception("Wystąpił problem podczas odtwarzania szczegółowych informacji.");
                    XmlReader xr = mf.GetReaderAtDetailContents();
                    XmlDocument xd = new XmlDocument();
                    xd.Load(xr);
                    XmlNode elemKomunikat = xd.SelectSingleNode("//*[local-name() = 'komunikat']");
                    XmlNode elemKod = xd.SelectSingleNode("//*[local-name() = 'kod']");
                    StringBuilder msg = new StringBuilder();
                    msg.Append("Wystąpił problem z doręczeniem dokumentów. Poniżej znajdują się szczegółowe informacje (komunikaty) przekazane przez ePUAP.");
                    msg.AppendFormat("Informacja z ePUAP: \"{0}, kod błędu: {1}\"", elemKomunikat.InnerText, elemKod.InnerText);
                    textBox1.AppendText(msg.ToString());
                }
                catch (Exception iex)
                {
                    //textBox1.AppendText(ex.Message);
                    //textBox1.AppendText(iex.Message);
                }
            }
            catch (Exception ex)
            {
                textBox1.AppendText(string.Format("Wystąpił błąd podczas pobierania liczby oczekujacych dokumentow" + ex.Message));
            }


        }

        private EndpointAddress CreatePullEndpoint()
        {
            //Adres endpointu
            Uri epUri = new Uri("https://ws-int.epuap.gov.pl/pk_external_ws/services/pull");
            EndpointIdentity endpointIdentity = EndpointIdentity.CreateDnsIdentity("ePUAP-INT-WS-Sign");
            EndpointAddress endPoint = new EndpointAddress(epUri, endpointIdentity);
            return endPoint;
        }

        private CustomBinding CreatePullBinding()
        {
            CustomBinding pullBinding = new CustomBinding();
            pullBinding.Name = "ePUAPBinding";

            SecurityBindingElement sBElement = SecurityBindingElement.CreateMutualCertificateBindingElement(
                MessageSecurityVersion.WSSecurity10WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10);

            AsymmetricSecurityBindingElement bindingAsymetryczny = (AsymmetricSecurityBindingElement)sBElement;

            bindingAsymetryczny.SetKeyDerivation(true);

            bindingAsymetryczny.EnableUnsecuredResponse = false;

            bindingAsymetryczny.AllowInsecureTransport = false;

            bindingAsymetryczny.AllowSerializedSigningTokenOnReply = true;

            bindingAsymetryczny.DefaultAlgorithmSuite = SecurityAlgorithmSuite.Basic192Rsa15;

            bindingAsymetryczny.IncludeTimestamp = true;

            bindingAsymetryczny.MessageProtectionOrder = MessageProtectionOrder.SignBeforeEncrypt;

            pullBinding.Elements.Clear();

            pullBinding.Elements.Add(bindingAsymetryczny);

            pullBinding.Elements.Add(new TextMessageEncodingBindingElement()
            {
                MessageVersion = MessageVersion.CreateVersion(EnvelopeVersion.Soap11, AddressingVersion.None),WriteEncoding = new UTF8Encoding()
            });

            HttpsTransportBindingElement httpsbinding = new HttpsTransportBindingElement();

            pullBinding.Elements.Add(httpsbinding);

            return pullBinding;
        }

        private X509Certificate2 GetClientCert()
        {
            bool jestCert = false;
            string szukajCertyfikat = "epuap_testy";  //FriendlyName

            X509Store keystore = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            keystore.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection certificates = keystore.Certificates;
            X509Certificate2 certificateClient = new X509Certificate2();
            foreach (var certificate in certificates)
            {
                var friendlyName = certificate.FriendlyName;
                //textBox1.AppendText("friendlyName: " + friendlyName + Environment.NewLine);

                if (friendlyName == szukajCertyfikat)
                {
                    string certExpiratioDate = certificate.GetExpirationDateString();
                    //textBox1.AppendText("Expiration date: " + certExpiratioDate + Environment.NewLine);

                    if (certificate.NotAfter <= DateTime.Now)
                    {
                        textBox1.AppendText("Pomijam certyfikat - przyjazna nazwa: " + certificate.FriendlyName + Environment.NewLine);
                        textBox1.AppendText("       Pomijam certyfikat - Wystawiono dla: " + certificate.SubjectName.Name + Environment.NewLine);
                        textBox1.AppendText("       Pomijam certyfikat - Wystawca: " + certificate.Issuer + Environment.NewLine);
                        textBox1.AppendText("       Pomijam certyfikat - Posiada klucz prywatny: " + certificate.HasPrivateKey.ToString() + Environment.NewLine);
                        textBox1.AppendText("       Pomijam certyfikat - WYGASŁ: " + certExpiratioDate + Environment.NewLine);
                        continue;
                    } else
                    {
                        textBox1.AppendText("Certyfikat - Przyjazna nazwa: " + certificate.FriendlyName + Environment.NewLine);
                        textBox1.AppendText("       Certyfikat - Wystawiono dla: " + certificate.SubjectName.Name + Environment.NewLine);
                        textBox1.AppendText("       Certyfikat - Wystawca: " + certificate.Issuer + Environment.NewLine);
                        textBox1.AppendText("       Certyfikat - Posiada klucz prywatny: " + certificate.HasPrivateKey.ToString() + Environment.NewLine);
                        textBox1.AppendText("       Certyfikat - Aktualny, ważny do: " + certExpiratioDate + Environment.NewLine);
                        jestCert = true;
                        certificateClient = certificate;
                        break;
                    }

                    //jestCert = true;
                    //certificateClient = certificate;
                }

            }
            if (!jestCert) MessageBox.Show("Nie znalazłem certyfikatu klienta wg FriendlyName: " +szukajCertyfikat);
            return certificateClient;
            keystore.Close();
        }

        private bool M_FindCertByFriendlyName(string FriendlyNameToFind, StoreName CertStoreName, StoreLocation CertStoreLocation, ref X509Certificate2 ReturnCertificate, bool CheckPrivateKey = false)
        {
            //Wyjście
            bool jestCert = false;

            //Otwarcie kontenera z certyfikatami
            X509Store keystore = new X509Store(CertStoreName, CertStoreLocation);
            keystore.Open(OpenFlags.ReadOnly);

            X509Certificate2Collection certificates = keystore.Certificates;
            foreach (var certificate in certificates)
            {
                var friendlyNameFromCert = certificate.FriendlyName;
                
                if (friendlyNameFromCert == FriendlyNameToFind)
                {
                    //Czy nie jest przeterminowany
                    string certExpiratioDate = certificate.GetExpirationDateString();
                    
                    if (certificate.NotAfter <= DateTime.Now)
                    {
                        textBox1.AppendText("Pomijam certyfikat - przyjazna nazwa: " + certificate.FriendlyName + Environment.NewLine);
                        textBox1.AppendText("       Pomijam certyfikat - Wystawiono dla: " + certificate.SubjectName.Name + Environment.NewLine);
                        textBox1.AppendText("       Pomijam certyfikat - Wystawca: " + certificate.Issuer + Environment.NewLine);
                        textBox1.AppendText("       Pomijam certyfikat - WYGASŁ: " + certExpiratioDate + Environment.NewLine);
                        continue;
                    }
                    else
                    {
                        textBox1.AppendText("Certyfikat - Przyjazna nazwa: " + certificate.FriendlyName + Environment.NewLine);
                        textBox1.AppendText("       Certyfikat - Wystawiono dla: " + certificate.SubjectName.Name + Environment.NewLine);
                        textBox1.AppendText("       Certyfikat - Wystawca: " + certificate.Issuer + Environment.NewLine);
                        textBox1.AppendText("       Certyfikat - Aktualny, ważny do: " + certExpiratioDate + Environment.NewLine);
                        ReturnCertificate = certificate;
                        
                        //Czy mam sprawdzać klucz prywatny
                        if (CheckPrivateKey == true)
                        {
                            if (ReturnCertificate.HasPrivateKey == true)
                            {
                                jestCert = true;
                                break;
                            }
                            else
                            {
                                jestCert = false;
                                textBox1.AppendText("       Pomijam certyfikat - BRAK KLUCZA PRYWATNEGO!!! " + Environment.NewLine);
                                //Szukam dalej
                                continue;
                            }
                        }
                        else
                        {
                            jestCert = true;
                            break;
                        }
                        
                    }
                }

            }
            keystore.Close();
            if (!jestCert) MessageBox.Show("Nie znalazłem certyfikatu klienta wg FriendlyName: " + FriendlyNameToFind);
            return jestCert;
        }

        private X509Certificate2 GetServiceCert()
        {
            X509Store store = new X509Store(StoreName.TrustedPeople, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            X509Certificate2 endPointCert = store.Certificates.Find(X509FindType.FindBySubjectName, "ePUAP-INT-WS-Sign", false)[0];
            store.Close();
            return endPointCert;
        }
    }
}

//Mój własny binding
//CustomBinding pullBinding = new CustomBinding();
//SymmetricSecurityBindingElement sbe = new SymmetricSecurityBindingElement();
//sbe.MessageProtectionOrder = MessageProtectionOrder.SignBeforeEncrypt;

//sbe.ProtectionTokenParameters = new KerberosSecurityTokenParameters();
////sbe.ProtectionTokenParameters = new X509SecurityTokenParameters();
////SecurityBindingElement sbe = SecurityBindingElement.CreateMutualCertificateBindingElement();

//sbe.MessageSecurityVersion = MessageSecurityVersion.WSSecurity10WSTrust13WSSecureConversation13WSSecurityPolicy12BasicSecurityProfile10;
//sbe.SecurityHeaderLayout = SecurityHeaderLayout.Strict;
//sbe.IncludeTimestamp = true;
//sbe.SetKeyDerivation(true);
//sbe.KeyEntropyMode = System.ServiceModel.Security.SecurityKeyEntropyMode.CombinedEntropy;
//sbe.DefaultAlgorithmSuite = SecurityAlgorithmSuite.Basic192Rsa15;

//pullBinding.Elements.Add(sbe);
//pullBinding.Elements.Add(new TextMessageEncodingBindingElement(MessageVersion.Soap11, System.Text.Encoding.UTF8));
//pullBinding.Elements.Add(new HttpsTransportBindingElement());

//X509Certificate2 endPointCert = new X509Certificate2();