package kz.bsbnb.portal.digisignservice.service.impl;

import kz.bsbnb.portal.digisignservice.model.SignVerificationInfo;
import kz.bsbnb.portal.digisignservice.model.SignatureInfo;
import kz.bsbnb.portal.digisignservice.service.DigisignService;
import kz.bsbnb.portal.digisignservice.util.DigiSignException;
import kz.bsbnb.portal.digisignservice.util.DigisignConfigProperties;
import kz.bsbnb.portal.digisignservice.util.OSCPCheck;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.jce.provider.cms.*;
import kz.gov.pki.kalkan.xmldsig.KncaXS;
import org.apache.commons.codec.binary.Hex;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.util.SerializationUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.bind.DatatypeConverter;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.*;

@Service
public class DigiSignServiceImpl implements DigisignService {
    private static final Logger logger = LoggerFactory.getLogger(DigiSignServiceImpl.class);
    @Value("${digisign.cer.path.root}")
    String rootCerPath;
    @Value("${digisign.cer.path.nca}")
    String ncaCerPath;
    @Value("${digisign.cer.path.key}")
    String keyCerPath;
    @Value("${digisign.oscp.url}")
    String oscpUrl;
    @Value("${digisign.crl.url}")
    String crlUrl;

    @Value("${http.proxyHost}")
    String proxyHostname;
    @Value("${http.proxyPort}")
    Integer proxyPort;

    String strPkiDeadline = "12.08.2018";
    SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy");

    @Autowired
    private DigisignConfigProperties digisignConfigProperties;
    private Boolean CRL = false;
    private Boolean D_CRL = false;

    public Boolean getCRL() {
        return CRL;
    }

    public void setCRL(Boolean CRL) {
        this.CRL = CRL;
    }

    public Boolean getD_CRL() {
        return D_CRL;
    }

    public void setD_CRL(Boolean d_CRL) {
        D_CRL = d_CRL;
    }

    //@Value(value = "classpath:GOSTKNCA_284e3708647f6fc17f35688604d589b3547e689f.p12")
    //private Resource resource;
    public DigiSignServiceImpl() {
    }

    public DigiSignServiceImpl(DigisignConfigProperties digisignConfigProperties) {
        this.digisignConfigProperties = digisignConfigProperties;
    }

    private boolean isSelfSigned(X509Certificate cert)
            throws CertificateException, NoSuchAlgorithmException,
            NoSuchProviderException {
        try {
            PublicKey key = cert.getPublicKey();
            cert.verify(key);
            return true;
        } catch (SignatureException | InvalidKeyException sigEx) {
            return false;
        }
    }


    private X509Certificate loadCert(String src) throws IOException {
        InputStream in = null;
        X509Certificate cert = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            in = new FileInputStream(src);
            cert = (X509Certificate) certFactory.generateCertificate(in);
        } catch (Throwable e) {
            logger.error(e.getMessage(), e);
        } finally {
            if (in != null) in.close();
        }
        return cert;
    }

    private X509Certificate loadCert(File src) throws IOException {
        InputStream in = null;
        X509Certificate cert = null;
        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            in = new FileInputStream(src);
            cert = (X509Certificate) certFactory.generateCertificate(in);
        } catch (Throwable e) {
            logger.error(e.getMessage(), e);
        } finally {
            if (in != null) in.close();
        }
        return cert;
    }

    private X509Certificate downloadCert(String urlString) {
        try {
            URL url = new URL(urlString);
            InputStream in = url.openStream();
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
            return cert;
        } catch (Throwable e) {
            logger.error(e.getMessage(), e);
            return null;
        }

    }

    private boolean verifyTrustChain(X509Certificate cert) throws DigiSignException {
        try {
            if (isSelfSigned(cert)) {
                throw new DigiSignException(
                        "The certificate is self-signed.");
            }
            Set<X509Certificate> additionalCerts = new HashSet<>();

            String issuer = cert.getIssuerX500Principal().getName();
            boolean isCertNew = IsCertNew(cert);
            String certPath1, certPath2;
            if (issuer.contains("RSA")) {
                logger.info("getTrust RSA");
                certPath1 = rootCerPath + "root_rsa.crt";
                if (!isCertNew) {
                    certPath2 = rootCerPath + "pki_rsa.crt";
                } else {
                    certPath2 = rootCerPath + "nca_rsa.crt";
                }
            } else {
                logger.info("getTrust GOST");
                certPath1 = rootCerPath + "root_gost.crt";
                if (!isCertNew) {
                    certPath2 = rootCerPath + "pki_gost.crt";
                } else {
                    certPath2 = rootCerPath + "nca_gost.crt";
                }
            }

            additionalCerts.add(loadCert(new File(certPath1)));
            additionalCerts.add(loadCert(new File(certPath2)));
            additionalCerts.add(cert);

            Set<X509Certificate> trustedRootCerts = new HashSet<X509Certificate>();
            Set<X509Certificate> intermediateCerts = new HashSet<X509Certificate>();
            for (X509Certificate additionalCert : additionalCerts) {
                if (isSelfSigned(additionalCert)) {
                    trustedRootCerts.add(additionalCert);
                } else {
                    intermediateCerts.add(additionalCert);
                }
            }

            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(cert);

            Set<TrustAnchor> trustAnchors = new HashSet<TrustAnchor>();
            for (X509Certificate trustedRootCert : trustedRootCerts) {
                trustAnchors.add(new TrustAnchor(trustedRootCert, null));
            }

            PKIXBuilderParameters pkixParams =
                    new PKIXBuilderParameters(trustAnchors, selector);

            pkixParams.setRevocationEnabled(false);

            CertStore intermediateCertStore = CertStore.getInstance("Collection",
                    new CollectionCertStoreParameters(intermediateCerts));
            pkixParams.addCertStore(intermediateCertStore);

            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");
            PKIXCertPathBuilderResult verifiedCertChai =
                    (PKIXCertPathBuilderResult) builder.build(pkixParams);


            return verifiedCertChai != null;
        } catch (CertPathBuilderException certPathEx) {
            throw new DigiSignException(
                    "Error building certification path: " +
                            cert.getSubjectX500Principal(), certPathEx);
        } catch (DigiSignException cvex) {
            throw cvex;
        } catch (Exception ex) {
            throw new DigiSignException(
                    "Error verifying the certificate: " +
                            cert.getSubjectX500Principal(), ex);
        }
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private boolean isSignCert(X509Certificate cert) {
        boolean[] usages = cert.getKeyUsage();
        return usages[0] && usages[1];
    }

    private boolean isAuthCert(X509Certificate cert) {
        try {
            if (cert.getExtendedKeyUsage() != null) {
                for (String exKeyUsage : cert.getExtendedKeyUsage()) {
                    if (exKeyUsage.equals("1.3.6.1.5.5.7.3.2")) {
                        return true;
                    }
                }
            }
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
        return false;
    }

    @Override
    public Boolean verifySignature(String document, String signatureString, String publicCertificate) throws DigiSignException {
        return verifySignature(document.getBytes(StandardCharsets.UTF_8), signatureString, publicCertificate);
    }

    private boolean IsCertNew(X509Certificate cert) throws ParseException {
        Date date = sdf.parse(strPkiDeadline);
        boolean isCertNew = false;
        if (cert.getNotBefore().before(date)) {
            isCertNew = false;
        } else {
            isCertNew = true;
        }
        return isCertNew;
    }

    private X509Certificate getCaCertForCheckRevoke(X509Certificate cert) throws ParseException, FileNotFoundException, CertificateException {
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        String caCertPath;

        boolean isCertNew = IsCertNew(cert);
        if (cert.getIssuerX500Principal().getName().contains("RSA")) {
            if (!isCertNew) {
                caCertPath = rootCerPath + "pki_rsa.crt";
            } else {
                caCertPath = rootCerPath + "nca_rsa.crt";
            }
        } else {
            if (!isCertNew) {
                caCertPath = rootCerPath + "pki_gost.crt";
            } else {
                caCertPath = rootCerPath + "nca_gost.crt";
            }
        }
        X509Certificate caCert = (X509Certificate) certFactory.generateCertificate(new FileInputStream(new File(caCertPath)));
        logger.info("OSCP_CHECK: Is cert new={}, caCertPath={}, certIssuer={}, caCertIssuer={} ", isCertNew, caCertPath, cert.getIssuerX500Principal().getName(), caCert.getIssuerX500Principal());
        return caCert;
    }

    @Override
    public Boolean verifySignature(byte[] document, String signatureString, String publicCertificate) throws DigiSignException {
        boolean result;
        try {
            Provider provider = new KalkanProvider();
            Security.addProvider(provider);

            ByteArrayInputStream in = new ByteArrayInputStream(publicCertificate.getBytes(StandardCharsets.UTF_8));
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);

            // validateCertificateType(cert, operationType);

            if (new Date().after(cert.getNotAfter())) { //Проверка даты по на валидность
                throw new DigiSignException("digisign.expired", DIGISIGN_ERROR_EXPIRED, DIGISIGN_ERROR_EXPIRED_MESSAGE_KEY);
            }

            //verifyTrustChain(cert);//Проверка цепочки доверия

            try {
                // TODO uncomment with  digisignConfigProperties
                // Проверка, не отозван ли сертификат пользователя по OSCP
                X509Certificate caCert = getCaCertForCheckRevoke(cert);

                String revokeStatus = OSCPCheck.checkForRevoked(cert, caCert, oscpUrl);
                if (revokeStatus.equals("UNKNOWN"))
                    isCertificeteRevoked(cert); // Проверка, не отозван ли сертификат пользователя по CRL
                else if (revokeStatus.equals("REVOKED")) {
                    throw new DigiSignException("digisign.revoked", DIGISIGN_ERROR_CODE_CERT_REVOKED, DIGISIGN_ERROR_REVOKED_MESSAGE_KEY);
                }
            } catch (Exception e) {
                if (e instanceof IOException) { // Continue code OSCP URL is Unreachable
                    isCertificeteRevoked(cert);// Проверка, не отозван ли сертификат пользователя по CRL
                } else {
                    logger.error(e.getMessage(), e);
                    throw new DigiSignException(e.getMessage(), e);
                }
            }

//            Signature signature = Signature.getInstance(cert.getSigAlgName(), provider.getName());
            Signature signature = Signature.getInstance(cert.getSigAlgName());
            signature.initVerify(cert);
            signature.update(document);
            result = signature.verify(DatatypeConverter.parseHexBinary(signatureString.replaceAll("\n", "")));//Проверка цифровой подписи
        } catch (CertificateException | SignatureException | InvalidKeyException | NoSuchAlgorithmException e) {
            logger.error(e.getMessage(), e);
            throw new DigiSignException(e.getMessage(), e);
        } catch (DigiSignException e) {
            logger.error(e.getMessage(), e);
            throw e;
        }
        return result;
    }

    private void verifySignature(X509Certificate cert) throws DigiSignException {
        if (new Date().after(cert.getNotAfter())) { //Проверка даты по на валидность
            throw new DigiSignException("digisign.expired", DIGISIGN_ERROR_EXPIRED, DIGISIGN_ERROR_EXPIRED_MESSAGE_KEY);
        }
        //verifyTrustChain(cert);//Проверка цепочки доверия

        try {
            // TODO uncomment with  digisignConfigProperties
            // Проверка, не отозван ли сертификат пользователя по OSCP
            X509Certificate caCert = getCaCertForCheckRevoke(cert);

            //TODO INDIRA_BPM_UNCOMMENT CRL CHECK
            String revokeStatus = "OK";//OSCPCheck.checkForRevoked(cert, caCert, oscpUrl);
            logger.info("OSCP_REVOKED_STATUS: {}", revokeStatus);
            if (revokeStatus.equals("UNKNOWN")) {
                isCertificeteRevoked(cert); // Проверка, не отозван ли сертификат пользователя по CRL
            } else if (revokeStatus.equals("REVOKED")) {
                throw new DigiSignException("digisign.revoked", DIGISIGN_ERROR_CODE_CERT_REVOKED, DIGISIGN_ERROR_REVOKED_MESSAGE_KEY);
            }
        } catch (Throwable e) {
            if (e instanceof DigiSignException)
                throw (DigiSignException) e;
            if (e instanceof IOException) { // Continue code OSCP URL is Unreachable
                logger.info("Continue code OSCP URL is Unreachable. Проверка, не отозван ли сертификат пользователя по CRL");
                logger.error(e.getMessage(), e);
                isCertificeteRevoked(cert);// Проверка, не отозван ли сертификат пользователя по CRL
            } else {
                logger.error(e.getMessage(), e);
                throw new DigiSignException(e.getMessage(), e);
            }
        }
    }

    @Override
    public Boolean verifyNCASignature(String document, String signatureString, int operationType) throws DigiSignException {
        return verifyNCASignature(document.getBytes(StandardCharsets.UTF_8), signatureString, operationType);
    }

    @Override
    public Boolean verifyNCASignature(byte[] document, String signatureString, int operationType) throws DigiSignException {
        boolean result = true;
        try {
            Provider provider = new KalkanProvider();
            Security.addProvider(provider);

            CMSSignedData e = new CMSSignedData(Base64.getDecoder().decode(String.valueOf(signatureString.getBytes(StandardCharsets.UTF_8))));
            boolean isAttachedContent = e.getSignedContent() != null;
            if (isAttachedContent) {
                e = new CMSSignedData(e.getEncoded());
            } else {
                CMSProcessableByteArray signers = new CMSProcessableByteArray(document);
                e = new CMSSignedData(signers, e.getEncoded());
            }

            SignerInformationStore signers1 = e.getSignerInfos();
            CertStore certs = e.getCertificatesAndCRLs("Collection", new KalkanProvider().getName());
            Iterator it = signers1.getSigners().iterator();

            while (it.hasNext()) {
                SignerInformation signer = (SignerInformation) it.next();
                SignerId signerConstraints = signer.getSID();
                Collection certCollection = certs.getCertificates(signerConstraints);

                X509Certificate cert;
                for (Object aCertCollection : certCollection) {
                    cert = (X509Certificate) aCertCollection;

                    if (new Date().after(cert.getNotAfter())) { //Проверка даты по на валидность
                        throw new DigiSignException("The certificate is expired");
                    }

                    validateCertificateType(cert, operationType);
                    verifyTrustChain(cert);//Проверка цепочки доверия
                    isCertificeteRevoked(cert);//Проверка, не отозван ли сертификат пользователя
                    result = result && signer.verify(cert, provider.getName());
                }
            }

        } catch (CertificateException | NoSuchAlgorithmException | CMSException | CertStoreException | IOException | NoSuchProviderException e) {
            logger.error(e.getMessage(), e);
            throw new DigiSignException(e.getMessage(), e);
        }
        return result;
    }

    private void validateCertificateType(X509Certificate cert, int operationType) throws DigiSignException {
        if (operationType == OPERATION_TYPE_AUTH && isSignCert(cert))//Если выполняется авторизация и выбран сертификат RSA
            throw new DigiSignException("Wrong certificate type. Must be AUTH, not RSA", DIGISIGN_ERROR_MUST_BE_AUTH_CERTIFICATE, "wrong_certificate_type_must_be_auth_message");
        if (operationType == OPERATION_TYPE_SIGN && isAuthCert(cert))//Если выполняется подписание и выбран сертификат AUTH
            throw new DigiSignException("Wrong certificate type. Must be RSA, not AUTH", DIGISIGN_ERROR_MUST_BE_RSA_CERTIFICATE, "wrong_certificate_type_must_be_rsa_message");
    }

    public String getPEMCertificate(Certificate certificate) {
        StringBuffer result = new StringBuffer();
        try {
            String cert_begin = "-----BEGIN CERTIFICATE-----\n";
            String end_cert = "\n-----END CERTIFICATE-----";
            String pemCertPre = new String(Base64.getEncoder().encode(certificate.getEncoded()));
            result.append(cert_begin).append(pemCertPre).append(end_cert);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
        return result.toString();
    }

    // resource is pkcs file path
    public SignatureInfo signString(String soap) {
        logger.info("Start signing");
//        Provider provider = new KalkanProvider();
//        Security.addProvider(provider);
        SignatureInfo result = new SignatureInfo();
        try {
//            File file = keystoreFile.getFile(keystoreFile);
//            String keystoreFileName = new StringBuffer(new File(this.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().getPath()).getParentFile().getParentFile().getPath()).append(CRL_FILE_DIR).append(digisignConfigProperties.getKeystoreFileName()).toString();
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            //keystore.load(resource.getInputStream(), digisignConfigProperties.getKeystoreFilePassword().toCharArray());
            keystore.load(new FileInputStream(new File(keyCerPath, digisignConfigProperties.getKeystoreFileName())),
                    digisignConfigProperties.getKeystoreFilePassword().toCharArray());
            keystore.load(new FileInputStream(new File(keyCerPath, digisignConfigProperties.getKeystoreFileName())), digisignConfigProperties.getKeystoreFilePassword().toCharArray());
            Enumeration<String> enumeration = keystore.aliases();
//            enumeration.hasMoreElements();
            String alias = enumeration.nextElement();
            PrivateKey key = (PrivateKey) keystore.getKey(alias, digisignConfigProperties.getKeystoreFilePassword().toCharArray());
            Certificate certificate = keystore.getCertificate(alias);
            System.out.print(certificate.getPublicKey().toString());

            final X509Certificate x509Certificate = (X509Certificate) keystore.getCertificate(alias);
            String sigAlgOid = x509Certificate.getSigAlgOID();

            //Signature signature = Signature.getInstance(digisignConfigProperties.getSignAlgName());
            Signature signature = Signature.getInstance(sigAlgOid);
            signature.initSign(key);
            signature.update(soap.getBytes());
            result.setSignature(new String(Hex.encodeHex(signature.sign())));
            result.setX509Certificate(getPEMCertificate(certificate));
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
        }
        return result;
    }

    public Principal getPrincipal(String x509Certificate) throws CertificateException {
        ByteArrayInputStream in = new ByteArrayInputStream(x509Certificate.getBytes(StandardCharsets.UTF_8));
        CertificateFactory certFactory = null;
        certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);
        return cert.getSubjectDN();
    }

    private X509CRL downloadCRL(String crlURL)
            throws IOException, CertificateException,
            CRLException {
        URL url = new URL(crlURL);
        InputStream crlStream = url.openStream();
        return loadCrlFromStream(crlStream);
    }

    private X509CRL loadFromFile(String src)
            throws IOException, CertificateException,
            CRLException {
        InputStream crlStream = new FileInputStream(src);
        return loadCrlFromStream(crlStream);
    }

    private X509CRL loadCrlFromStream(InputStream crlStream) throws CertificateException, CRLException, IOException {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509CRL crl = (X509CRL) cf.generateCRL(crlStream);
            return crl;
        } finally {
            crlStream.close();
        }
    }

    private void isCertificeteRevoked(X509Certificate cert, String crlFileName)
            throws DigiSignException {
        try {
            X509CRL crl = loadFromFile(new File(ncaCerPath, crlFileName).getAbsolutePath());

            if (crl.isRevoked(cert)) {
                logger.error("CRL_CHECK FROM FILE={}, STATUS: REVOKED", crlFileName);
                throw new DigiSignException("digisign.revoked", DIGISIGN_ERROR_CODE_CERT_REVOKED, DIGISIGN_ERROR_REVOKED_MESSAGE_KEY);
            }
        } catch (Exception ex) {
            logger.error(ex.getMessage(), ex);
            if (ex instanceof DigiSignException) {
                throw (DigiSignException) ex;
            } else {
                throw new DigiSignException(
                        "Can not verify CRL for certificate: " +
                                cert.getSubjectX500Principal() + ", original exception = " + ex.getMessage());
            }
        }
    }

    private void isCertificeteRevoked(X509Certificate cert)
            throws DigiSignException {
        for (String crlFileName : CRL_FILE_NAMES) {
            isCertificeteRevoked(cert, crlFileName);
        }
    }

    private void replaceFileNew(String srcUrl, String dstFileName, Boolean force) {
        logger.info(LocalDateTime.now().toString() + " Update started->" + dstFileName);
        try {
            URL link = new URL(srcUrl);
            logger.info("->WithProxy url={}, proxy={}:{}", srcUrl, proxyHostname, proxyPort);
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHostname, proxyPort));
            URLConnection con = null;
            InputStream in = null;
            try {
                con = link.openConnection(proxy);
                con.setConnectTimeout(120000);
                con.setReadTimeout(120000);
                in = con.getInputStream();

            } catch (Exception e) {
                logger.error(e.getMessage(), e);
                logger.info("->No Proxy");
                con = link.openConnection();
                con.setConnectTimeout(120000);
                con.setReadTimeout(120000);
                in = con.getInputStream();
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int n = 0;
            while (-1 != (n = in.read(buf))) {
                out.write(buf, 0, n);
            }
            out.close();
            in.close();
            byte[] response = out.toByteArray();

            File crlFile = new File(dstFileName);
            if (crlFile.exists() && response != null) {
                FileOutputStream fos = new FileOutputStream(crlFile, false);
                fos.write(response);
                fos.close();
            }
            if (dstFileName.equals(this.CRL_FILE_NAME)) {
                setCRL(true);
            } else {
                setD_CRL(true);
            }
            logger.info(LocalDateTime.now().toString() + " Success->" + dstFileName);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            if (dstFileName.equals(this.CRL_FILE_NAME)) {
                setCRL(false);
            } else {
                setD_CRL(false);
            }
        }
    }

    //@Scheduled(cron = "0 * * * * *") // At second :00, at minute :00, every 2 hours starting at 00am, of every day
    //public void test() {
    //    logger.info("TEST SCHEDULING");
    //}

    @Scheduled(cron = "0 0 0/2 * * *") // At second :00, at minute :00, every 2 hours starting at 00am, of every day
    public void updateDeltaCrlFile() {
        logger.info("Update Delta CRL file");
        try {
            replaceFileNew(crlUrl+ DELTA_GOST_FILE_NAME, ncaCerPath+DELTA_GOST_FILE_NAME, true);
            replaceFileNew(crlUrl+DELTA_CRL_FILE_NAME, ncaCerPath+DELTA_CRL_FILE_NAME, true);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Scheduled(cron = "0 0 6,20 ? * *") // At second :00, at minute :00, at 06am and 20pm, of every day
    public void updateCrlFiles() {
        try {
            if (!getCRL()) {
                replaceFileNew(crlUrl + CRL_FILE_NAME, ncaCerPath+CRL_FILE_NAME,  false);
                replaceFileNew(crlUrl + GOST_FILE_NAME, ncaCerPath + GOST_FILE_NAME, false);
            }
            if (!getD_CRL()) {
                replaceFileNew(crlUrl+ DELTA_GOST_FILE_NAME, ncaCerPath+DELTA_GOST_FILE_NAME, false);
                replaceFileNew(crlUrl+DELTA_CRL_FILE_NAME, ncaCerPath+DELTA_CRL_FILE_NAME, false);
            }
        } catch (Exception e) {
            logger.error("Update CRL file", e);
            e.printStackTrace();
        }
    }

    @Override
    public SignVerificationInfo verifyXmlSignature(String xmlString) {
        SignVerificationInfo signVerificationInfo = new SignVerificationInfo();
        try {
            Provider provider = new KalkanProvider();
            Security.addProvider(provider);
            // загружаем конфигурацию либо магической функцией
            KncaXS.loadXMLSecurity();

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);

            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Document doc = documentBuilder.parse(new ByteArrayInputStream(xmlString.getBytes("UTF-8")));
            signVerificationInfo.setDocument(doc);

            Element sigElement = null;
            Element rootEl = (Element) doc.getFirstChild();

            NodeList list = rootEl.getElementsByTagName("ds:Signature");
            int length = list.getLength();

            Node sigNode = list.item(length - 1);
            sigElement = (Element) sigNode;
            if (sigElement == null) {
                logger.error("Bad signature: Element 'ds:Reference' is not found in XML document");
            }
            XMLSignature signature = new XMLSignature(sigElement, "");
            KeyInfo ki = signature.getKeyInfo();
            X509Certificate cert = ki.getX509Certificate();

            try {
                logger.info("verifySignature subDn={}", cert.getSubjectDN());
                if (cert != null) {
                    signVerificationInfo.setPrincipal(cert.getSubjectDN().getName());
                    signVerificationInfo.setCertificate(SerializationUtils.serialize(cert));
                }
                verifySignature(cert);
                signVerificationInfo.setSignatureValid(true);

            } catch (DigiSignException exp) {
                if (exp.getErrorCode() == DIGISIGN_ERROR_CODE_CERT_REVOKED) {
                    logger.error(":: SIGN_ERROR subDn=" + cert.getSubjectDN() + ", CERT_REVOKED");
                    signVerificationInfo.setSignatureRevoked(true);
                    return signVerificationInfo;
                } else if (exp.getErrorCode() == DIGISIGN_ERROR_EXPIRED) {
                    logger.error(":: SIGN_ERROR subDn=" + cert.getSubjectDN() + ", CERT_EXPIRED");
                    signVerificationInfo.setSignaturExpired(true);
                    return signVerificationInfo;
                } else {
                    signVerificationInfo.setSignatureValid(false);
                    logger.error(":: SIGN_EXP subDn=" + cert.getSubjectDN(), exp);
                    return signVerificationInfo;
                }
            }
        } catch (Exception e) {
            signVerificationInfo.setSignatureValid(false);
            logger.error("VERIFICATION RESULT IS: " + signVerificationInfo.isSignatureValid(), e);
        }
        return signVerificationInfo;
    }
}
