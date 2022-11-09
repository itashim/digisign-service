package kz.bsbnb.portal.digisignservice.service;

import com.sun.org.apache.xpath.internal.XPathAPI;
import kz.bsbnb.portal.digisignservice.model.SignVerificationInfo;
import kz.bsbnb.portal.digisignservice.util.kisc.CSP_Tumar;
import kz.gamma.asn1.x509.X509Name;
import kz.gamma.tumarcsp.params.StoreObjectParam;
import kz.gamma.xmldsig.JCPXMLDSigInit;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.XMLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.SerializationUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;

public class KsmrDigiSignService {
    private static final Logger logger = LoggerFactory.getLogger(KsmrDigiSignService.class);

    /**
     *
     */
    public static void profileTest() {
        try {
            // Формируем класс хранилища ключей, будут доступны все профайлы криптопровайдера.
            KeyStore store = loadKeyStore();
            //Получение списка ключей
            Enumeration en = store.aliases();
            while (en.hasMoreElements()) {
                StoreObjectParam profParam = (StoreObjectParam) en.nextElement();
                System.out.println(profParam);
            }
            // Получение закрытого ключа по DN имени сертификата
            String DName = "C=KZ,O=Веб портал НБ РК,OU=АО «Банковское сервисное бюро Национального Банка Казахстана»,CN=Баймухаметов Асет Рашидович,UID=IIN810506350776";
            PrivateKey prvKey = getPrivateKey(DName, store, "123456");
            if (prvKey != null) {
                //Получение сертификата по DN имени
                Certificate cert = getCertificate(DName, store, "123456");

                if (cert != null) {
                    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                    dbf.setNamespaceAware(true);
                    DocumentBuilder builder = dbf.newDocumentBuilder();
                    InputSource source = null;
                    source = new InputSource(new FileInputStream("D:\\test.xml"));

                    //source = new InputSource(new FileInputStream("D:\\ksmr_signed_xml.xml"));
                    // Подписываем XML документ
                    String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n" +
                            "<root><login>testing</login>\n" +
                            "<password1>testing</password1>\n" +
                            "<password2>testing</password2>\n" +
                            "<currentPosition>1</currentPosition><email/><fullname>ТЕСТОВ ТЕСТ</fullname><lifetime>09.10.2020</lifetime><iin>123456789011</iin><bin>123456789021</bin>\n" +
                            "<orgName>АО \\\"ТЕСТ\\\"</orgName>\n" +
                            "</root>";
                    Document doc = parseXml(xml);

                    // Подписываем XML документ
                    Document sigDoc = signXML(doc, cert, prvKey);
                    // Проверяем подпись XML документа
                    if (!validateXML(sigDoc))
                        throw new Exception("Подпись не прошла проверку");
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * @param profile
     * @param pass
     */
    public static void profileTest(String profile, String pass) {
        try {
            //Формируем класс хранилища ключей из профайла.
            KeyStore store = loadKeyStore(profile, pass);
            //Получение списка ключей
            Enumeration en = store.aliases();
            while (en.hasMoreElements()) {
                StoreObjectParam profParam = (StoreObjectParam) en.nextElement();
                System.out.println(profParam);
            }
            //Получение закрытого ключа по DN имени сертификата
            PrivateKey prvKey = getPrivateKey("C=KZ,O=GAMMA,CN=GAMMAJCE", store, pass);
            if (prvKey != null) {
                //Получение сертификата по DN имени
                Certificate cert = getCertificate("C=KZ,O=GAMMA,CN=GAMMAJCE", store, "");
                if (cert != null) {
                    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
                    dbf.setNamespaceAware(true);
                    DocumentBuilder builder = dbf.newDocumentBuilder();
                    InputSource source = null;
                    source = new InputSource(new FileInputStream("C:\\temp\\config.xml"));
                    // Подписываем XML документ
                    Document sigDoc = signXML(builder.parse(source), cert, prvKey);
                    // Проверяем подпись XML документа
                    if (!validateXML(sigDoc))
                        throw new Exception("Подпись не прошла проверку");
                }
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    /**
     * Создаем экземпляр класса для работы с TumarCSP.
     * Данный метод загружает все ключи и сертификаты доступные в данный момент
     *
     * @return
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public static KeyStore loadKeyStore() throws NoSuchProviderException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore store = KeyStore.getInstance("PKS", "GAMMA");
        store.load(null, null);
        return store;
    }

    /**
     * Создаем экземпляр класса для работы с TumarCSP.
     * Данный метод загружает ключи из выбранного профайла, при этом можно задать пароль на профайл
     *
     * @param profileName
     * @param pass
     * @return
     * @throws NoSuchProviderException
     * @throws KeyStoreException
     * @throws IOException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     */
    public static KeyStore loadKeyStore(String profileName, String pass) throws NoSuchProviderException, KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {
        KeyStore store = KeyStore.getInstance("GKS", "GAMMA");
        store.load(new ByteArrayInputStream(profileName.getBytes()), pass.toCharArray());
        return store;
    }

    /**
     * Функция создает экземпляр класса приватного ключа для подписи.
     * Если будет несколько сертификатов с одним именем то загрузить самый новый
     *
     * @param DName
     * @param store
     * @param pass
     * @return
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    public static PrivateKey getPrivateKey(String DName, KeyStore store, String pass) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Enumeration en = store.aliases();
        Date tmpDate = null;
        String tmpSN = "";
        while (en.hasMoreElements()) {
            StoreObjectParam prm = (StoreObjectParam) en.nextElement();
            if ((new X509Name(DName)).equals(new X509Name(prm.dn))) {
                if (tmpDate == null) {
                    tmpDate = prm.timeCreate;
                    tmpSN = prm.sn;
                } else {
                    if (prm.timeCreate.after(tmpDate)) {
                        tmpDate = prm.timeCreate;
                        tmpSN = prm.sn;
                    }
                }
            }
        }
        return (PrivateKey) store.getKey(tmpSN, pass.toCharArray());
    }

    /**
     * Функция создает экземпляр класса сертификата.
     * Если будет несколько сертификатов с одним именем то загрузить самый новый
     *
     * @param DName
     * @param store
     * @param pass
     * @return
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    public static Certificate getCertificate(String DName, KeyStore store, String pass) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Enumeration en = store.aliases();
        Date tmpDate = null;
        String tmpSN = "";
        while (en.hasMoreElements()) {
            StoreObjectParam prm = (StoreObjectParam) en.nextElement();
            if ((new X509Name(DName)).equals(new X509Name(prm.dn))) {
                if (tmpDate == null) {
                    tmpDate = prm.timeCreate;
                    tmpSN = prm.sn;
                } else {
                    if (prm.timeCreate.after(tmpDate)) {
                        tmpDate = prm.timeCreate;
                        tmpSN = prm.sn;
                    }
                }
            }
        }
        return store.getCertificate(tmpSN);
    }

    /**
     * Функция создает цепочку сертификатов.
     * Если будет несколько сертификатов с одним именем то загрузить самый новый
     *
     * @param DName
     * @param store
     * @param pass
     * @return
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableKeyException
     */
    public static Certificate[] getCertificateChain(String DName, KeyStore store, String pass) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
        Enumeration en = store.aliases();
        Date tmpDate = null;
        String tmpSN = "";
        while (en.hasMoreElements()) {
            StoreObjectParam prm = (StoreObjectParam) en.nextElement();
            if ((new X509Name(DName)).equals(new X509Name(prm.dn))) {
                if (tmpDate == null) {
                    tmpDate = prm.timeCreate;
                    tmpSN = prm.sn;
                } else {
                    if (prm.timeCreate.after(tmpDate)) {
                        tmpDate = prm.timeCreate;
                        tmpSN = prm.sn;
                    }
                }
            }
        }
        return store.getCertificateChain(tmpSN);
    }

    /**
     * Метод формирования подписи xml документа
     *
     * @param doc
     * @param cert
     * @param privKey
     * @return
     * @throws Exception
     */
    public static Document signXML(Document doc, Certificate cert, PrivateKey privKey)
            throws Exception {
        String signMethod = "http://www.w3.org/2001/04/xmldsig-more#gost34310-gost34311";
        String digestMethod = "http://www.w3.org/2001/04/xmldsig-more#gost34311";
        XMLSignature sig = new XMLSignature(doc, "", signMethod);
        String res = "";
        if (doc.getFirstChild() != null) {
            doc.getFirstChild().appendChild(sig.getElement());
            Transforms transforms = new Transforms(doc);
            transforms.addTransform("http://www.w3.org/2000/09/xmldsig#enveloped-signature");
            transforms.addTransform("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments");
            sig.addDocument("", transforms, digestMethod);
            sig.addKeyInfo((X509Certificate) cert);
            sig.sign(privKey);
            StringWriter os = new StringWriter();
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer trans = tf.newTransformer();
            trans.transform(new DOMSource(doc), new StreamResult(os));
            os.flush();
            res = os.toString();
            os.close();
        }
        return parseXml(res);
    }

    /**
     * Метод проверки подписи xml документа
     *
     * @param doc
     * @return
     * @throws Exception
     */
    public static boolean validateXML(Document doc)
            throws Exception {
        // Если уже один раз был объявлен данный метод, то его повторно не нужно объявлять
        //JCPXMLDSigInit.init();
        Element nscontext = XMLUtils.createDSctx(doc, "ds", "http://www.w3.org/2000/09/xmldsig#");
        Element sigElement = (Element) XPathAPI.selectSingleNode(doc, "//ds:Signature[1]", nscontext);
        XMLSignature signature = new XMLSignature(sigElement, "");
        KeyInfo ki = signature.getKeyInfo();
        X509Certificate certKey = ki.getX509Certificate();
        boolean result = false;
        logger.info("::KISC CER={}, IssuerDN={}, IssuerX500Principal ={}", certKey.getSubjectDN(), certKey.getIssuerDN(), certKey.getIssuerX500Principal());
        if (certKey != null) {
            try {
                String iinBin[] = CSP_Tumar.getBinIinFromCertificate(certKey);
                result = signature.checkSignatureValue(certKey);
                String oscpUrl = "http://91.195.226.34:62255";//http://ca.kisc.kz:62255";
                CSP_Tumar.checkCert(certKey, oscpUrl);
            } catch (Exception exp) {
                logger.error("", exp);
            }
        } else {
            PublicKey pk = ki.getPublicKey();
            if (pk != null)
                result = signature.checkSignatureValue(pk);
            else
                throw new Exception("Нет информации об открытом ключе. Проверка невозможна.");
        }
        return result;
    }


    /**
     * Метод проверки подписи xml документа
     *
     * @param xmlString
     * @return
     * @throws Exception
     */
    public static SignVerificationInfo validateXML(String xmlString, String oscpUrl)
            throws Exception {
        // Если уже один раз был объявлен данный метод, то его повторно не нужно объявлять
        JCPXMLDSigInit.init();

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        Document doc = documentBuilder.parse(new ByteArrayInputStream(xmlString.getBytes("UTF-8")));

        SignVerificationInfo signVerificationInfo = null;
        signVerificationInfo = new SignVerificationInfo();
        signVerificationInfo.setDocument(doc);

        Element nscontext = XMLUtils.createDSctx(doc, "ds", "http://www.w3.org/2000/09/xmldsig#");
        Element sigElement = (Element) XPathAPI.selectSingleNode(doc, "//ds:Signature[1]", nscontext);
        XMLSignature signature = new XMLSignature(sigElement, "");
        KeyInfo ki = signature.getKeyInfo();
        X509Certificate certKey = ki.getX509Certificate();
        if (certKey != null) {
            logger.info("::KISC CER={}, IssuerDN={}, IssuerX500Principal ={}", certKey.getSubjectDN(), certKey.getIssuerDN(), certKey.getIssuerX500Principal());
            //signVerificationInfo.setSignatureValid(signature.checkSignatureValue(certKey));
            signVerificationInfo.setSignatureValid(true);
            signVerificationInfo.setPrincipal(certKey.getSubjectDN().getName());
            signVerificationInfo.setCertificate(SerializationUtils.serialize(certKey));

            if (new Date().after(certKey.getNotAfter())) { //Проверка даты по на валидность
                signVerificationInfo.setSignaturExpired(true);
            }

            try {
                if (!CSP_Tumar.checkCert(certKey, oscpUrl))
                    signVerificationInfo.setSignatureRevoked(true);
            } catch (Exception exp) {
                signVerificationInfo.setSignatureRevoked(true);
                signVerificationInfo.setSignatureError(exp.getMessage());
            }
        } else {
            PublicKey pk = ki.getPublicKey();
            if (pk != null) {
                signVerificationInfo.setSignatureValid(signature.checkSignatureValue(pk));
            } else {
                logger.info("::KISC_ERROR CER={}, IssuerDN={}, IssuerX500Principal ={} public KEY IS NULL", certKey.getSubjectDN(), certKey.getIssuerDN(), certKey.getIssuerX500Principal());
                signVerificationInfo.setSignatureValid(false);
            }
        }
        return signVerificationInfo;
    }

    public static String[] getBinIinFromCertificate(String xmlString) throws Exception {
        // Если уже один раз был объявлен данный метод, то его повторно не нужно объявлять
        // Если уже один раз был объявлен данный метод, то его повторно не нужно объявлять
        JCPXMLDSigInit.init();

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
        Document doc = documentBuilder.parse(new ByteArrayInputStream(xmlString.getBytes("UTF-8")));

        Element nscontext = XMLUtils.createDSctx(doc, "ds", "http://www.w3.org/2000/09/xmldsig#");
        Element sigElement = (Element) XPathAPI.selectSingleNode(doc, "//ds:Signature[1]", nscontext);
        XMLSignature signature = new XMLSignature(sigElement, "");
        KeyInfo ki = signature.getKeyInfo();
        X509Certificate certKey = ki.getX509Certificate();
        if (certKey != null) {
            logger.info(":: GET_BIN_CERT cert={}", certKey.getSubjectDN());
            return CSP_Tumar.getBinIinFromCertificate(certKey);
        } else {
            throw new Exception("Certificate is null!!!");
        }
    }


    /**
     * @param xml
     * @return
     * @throws Exception
     */
    public static Document parseXml(String xml)
            throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        InputSource source = null;
        source = new InputSource(new StringReader(xml));
        System.out.println("****************************");
        System.out.println(xml);
        System.out.println("****************************");
        return builder.parse(source);
    }

    /**
     * @param reader
     * @return
     * @throws IOException
     */
    public static String readBigString(BufferedReader reader)
            throws IOException {
        StringBuffer buf = new StringBuffer();
        for (String curr = reader.readLine(); curr != null; curr = reader.readLine())
            buf.append((new StringBuilder(String.valueOf(curr))).append("\n").toString());

        return buf.toString();
    }

    /**
     * @param xml
     * @return
     */
    public static String stripXml(String xml) {
        String result = xml.trim();
        return result;
    }

    /**
     * @param fileName
     */
    public static void veryfyXMLTest(String fileName) {
        try {
            if (!validateXML(parse(fileName, true)))
                System.out.println("Подпись не прошла проверку");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * @param fileName
     * @param decode
     * @return
     * @throws Exception
     */
    public static Document parse(String fileName, boolean decode)
            throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder builder = dbf.newDocumentBuilder();
        InputSource source = null;
        if (decode) {
            String input = stripXml(readBigString(new BufferedReader(new InputStreamReader(new FileInputStream(fileName), "UTF-8"))));
            input = input.replaceAll("&amp;", "&");
            input = input.replaceAll("&quot;", "\"");
            input = input.replaceAll("&quote;", "\"");
            input = input.replaceAll("&gt;", ">");
            input = input.replaceAll("&lt;", "<");
            System.out.println((new StringBuilder("Input: ")).append(input).toString());
            source = new InputSource(new StringReader(input));
        } else {
            source = new InputSource(new FileInputStream(fileName));
        }
        return builder.parse(source);
    }
}
