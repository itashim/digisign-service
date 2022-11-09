package kz.bsbnb.portal.digisignservice.util;

import kz.gov.pki.kalkan.asn1.ASN1InputStream;
import kz.gov.pki.kalkan.asn1.DERObject;
import kz.gov.pki.kalkan.asn1.DEROctetString;
import kz.gov.pki.kalkan.asn1.ocsp.OCSPObjectIdentifiers;
import kz.gov.pki.kalkan.asn1.x509.X509Extension;
import kz.gov.pki.kalkan.asn1.x509.X509Extensions;
import kz.gov.pki.kalkan.jce.provider.KalkanProvider;
import kz.gov.pki.kalkan.ocsp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.io.ClassPathResource;

import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Hashtable;

public class OSCPCheck {
    private static final Logger logger = LoggerFactory.getLogger(OSCPCheck.class);
    // путь к сертификату который скачен с http://pki.gov.kz/cert/nca_gost.cer
    static final String CA_CERT_FILE = "nca_gost.cer";
    static final String OCSP_URL = "http://ocsp.pki.gov.kz";
    static byte[] nonce;

    static String strPkiDeadline = "12.08.2018";
    static SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy");

    /* Проверка ЭЦП на отозванность
     * certForCheck - сертификату ЭЦП человека
     * caCertFile - путь к сертификату который скачен с http://pki.gov.kz/cert/nca_gost.cer
     * OCSP_URL - "http://ocsp.pki.gov.kz"
     * */
    public static String checkForRevoked(X509Certificate certForCheck, X509Certificate cacert, String oscpUrl) throws Exception {
        String result = null;
        Security.addProvider(new KalkanProvider());

        URL url;
        HttpURLConnection con;
        OutputStream os;
        byte[] ocspReq = getOcspPackage(certForCheck.getSerialNumber(), cacert, CertificateID.HASH_GOST34311);
        logger.info("OSCP_CHECK IS_REVOKED " + ocspReq.toString());
        String b64Req = new String(java.util.Base64.getEncoder().encode(ocspReq));
        String getUrl = oscpUrl + "/" + b64Req;
        // сервис понимает и POST и GET, можно выбрать что-то одно
        logger.info("oscpUrl ={}", getUrl);
        if (getUrl.length() <= 2) {
            url = new URL(getUrl);
            con = (HttpURLConnection) url.openConnection();
        } else {
            url = new URL(oscpUrl);
            con = (HttpURLConnection) url.openConnection();
            con.setDoOutput(true);
            con.setRequestMethod("POST");
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            os = con.getOutputStream();
            os.write(ocspReq);
            os.close();
        }
        result = makeOcspResponse(con);
        con.disconnect();
        return result;
    }

    private static String makeOcspResponse(HttpURLConnection con)
            throws Exception {
        InputStream in = con.getInputStream();
        OCSPResp response = new OCSPResp(in);
        in.close();

        if (response.getStatus() != 0) {
            logger.error("Unsuccessful request. Status: "
                    + response.getStatus());
            throw new OCSPException("Unsuccessful request. Status: "
                    + response.getStatus());
        }
        BasicOCSPResp brep = (BasicOCSPResp) response.getResponseObject();
        byte[] respNonceExt = brep
                .getExtensionValue(OCSPObjectIdentifiers.id_pkix_ocsp_nonce
                        .getId());
        if (respNonceExt != null) {
            ASN1InputStream asn1In = new ASN1InputStream(respNonceExt);
            DERObject derObj = asn1In.readObject();
            asn1In.close();
            byte[] extV = DEROctetString.getInstance(derObj).getOctets();
            asn1In = new ASN1InputStream(extV);
            derObj = asn1In.readObject();
            asn1In.close();
            logger.info("nonces are equal: "
                    + java.util.Arrays.equals(nonce, DEROctetString.getInstance(derObj).getOctets()));
        }
        X509Certificate ocspcert = brep.getCerts(KalkanProvider.PROVIDER_NAME)[0];
        logger.info("OCSP Response sigAlg: "
                + brep.getSignatureAlgName());
        logger.info("OCSP Response verify: "
                + brep.verify(ocspcert.getPublicKey(), KalkanProvider.PROVIDER_NAME));

        SingleResp[] singleResps = brep.getResponses();
        SingleResp singleResp = singleResps[0];
        Object status = singleResp.getCertStatus();

        String result = "UNKNOWN";
        if (status == null) {
            logger.info("OCSP Response is GOOD");
            result = "GOOD";
        }
        if (status instanceof RevokedStatus) {
            result = "REVOKED";
            if (((RevokedStatus) status).hasRevocationReason()) {
                logger.info("REVOKED Time: " + ((RevokedStatus) status).getRevocationTime());
                logger.info("REVOKED Reason: " + ((RevokedStatus) status).getRevocationReason());
            }
        }
        if (status instanceof UnknownStatus) {
            result = "UNKNOWN";
            logger.info("OCSP Response is UNKNOWN");
        }
        return result;
    }

    private static byte[] getOcspPackage(BigInteger serialNr,
                                         Certificate cacert, String hashAlg) throws Exception {
        OCSPReqGenerator gen = new OCSPReqGenerator();
        CertificateID certId = new CertificateID(hashAlg,
                (X509Certificate) cacert, serialNr,
                KalkanProvider.PROVIDER_NAME);
        gen.addRequest(certId);
        gen.setRequestExtensions(generateExtensions());
        OCSPReq req;
        req = gen.generate();
        return req.getEncoded();
    }

    private static X509Extensions generateExtensions() {
        SecureRandom sr = new SecureRandom();
        nonce = new byte[8];
        sr.nextBytes(nonce);
        Hashtable exts = new Hashtable();
        X509Extension nonceext = new X509Extension(false,
                new DEROctetString(new DEROctetString(nonce)));
        // добавляем необязательный nonce, случайное число произвольной длины
        exts.put(OCSPObjectIdentifiers.id_pkix_ocsp_nonce, nonceext);
        return new X509Extensions(exts);
    }

    private static X509Certificate generateCert(String certFile)
            throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509",
                KalkanProvider.PROVIDER_NAME).generateCertificate(
                new FileInputStream(new ClassPathResource(certFile).getFile()));
    }
}
