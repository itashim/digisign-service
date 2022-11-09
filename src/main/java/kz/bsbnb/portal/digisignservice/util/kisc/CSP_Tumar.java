package kz.bsbnb.portal.digisignservice.util.kisc;

import kz.bsbnb.portal.digisignservice.util.DigiSignException;
import kz.gamma.asn1.ASN1InputStream;
import kz.gamma.asn1.DEROctetString;
import kz.gamma.asn1.DERSequence;
import kz.gamma.asn1.DERTaggedObject;
import kz.gamma.asn1.ocsp.OCSPResponseStatus;
import kz.gamma.cms.Pkcs7Data;
import kz.gamma.jce.X509Principal;
import kz.gamma.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.cert.CertificateException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

public class CSP_Tumar {
    private static final Logger _log = LoggerFactory.getLogger(CSP_Tumar.class);

    public static X509Certificate getCertificateFromString(String pCert)
            throws CertificateExpiredException, CertificateNotYetValidException, Exception {
        _log.trace("getCertificateFromString");
        byte[] pkcs7_bytes;
        X509Certificate cer_ = null;
        pkcs7_bytes = Base64.decode(pCert);
        Pkcs7Data pkcs7 = new Pkcs7Data(pkcs7_bytes);
        //Pkcs7Data pkcs7 = new Pkcs7Data(pCert.getBytes());
        cer_ = pkcs7.getCertificateOfSigner();
        _log.trace("return certificate");
        _log.debug(cer_.toString());
        return cer_;
    }

    public static X509Certificate convertToX509Certificate(String pem) throws CertificateException, IOException {
        CertificateFactory certFactory = null;
        X509Certificate cert = null;
        String cerHead = "-----BEGIN CERTIFICATE-----\n";
        String cerEnd = "\n-----END CERTIFICATE-----";
        String cert_str = cerHead.concat(pem).concat(cerEnd);

        try {
            certFactory = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(cert_str.getBytes());
            cert = (X509Certificate) certFactory.generateCertificate(in);
        } catch (java.security.cert.CertificateException e) {
            // TODO Auto-generated catch block
            _log.error("", e);
        }
        return cert;
    }

    public static String[] getBinIinFromCertificate(X509Certificate userCertificate) {
        _log.info("getBinIinFromCertificate input");
        String[] data = null;
//        SubjectDNParser dnParser = new SubjectDNParser(userCertificate.getSubjectDN());
//        _log.info("iin = "+dnParser.getIin());
//        _log.info("bin = "+dnParser.getBin());
        ASN1InputStream extensionStream = null;
        try {
            byte[] extensionBytes =
                    userCertificate.getExtensionValue("2.5.29.17");
            _log.info("extensionBytes " + extensionBytes.toString());
            if (extensionBytes != null) {
                _log.info("if");
                extensionStream = new ASN1InputStream(extensionBytes);
                DEROctetString octetString = (DEROctetString) extensionStream.readObject();
                extensionStream.close();
                extensionStream = new ASN1InputStream(octetString.getOctets());
                DERSequence sequence = (DERSequence) extensionStream.readObject();
                extensionStream.close();
                _log.info("subjectAltNames");
                Enumeration subjectAltNames = sequence.getObjects();
                String bin = null;
                String iin = null;
                List<String[]> aliasList = new ArrayList<String[]>();
                while (subjectAltNames.hasMoreElements()) {
                    DERTaggedObject nextElement = (DERTaggedObject) subjectAltNames.nextElement();
                    _log.info("while " + nextElement.toString());
                    X509Principal x509Principal = new X509Principal(nextElement.getObject().getEncoded());
                    _log.info(x509Principal.toString());
                    aliasList.add(x509Principal.toString().split(","));

                }
                _log.info("alias size =" + aliasList.size());
                if (aliasList.size() == 3) {
                    bin = getSerialNumber(aliasList.get(1));
                    iin = getSerialNumber(aliasList.get(2));

                } else {
                    iin = getSerialNumber(aliasList.get(1));
                }
                _log.trace("get iin bin");
                if (bin != null && iin != null) { // est' i bin i iin
                    _log.debug("bin :" + bin);
                    _log.debug("iin :" + iin);
                    data = new String[2];
                    data[1] = bin;
                    data[0] = iin;
                } else if (iin != null) { // tol'ko iin
                    _log.debug("iin :" + iin);
                    data = new String[1];
                    data[0] = iin;
                }
            }
        } catch (Exception e) {
            _log.error(":: CERT=" + userCertificate.getSubjectDN(), e);
        } finally {
            if (extensionStream != null) {
                try {
                    extensionStream.close();
                } catch (IOException e) {
                    _log.error(":: CERT=" + userCertificate.getSubjectDN(), e);
                }
            }
        }
        _log.trace("getBinIinFromCertificate return");
        return data;
    }

    private static String getSerialNumber(String[] str) {
        String result = null;
        for (int i = 0; i < str.length; i++) {
            String[] str_values = str[i].split("=");
            if (str_values[0].equals("SERIALNUMBER")) {
                result = str_values[1];
                break;
            }
        }
        return result;
    }

    public static boolean checkCert(X509Certificate p_cert, String oscpUrl) throws DigiSignException {
        try {
            p_cert.checkValidity(new Date());
        } catch (CertificateExpiredException ce) {
            _log.error("CertificateExpiredException", ce);
            throw new DigiSignException(DigiSignException.CERT_EXPIRED, ce.getMessage());
        } catch (CertificateNotYetValidException cnyve) {
            _log.error("CertificateNotYetValidException", cnyve);
            throw new DigiSignException(DigiSignException.CERT_NOT_VALID, cnyve.getMessage());
        } catch (Exception e) {
            _log.error("CertificateException", e);
            throw new DigiSignException(DigiSignException.CERT_ERROR, e.getMessage());
        }

        try {
            int ocspResult = OcspRequest.getOCSPStatus(p_cert, oscpUrl);
            String result = "";
            switch (ocspResult) {
                case OCSPResponseStatus.SUCCESSFUL:
                    result = "SUCCESSFUL";
                    break;
                case OCSPResponseStatus.MALFORMED_REQUEST:
                    result = "MALFORMED_REQUEST";
                    break;
                case OCSPResponseStatus.INTERNAL_ERROR:
                    result = "INTERNAL_ERROR";
                    break;
                case OCSPResponseStatus.TRY_LATER:
                    result = "TRY_LATER";
                    break;
                case OCSPResponseStatus.SIG_REQUIRED:
                    result = "SIG_REQUIRED";
                    break;
                case OCSPResponseStatus.UNAUTHORIZED:
                    result = "UNAUTHORIZED";
                    break;
                default:
                    result = "UNKNOWN RESULT";
                    break;
            }
            _log.info("RESULT STATUS OSCP: " + result + ", " + ocspResult + ", cer=" + p_cert.getSubjectDN());
            if (ocspResult == OCSPResponseStatus.SUCCESSFUL) {
                return true;
            } else {
                throw new DigiSignException(DigiSignException.CERT_ERROR, result);
            }
        } catch (Exception e) {
            _log.error("CertificateEXCEPTION cert=" + p_cert.getSubjectDN(), e);
            throw new DigiSignException(DigiSignException.CERT_ERROR, e.getMessage());
        }
    }
}

