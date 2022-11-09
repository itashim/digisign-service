package kz.bsbnb.portal.digisignservice.service;

import kz.bsbnb.portal.digisignservice.model.SignVerificationInfo;
import kz.bsbnb.portal.digisignservice.model.SignatureInfo;
import kz.bsbnb.portal.digisignservice.util.DigiSignException;

import java.security.Principal;
import java.security.cert.CertificateException;

public interface DigisignService {
    int DIGISIGN_ERROR_CODE_CERT_REVOKED = 1;
    int DIGISIGN_ERROR_MUST_BE_RSA_CERTIFICATE = 2;
    int DIGISIGN_ERROR_MUST_BE_AUTH_CERTIFICATE = 3;
    int DIGISIGN_ERROR_EXPIRED = 4;
    String DIGISIGN_ERROR_EXPIRED_MESSAGE_KEY = "cert_experied_message";
    String DIGISIGN_ERROR_REVOKED_MESSAGE_KEY = "cert_revoked_message";

    //Если выполняется авторизация и выбран сертификат RSA
    int OPERATION_TYPE_SIGN = 2;
    //Если выполняется подписание и выбран сертификат AUTH
    int OPERATION_TYPE_AUTH = 3;

    String CRL_FILE_NAME = "nca_rsa.crl";
    String GOST_FILE_NAME = "nca_gost.crl";
    String DELTA_CRL_FILE_NAME = "nca_d_rsa.crl";
    String DELTA_GOST_FILE_NAME = "nca_d_gost.crl";

    String[] CRL_FILE_NAMES = new String[]{DELTA_CRL_FILE_NAME, DELTA_GOST_FILE_NAME, CRL_FILE_NAME, GOST_FILE_NAME};

    // String CRL_FILE_URL = "http://crl.pki.gov.kz/rsa.crl";
    // String DELTA_CRL_FILE_URL = "http://crl.pki.gov.kz/d_rsa.crl";

    Boolean verifySignature(String document, String signatureString, String publicCertificate) throws DigiSignException;

    Boolean verifySignature(byte[] document, String signatureString, String publicCertificate) throws DigiSignException;

    Boolean verifyNCASignature(String document, String signatureString, int operationType) throws DigiSignException;

    Boolean verifyNCASignature(byte[] document, String signatureString, int operationType) throws DigiSignException;

    SignatureInfo signString(String soap);

    Principal getPrincipal(String x509Certificate) throws CertificateException;

    SignVerificationInfo verifyXmlSignature(String xmlString);
}
