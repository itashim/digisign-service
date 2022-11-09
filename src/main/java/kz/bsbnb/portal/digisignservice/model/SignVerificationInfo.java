package kz.bsbnb.portal.digisignservice.model;

import org.w3c.dom.Document;

public class SignVerificationInfo {
    private boolean isSignatureValid;
    private boolean isSignaturExpired;
    private boolean isSignatureRevoked;
    private String signatureError;
    private Document document;
    private String principal;
    private byte[] certificate;

    public boolean isSignatureValid() {
        return isSignatureValid;
    }

    public void setSignatureValid(boolean signatureValid) {
        isSignatureValid = signatureValid;
    }

    public boolean isSignaturExpired() {
        return isSignaturExpired;
    }

    public void setSignaturExpired(boolean signaturExpired) {
        isSignaturExpired = signaturExpired;
    }

    public boolean isSignatureRevoked() {
        return isSignatureRevoked;
    }

    public void setSignatureRevoked(boolean signatureRevoked) {
        isSignatureRevoked = signatureRevoked;
    }

    public Document getDocument() {
        return document;
    }

    public void setDocument(Document document) {
        this.document = document;
    }

    public String getPrincipal() {
        return principal;
    }

    public void setPrincipal(String principal) {
        this.principal = principal;
    }

    public byte[] getCertificate() {
        return certificate;
    }

    public void setCertificate(byte[] certificate) {
        this.certificate = certificate;
    }

    public String getSignatureError() {
        return signatureError;
    }

    public void setSignatureError(String signatureError) {
        this.signatureError = signatureError;
    }
}
