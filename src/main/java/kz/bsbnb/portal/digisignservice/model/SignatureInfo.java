package kz.bsbnb.portal.digisignservice.model;

import java.io.Serializable;

public class SignatureInfo implements Serializable {
    private String forSign; // то что нужно подписать
    private String signature; // подписанный документ
    private String x509Certificate; // публичный ключ

    public String getForSign() {
        return forSign;
    }

    public void setForSign(String forSign) {
        this.forSign = forSign;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getX509Certificate() {
        return x509Certificate;
    }

    public void setX509Certificate(String x509Certificate) {
        this.x509Certificate = x509Certificate;
    }
}
