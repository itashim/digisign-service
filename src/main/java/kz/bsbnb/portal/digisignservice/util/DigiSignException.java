package kz.bsbnb.portal.digisignservice.util;

public class DigiSignException extends Exception {
    private static final long serialVersionUID = 1L;
    public static final int CERT_EXPIRED = 1;
    public static final int CERT_NOT_VALID = 2;
    public static final int CERT_ERROR = 3;
    public static final int CERT_REVOKED = 4;

    private int errorCode = 0;

    private String errorMessageKey;

    public int getErrorCode() {
        return errorCode;
    }

    public void setErrorCode(int errorCode) {
        this.errorCode = errorCode;
    }

    public DigiSignException(String message, Throwable cause, int errCode) {
        super(message, cause);
        this.errorCode = errCode;
    }

    public String getErrorMessageKey() {
        return errorMessageKey;
    }

    public void setErrorMessageKey(String errorMessageKey) {
        this.errorMessageKey = errorMessageKey;
    }

    public DigiSignException(String message, Throwable cause) {
        super(message, cause);
    }

    public DigiSignException(String message) {
        super(message);
    }

    public DigiSignException(String message, int errCode, String errorMessageKey) {
        super(message);
        this.errorCode = errCode;
        this.errorMessageKey = errorMessageKey;
    }

    public DigiSignException(int errCode, String message) {
        super(message);
        this.errorCode = errCode;
    }
}
