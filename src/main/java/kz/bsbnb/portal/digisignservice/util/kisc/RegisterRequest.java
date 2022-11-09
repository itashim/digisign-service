package kz.bsbnb.portal.digisignservice.util.kisc;

import javax.naming.NamingException;
import javax.naming.ldap.ExtendedRequest;
import javax.naming.ldap.ExtendedResponse;

public class RegisterRequest implements ExtendedRequest {

    private byte[] cert;
    private String service;

    /**
     * @param certificate
     * @param srv
     */
    public RegisterRequest(byte[] certificate, String srv) {
        this.cert = certificate;
        this.service = srv;
    }

    /**
     * @return
     */
    public String getID() {
        return service;
    }

    /**
     * @return
     */
    public byte[] getEncodedValue() {
        return cert;
    }

    /**
     * @param id
     * @param berValue
     * @param offset
     * @param length
     * @return
     * @throws NamingException
     */
    public ExtendedResponse createExtendedResponse(String id, byte[] berValue, int offset, int length) throws NamingException {
        return new RegisterResponse(id, berValue, offset, length);
    }
}
