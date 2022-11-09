package kz.bsbnb.portal.digisignservice.util.kisc;

import javax.naming.NamingException;
import javax.naming.ldap.ExtendedResponse;

/**
 *
 */
public class RegisterResponse implements ExtendedResponse {

    private byte[] data;

    /**
     * @param id
     * @param berValue
     * @param offset
     * @param length
     * @throws NamingException
     */
    public RegisterResponse(String id, byte[] berValue, int offset, int length) throws NamingException {
        data = subArray(berValue, offset, length);
    }

    /**
     * @return
     */
    public String getID() {
        return "1.3.6.1.4.1.6801.11.1.2";
    }

    /**
     * @return
     */
    public byte[] getEncodedValue() {
        return data;
    }

    private byte[] subArray(byte[] data, int offset, int length) {
        if (data == null) return null;
        if (offset < 0) return new byte[]{};
        if (offset > data.length) return new byte[]{};
        if (offset + length > data.length) length = data.length - offset;
        if (length <= 0) return new byte[]{};
        byte[] retVal = new byte[length];
        for (int i = 0; i < length; i++) {
            retVal[i] = data[offset + i];
        }
        return retVal;
    }
}

