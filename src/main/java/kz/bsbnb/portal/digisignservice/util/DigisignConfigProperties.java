package kz.bsbnb.portal.digisignservice.util;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "digisign.config")
public class DigisignConfigProperties {

    private String keystoreFileName;
    private String keystoreFilePassword;
    private String signAlias;
    private String signAlgName;
    private String oscpUrl;
    private String caCertFileName;

    public String getCaCertFileName() {
        return caCertFileName;
    }

    public void setCaCertFileName(String caCertFileName) {
        this.caCertFileName = caCertFileName;
    }

    public String getOscpUrl() {
        return oscpUrl;
    }

    public void setOscpUrl(String oscpUrl) {
        this.oscpUrl = oscpUrl;
    }

    public String getSignAlgName() {
        return signAlgName;
    }

    public void setSignAlgName(String signAlgName) {
        this.signAlgName = signAlgName;
    }

    public String getKeystoreFileName() {
        return keystoreFileName;
    }

    public void setKeystoreFileName(String keystoreFileName) {
        this.keystoreFileName = keystoreFileName;
    }

    public String getKeystoreFilePassword() {
        return keystoreFilePassword;
    }

    public void setKeystoreFilePassword(String keystoreFilePassword) {
        this.keystoreFilePassword = keystoreFilePassword;
    }

    public String getSignAlias() {
        return signAlias;
    }

    public void setSignAlias(String signAlias) {
        this.signAlias = signAlias;
    }
}
