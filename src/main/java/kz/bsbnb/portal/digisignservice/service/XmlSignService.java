package kz.bsbnb.portal.digisignservice.service;

public interface XmlSignService {
    String signXML(String xmlString, final String container, String password);

    boolean verifyXml(String xmlString) throws Exception;
}
