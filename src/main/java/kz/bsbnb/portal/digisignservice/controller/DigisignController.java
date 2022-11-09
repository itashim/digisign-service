package kz.bsbnb.portal.digisignservice.controller;


import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import kz.bsbnb.portal.digisignservice.model.SignVerificationInfo;
import kz.bsbnb.portal.digisignservice.service.DigisignService;
import kz.bsbnb.portal.digisignservice.service.KsmrDigiSignService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/digisign")
@Api("НУЦ ЭЦП методы")
public class DigisignController {
    @Value("${digisign.kisc.oscp.url}")
    private String oscpUrl;
    @Autowired
    private DigisignService digisignService;

    public @ResponseBody
    @PostMapping("/verifyXmlSignature")
    @ApiOperation("Проверка ЭЦП подписи в формате xml")
    SignVerificationInfo verifyXmlSignature(@RequestParam("xmlString") String xmlString) {
        return digisignService.verifyXmlSignature(xmlString);
    }

    public @ResponseBody
    @PostMapping("/verifyXmlSignatureBody")
    @ApiOperation("Проверка ЭЦП подписи в формате xml")
    SignVerificationInfo verifyXmlSignatureBody(@RequestBody String xmlString) {
        return digisignService.verifyXmlSignature(xmlString);
    }
    public @ResponseBody
    @PostMapping("/verifyKsmrXmlSignature")
    @ApiOperation("Проверка КЦМР ЭЦП подписи в формате xml")
    SignVerificationInfo verifyKsmrXmlSignature(@RequestParam("xmlString") String xmlString) throws Exception {
        return KsmrDigiSignService.validateXML(xmlString, oscpUrl);
    }

}


