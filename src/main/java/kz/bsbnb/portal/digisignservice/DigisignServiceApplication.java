package kz.bsbnb.portal.digisignservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.netflix.eureka.EnableEurekaClient;

@SpringBootApplication
@EnableEurekaClient
public class DigisignServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(DigisignServiceApplication.class, args);
    }

}
