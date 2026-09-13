package com.xs.gatewaty;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.client.discovery.EnableDiscoveryClient;

@SpringBootApplication
@EnableDiscoveryClient
public class GatewatyApplication {

    public static void main(String[] args) {
        SpringApplication.run(GatewatyApplication.class, args);
    }

}
