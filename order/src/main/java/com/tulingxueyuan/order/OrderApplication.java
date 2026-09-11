package com.tulingxueyuan.order;

import com.tulingxueyuan.order.controller.OrderController;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;

/***
 * @Author 徐庶   
 * @@Slogan 致敬大师，致敬未来的你
 */
@SpringBootApplication
public class OrderApplication {

    public static void main(String[] args) {
        SpringApplication.run(OrderApplication.class,args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

}
