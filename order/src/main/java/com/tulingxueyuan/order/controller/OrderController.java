package com.tulingxueyuan.order.controller;

import com.tulingxueyuan.order.feignService.StockFeignService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import javax.swing.*;

/***
 * @Author 徐庶   
 * @Slogan 致敬大师，致敬未来的你
 */
@RestController
@RequestMapping("/order")
public class OrderController {

    @Autowired
    RestTemplate restTemplate;
    @Autowired
    StockFeignService stockFeignService;

    // 插入订单信息
    @RequestMapping("/add")
    public String add(){
//        String forObject = restTemplate.getForObject("http://stock-server/stock/reduct", String.class);
        String reduct = stockFeignService.reduct();
        System.out.println("成功下单");
        return "hello,world!" + reduct;
    }
}
