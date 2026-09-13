package com.tulingxueyuan.order.controller;

import com.tulingxueyuan.order.feignService.StockFeignService;
import com.tulingxueyuan.order.pojo.Order;
import com.tulingxueyuan.order.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.context.config.annotation.RefreshScope;
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
@RefreshScope
public class OrderController {

    @Autowired
    RestTemplate restTemplate;
    @Autowired
    StockFeignService stockFeignService;
    @Value("${author}")
    String author;
    @Autowired
    OrderService orderService;

    // 插入订单信息
    @RequestMapping("/add")
    public String add(){
        Order order=new Order();
        order.setProductId(9);
        order.setStatus(0);
        order.setTotalAmount(100);

        orderService.create(order);
        return "下单成功";
    }
}
