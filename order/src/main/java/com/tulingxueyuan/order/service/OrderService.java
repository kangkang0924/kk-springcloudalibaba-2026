package com.tulingxueyuan.order.service;

import com.tulingxueyuan.order.pojo.Order;

import java.util.List;

/***
 * @Author 徐庶   QQ:1092002729
 * @Slogan 致敬大师，致敬未来的你
 */
public interface OrderService {

     Order create(Order order);

    List<Order> all() throws InterruptedException;

    Order get(Integer id);
}
