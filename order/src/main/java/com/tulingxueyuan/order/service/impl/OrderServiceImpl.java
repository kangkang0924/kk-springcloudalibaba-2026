package com.tulingxueyuan.order.service.impl;

import com.tulingxueyuan.order.feignService.StockFeignService;
import com.tulingxueyuan.order.mapper.OrderMapper;
import com.tulingxueyuan.order.pojo.Order;
import com.tulingxueyuan.order.service.OrderService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.concurrent.TimeUnit;

/***
 * @Author 徐庶   QQ:1092002729
 * @Slogan 致敬大师，致敬未来的你
 */
@Service
public class OrderServiceImpl implements OrderService {


    @Autowired
    OrderMapper orderMapper;

    @Autowired
    StockFeignService stockService;

    /**
     * 下单
     * @return
     */
    @Override
    @Transactional
    public Order create(Order order) {
        // 插入能否成功？
        orderMapper.insert(order);

        // 扣减库存 能否成功？
        stockService.reduct(order.getProductId());

        // 异常
        int a=1/0;

        return order;
    }

    @Override
    public List<Order> all() throws InterruptedException {
        TimeUnit.SECONDS.sleep(2);
        return orderMapper.selectAll();
    }

    @Override
    public Order get(Integer id) {
        return orderMapper.selectByPrimaryKey(id);
    }
}
