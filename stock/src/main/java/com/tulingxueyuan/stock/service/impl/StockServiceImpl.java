package com.tulingxueyuan.stock.service.impl;

import com.tulingxueyuan.stock.mapper.StockMapper;
import com.tulingxueyuan.stock.service.StockService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/***
 * @Author 徐庶   QQ:1092002729
 * @Slogan 致敬大师，致敬未来的你
 */
@Service
public class StockServiceImpl implements StockService {

    @Autowired
    StockMapper stockMapper;

    @Override
    public void reduct(Integer productId) {
        System.out.println("更新商品:"+productId);
        stockMapper.reduct(productId);
    }
}
