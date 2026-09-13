package com.tulingxueyuan.stock.controller;

import com.tulingxueyuan.stock.service.StockService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.concurrent.TimeUnit;

/***
 * @Author 徐庶   
 * @Slogan 致敬大师，致敬未来的你
 */
@RestController
@RequestMapping("/stock")
public class StockController {
    @Autowired
    StockService stockSerivce;

    @RequestMapping("/reduct")
    public String reduct(@RequestParam(value = "productId")Integer productId) throws InterruptedException {
        stockSerivce.reduct(productId);
        TimeUnit.SECONDS.sleep(1);
        System.out.println("扣减库存");
        return "扣减库存";
    }


}
