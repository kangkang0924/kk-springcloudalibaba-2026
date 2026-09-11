package com.tulingxueyuan.order.feignService;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author ~
 * @version 1.0
 * @time 2026/09/11/14:41
 */
@FeignClient(name="stock-server",path ="/stock")
public interface StockFeignService {

    // 声明需要调用的rest接口对应的方法
    @RequestMapping("/reduct")
    String reduct();
}