package com.tulingxueyuan.order.config;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.context.annotation.Configuration;

/***
 * @Author 徐庶   QQ:1092002729
 * @Slogan 致敬大师，致敬未来的你
 */
@Configuration
@MapperScan("com.tulingxueyuan.order.mapper")   // 扫描Mapper接口，整合MyBatis
public class MyBatisConfig {

}
