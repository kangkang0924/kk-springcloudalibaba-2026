package com.tulingxueyuan.order.mapper;

import com.tulingxueyuan.order.pojo.Order;

import java.util.List;
public interface OrderMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(Order record);

    Order selectByPrimaryKey(Integer id);

    List<Order> selectAll();

    int updateByPrimaryKey(Order record);
}