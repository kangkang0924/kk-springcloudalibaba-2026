package com.tulingxueyuan.stock.mapper;

import com.tulingxueyuan.stock.pojo.Stock;

import java.util.List;

public interface StockMapper {
    int deleteByPrimaryKey(Integer id);

    int insert(Stock record);

    Stock selectByPrimaryKey(Integer id);

    List<Stock> selectAll();

    int updateByPrimaryKey(Stock record);

    void reduct(Integer productId);
}