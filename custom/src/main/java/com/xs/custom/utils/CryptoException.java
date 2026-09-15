package com.xs.custom.utils;

/**
 * 统一加解密运行时异常，调用方无需处理受检异常。
 */
public class CryptoException extends RuntimeException {

    public CryptoException(String message) {
        super(message);
    }

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }
}
