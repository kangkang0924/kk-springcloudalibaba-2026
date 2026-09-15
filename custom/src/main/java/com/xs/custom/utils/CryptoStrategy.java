package com.xs.custom.utils;

/**
 * 加密策略（策略模式）：算法细节对调用方透明，实现类须线程安全。
 */
public interface CryptoStrategy {

    /** 加密任意长度的字节数组 */
    byte[] encrypt(byte[] plain);

    /** 解密字节数组（含完整性校验，被篡改会抛出 {@link CryptoException}） */
    byte[] decrypt(byte[] cipher);

    /** 加密文件（大文件自动分块流式处理，内存占用恒定） */
    void encryptFile(java.nio.file.Path source, java.nio.file.Path target);

    /** 解密文件 */
    void decryptFile(java.nio.file.Path source, java.nio.file.Path target);
}
