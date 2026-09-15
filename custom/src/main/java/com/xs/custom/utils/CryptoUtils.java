package com.xs.custom.utils;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Base64;

/**
 * 加解密工具类（开箱即用，无需传入密钥 / 证书）。
 *
 * <pre>{@code
 * String cipher = CryptoUtils.encrypt("机密内容");        // → Base64 密文
 * String plain  = CryptoUtils.decrypt(cipher);            // → 原文
 *
 * CryptoUtils.encryptFile("D:/a.xlsx");                   // → D:/a.xlsx.enc
 * CryptoUtils.decryptFile("D:/a.xlsx.enc");               // → D:/a.xlsx
 * }</pre>
 *
 * 密钥来源：classpath 下 {@code SSL/} 目录的公钥证书与私钥（ECIES 混合加密）。
 * <ul>
 *   <li>加密：用证书公钥 + 临时密钥对做 ECDH，只有私钥持有者能解密</li>
 *   <li>解密：用配对私钥还原 —— 因此本工具同时加载公钥与私钥</li>
 * </ul>
 */
public final class CryptoUtils {

    /** 密文文件默认后缀（解密时也认这个后缀） */
    public static final String FILE_SUFFIX = ".enc";

    private static final CryptoStrategy STRATEGY = new CryptoStrategyHolder().strategy;

    private CryptoUtils() {}

    // ---------------- 字符串 ----------------

    /** 加密字符串，返回 Base64 密文（可直接存库 / 放配置 / 走 HTTP 传输） */
    public static String encrypt(String plain) {
        return Base64.getEncoder().encodeToString(
                STRATEGY.encrypt(plain.getBytes(StandardCharsets.UTF_8)));
    }

    /** 解密 {@link #encrypt(String)} 产生的 Base64 密文 */
    public static String decrypt(String cipherBase64) {
        return new String(STRATEGY.decrypt(Base64.getDecoder().decode(cipherBase64)),
                StandardCharsets.UTF_8);
    }

    // ---------------- 文件 ----------------

    /** 加密文件，生成 {@code <文件>.enc}，返回密文文件路径 */
    public static Path encryptFile(String sourceFile) {
        return encryptFile(sourceFile, sourceFile + FILE_SUFFIX);
    }

    /** 加密文件到指定路径 */
    public static Path encryptFile(String sourceFile, String targetFile) {
        Path target = Path.of(targetFile);
        STRATEGY.encryptFile(Path.of(sourceFile), target);
        return target;
    }

    /** 解密文件，自动去掉 {@code .enc} 后缀；无该后缀则加 {@code .dec} */
    public static Path decryptFile(String cipherFile) {
        String out = cipherFile.endsWith(FILE_SUFFIX)
                ? cipherFile.substring(0, cipherFile.length() - FILE_SUFFIX.length())
                : cipherFile + ".dec";
        return decryptFile(cipherFile, out);
    }

    /** 解密文件到指定路径 */
    public static Path decryptFile(String cipherFile, String targetFile) {
        Path target = Path.of(targetFile);
        STRATEGY.decryptFile(Path.of(cipherFile), target);
        return target;
    }

    /**
     * 密钥持有器：证书加载与策略创建收敛到一处，且类初始化时只执行一次。
     */
    private static final class CryptoStrategyHolder {
        private final CryptoStrategy strategy;

        CryptoStrategyHolder() {
            this.strategy = new EciesCrypto(CryptoKeyLoader.publicKey(), CryptoKeyLoader.privateKey());
        }
    }
}
