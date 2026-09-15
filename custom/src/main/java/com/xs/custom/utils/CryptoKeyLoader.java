package com.xs.custom.utils;

import java.io.InputStream;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * 证书密钥加载器：从 classpath 下的 {@code SSL/} 目录读取公钥与私钥，
 * 让调用方无需关心证书文件位置与格式。
 * <p>可用系统属性覆盖默认路径：
 * <pre>{@code
 * -Dcrypto.cert=SSL/774778.xyz-crt.pem
 * -Dcrypto.key=SSL/774778.xyz-key.pem
 * }</pre>
 */
final class CryptoKeyLoader {

    private static final String DEFAULT_CERT = "SSL/774778.xyz-crt.pem";
    private static final String DEFAULT_KEY = "SSL/774778.xyz-key.pem";

    private CryptoKeyLoader() {}

    static PublicKey publicKey() {
        String path = System.getProperty("crypto.cert", DEFAULT_CERT);
        try (InputStream in = open(path)) {
            return PemUtils.loadPublicKey(in);
        } catch (Exception e) {
            throw new CryptoException("加载公钥证书失败: " + path, e);
        }
    }

    static PrivateKey privateKey() {
        String path = System.getProperty("crypto.key", DEFAULT_KEY);
        try (InputStream in = open(path)) {
            return PemUtils.loadPrivateKey(in);
        } catch (Exception e) {
            throw new CryptoException("加载私钥失败: " + path, e);
        }
    }

    /** 资源必须存在，否则装配阶段就报错，避免运行到一半才发现 */
    private static InputStream open(String name) {
        // 先按类加载器找，再退回绝对路径 / classpath 根，兼容 IDE 与打包两种运行方式
        InputStream in = CryptoKeyLoader.class.getClassLoader().getResourceAsStream(name);
        if (in == null) {
            in = CryptoKeyLoader.class.getResourceAsStream("/" + name);
        }
        if (in == null) {
            throw new CryptoException("classpath 下找不到资源: " + name);
        }
        return in;
    }
}
