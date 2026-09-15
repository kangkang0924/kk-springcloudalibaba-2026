package com.xs.custom.utils;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

/**
 * PEM 证书/密钥加载工具（基于 BouncyCastle，无需手动处理 DER/TLV）：
 * <ul>
 *   <li>公钥：从 X.509 证书 PEM（-----BEGIN CERTIFICATE-----）提取</li>
 *   <li>私钥：支持 EC（SEC1）、RSA（PKCS#1）、PKCS#8 三种格式</li>
 * </ul>
 * 注意：InputStream 入参在读取完成后会被一并关闭。
 */
public final class PemUtils {

    private PemUtils() {}

    public static X509Certificate loadCertificate(Path pemFile) {
        try (InputStream in = Files.newInputStream(pemFile)) {
            return loadCertificate(in);
        } catch (IOException e) {
            throw new CryptoException("读取证书失败: " + pemFile, e);
        }
    }

    public static X509Certificate loadCertificate(InputStream in) {
        Object obj = readPem(in, "证书");
        if (!(obj instanceof X509CertificateHolder holder)) {
            throw new CryptoException("PEM 中未找到 CERTIFICATE 块，实际为: " + obj.getClass().getSimpleName());
        }
        try {
            return new JcaX509CertificateConverter().getCertificate(holder);
        } catch (Exception e) {
            throw new CryptoException("解析 X.509 证书失败", e);
        }
    }

    public static PublicKey loadPublicKey(Path pemFile) {
        return loadCertificate(pemFile).getPublicKey();
    }

    public static PublicKey loadPublicKey(InputStream in) {
        return loadCertificate(in).getPublicKey();
    }

    public static PrivateKey loadPrivateKey(Path pemFile) {
        try (InputStream in = Files.newInputStream(pemFile)) {
            return loadPrivateKey(in);
        } catch (IOException e) {
            throw new CryptoException("读取私钥失败: " + pemFile, e);
        }
    }

    public static PrivateKey loadPrivateKey(InputStream in) {
        Object obj = readPem(in, "私钥");
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
        try {
            if (obj instanceof PrivateKeyInfo info) {   // PKCS#8: -----BEGIN PRIVATE KEY-----
                return converter.getPrivateKey(info);
            }
            if (obj instanceof PEMKeyPair pair) {       // SEC1 / PKCS#1: -----BEGIN EC/RSA PRIVATE KEY-----
                return converter.getPrivateKey(pair.getPrivateKeyInfo());
            }
        } catch (Exception e) {
            throw new CryptoException("解析私钥失败", e);
        }
        throw new CryptoException("PEM 中未找到私钥块，实际为: " + obj.getClass().getSimpleName());
    }

    // ---------------- 内部实现 ----------------

    /** 读取第一个 PEM 块 */
    private static Object readPem(InputStream in, String what) {
        try (PEMParser parser = new PEMParser(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            Object obj = parser.readObject();
            if (obj == null) {
                throw new CryptoException("PEM 为空或不含 " + what + " 块");
            }
            return obj;
        } catch (IOException e) {
            throw new CryptoException("读取 PEM 失败", e);
        }
    }
}
