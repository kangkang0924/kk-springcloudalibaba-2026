package com.xs.custom.utils;

import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

/**
 * RFC 5869 HKDF-SHA256（BouncyCastle 实现，JDK 原生未内置）。
 */
final class Hkdf {

    private Hkdf() {}

    /**
     * @param ikm    输入密钥材料（如 ECDH 共享密钥）
     * @param salt   随机盐（可为空数组）
     * @param info   上下文绑定信息（协议标识 / 临时公钥等）
     * @param outLen 输出密钥字节数
     */
    static byte[] deriveSha256(byte[] ikm, byte[] salt, byte[] info, int outLen) {
        try {
            HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
            hkdf.init(new HKDFParameters(ikm, salt, info));
            byte[] okm = new byte[outLen];
            hkdf.generateBytes(okm, 0, outLen);
            return okm;
        } catch (Exception e) {   // 参数非法时 BC 抛出运行时异常，统一包装
            throw new CryptoException("HKDF 派生失败", e);
        }
    }
}
