package com.xs.custom.utils;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

/**
 * ECIES 风格混合加密（纯 JDK、零第三方依赖）：
 * <p>每次加密生成与接收方公钥同曲线（P-256/P-384 等，自动适配证书）的全新临时密钥对，
 * 以 ECDH(临时私钥, 接收方公钥) 计算共享密钥，
 * 经 HKDF-SHA256 派生 AES-256 会话密钥后做 AES-GCM 认证加密 —— 前向保密，
 * 无需预先共享口令，接收方公钥可直接取自 X.509 证书（{@link PemUtils}）。
 * <p>字符串密文格式: pubLen(2) | ephemeralPub(X.509) | nonce(12) | ciphertext+tag
 * <p>文件格式: MAGIC"ECI1" | pubLen(2) | ephemeralPub | baseNonce(12) | chunkCount(8) | 分块密文
 */
public final class EciesCrypto implements CryptoStrategy {

    static final byte[] FILE_MAGIC = {'E', 'C', 'I', '1'};
    private static final byte[] HKDF_INFO = "kk-custom/ecies-aes256-gcm".getBytes(StandardCharsets.US_ASCII);
    private static final int NONCE_LEN = 12;
    private static final int TAG_BITS = 128;
    private static final int KEY_LEN = 32;

    private final ECPublicKey receiverPublicKey;
    private final PrivateKey receiverPrivateKey;
    /** 接收方曲线坐标定长，用于 ECDH 共享密钥归一化（去前导零问题） */
    private final int coordLen;
    private final SecureRandom random = new SecureRandom();

    /** 仅加密场景：只需接收方公钥（如来自证书），无私钥则无法解密 */
    public EciesCrypto(PublicKey receiverPublicKey) {
        this(receiverPublicKey, null);
    }

    /** 加密 + 解密：需要接收方公钥与配对私钥 */
    public EciesCrypto(PublicKey receiverPublicKey, PrivateKey receiverPrivateKey) {
        if (!(receiverPublicKey instanceof ECPublicKey ecKey)) {
            throw new CryptoException("接收方公钥必须是 EC 公钥（可从 X.509 证书提取）");
        }
        this.receiverPublicKey = ecKey;
        this.receiverPrivateKey = receiverPrivateKey;
        this.coordLen = (ecKey.getParams().getCurve().getField().getFieldSize() + 7) / 8;
    }

    @Override
    public byte[] encrypt(byte[] plain) {
        try {
            KeyPair ephemeral = newEphemeral();
            byte[] ephemeralPub = ephemeral.getPublic().getEncoded();
            byte[] nonce = randomBytes(NONCE_LEN);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, sessionKeyForEncrypt(ephemeral, ephemeralPub),
                    new GCMParameterSpec(TAG_BITS, nonce));
            byte[] cipherText = cipher.doFinal(plain);
            return ByteBuffer.allocate(2 + ephemeralPub.length + NONCE_LEN + cipherText.length)
                    .putShort((short) ephemeralPub.length)
                    .put(ephemeralPub).put(nonce).put(cipherText).array();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("ECIES 加密失败", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] data) {
        requirePrivateKey();
        try {
            ByteBuffer buf = ByteBuffer.wrap(data);
            byte[] ephemeralPub = readEphemeral(buf);
            byte[] nonce = new byte[NONCE_LEN];
            buf.get(nonce);
            byte[] cipherText = new byte[buf.remaining()];
            buf.get(cipherText);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, sessionKeyForDecrypt(ephemeralPub),
                    new GCMParameterSpec(TAG_BITS, nonce));
            return cipher.doFinal(cipherText);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("ECIES 解密失败（密文被篡改或密钥不匹配）", e);
        }
    }

    @Override
    public void encryptFile(Path source, Path target) {
        try {
            long plainSize = Files.size(source);
            KeyPair ephemeral = newEphemeral();
            byte[] ephemeralPub = ephemeral.getPublic().getEncoded();
            byte[] baseNonce = randomBytes(NONCE_LEN);
            long chunkCount = (plainSize + ChunkedAesGcm.CHUNK_SIZE - 1) / ChunkedAesGcm.CHUNK_SIZE;
            byte[] header = ByteBuffer.allocate(4 + 2 + ephemeralPub.length + NONCE_LEN + 8)
                    .put(FILE_MAGIC)
                    .putShort((short) ephemeralPub.length)
                    .put(ephemeralPub).put(baseNonce).putLong(chunkCount).array();
            ChunkedAesGcm.encrypt(source, target, sessionKeyForEncrypt(ephemeral, ephemeralPub),
                    header, baseNonce, plainSize);
        } catch (IOException | GeneralSecurityException e) {
            throw new CryptoException("文件加密失败: " + source, e);
        }
    }

    @Override
    public void decryptFile(Path source, Path target) {
        requirePrivateKey();
        try (InputStream in = new BufferedInputStream(Files.newInputStream(source));
             OutputStream out = new BufferedOutputStream(Files.newOutputStream(target))) {
            byte[] head = in.readNBytes(6);
            if (head.length < 6 || !Arrays.equals(Arrays.copyOfRange(head, 0, 4), FILE_MAGIC)) {
                throw new CryptoException("不是合法的 ECI1 加密文件");
            }
            int pubLen = ((head[4] & 0xFF) << 8) | (head[5] & 0xFF);
            byte[] ephemeralPub = in.readNBytes(pubLen);
            byte[] tail = in.readNBytes(NONCE_LEN + 8);
            if (ephemeralPub.length < pubLen || tail.length < NONCE_LEN + 8) {
                throw new CryptoException("加密文件头不完整");
            }
            ByteBuffer buf = ByteBuffer.wrap(tail);
            byte[] baseNonce = new byte[NONCE_LEN];
            buf.get(baseNonce);
            long chunkCount = buf.getLong();
            ChunkedAesGcm.decrypt(in, out, sessionKeyForDecrypt(ephemeralPub), baseNonce, chunkCount);
        } catch (IOException | GeneralSecurityException e) {
            throw new CryptoException("文件解密失败: " + source, e);
        }
    }

    // ---------------- 内部实现 ----------------

    /** 加密方向会话密钥: ECDH(临时私钥, 接收方公钥) → HKDF(salt=临时公钥, info=协议标识) */
    private SecretKeySpec sessionKeyForEncrypt(KeyPair ephemeral, byte[] ephemeralPub)
            throws GeneralSecurityException {
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(ephemeral.getPrivate());
        agreement.doPhase(receiverPublicKey, true);
        return new SecretKeySpec(Hkdf.deriveSha256(normalize(agreement.generateSecret()),
                ephemeralPub, HKDF_INFO, KEY_LEN), "AES");
    }

    /** 解密方向会话密钥: ECDH(接收方私钥, 临时公钥) → HKDF(salt=临时公钥, info=协议标识) */
    private SecretKeySpec sessionKeyForDecrypt(byte[] ephemeralPub) throws GeneralSecurityException {
        PublicKey ephemeralPublicKey = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(ephemeralPub));
        KeyAgreement agreement = KeyAgreement.getInstance("ECDH");
        agreement.init(receiverPrivateKey);
        agreement.doPhase(ephemeralPublicKey, true);
        return new SecretKeySpec(Hkdf.deriveSha256(normalize(agreement.generateSecret()),
                ephemeralPub, HKDF_INFO, KEY_LEN), "AES");
    }

    /** 临时密钥对与接收方证书同曲线，保证 ECDH 参数一致 */
    private KeyPair newEphemeral() throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(receiverPublicKey.getParams(), random);
        return generator.generateKeyPair();
    }

    /** 读取并校验密文中的临时公钥及其后续最小长度 */
    private static byte[] readEphemeral(ByteBuffer buf) {
        if (buf.remaining() < 2) {
            throw new CryptoException("密文长度非法");
        }
        int len = Short.toUnsignedInt(buf.getShort());
        if (len <= 0 || len > 1024) {
            throw new CryptoException("临时公钥长度非法: " + len);
        }
        if (buf.remaining() < len + NONCE_LEN + TAG_BITS / 8) {
            throw new CryptoException("密文长度非法");
        }
        byte[] ephemeralPub = new byte[len];
        buf.get(ephemeralPub);
        return ephemeralPub;
    }

    /** ECDH 输出可能被去掉前导零，统一右对齐到曲线坐标定长 */
    private byte[] normalize(byte[] secret) {
        if (secret.length > coordLen) {
            throw new CryptoException("ECDH 共享密钥长度异常: " + secret.length);
        }
        byte[] fixed = new byte[coordLen];
        System.arraycopy(secret, 0, fixed, coordLen - secret.length, secret.length);
        return fixed;
    }

    private void requirePrivateKey() {
        if (receiverPrivateKey == null) {
            throw new CryptoException("未配置接收方私钥，无法解密");
        }
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
