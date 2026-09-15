package com.xs.custom.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * 口令对称策略：PBKDF2-HMAC-SHA256 派生密钥 + AES-256-GCM 认证加密。
 * <p>字符串密文格式: salt(16) | nonce(12) | ciphertext+tag
 * <p>文件格式: MAGIC"AGC1" | salt(16) | baseNonce(12) | chunkCount(8) | 分块密文
 */
public final class AesGcmCrypto implements CryptoStrategy {

    static final byte[] FILE_MAGIC = {'A', 'G', 'C', '1'};
    private static final int FILE_HEADER_LEN = 4 + 16 + 12 + 8;
    private static final int SALT_LEN = 16;
    private static final int NONCE_LEN = 12;
    private static final int KEY_BITS = 256;
    private static final int TAG_BITS = 128;
    /** OWASP 2023 对 PBKDF2-HMAC-SHA256 的建议值 */
    private static final int PBKDF2_ITERATIONS = 210_000;

    private final char[] password;
    private final SecureRandom random = new SecureRandom();

    public AesGcmCrypto(CharSequence password) {
        this.password = password.toString().toCharArray();
    }

    @Override
    public byte[] encrypt(byte[] plain) {
        try {
            byte[] salt = randomBytes(SALT_LEN);
            byte[] nonce = randomBytes(NONCE_LEN);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, deriveKey(salt), new GCMParameterSpec(TAG_BITS, nonce));
            byte[] cipherText = cipher.doFinal(plain);
            return ByteBuffer.allocate(SALT_LEN + NONCE_LEN + cipherText.length)
                    .put(salt).put(nonce).put(cipherText).array();
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AES 加密失败", e);
        }
    }

    @Override
    public byte[] decrypt(byte[] data) {
        if (data.length < SALT_LEN + NONCE_LEN + TAG_BITS / 8) {
            throw new CryptoException("密文长度非法");
        }
        try {
            ByteBuffer buf = ByteBuffer.wrap(data);
            byte[] salt = new byte[SALT_LEN];
            buf.get(salt);
            byte[] nonce = new byte[NONCE_LEN];
            buf.get(nonce);
            byte[] cipherText = new byte[buf.remaining()];
            buf.get(cipherText);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, deriveKey(salt), new GCMParameterSpec(TAG_BITS, nonce));
            return cipher.doFinal(cipherText);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("AES 解密失败（密文被篡改或口令错误）", e);
        }
    }

    @Override
    public void encryptFile(Path source, Path target) {
        try {
            long plainSize = Files.size(source);
            byte[] salt = randomBytes(SALT_LEN);
            byte[] baseNonce = randomBytes(NONCE_LEN);
            long chunkCount = (plainSize + ChunkedAesGcm.CHUNK_SIZE - 1) / ChunkedAesGcm.CHUNK_SIZE;
            byte[] header = ByteBuffer.allocate(FILE_HEADER_LEN)
                    .put(FILE_MAGIC).put(salt).put(baseNonce).putLong(chunkCount).array();
            ChunkedAesGcm.encrypt(source, target, deriveKey(salt), header, baseNonce, plainSize);
        } catch (IOException | GeneralSecurityException e) {
            throw new CryptoException("文件加密失败: " + source, e);
        }
    }

    @Override
    public void decryptFile(Path source, Path target) {
        try (InputStream in = new BufferedInputStream(Files.newInputStream(source));
             OutputStream out = new BufferedOutputStream(Files.newOutputStream(target))) {
            byte[] header = in.readNBytes(FILE_HEADER_LEN);
            if (header.length < FILE_HEADER_LEN) {
                throw new CryptoException("加密文件头不完整");
            }
            ByteBuffer buf = ByteBuffer.wrap(header);
            byte[] magic = new byte[4];
            buf.get(magic);
            if (!Arrays.equals(magic, FILE_MAGIC)) {
                throw new CryptoException("不是合法的 AGC1 加密文件");
            }
            byte[] salt = new byte[SALT_LEN];
            buf.get(salt);
            byte[] baseNonce = new byte[NONCE_LEN];
            buf.get(baseNonce);
            long chunkCount = buf.getLong();
            ChunkedAesGcm.decrypt(in, out, deriveKey(salt), baseNonce, chunkCount);
        } catch (IOException | GeneralSecurityException e) {
            throw new CryptoException("文件解密失败: " + source, e);
        }
    }

    private SecretKeySpec deriveKey(byte[] salt) throws GeneralSecurityException {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_BITS);
        try {
            return new SecretKeySpec(SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                    .generateSecret(spec).getEncoded(), "AES");
        } finally {
            spec.clearPassword();
        }
    }

    private byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
