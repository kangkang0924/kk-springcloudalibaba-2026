package com.xs.custom.crypto;

import com.xs.custom.utils.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Random;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 纯单元测试（不启动 Spring 上下文）：
 * <ul>
 *   <li>{@link EciesCrypto} 使用 src/main/resources/SSL 下的 Let's Encrypt EC P-256 证书验证</li>
 *   <li>两种策略均覆盖 字符串/文件 往返、跨分块大文件、空数据、防篡改、口令/密钥错误等场景</li>
 * </ul>
 */
class CryptoStrategyTest {

    private static final String CERT = "/SSL/774778.xyz-crt.pem";
    private static final String KEY = "/SSL/774778.xyz-key.pem";

    @TempDir
    Path tempDir;

    // ---------- AesGcmCrypto（口令对称） ----------

    @Test
    void aesGcmRoundTripString() {
        CryptoStrategy crypto = new AesGcmCrypto("correct horse battery staple");
        byte[] plain = "你好，Spring Cloud Alibaba！".repeat(100).getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(plain, crypto.decrypt(crypto.encrypt(plain)));
    }

    @Test
    void aesGcmWrongPasswordRejected() {
        byte[] cipher = new AesGcmCrypto("right-password").encrypt("secret".getBytes(StandardCharsets.UTF_8));
        assertThrows(CryptoException.class, () -> new AesGcmCrypto("wrong-password").decrypt(cipher));
    }

    @Test
    void aesGcmTamperRejected() {
        byte[] cipher = new AesGcmCrypto("pw").encrypt("secret".getBytes(StandardCharsets.UTF_8));
        cipher[cipher.length - 1] ^= 0x01;
        assertThrows(CryptoException.class, () -> new AesGcmCrypto("pw").decrypt(cipher));
    }

    @Test
    void aesGcmFileRoundTripCrossesChunks() throws Exception {
        CryptoStrategy crypto = new AesGcmCrypto("file-password");
        byte[] data = randomBytes(3 * 64 * 1024 + 123);
        Path plain = write("plain.bin", data);
        Path encrypted = tempDir.resolve("plain.bin.agc");
        Path decrypted = tempDir.resolve("plain.out");
        crypto.encryptFile(plain, encrypted);
        assertNotEquals(data.length, Files.size(encrypted));
        crypto.decryptFile(encrypted, decrypted);
        assertArrayEquals(data, Files.readAllBytes(decrypted));
    }

    @Test
    void aesGcmEmptyFileRoundTrip() throws Exception {
        CryptoStrategy crypto = new AesGcmCrypto("pw");
        Path plain = write("empty.bin", new byte[0]);
        Path encrypted = tempDir.resolve("empty.bin.agc");
        Path decrypted = tempDir.resolve("empty.out");
        crypto.encryptFile(plain, encrypted);
        crypto.decryptFile(encrypted, decrypted);
        assertEquals(0, Files.size(decrypted));
    }

    // ---------- EciesCrypto（证书混合加密） ----------

    @Test
    void eciesRoundTripString() throws Exception {
        EciesCrypto crypto = newEcies();
        byte[] plain = "ECIES hybrid encryption, no shared password needed. "
                .repeat(50).getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(plain, crypto.decrypt(crypto.encrypt(plain)));
    }

    @Test
    void eciesSameInputDifferentCipherText() throws Exception {
        EciesCrypto crypto = newEcies();
        byte[] plain = "same input".getBytes(StandardCharsets.UTF_8);
        assertFalse(Arrays.equals(crypto.encrypt(plain), crypto.encrypt(plain)), "临时密钥对+随机 nonce 应使密文每次不同");
    }

    @Test
    void eciesFileRoundTripCrossesChunks() throws Exception {
        EciesCrypto crypto = newEcies();
        byte[] data = randomBytes(2 * 64 * 1024 + 7);
        Path plain = write("data.bin", data);
        Path encrypted = tempDir.resolve("data.bin.eci");
        Path decrypted = tempDir.resolve("data.out");
        crypto.encryptFile(plain, encrypted);
        crypto.decryptFile(encrypted, decrypted);
        assertArrayEquals(data, Files.readAllBytes(decrypted));
    }

    @Test
    void eciesTamperRejected() throws Exception {
        EciesCrypto crypto = newEcies();
        byte[] cipher = crypto.encrypt("secret".getBytes(StandardCharsets.UTF_8));
        cipher[cipher.length - 1] ^= 0x01;
        assertThrows(CryptoException.class, () -> crypto.decrypt(cipher));
    }

    @Test
    void eciesDecryptWithoutPrivateKeyRejected() throws Exception {
        EciesCrypto encryptOnly = new EciesCrypto(publicKey());
        byte[] cipher = encryptOnly.encrypt("hello".getBytes(StandardCharsets.UTF_8));
        assertThrows(CryptoException.class, () -> encryptOnly.decrypt(cipher));
    }

    // ---------- 工具 ----------

    private static EciesCrypto newEcies() throws Exception {
        return new EciesCrypto(publicKey(), privateKey());
    }

    private static PublicKey publicKey() throws Exception {
        try (InputStream in = resource(CERT)) {
            return PemUtils.loadPublicKey(in);
        }
    }

    private static PrivateKey privateKey() throws Exception {
        try (InputStream in = resource(KEY)) {
            return PemUtils.loadPrivateKey(in);
        }
    }

    private static InputStream resource(String name) {
        InputStream in = CryptoStrategyTest.class.getResourceAsStream(name);
        assertNotNull(in, "缺少测试资源 " + name);
        return in;
    }

    private Path write(String name, byte[] data) throws Exception {
        Path file = tempDir.resolve(name);
        Files.write(file, data);
        return file;
    }

    private static byte[] randomBytes(int length) {
        byte[] data = new byte[length];
        new Random(42).nextBytes(data);
        return data;
    }
}
