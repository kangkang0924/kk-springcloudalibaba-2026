package com.xs.custom.crypto;

import com.xs.custom.utils.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 边界与安全回归测试（不重复 {@link CryptoStrategyTest} 已覆盖的常规往返）：
 * <ul>
 *   <li>Unicode / emoji / 超长文本</li>
 *   <li>恰好一个分块 / 分块 + 1 字节 的文件边界</li>
 *   <li>空数据、超短密文</li>
 *   <li>加密文件中段篡改、跨格式（AGC1 文件喂给 ECIES）</li>
 *   <li>曲线自适应：P-384 证书之外，运行时生成的 P-256 密钥对也能用（回归守护）</li>
 *   <li>PEM 元数据校验、垃圾输入拒绝</li>
 *   <li>多线程并发共享同一实例（线程安全承诺）</li>
 * </ul>
 */
class CryptoEdgeCasesTest {

    private static final String CERT = "/SSL/774778.xyz-crt.pem";
    private static final String KEY = "/SSL/774778.xyz-key.pem";

    @TempDir
    Path tempDir;

    // ---------- 数据边界 ----------

    @Test
    void unicodeEmojiAndLongTextRoundTrip() {
        CryptoStrategy crypto = new AesGcmCrypto("口令-🔐");
        byte[] plain = ("中文加密测试🔐🚀 " + "x".repeat(10_000))
                .getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(plain, crypto.decrypt(crypto.encrypt(plain)));
    }

    @Test
    void emptyByteArrayRoundTripBothStrategies() throws Exception {
        for (CryptoStrategy crypto : List.of(new AesGcmCrypto("pw"), newEcies())) {
            assertArrayEquals(new byte[0], crypto.decrypt(crypto.encrypt(new byte[0])));
        }
    }

    @Test
    void tooShortCiphertextRejected() throws Exception {
        assertThrows(CryptoException.class, () -> new AesGcmCrypto("pw").decrypt(new byte[10]));
        assertThrows(CryptoException.class, () -> newEcies().decrypt(new byte[10]));
    }

    // ---------- 文件边界与篡改 ----------

    @Test
    void fileAtExactChunkBoundary() throws Exception {
        CryptoStrategy crypto = new AesGcmCrypto("pw");
        // 恰好一个 64KB 分块
        roundTripFile(crypto, 64 * 1024);
        // 一个分块 + 1 字节（最坏跨块情形）
        roundTripFile(crypto, 64 * 1024 + 1);
    }

    @Test
    void fileTamperedInMiddleRejected() throws Exception {
        EciesCrypto crypto = newEcies();
        Path plain = write("t.bin", randomBytes(150_000));
        Path encrypted = tempDir.resolve("t.bin.eci");
        crypto.encryptFile(plain, encrypted);

        byte[] all = Files.readAllBytes(encrypted);
        all[all.length / 2] ^= 0x01;                 // 篡改密文中段（避开文件头）
        Files.write(encrypted, all);

        assertThrows(CryptoException.class,
                () -> crypto.decryptFile(encrypted, tempDir.resolve("t.out")));
    }

    @Test
    void crossFormatFileRejected() throws Exception {
        // AGC1 文件喂给 ECIES 策略：魔数不匹配必须拒绝，而不是错误解读
        CryptoStrategy aes = new AesGcmCrypto("pw");
        Path plain = write("x.bin", "data".getBytes(StandardCharsets.UTF_8));
        Path encrypted = tempDir.resolve("x.bin.agc");
        aes.encryptFile(plain, encrypted);
        assertThrows(CryptoException.class,
                () -> newEcies().decryptFile(encrypted, tempDir.resolve("x.out")));
    }

    // ---------- 曲线自适应（回归守护：修复过 P-384 证书 Invalid coordinate 问题） ----------

    @Test
    void eciesAdaptsToReceiverCurve() throws Exception {
        // 证书是 P-384；这里换运行时生成的 P-256 密钥对，验证临时密钥对跟随接收方曲线
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();

        EciesCrypto crypto = new EciesCrypto(pair.getPublic(), pair.getPrivate());
        byte[] plain = "curve-adaptive".getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(plain, crypto.decrypt(crypto.encrypt(plain)));
    }

    @Test
    void eciesHundredRoundsAreStable() throws Exception {
        EciesCrypto crypto = newEcies();
        for (int i = 0; i < 100; i++) {
            byte[] plain = ("round-" + i).getBytes(StandardCharsets.UTF_8);
            assertArrayEquals(plain, crypto.decrypt(crypto.encrypt(plain)), "第 " + i + " 轮失败");
        }
    }

    // ---------- PemUtils ----------

    @Test
    void certificateMetadataAsExpected() throws Exception {
        X509Certificate cert;
        try (InputStream in = resource(CERT)) {
            cert = PemUtils.loadCertificate(in);
        }
        assertEquals("EC", cert.getPublicKey().getAlgorithm());
        assertTrue(cert.getSubjectX500Principal().getName().contains("774778.xyz"));
        ECPublicKey pub = (ECPublicKey) cert.getPublicKey();
        assertEquals(384, pub.getParams().getCurve().getField().getFieldSize(), "应为 NIST P-384 证书");
    }

    @Test
    void garbagePemRejected() {
        byte[] garbage = "this is not a pem file at all".getBytes(StandardCharsets.UTF_8);
        assertThrows(CryptoException.class,
                () -> PemUtils.loadCertificate(new ByteArrayInputStream(garbage)));
        assertThrows(CryptoException.class,
                () -> PemUtils.loadPrivateKey(new ByteArrayInputStream(garbage)));
    }

    // ---------- 并发 ----------

    @Test
    void sharedInstanceIsThreadSafe() throws Exception {
        CryptoStrategy crypto = new AesGcmCrypto("shared-password");
        ExecutorService pool = Executors.newFixedThreadPool(8);
        try {
            List<Future<byte[]>> futures = new ArrayList<>();
            for (int i = 0; i < 8; i++) {
                byte[] plain = ("payload-of-thread-" + i).getBytes(StandardCharsets.UTF_8);
                futures.add(pool.submit(() -> crypto.decrypt(crypto.encrypt(plain))));
            }
            for (int i = 0; i < 8; i++) {
                assertArrayEquals(("payload-of-thread-" + i).getBytes(StandardCharsets.UTF_8),
                        futures.get(i).get(), "线程 " + i + " 结果不匹配");
            }
        } finally {
            pool.shutdownNow();
        }
    }

    // ---------- 工具 ----------

    private static EciesCrypto newEcies() throws Exception {
        PublicKey publicKey;
        PrivateKey privateKey;
        try (InputStream certIn = resource(CERT); InputStream keyIn = resource(KEY)) {
            publicKey = PemUtils.loadPublicKey(certIn);
            privateKey = PemUtils.loadPrivateKey(keyIn);
        }
        return new EciesCrypto(publicKey, privateKey);
    }

    private static InputStream resource(String name) {
        InputStream in = CryptoEdgeCasesTest.class.getResourceAsStream(name);
        assertNotNull(in, "缺少测试资源 " + name);
        return in;
    }

    private Path write(String name, byte[] data) throws Exception {
        Path file = tempDir.resolve(name);
        Files.write(file, data);
        return file;
    }

    private void roundTripFile(CryptoStrategy crypto, int size) throws Exception {
        byte[] data = randomBytes(size);
        Path plain = write("rt-" + size + ".bin", data);
        Path encrypted = tempDir.resolve("rt-" + size + ".bin.enc");
        Path decrypted = tempDir.resolve("rt-" + size + ".out");
        crypto.encryptFile(plain, encrypted);
        crypto.decryptFile(encrypted, decrypted);
        assertArrayEquals(data, Files.readAllBytes(decrypted));
    }

    private static byte[] randomBytes(int length) {
        byte[] data = new byte[length];
        new Random(2026).nextBytes(data);
        return data;
    }

    private static void assertNotNull(Object value, String message) {
        assertTrue(value != null, message);
    }
}
