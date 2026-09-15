package com.xs.custom.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * {@link CryptoUtils} 测试：调用方不传密钥 / 证书，内部自动使用 SSL 目录下的证书。
 */
class CryptoUtilsTest {

    @TempDir
    Path tempDir;

    @Test
    void stringRoundTripWithCertificate() {
        String plain = "这是一段机密消息 123abc";

        String cipher = CryptoUtils.encrypt(plain);

        assertNotEquals(plain, cipher);
        assertEquals(plain, CryptoUtils.decrypt(cipher));
    }

    @Test
    void sameStringEncryptsDifferently() {
        // 每次加密生成临时密钥对，密文必然不同
        assertNotEquals(CryptoUtils.encrypt("same"), CryptoUtils.encrypt("same"));
    }

    @Test
    void fileRoundTripWithCertificate() throws Exception {
        Path source = tempDir.resolve("report.txt");
        byte[] content = "文件内容\n第二行".getBytes(StandardCharsets.UTF_8);
        Files.write(source, content);

        Path encrypted = CryptoUtils.encryptFile(source.toString());
        assertEquals("report.txt.enc", encrypted.getFileName().toString());
        assertTrue(Files.exists(encrypted));

        Path decrypted = CryptoUtils.decryptFile(encrypted.toString());
        assertEquals("report.txt", decrypted.getFileName().toString());
        assertArrayEquals(content, Files.readAllBytes(decrypted));
    }


    @Test
    void stringEncrypt() {
        String plain = "这是一段机密消息 123abc";

        String cipher = CryptoUtils.encrypt(plain);

        System.out.println(
                "明文：" + plain + "\n" +
                "密文：" + cipher + "\n" +
                "解密：" + CryptoUtils.decrypt(cipher)
        );
    }
    // 解密随机密文：密文必须由本次运行生成，无法跨运行预设
    @Test
    void stringDecrypt() {
        String plain = "随便一段随机内容 " + System.nanoTime();
        String cipher = CryptoUtils.encrypt(plain);

        System.out.println(
                "明文：" + plain + "\n" +
                "密文：" + cipher + "\n" +
                "解密：" + CryptoUtils.decrypt(cipher)
        );

        assertEquals(plain, CryptoUtils.decrypt(cipher));
    }

    // 加密解密资源文件夹下的真实文件：密文也生成在资源文件夹中，原文件不删除
    @Test
    void fileEncryptDecrypt() throws Exception {
        // 资源文件夹路径：src/main/resources
        Path resourceDir = Path.of("src/main/resources");
        Path source = resourceDir.resolve("application.yaml");
        assertTrue(Files.exists(source), "资源文件不存在: " + source.toAbsolutePath());

        byte[] content = Files.readAllBytes(source);

        // 加密：密文生成在资源文件夹中（application.yaml.enc），原文件保留
        Path encrypted = CryptoUtils.encryptFile(source.toString());
        assertEquals("application.yaml.enc", encrypted.getFileName().toString());
        assertEquals(resourceDir.toAbsolutePath(), encrypted.toAbsolutePath().getParent(),
                "密文应生成在资源文件夹中");
        assertTrue(Files.exists(source), "加密后原文件不应被删除");

        // 解密：还原结果也放在资源文件夹中，避免覆盖原文件
        Path decrypted = CryptoUtils.decryptFile(encrypted.toString(),
                resourceDir.resolve("application.restored.yaml").toString());
        assertTrue(Files.exists(encrypted), "解密后密文文件不应被删除");

        System.out.println(
                "原文件：" + source.toAbsolutePath() + "\n" +
                "密文文件：" + encrypted.toAbsolutePath() + "\n" +
                "解密文件：" + decrypted.toAbsolutePath()
        );

        // 还原结果与原文逐字节一致；原文件内容未被改动
        assertArrayEquals(content, Files.readAllBytes(decrypted));
        assertArrayEquals(content, Files.readAllBytes(source));
    }
}
