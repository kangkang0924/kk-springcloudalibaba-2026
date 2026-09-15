package com.xs.custom.crypto;

import com.xs.custom.utils.*;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * 字符串加解密测试。
 */
class CryptoToolTest {

    private static final String PASSWORD = "test1234";

    @Test
    void passwordRoundTrip() {
        CryptoStrategy crypto = new AesGcmCrypto(PASSWORD);
        String plain = "这是一段机密消息 123abc";

        byte[] cipher = crypto.encrypt(plain.getBytes(StandardCharsets.UTF_8));
        assertEquals(plain, new String(crypto.decrypt(cipher), StandardCharsets.UTF_8));

        // 口令错误则解密失败
        assertThrows(CryptoException.class,
                () -> new AesGcmCrypto("wrong").decrypt(cipher));
    }

    @Test
    void certificateEncryptOnly() {
        CryptoStrategy crypto = new EciesCrypto(PemUtils.loadPublicKey(
                CryptoToolTest.class.getResourceAsStream("/SSL/774778.xyz-crt.pem")));
        String plain = "只有接收方能看的内容";

        byte[] cipher = crypto.encrypt(plain.getBytes(StandardCharsets.UTF_8));
        // 只持公钥无法解密
        assertThrows(CryptoException.class, () -> crypto.decrypt(cipher));
    }
}
