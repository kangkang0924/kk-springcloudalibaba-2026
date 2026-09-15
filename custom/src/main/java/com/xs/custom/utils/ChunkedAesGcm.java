package com.xs.custom.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;

/**
 * 大文件分块 AES-GCM 流式加解密（包内工具类）：
 * <ul>
 *   <li>每块 nonce = baseNonce XOR 块序号（TLS 1.3 记录 nonce 风格），无需存储逐块 nonce</li>
 *   <li>AAD 绑定 总块数 + 块序号，天然防重排、防截断、防拼接</li>
 *   <li>每次加密使用全新随机会话密钥 + 随机 baseNonce，单文件加密量远低于 GCM 安全上限</li>
 *   <li>内存占用恒定（一个 64KB 缓冲区），可处理任意大小文件</li>
 * </ul>
 * 文件体格式（每块）：[密文长度(4)][密文+GCM标签]
 */
final class ChunkedAesGcm {

    static final int CHUNK_SIZE = 64 * 1024;
    private static final int TAG_BITS = 128;

    private ChunkedAesGcm() {}

    /** 加密：header 由调用方生成并写入文件头，plainSize 用于计算分块 */
    static void encrypt(Path source, Path target, SecretKey key,
                        byte[] header, byte[] baseNonce, long plainSize) {
        long chunkCount = (plainSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
        try (InputStream in = new BufferedInputStream(Files.newInputStream(source));
             OutputStream out = new BufferedOutputStream(Files.newOutputStream(target))) {
            out.write(header);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] chunk = new byte[CHUNK_SIZE];
            for (long index = 0; index < chunkCount; index++) {
                int plainLen = (int) Math.min(plainSize - index * CHUNK_SIZE, CHUNK_SIZE);
                readExactly(in, chunk, plainLen);
                cipher.init(Cipher.ENCRYPT_MODE, key,
                        new GCMParameterSpec(TAG_BITS, nonceOf(baseNonce, index)));
                cipher.updateAAD(aadOf(chunkCount, index));
                byte[] cipherChunk = cipher.doFinal(chunk, 0, plainLen);
                writeInt(out, cipherChunk.length);
                out.write(cipherChunk);
            }
        } catch (IOException | GeneralSecurityException e) {
            throw new CryptoException("文件加密失败: " + source, e);
        }
    }

    /** 解密：入参流已越过文件头，读完 chunkCount 个块后必须恰好到达文件末尾 */
    static void decrypt(InputStream in, OutputStream out, SecretKey key,
                        byte[] baseNonce, long chunkCount) {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            for (long index = 0; index < chunkCount; index++) {
                int cipherLen = readInt(in);
                if (cipherLen < TAG_BITS / 8 || cipherLen > CHUNK_SIZE + TAG_BITS / 8) {
                    throw new CryptoException("密文块长度非法: " + cipherLen);
                }
                byte[] cipherChunk = in.readNBytes(cipherLen);
                if (cipherChunk.length < cipherLen) {
                    throw new CryptoException("密文块被截断");
                }
                cipher.init(Cipher.DECRYPT_MODE, key,
                        new GCMParameterSpec(TAG_BITS, nonceOf(baseNonce, index)));
                cipher.updateAAD(aadOf(chunkCount, index));
                out.write(cipher.doFinal(cipherChunk));
            }
            if (in.read() != -1) {
                throw new CryptoException("密文包含多余数据");
            }
        } catch (IOException | GeneralSecurityException e) {
            throw new CryptoException("文件解密失败（密文被篡改或密钥不匹配）", e);
        }
    }

    /** nonce = baseNonce 的低 8 字节 XOR 大端块序号（TLS 1.3 风格） */
    private static byte[] nonceOf(byte[] base, long index) {
        byte[] nonce = base.clone();
        for (int i = 0; i < 8; i++) {
            nonce[11 - i] ^= (byte) (index >>> (8 * i));
        }
        return nonce;
    }

    private static byte[] aadOf(long chunkCount, long index) {
        return ByteBuffer.allocate(16).putLong(chunkCount).putLong(index).array();
    }

    private static void readExactly(InputStream in, byte[] buf, int len) throws IOException {
        int off = 0;
        while (off < len) {
            int read = in.read(buf, off, len - off);
            if (read < 0) {
                throw new IOException("源文件在加密过程中被截断");
            }
            off += read;
        }
    }

    private static int readInt(InputStream in) throws IOException {
        byte[] b = in.readNBytes(4);
        if (b.length < 4) {
            throw new IOException("文件已截断");
        }
        return ((b[0] & 0xFF) << 24) | ((b[1] & 0xFF) << 16) | ((b[2] & 0xFF) << 8) | (b[3] & 0xFF);
    }

    private static void writeInt(OutputStream out, int value) throws IOException {
        out.write(new byte[]{(byte) (value >>> 24), (byte) (value >>> 16),
                (byte) (value >>> 8), (byte) value});
    }
}
