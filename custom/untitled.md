com.xs.custom.crypto
│
│  ① 你直接用的（4 个公开类）
├── CryptoStrategy   接口：定义 encrypt/decrypt + encryptFile/decryptFile 四个方法
├── AesGcmCrypto     口令加密：PBKDF2 派生密钥 + AES-256-GCM
├── EciesCrypto      证书加密：ECDH + HKDF + AES-256-GCM（前向保密）
├── PemUtils         工具：从 PEM 文件加载证书/公钥/私钥
│
│  ② 被内部调用的（2 个包私有类，你不用碰）
├── ChunkedAesGcm    大文件 64KB 分块流式加解密（两种策略共用）
├── Hkdf             RFC 5869 密钥派生（EciesCrypto 内部用）
│
│  ③ CryptoException  统一运行时异常（口令错/密文被篡改都抛它）
