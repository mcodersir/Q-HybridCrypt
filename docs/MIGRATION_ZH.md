# Q-HybridCrypt v2.0 "PHOENIX" — 迁移指南

## 目录

1. [迁移概述](#迁移概述)
2. [迁移流程](#迁移流程)
3. [从 PyCryptodome 迁移](#从-pycryptodome-迁移)
4. [从 cryptography/Fernet 迁移](#从-cryptographyfernet-迁移)
5. [从 PyNaCl 迁移](#从-pynacl-迁移)
6. [从自定义 AES-GCM 迁移](#从自定义-aes-gcm-迁移)
7. [批量迁移](#批量迁移)
8. [透明重加密](#透明重加密)
9. [最佳实践](#最佳实践)
10. [回滚策略](#回滚策略)

---

## 迁移概述

从现有加密库迁移到 Q-HybridCrypt v2.0 "PHOENIX" 是一个设计为简单、低风险的过程。迁移SDK为最常用的 Python 密码学库提供了专用的迁移器类，同时还提供了通用的 `migrate_from()` 便捷函数，可以与任何加密方案配合使用。整个迁移框架围绕**透明重加密**原则构建：您的应用程序代码永远不会处理中间明文，旧的解密逻辑被封装在一个单一的回调函数中，由 SDK 在内部调用。

迁移旅程通常涉及三个阶段。首先，评估您当前的加密资产清单，识别正在使用哪些库和算法、加密数据存储在哪里以及涉及哪些密钥。其次，使用 SDK 执行迁移，逐条或批量将所有数据重新加密为 PHOENIX 三层级联协议格式。第三，通过解密新加密数据的统计样本并与原始明文进行比较来验证迁移，确保在转换过程中没有数据丢失或损坏。这三个阶段构成了一个完整的迁移生命周期，每个阶段都有明确的目标和可验证的成果。

![迁移流程](images/migration_flow.png)

Q-HybridCrypt 的迁移SDK支持四个主要的源库：PyCryptodome、`cryptography` 包（包括 Fernet）、PyNaCl/NaCl 和自定义 AES-GCM 实现。每个迁移器类提供了针对其源库约定和数据格式量身定制的简化 API，而通用的 `migrate_from()` 函数则提供了一个库无关的入口点，只需要一个解密回调即可。这种灵活性意味着您可以从几乎任何加密方案迁移，包括专有或自制的实现，而无需编写自定义集成代码。

---

## 迁移流程

### 分步迁移工作流

迁移过程遵循一系列定义明确的步骤，确保每个阶段的数据完整性和安全性。理解每个步骤有助于您有效规划迁移并避免可能导致数据丢失或安全漏洞的常见陷阱。迁移不是一次性的操作，而是一个需要谨慎规划和执行的系统工程任务。

1. **资产清查**：在编写任何迁移代码之前，您必须编目系统中所有加密数据。识别哪些库加密了每条数据、使用了哪些密钥以及密文和密钥的存储位置。这份清单构成了迁移计划的基础，帮助您估算所需的工作量。特别需要注意可能使用多层加密或密钥随时间轮换的数据。遗漏任何加密数据都可能导致迁移后系统中同时存在新旧两种格式，增加维护的复杂性和安全风险。

2. **密钥提取**：确保您可以访问旧格式所需的所有解密密钥。如果密钥存储在密钥管理服务（KMS）、硬件安全模块（HSM）或环境变量中，请验证迁移过程是否能够访问它们。在开始完整迁移之前测试解密一个小样本，因为在迁移过程中发现缺少密钥可能会使整个过程停滞，并使您的数据处于不一致状态。建议为每个密钥建立访问测试脚本，确保在迁移执行窗口内能够顺利获取所需密钥。

3. **迁移执行**：使用适当的迁移器类或 `migrate_from()` 函数重新加密每条数据。SDK 在内部处理旧格式的解密和 PHOENIX 下的重加密，因此您的应用程序代码不会看到明文。每次迁移调用返回新的密文以及未来加密操作所需的 PHOENIX 公钥。请注意，迁移器在内部生成的私钥必须被安全存储——这是迁移过程中最关键的安全步骤之一。

4. **验证**：迁移后，通过使用 PHOENIX 解密统计显著数量的已迁移数据并与原始明文进行比较来验证。强烈建议使用自动化的验证脚本，特别是对于手动验证不切实际的大数据集。考虑保留原始明文的校验和（如 SHA3-256）用于比较目的。验证样本量通常应至少覆盖总数据量的 5-10%，或不少于 100 条记录，以获得统计上的置信度。

5. **密钥轮换**：一旦迁移得到验证，使用认证的销毁方法安全地销毁旧加密密钥。将 PHOENIX 私钥保留在安全存储中。更新所有应用程序配置以指向新的密文和密钥，并从代码库中删除对旧加密库的引用。密钥销毁应使用安全的擦除方法，如多次覆写，并确保销毁操作在日志中留有审计记录。

### 迁移架构

```
┌──────────────────┐     ┌──────────────────┐     ┌──────────────────┐
│  旧密文           │────▶│  迁移 SDK         │────▶│  PHOENIX 密文     │
│  (任意格式)       │     │  (透明重加密)      │     │  (QHC2 格式)     │
│                   │     │                   │     │                  │
└──────────────────┘     └────────┬─────────┘     └──────────────────┘
                                  │
                         ┌────────┴─────────┐
                         │  旧解密函数        │
                         │  (您的回调)        │
                         └──────────────────┘
```

迁移SDK从不在内存中存储明文超过必要时间。重加密完成后，明文缓冲区被释放并有资格进行垃圾回收。为了额外的安全性，您可以使用 `qhybridcrypt.utils` 中的 `zero_memory()` 工具函数在敏感缓冲区超出作用域之前显式覆写它们。这种主动内存清零的做法在处理高度敏感数据时尤为重要，可以防止因内存转储或核心转储导致的明文泄露。

---

## 从 PyCryptodome 迁移

PyCryptodome 是 Python 生态中使用最广泛的密码学库之一，提供包括 AES、RSA、ChaCha20 和众多哈希函数在内的广泛算法支持。从 PyCryptodome 迁移到 Q-HybridCrypt 非常简单，因为 `PyCryptodomeMigrator` 类接受一个简单的解密回调，封装了您现有的 PyCryptodome 解密逻辑。这意味着您不需要改变使用 PyCryptodome 解密的方式；只需将解密函数传递给迁移器即可获得 PHOENIX 加密的输出。

最常见的 PyCryptodome 加密模式涉及 AES-GCM、带 PKCS7 填充的 AES-CBC 以及 RSA-OAEP。每种模式需要略微不同的解密回调，但迁移过程本身保持一致。关键洞察是迁移器不关心旧密文的内部结构；它只需要一个能将旧密文字节转换为明文字节的函数。这种设计将迁移逻辑与特定加密方案解耦，使其对 PyCryptodome 配置的变化具有鲁棒性。

### 迁移 AES-GCM 数据

```python
from qhybridcrypt.migration import PyCryptodomeMigrator

# 您现有的 PyCryptodome AES-GCM 配置
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

aes_key = get_random_bytes(32)  # 您现有的 AES-256 密钥

# 旧加密函数（您当前的加密方式）
def old_aes_gcm_encrypt(plaintext: bytes) -> bytes:
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext  # nonce(16) + tag(16) + ciphertext

# 为迁移器定义解密回调
def old_aes_gcm_decrypt(ciphertext_bytes: bytes) -> bytes:
    nonce = ciphertext_bytes[:16]
    tag = ciphertext_bytes[16:32]
    ct = ciphertext_bytes[32:]
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ct, tag)

# --- 迁移 ---
migrator = PyCryptodomeMigrator(security_level=3)

# 迁移单条加密数据
old_ciphertext = old_aes_gcm_encrypt(b"使用 PyCryptodome 加密的敏感数据")
new_ciphertext, phoenix_public_key = migrator.migrate(
    old_ciphertext,
    old_aes_gcm_decrypt,
    associated_data=b"migration:pycryptodome->phoenix"
)

print(f"旧密文大小: {len(old_ciphertext)} 字节")
print(f"新 PHOENIX 密文大小: {len(new_ciphertext)} 字节")
print(f"PHOENIX 公钥大小: {len(phoenix_public_key)} 字节")
```

### 迁移 AES-CBC 数据

AES-CBC 模式在早期的加密实现中非常常见，许多遗留系统仍在使用这种模式。与 GCM 模式不同，CBC 模式本身不提供认证，通常需要配合 HMAC 进行完整性验证。在迁移时，您的解密回调应该处理完整的 CBC 解密逻辑，包括 PKCS7 填充的移除。迁移完成后，PHOENIX 的三重认证机制将自动为数据提供远超 CBC+HMAC 的认证保护。

```python
from qhybridcrypt.migration import PyCryptodomeMigrator
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

aes_key = b'your-32-byte-aes-key-here-1234567890'  # 您现有的密钥

def old_aes_cbc_decrypt(ciphertext_bytes: bytes) -> bytes:
    iv = ciphertext_bytes[:16]
    ct = ciphertext_bytes[16:]
    cipher = AES.new(aes_key, AES.MODE_CBC, iv=iv)
    return unpad(cipher.decrypt(ct), AES.block_size)

migrator = PyCryptodomeMigrator()
old_ct = b'...'  # 您的 AES-CBC 加密数据
new_ct, new_pk = migrator.migrate(old_ct, old_aes_cbc_decrypt)
```

### 迁移 RSA 加密数据

RSA 加密数据的迁移需要特别注意密钥长度限制。RSA 加密有明文大小限制（例如 RSA-2048 配合 OAEP-SHA256 仅支持 190 字节），因此许多应用使用混合 RSA+AES 加密方案。在迁移时，解密回调应该处理完整的混合解密逻辑，将最终明文返回给迁移器。迁移完成后，量子安全的 Module-LWE KEM 将替代脆弱的 RSA 密钥交换，彻底消除 Shor 算法带来的威胁。

```python
from qhybridcrypt.migration import PyCryptodomeMigrator
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# 加载您现有的 RSA 私钥
with open('private_key.pem', 'rb') as f:
    rsa_key = RSA.import_key(f.read())

def old_rsa_decrypt(ciphertext_bytes: bytes) -> bytes:
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(ciphertext_bytes)

migrator = PyCryptodomeMigrator(security_level=5)  # 替代 RSA 使用最高安全等级
new_ct, new_pk = migrator.migrate(old_rsa_ciphertext, old_rsa_decrypt)
```

**重要提示**：RSA 加密的明文大小有限（例如 RSA-2048 配合 OAEP-SHA256 仅支持 190 字节）。如果您的应用使用混合 RSA+AES 加密（RSA 加密 AES 密钥，然后 AES 加密数据），您的解密回调应在内部处理完整的混合解密逻辑，将最终明文返回给迁移器。

---

## 从 cryptography/Fernet 迁移

`cryptography` 库是 Python 功能最丰富且维护最好的密码学库。它同时提供低级原语（AES-GCM、ChaCha20）和 Fernet 等高级构造。`CryptographyIOMigrator` 类通过 `migrate_fernet()` 便捷方法为 Fernet 令牌提供专用支持，自动处理 base64 解码和 Fernet 解密。对于 `cryptography` 库的其他原语，标准的 `migrate()` 方法配合自定义解密回调可以无缝工作。

Fernet 之所以特别流行，是因为它提供了一个简单的、自包含的加密 API，在单一的 `encrypt()`/`decrypt()` 接口中处理密钥生成、nonce 管理和认证。然而，Fernet 使用 AES-128-CBC 配合 HMAC-SHA256 进行认证，仅提供 128 位安全性——远低于 PHOENIX 提供的 192 位经典安全性和 128 位量子安全性。从 Fernet 迁移到 Q-HybridCrypt 代表了一次重大的安全升级，特别是对于关注后量子威胁的组织而言。Fernet 的 AES-128 密钥在量子计算环境下仅提供 64 位安全性，这对于长期数据保护来说是不够的。

### 迁移 Fernet 令牌

```python
from qhybridcrypt.migration import CryptographyIOMigrator

# 您现有的 Fernet 配置
from cryptography.fernet import Fernet

fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)

# 使用 Fernet 加密一些数据（旧方式）
old_token = fernet.encrypt(b"之前使用 Fernet 加密的数据")

# --- 使用 migrate_fernet() 进行一步式迁移 ---
migrator = CryptographyIOMigrator(security_level=3)
new_ciphertext, phoenix_pk = migrator.migrate_fernet(
    old_token,
    fernet_key,  # 直接传入 Fernet 密钥
    associated_data=b"migration:fernet->phoenix"
)

print(f"Fernet 令牌大小: {len(old_token)} 字节")
print(f"PHOENIX 密文大小: {len(new_ciphertext)} 字节")
```

### 从 cryptography 库迁移 AES-GCM

`cryptography` 库的 AES-GCM 实现是许多 Python 应用的加密基础。与 Fernet 不同，AES-GCM 不提供自包含的令牌格式，因此 nonce 和认证标签需要与密文一起存储。在迁移时，您需要将 nonce 和密文组合成迁移器期望的格式，然后在解密回调中正确地拆分它们。这种格式处理是 AES-GCM 迁移中最常见的错误来源，因此建议仔细检查您的密文存储格式。

```python
from qhybridcrypt.migration import CryptographyIOMigrator
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

aes_key = AESGCM.generate_key(bit_length=256)
aesgcm = AESGCM(aes_key)
nonce = b'12-byte-nonce'

# 旧加密
old_ct = aesgcm.encrypt(nonce, b"使用 cryptography 库 AES-GCM 加密的数据", None)

# 解密回调
def old_decrypt(ciphertext_bytes: bytes) -> bytes:
    # 假设格式: nonce(12) + aes_gcm_ct
    n = ciphertext_bytes[:12]
    ct = ciphertext_bytes[12:]
    return aesgcm.decrypt(n, ct, None)

# 迁移
migrator = CryptographyIOMigrator()
combined_old = nonce + old_ct  # 为迁移器组合
new_ct, new_pk = migrator.migrate(combined_old, old_decrypt)
```

### 从 cryptography.io ChaCha20-Poly1305 迁移

```python
from qhybridcrypt.migration import CryptographyIOMigrator
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

key = ChaCha20Poly1305.generate_key()
chacha = ChaCha20Poly1305(key)
nonce = b'12-byte-nc'

old_ct = chacha.encrypt(nonce, b"ChaCha20 加密数据", None)

def old_chacha_decrypt(ct_bytes: bytes) -> bytes:
    n = ct_bytes[:12]
    ct = ct_bytes[12:]
    return chacha.decrypt(n, ct, None)

migrator = CryptographyIOMigrator()
new_ct, new_pk = migrator.migrate(nonce + old_ct, old_chacha_decrypt)
```

---

## 从 PyNaCl 迁移

PyNaCl 提供了对 NaCl（网络和密码学）库的 Python 绑定，实现了 Daniel Bernstein 的密码学原语，包括 XSalsa20-Poly1305 认证加密、X25519 密钥交换和 Ed25519 签名。`NaClMigrator` 类专门设计用于处理 NaCl 密文格式，该格式包括预置在密文前的 16 字节 Poly1305 标签。迁移过程与其他迁移器相同：您提供使用现有 NaCl 解密代码的解密回调，迁移器返回 PHOENIX 加密的输出。

NaCl 的 `SecretBox` 使用 XSalsa20-Poly1305，提供 256 位密钥安全性和 192 位 nonce。虽然 XSalsa20-Poly1305 被认为是安全的，但它在 KEM 意义上并非量子抗性的——密钥交换机制（X25519）容易受到量子计算机上 Shor 算法的攻击。通过迁移到 Q-HybridCrypt，您用抵抗经典和量子密码分析的 Module-LWE KEM 替换了量子脆弱的 X25519 密钥交换，同时获得了三层级联加密的好处。这意味着即使攻击者拥有大规模量子计算机，也无法通过攻破密钥交换来获取您的数据。

### 迁移 SecretBox 数据

```python
from qhybridcrypt.migration import NaClMigrator

# 您现有的 PyNaCl 配置
from nacl.secret import SecretBox
from nacl.utils import random

nacl_key = random(SecretBox.KEY_SIZE)  # 32 字节
box = SecretBox(nacl_key)

# 旧加密
old_ciphertext = box.encrypt(b"使用 PyNaCl SecretBox 加密的数据")

# 解密回调
def nacl_decrypt(ct_bytes: bytes) -> bytes:
    return box.decrypt(ct_bytes)

# --- 迁移 ---
migrator = NaClMigrator(security_level=3)
new_ciphertext, phoenix_pk = migrator.migrate(
    old_ciphertext,
    nacl_decrypt,
    associated_data=b"migration:nacl->phoenix"
)

print(f"NaCl 密文大小: {len(old_ciphertext)} 字节")
print(f"PHOENIX 密文大小: {len(new_ciphertext)} 字节")
```

### 迁移 SealedBox（公钥加密）

SealedBox 是 NaCl 中公钥加密的高级接口，底层使用 X25519 密钥交换和 XSalsa20-Poly1305 认证加密。X25519 基于椭圆曲线 Diffie-Hellman 密钥交换，其安全性依赖于椭圆曲线离散对数问题的困难性。然而，Shor 算法可以在量子计算机上高效求解离散对数问题，这意味着 X25519 在后量子时代将不再安全。通过迁移到 Q-HybridCrypt，您将 X25519 替换为 Module-LWE KEM，后者被认为对量子计算机是困难的。

```python
from qhybridcrypt.migration import NaClMigrator
from nacl.public import PrivateKey, SealedBox

# 您现有的 NaCl 密钥对
nacl_private_key = PrivateKey.generate()
nacl_public_key = nacl_private_key.public_key

sealed_box = SealedBox(nacl_private_key)

# 旧加密
old_ct = SealedBox(nacl_public_key).encrypt(b"公钥加密数据")

# 解密回调
def nacl_sealed_decrypt(ct_bytes: bytes) -> bytes:
    return sealed_box.decrypt(ct_bytes)

# 迁移 — 用 Module-LWE 替代量子脆弱的 X25519
migrator = NaClMigrator(security_level=3)
new_ct, new_pk = migrator.migrate(old_ct, nacl_sealed_decrypt)
```

---

## 从自定义 AES-GCM 迁移

许多应用实现了自己的 AES-GCM 加密方案，通常具有自定义的 nonce 管理、密钥派生或密文打包格式。`CustomAESMigrator` 类提供了专门的 `migrate_aes_gcm()` 方法，接受原始 AES-GCM 组件（nonce、密文、标签和密钥）作为独立参数，使用 `cryptography` 库或 PyCryptodome 作为后端在内部处理解密。这消除了为常见 AES-GCM 场景编写解密回调的需要。

迁移器支持最常见的 AES-GCM 密文格式，包括 nonce-前置（nonce + 密文 + 标签）、标签-后置（nonce + 密文 + 标签）以及 nonce、密文和标签存储在不同位置的独立组件格式。通过单独提供各组件，`migrate_aes_gcm()` 可以处理任何这些格式，而无需您先将它们连接成单个字节串。该方法还接受可选的关联数据（AAD），用于原始加密过程中使用了 AAD 的格式。

### 使用 migrate_aes_gcm()

```python
from qhybridcrypt.migration import CustomAESMigrator

# 您现有的 AES-GCM 组件
aes_key = b'0123456789abcdef0123456789abcdef'  # 32 字节密钥
nonce = b'0123456789ab'                         # 12 字节 nonce
ciphertext = b'...'                             # AES-GCM 密文
tag = b'0123456789abcdef'                       # 16 字节 GCM 标签

# --- 迁移 ---
migrator = CustomAESMigrator(security_level=3)
new_ciphertext, phoenix_pk = migrator.migrate_aes_gcm(
    nonce=nonce,
    ciphertext=ciphertext,
    tag=tag,
    aes_key=aes_key,
    associated_data=b"optional_aad"
)

print(f"新 PHOENIX 密文大小: {len(new_ciphertext)} 字节")
```

### 迁移独立组件的自定义格式

在实际生产环境中，加密数据往往以分散的方式存储。nonce 可能存储在数据库的一个列中，密文存储在另一个列中，而标签则存储在第三个列或完全不同的表中。密钥可能由密钥管理服务（KMS）动态提供，而非静态存储。`migrate_aes_gcm()` 方法的设计充分考虑了这些实际场景，允许您分别传入各个组件，而无需先将它们组装成特定格式。

```python
from qhybridcrypt.migration import CustomAESMigrator

# 如果您的自定义格式将组件分开存储
# （例如 nonce 在数据库的一个列中，密文在另一个列中）
import base64

# 从存储中加载组件
nonce = base64.b64decode(stored_nonce_b64)
ciphertext = base64.b64decode(stored_ct_b64)
tag = base64.b64decode(stored_tag_b64)
aes_key = kms_get_key('my-aes-key-id')

migrator = CustomAESMigrator()
new_ct, pk = migrator.migrate_aes_gcm(
    nonce=nonce,
    ciphertext=ciphertext,
    tag=tag,
    aes_key=aes_key
)

# 在数据库中存储 new_ct 和 pk
store_phoenix_ciphertext(record_id, new_ct, pk)
```

### 使用自定义解密回调迁移

对于真正自定义的实现（如非标准填充、自定义密钥派生等），您仍然可以使用通用的 `migrate()` 方法配合自定义解密回调。这种方法提供了最大的灵活性，允许您处理任何加密格式，无论其多么特殊。解密回调的唯一要求是接受字节串输入并返回明文字节串输出。

```python
from qhybridcrypt.migration import CustomAESMigrator

# 对于真正的自定义实现（例如非标准填充、自定义密钥派生）
def my_custom_decrypt(ct_bytes: bytes) -> bytes:
    # 您的自定义解密逻辑
    nonce = ct_bytes[:12]
    tag = ct_bytes[-16:]
    ct = ct_bytes[12:-16]
    # ... 自定义解密 ...
    return plaintext

migrator = CustomAESMigrator()
new_ct, pk = migrator.migrate(old_ct_bytes, my_custom_decrypt)
```

---

## 批量迁移

对于拥有大型数据集的应用——如包含数千或数百万加密记录的数据库——迁移SDK提供了 `batch_migrate()` 方法，可以在单次操作中高效处理多个密文。批量迁移中的所有条目使用相同的 PHOENIX 密钥对进行迁移，这减少了密钥管理开销并简化了已迁移数据的部署。批量迁移器还支持进度回调函数，允许您实时监控迁移进度，这对于长时间运行的大型数据集迁移至关重要。

批量迁移在设计上考虑了容错性。如果任何单个条目迁移失败（例如解密回调因损坏的密文而抛出异常），整个批量操作将被中止，并附带描述性错误消息指示哪个条目失败以及原因。这种"全有或全无"的方法确保了数据一致性：要么所有条目成功迁移，要么都不迁移，防止可能使数据处于不一致状态的部分迁移。对于单个条目失败不应阻塞整个迁移的数据集，您可以在解密回调中实现重试逻辑或跳过逻辑。

### 批量迁移示例

```python
from qhybridcrypt.migration import MigrationSDK

# 假设您有 1000 条来自旧系统的加密记录
old_records = []  # 字节列表，每条都是旧格式密文
for i in range(1000):
    old_records.append(old_encrypt(f"Record {i}".encode()))

# 定义旧解密函数
def old_decrypt(ct: bytes) -> bytes:
    # 您现有的解密逻辑
    return old_decrypt_impl(ct)

# --- 批量迁移 ---
sdk = MigrationSDK(security_level=3)

def progress_callback(current: int, total: int) -> None:
    pct = (current / total) * 100
    print(f"\r迁移中: {current}/{total} ({pct:.1f}%)", end='', flush=True)

new_ciphertexts, phoenix_pk = sdk.batch_migrate(
    old_ciphertexts=old_records,
    old_decrypt_fn=old_decrypt,
    associated_data=b"batch:migration:2024",
    on_progress=progress_callback
)

print(f"\n迁移完成! {len(new_ciphertexts)} 条记录已迁移。")
print(f"PHOENIX 公钥: {phoenix_pk.hex()[:32]}...")
```

### 带错误处理的批量迁移

在实际生产环境中，数据质量往往不够理想——可能存在损坏的密文、过期的密钥或不完整的记录。对于这类数据集，建议使用逐条迁移配合独立的错误处理，而非批量迁移的"全有或全无"模式。这样可以将成功迁移的记录和失败记录分别跟踪，便于后续排查和修复问题。

```python
from qhybridcrypt.migration import MigrationSDK, MigrationError

sdk = MigrationSDK()

# 对于某些记录可能损坏的数据集，使用逐条迁移配合错误处理
# 而非 batch_migrate()
successful = []
failed = []

for i, old_ct in enumerate(old_records):
    try:
        new_ct, pk = sdk.migrate_encrypted_data(old_ct, old_decrypt)
        successful.append((i, new_ct, pk))
    except MigrationError as e:
        failed.append((i, str(e)))
        print(f"记录 {i} 失败: {e}")

print(f"成功: {len(successful)}, 失败: {len(failed)}")
```

---

## 透明重加密

**透明重加密**是 Q-HybridCrypt 迁移SDK的旗舰功能。它提供了一步式迁移路径，读取旧格式密文并输出 PHOENIX 格式密文，而不会在应用程序代码中暴露明文。这是一个关键的安全功能：因为解密和重加密在 SDK 内部完成，所以不存在明文作为应用程序内存空间中变量被记录、转储或通过异常回溯意外暴露的时间窗口。

透明重加密的实现简单而强大。`migrate_encrypted_data()` 方法接受两个主要参数：旧密文字节和解密回调函数。SDK 调用回调获取明文，立即使用 PHOENIX 协议通过新的 KEM 封装进行重加密，并返回新的密文以及未来加密所需的公钥。明文仅作为 SDK 内部作用域中的临时变量存在，一旦重加密完成即有资格被垃圾回收。这种设计确保了即使在迁移过程中应用程序崩溃，明文也不会持久化到磁盘或日志中。

### 透明重加密工作原理

```
┌─────────────────┐
│  旧密文           │
│  (任意格式)       │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────────┐
│           迁移 SDK 内部逻辑                    │
│                                              │
│  1. 调用 old_decrypt_fn(old_ciphertext)      │
│     └──▶ plaintext (临时, 内存中)             │
│                                              │
│  2. 生成新的 PHOENIX 密钥对                    │
│     └──▶ public_key, private_key             │
│                                              │
│  3. crypto.encrypt(plaintext, public_key)    │
│     └──▶ new_ciphertext                      │
│                                              │
│  4. 从内存中释放明文                           │
│                                              │
└────────┬──────────────────────┬──────────────┘
         │                      │
         ▼                      ▼
┌─────────────────┐   ┌─────────────────┐
│  新密文           │   │  公钥             │
│  (QHC2 格式)     │   │  (用于未来加密)    │
│                  │   │                  │
└─────────────────┘   └─────────────────┘
```

### 使用便捷函数

使用透明重加密最简单的方式是通过 `migrate_from()` 便捷函数，它只需要源库名称、旧密文和解密回调。此函数自动选择适当的迁移器类并在单次调用中处理整个迁移过程。无论您的数据来自哪个加密库，`migrate_from()` 都能提供统一的迁移体验，大大降低了迁移的认知负担。

```python
from qhybridcrypt.migration import migrate_from

# 从任意库进行通用一步式迁移
def my_decrypt(ct: bytes) -> bytes:
    # 您现有的解密逻辑 — 适用于任意库
    return plaintext_bytes

new_ct, pk = migrate_from(
    library='pycryptodome',  # 或 'cryptography', 'nacl', 'custom', 'aes-gcm'
    old_ciphertext=old_encrypted_data,
    old_decrypt_fn=my_decrypt,
    security_level=3,
    associated_data=b"optional_context"
)

# new_ct 现已使用 PHOENIX 加密; pk 是用于未来加密的公钥
```

---

## 最佳实践

### 迁移前检查清单

在开始迁移之前，请确保您已经处理了以下每个事项。准备不充分可能导致数据丢失、停机时间延长或迁移窗口期间的安全漏洞。每一项检查都对应着迁移过程中可能遇到的实际风险，提前解决这些问题可以大大提高迁移的成功率。

1. **完整数据清单**：记录加密数据的每个存储位置，包括数据库、文件系统、备份、缓存和消息队列。未纳入迁移的加密数据将保留旧格式，可能造成双重加密维护负担。特别关注可能分散在多个微服务、日志系统或数据仓库中的加密数据。

2. **密钥可访问性**：验证旧格式的所有解密密钥均可访问且功能正常。在开始完整迁移之前测试解密一个代表性样本。存储在 HSM 或云 KMS 服务中的密钥可能需要提前配置特殊访问权限。建议为每个密钥建立访问性测试，确认迁移进程具有足够的权限来执行解密操作。

3. **备份策略**：在开始迁移之前创建所有加密数据和解密密钥的验证备份。这些备份是您遇到意外问题时的安全网。备份完成后，务必通过从备份恢复少量数据并验证其正确性来测试备份的完整性和可用性。

4. **回滚计划**：定义清晰的回滚程序，允许您在迁移失败或产生意外结果时恢复到旧加密格式。详见[回滚策略](#回滚策略)部分。回滚计划应该在迁移开始之前就制定完成并获得相关利益方批准，而不是在出现问题时才临时制定。

5. **停机窗口**：规划维护窗口，确保迁移期间数据不会被积极读取或写入。迁移期间的并发修改可能导致数据不一致或丢失。对于 24/7 运行的系统，考虑实施双写策略或使用功能标志来控制迁移的启用和禁用。

### 迁移期间的安全考虑

- **密钥存储**：迁移期间生成的 PHOENIX 私钥必须以与原始密钥相同或更高的保护级别存储。考虑使用硬件安全模块（HSM）或云 KMS 进行生产密钥存储。绝不要将私钥存储在源代码、版本控制中的配置文件或未加密的环境变量中。私钥泄露将直接导致所有使用该密钥加密的数据可被解密。

- **内存处理**：虽然迁移SDK最小化了明文暴露，但 Python 的垃圾回收器不保证立即清零内存。对于处理高度敏感数据的应用，考虑使用 `qhybridcrypt.utils` 中的 `zero_memory()` 工具函数在敏感字节数组超出作用域之前显式覆写它们。这种做法虽然增加了少量性能开销，但对于金融、医疗等高度敏感领域是必要的安全措施。

- **迁移日志**：SDK 维护一个内部迁移日志，记录每条旧密文的哈希、新公钥的哈希和迁移状态。通过 `sdk.get_migration_log()` 访问此日志以进行审计。请注意，此日志包含密文的密码学哈希，如果被攻击者获取可能有用——请相应地保护日志。建议将迁移日志存储在与密文相同的保护级别下。

- **关联数据一致性**：使用关联数据（AAD）迁移时，确保迁移期间使用的 AAD 与解密时将使用的 AAD 匹配。不匹配的 AAD 将导致解密失败，即使使用正确的私钥。良好的做法是在 AAD 中包含迁移时间戳和源库标识符，为未来的解密操作提供上下文。例如：`aad = b"migration:2024-01-15:fernet->phoenix:record_type:user_data"`。

- **量子威胁时间线**：虽然当前的量子计算机无法破解 RSA、ECC 或对称加密，但"先收集，后解密"的威胁是真实的。攻击者可能今天收集加密数据，等待量子计算机可用后再解密。尽快迁移到 Q-HybridCrypt 可确保在 PHOENIX 协议下加密的数据即使面对未来的量子对手也保持安全。对于具有长保密周期的数据（如医疗记录、金融数据、国家机密），这一威胁尤为紧迫。

### 性能优化

- **批量处理**：对大型数据集使用 `batch_migrate()` 而非在循环中调用 `migrate_encrypted_data()`。批量迁移为所有条目生成单一密钥对，减少密钥管理开销并简化存储。批量迁移还减少了密钥生成的总时间，因为只需生成一次密钥对。

- **降低安全等级用于测试**：开发和测试期间，使用 `security_level=1` 获得更快的密钥生成和加密速度。生产环境切换到 `security_level=3`（默认）或 `security_level=5`。安全等级 1 的密钥生成速度大约是等级 3 的 2-3 倍，这对于频繁运行的测试套件来说可以节省大量时间。

- **并发迁移**：对于非常大的数据集，可以对数据进行分区并运行多个并行迁移进程，每个处理一部分记录。确保每个分区使用自己的密钥对以维护密钥分离。并发迁移可以显著减少总迁移时间，但需要注意数据库连接池和 I/O 瓶颈的影响。

---

## 回滚策略

稳健的回滚策略对于任何迁移项目都是必不可少的。即使经过充分测试，生产迁移中也可能出现需要恢复到旧加密格式的意外问题。Q-HybridCrypt 迁移SDK通过多种机制支持回滚，每种机制适用于不同的场景和风险容忍度。选择哪种回滚策略取决于您的数据量、停机时间容忍度和风险承受能力。

### 策略1：双写（推荐用于生产环境）

双写策略在迁移期间同时维护旧格式和新格式密文。应用程序代码从新格式读取但继续写入两种格式，直到迁移完全验证通过。这种策略提供了最安全的回滚路径，因为您可以通过切换读取路径立即恢复到旧格式，数据丢失风险为零。双写期间虽然增加了存储开销和写入延迟，但与迁移失败可能导致的数据不可用相比，这些代价是完全值得的。

```python
# 迁移期间的双写模式
class DualWriteCrypto:
    def __init__(self, old_encrypt_fn, old_decrypt_fn, phoenix_crypto, phoenix_pk):
        self.old_encrypt = old_encrypt_fn
        self.old_decrypt = old_decrypt_fn
        self.phoenix = phoenix_crypto
        self.phoenix_pk = phoenix_pk
        self.use_phoenix = True  # 切换开关用于回滚

    def encrypt(self, plaintext: bytes) -> dict:
        old_ct = self.old_encrypt(plaintext)
        new_ct = self.phoenix.encrypt(plaintext, self.phoenix_pk)
        return {'old': old_ct, 'new': new_ct}

    def decrypt(self, data: dict) -> bytes:
        if self.use_phoenix:
            return self.phoenix.decrypt(data['new'], self.phoenix_sk)
        else:
            return self.old_decrypt(data['old'])
```

### 策略2：密钥引用保留

`migrate_encrypted_data()` 方法支持 `keep_old_key_ref` 参数，存储旧加密密钥的哈希引用。虽然这不直接支持回滚（旧密钥本身不被存储），但它提供了将每个 PHOENIX 密文链接到其源加密的审计跟踪。这对于合规性和取证目的非常有用。当您需要确认某条数据是从哪个旧密钥迁移而来时，密钥引用可以提供关键线索。

```python
sdk = MigrationSDK()

# 保留旧密钥引用用于审计跟踪
new_ct, pk = sdk.migrate_encrypted_data(
    old_ciphertext,
    old_decrypt_fn,
    keep_old_key_ref=True  # 在迁移日志中存储 SHA3-256(old_ct[:64])
)

# 查看审计跟踪
log = sdk.get_migration_log()
for entry in log:
    print(f"状态: {entry['status']}")
    print(f"旧格式哈希: {entry['old_format_hash']}")
    print(f"旧密钥引用: {entry['old_key_ref']}")
    print(f"新密钥哈希: {entry['new_key_hash']}")
```

### 策略3：备份恢复

最简单的回滚策略是维护旧加密数据和解密密钥的完整备份。如果迁移需要回滚，从备份恢复旧密文并重新配置应用程序使用旧加密库。这种策略需要足够的备份存储空间和经过测试的恢复程序。备份恢复的可靠性完全取决于备份的完整性和恢复程序的正确性，因此务必在迁移前验证备份的可用性。

```python
# 迁移前: 创建验证过的备份
import shutil

def backup_before_migration(data_store_path, backup_path):
    shutil.copytree(data_store_path, backup_path)
    # 验证备份完整性
    verify_backup_integrity(data_store_path, backup_path)

# 迁移后: 如需回滚
def rollback_to_old_format(backup_path, data_store_path):
    shutil.copytree(backup_path, data_store_path, dirs_exist_ok=True)
    # 重新配置应用使用旧加密库
    update_config('encryption_library', 'old_library')
```

### 策略4：功能标志渐进式迁移

对于大规模部署，使用功能标志控制每个组件或用户段使用哪种加密格式。这允许您逐步迁移、独立验证每个段并在不影响整个系统的情况下回滚单个段。功能标志方法特别适用于多租户系统或微服务架构，其中不同组件可以独立控制其加密策略，从而将迁移风险隔离在最小范围内。

```python
# 基于功能标志的迁移
import flags  # 您的功能标志系统

def get_crypto_for_user(user_id: str):
    if flags.is_enabled('phoenix_encryption', user_id):
        return phoenix_crypto, phoenix_pk
    else:
        return old_crypto, old_key

# 逐段迁移用户
for segment in user_segments:
    migrate_segment(segment)
    validate_segment(segment)
    flags.enable('phoenix_encryption', segment)
```

---

## 快速参考

| 迁移器类 | 源库 | 关键方法 | 便捷方法 |
|---------|------|---------|---------|
| `PyCryptodomeMigrator` | PyCryptodome | `.migrate(ct, decrypt_fn)` | — |
| `CryptographyIOMigrator` | cryptography/Fernet | `.migrate(ct, decrypt_fn)` | `.migrate_fernet(token, key)` |
| `NaClMigrator` | PyNaCl/NaCl | `.migrate(ct, decrypt_fn)` | — |
| `CustomAESMigrator` | 自定义 AES-GCM | `.migrate(ct, decrypt_fn)` | `.migrate_aes_gcm(n, ct, tag, key)` |
| `migrate_from()` | 任意 | — | 通用函数 |
| `MigrationSDK.batch_migrate()` | 任意（批量） | — | 进度回调支持 |

![对比图](images/comparison_chart.png)
