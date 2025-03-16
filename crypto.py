import os
import base64
import logging
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class CryptoManager:
    def __init__(self, key_path=None, is_server=False):
        self.is_server = is_server
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.session_key = None
        
        if key_path and os.path.exists(key_path + ".pem"):
            self.load_key(key_path)
        else:
            self.generate_key(key_path)
    
    def generate_key(self, save_path=None):
        # 生成RSA密钥对
        logger.info("生成新的RSA密钥对")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        if save_path:
            # 保存私钥
            private_pem = self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # 保存公钥
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # 确保目录存在
            os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
            
            with open(save_path + ".pem", 'wb') as f:
                f.write(private_pem)
            
            with open(save_path + ".pub", 'wb') as f:
                f.write(public_pem)
    
    def load_key(self, key_path):
        # 加载私钥
        try:
            logger.info(f"从{key_path}.pem加载密钥")
            with open(key_path + ".pem", "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
                self.public_key = self.private_key.public_key()
        except Exception as e:
            logger.error(f"加载密钥失败: {e}")
            self.generate_key(key_path)
    
    def load_peer_public_key(self, key_data):
        try:
            if isinstance(key_data, str):
                key_data = key_data.encode()
            
            self.peer_public_key = serialization.load_pem_public_key(
                key_data,
                backend=default_backend()
            )
            logger.debug("成功加载对方公钥")
        except Exception as e:
            logger.error(f"加载对方公钥失败: {e}")
            raise
    
    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def encrypt_with_rsa(self, data):
        if not self.peer_public_key:
            raise ValueError("缺少对方的公钥")
        
        try:
            if isinstance(data, str):
                data = data.encode()
                
            # RSA加密有大小限制，通常只用来加密会话密钥
            encrypted = self.peer_public_key.encrypt(
                data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logger.debug(f"RSA加密成功，长度: {len(encrypted)}字节")
            return encrypted
        except Exception as e:
            logger.error(f"RSA加密失败: {e}")
            raise
    
    def decrypt_with_rsa(self, encrypted_data):
        if not self.private_key:
            raise ValueError("缺少私钥")
        
        try:    
            # 解密RSA加密的数据
            decrypted = self.private_key.decrypt(
                encrypted_data,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            logger.debug(f"RSA解密成功，长度: {len(decrypted)}字节")
            return decrypted
        except Exception as e:
            logger.error(f"RSA解密失败: {e}")
            raise
    
    def generate_session_key(self):
        # 生成随机会话密钥
        self.session_key = os.urandom(32)  # 256位AES密钥
        logger.info(f"生成新的会话密钥，长度: {len(self.session_key)}字节")
        return self.session_key
    
    def set_session_key(self, key):
        if len(key) != 32:
            logger.warning(f"会话密钥长度 {len(key)} 不是32字节")
        self.session_key = key
        logger.info(f"设置会话密钥，长度: {len(self.session_key)}字节")
    
    def encrypt_data(self, data):
        if not self.session_key:
            raise ValueError("缺少会话密钥")
        
        try:     
            if isinstance(data, str):
                data = data.encode()
                
            # 使用AES-GCM加密大块数据
            iv = os.urandom(12)
            encryptor = Cipher(
                algorithms.AES(self.session_key),
                modes.GCM(iv),
                backend=default_backend()
            ).encryptor()
            
            # 这里不要添加关联数据，保持简单
            ciphertext = encryptor.update(data) + encryptor.finalize()
            
            # 返回IV、标签和密文 - 明确的格式很重要
            result = iv + encryptor.tag + ciphertext
            logger.debug(f"AES加密成功，数据长度: {len(data)}字节，密文长度: {len(result)}字节")
            
            # Base64编码
            return base64.b64encode(result).decode('utf-8')
        except Exception as e:
            logger.error(f"AES加密失败: {e}")
            raise
    
    def decrypt_data(self, encrypted_data):
        if not self.session_key:
            raise ValueError("缺少会话密钥")
        
        try:
            # Base64解码
            if isinstance(encrypted_data, str):
                encrypted_data = base64.b64decode(encrypted_data)
            
            # 检查数据长度
            if len(encrypted_data) < 28:  # IV(12) + Tag(16)
                raise ValueError(f"加密数据太短: {len(encrypted_data)}字节")
            
            # 提取IV、标签和密文
            iv = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            logger.debug(f"解密 - IV长度: {len(iv)}字节, Tag长度: {len(tag)}字节, 密文长度: {len(ciphertext)}字节")
            
            # 解密数据
            decryptor = Cipher(
                algorithms.AES(self.session_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()
            
            # 这里不要添加关联数据，保持简单
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()
            logger.debug(f"AES解密成功，解密后长度: {len(decrypted)}字节")
            return decrypted
        except Exception as e:
            logger.error(f"AES解密失败: {e}")
            # 在解密失败时打印更多诊断信息
            logger.error(f"会话密钥长度: {len(self.session_key) if self.session_key else 0}字节")
            if isinstance(encrypted_data, bytes):
                logger.error(f"加密数据样本: {encrypted_data[:20].hex()}")
            raise