import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class CryptoManager:
    def __init__(self, key_path=None, is_server=False):
        self.is_server = is_server
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        self.session_key = None
        
        if key_path and os.path.exists(key_path):
            self.load_key(key_path)
        else:
            self.generate_key(key_path)
    
    def generate_key(self, save_path=None):
        # 生成RSA密钥对
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
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            with open(save_path + ".pem", 'wb') as f:
                f.write(private_pem)
            
            with open(save_path + ".pub", 'wb') as f:
                f.write(public_pem)
    
    def load_key(self, key_path):
        # 加载私钥
        try:
            with open(key_path + ".pem", "rb") as key_file:
                self.private_key = serialization.load_pem_private_key(
                    key_file.read(),
                    password=None,
                    backend=default_backend()
                )
                self.public_key = self.private_key.public_key()
        except Exception as e:
            print(f"加载密钥失败: {e}")
            self.generate_key(key_path)
    
    def load_peer_public_key(self, key_data):
        if isinstance(key_data, str):
            key_data = key_data.encode()
        
        self.peer_public_key = serialization.load_pem_public_key(
            key_data,
            backend=default_backend()
        )
    
    def get_public_key_pem(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def encrypt_with_rsa(self, data):
        if not self.peer_public_key:
            raise ValueError("缺少对方的公钥")
        
        if isinstance(data, str):
            data = data.encode()
            
        # RSA加密有大小限制，通常只用来加密会话密钥
        return self.peer_public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt_with_rsa(self, encrypted_data):
        if not self.private_key:
            raise ValueError("缺少私钥")
            
        # 解密RSA加密的数据
        return self.private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def generate_session_key(self):
        # 生成随机会话密钥
        self.session_key = os.urandom(32)  # 256位AES密钥
        return self.session_key
    
    def set_session_key(self, key):
        self.session_key = key
    
    def encrypt_data(self, data):
        if not self.session_key:
            raise ValueError("缺少会话密钥")
            
        if isinstance(data, str):
            data = data.encode()
            
        # 使用AES-GCM加密大块数据
        iv = os.urandom(12)
        encryptor = Cipher(
            algorithms.AES(self.session_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # 返回IV、标签和密文
        return base64.b64encode(iv + encryptor.tag + ciphertext).decode('utf-8')
    
    def decrypt_data(self, encrypted_data):
        if not self.session_key:
            raise ValueError("缺少会话密钥")
            
        try:
            if isinstance(encrypted_data, str):
                encrypted_data = base64.b64decode(encrypted_data)
            
            # 检查数据长度
            if len(encrypted_data) < 28:  # IV(12) + Tag(16)
                print(f"错误: 加密数据太短，长度为 {len(encrypted_data)} 字节")
                raise ValueError(f"加密数据太短: {len(encrypted_data)} 字节")
            
            # 提取IV、标签和密文
            iv = encrypted_data[:12]
            tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            
            print(f"解密 - IV长度: {len(iv)}字节, Tag长度: {len(tag)}字节, 密文长度: {len(ciphertext)}字节")
            
            # 解密数据
            decryptor = Cipher(
                algorithms.AES(self.session_key),
                modes.GCM(iv, tag),
                backend=default_backend()
            ).decryptor()
            
            return decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            print(f"解密失败: {str(e)}")
            print(f"会话密钥长度: {len(self.session_key) if self.session_key else 0}字节")
            # 打印一些数据样本以帮助调试（不要打印完整数据）
            if isinstance(encrypted_data, bytes):
                print(f"加密数据样本: {encrypted_data[:20].hex()}")
            raise