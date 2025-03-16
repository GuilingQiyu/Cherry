import os
import logging
import time
from crypto import CryptoManager

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("CryptoTest")

def test_key_generation_and_loading():
    logger.info("===== 测试密钥生成和加载 =====")
    
    # 生成新的密钥
    key_path = "client_key"
    client = CryptoManager()
    client.generate_key(key_path)
    logger.info(f"密钥已保存到 {key_path}.pem 和 {key_path}.pub")
    
    # 从文件加载密钥
    client2 = CryptoManager(key_path)
    logger.info("从文件加载密钥成功")
    
    # 检查公钥是否相同
    pk1 = client.get_public_key_pem()
    pk2 = client2.get_public_key_pem()
    assert pk1 == pk2, "加载的密钥与生成的不匹配"
    logger.info("密钥匹配验证成功")
    
    return client

def test_rsa_encryption():
    logger.info("===== 测试RSA加密和解密 =====")
    
    # 创建客户端和服务器
    client = CryptoManager(is_server=False)
    server = CryptoManager(is_server=True)
    
    # 交换公钥
    server_public_key = server.get_public_key_pem()
    client_public_key = client.get_public_key_pem()
    
    client.load_peer_public_key(server_public_key)
    server.load_peer_public_key(client_public_key)
    logger.info("公钥交换成功")
    
    # 测试RSA加密和解密
    test_data = "这是一个测试消息"
    encrypted = client.encrypt_with_rsa(test_data.encode())
    decrypted = server.decrypt_with_rsa(encrypted)
    
    logger.info(f"原始数据: {test_data}")
    logger.info(f"解密结果: {decrypted.decode()}")
    assert test_data.encode() == decrypted, "RSA加密解密结果不匹配"
    logger.info("RSA加密解密测试成功")
    
    return client, server

def test_aes_encryption(client, server):
    logger.info("===== 测试会话密钥和AES加密 =====")
    
    # 客户端生成会话密钥
    session_key = client.generate_session_key()
    logger.info(f"会话密钥已生成: {len(session_key)} 字节")
    
    # 使用RSA加密会话密钥并发送给服务器
    encrypted_key = client.encrypt_with_rsa(session_key)
    logger.info(f"会话密钥已加密: {len(encrypted_key)} 字节")
    
    # 服务器解密会话密钥
    decrypted_key = server.decrypt_with_rsa(encrypted_key)
    server.set_session_key(decrypted_key)
    logger.info("服务器成功接收会话密钥")
    
    # 测试使用会话密钥进行AES加密和解密
    test_data = "这是一个使用AES加密的较长消息。" * 10
    
    # 客户端加密
    encrypted_data = client.encrypt_data(test_data)
    logger.info(f"AES加密后数据长度: {len(encrypted_data)}")
    
    # 服务器解密
    decrypted_data = server.decrypt_data(encrypted_data)
    logger.info(f"AES解密后数据长度: {len(decrypted_data)}")
    
    assert test_data.encode() == decrypted_data, "AES加密解密结果不匹配"
    logger.info("AES加密解密测试成功")

def test_error_handling():
    logger.info("===== 测试错误处理 =====")
    
    crypto = CryptoManager()
    
    # 测试缺少对方公钥时的加密
    try:
        crypto.encrypt_with_rsa("测试")
        assert False, "应该抛出错误"
    except ValueError as e:
        logger.info(f"预期错误: {e}")
    
    # 测试缺少会话密钥时的加密
    try:
        crypto.encrypt_data("测试")
        assert False, "应该抛出错误"
    except ValueError as e:
        logger.info(f"预期错误: {e}")
    
    # 测试错误格式的加密数据
    crypto.set_session_key(os.urandom(32))
    try:
        crypto.decrypt_data("不是有效的Base64")
        assert False, "应该抛出错误"
    except Exception as e:
        logger.info(f"预期错误: {e}")
    
    logger.info("错误处理测试成功")

def test_performance():
    logger.info("===== 测试性能 =====")
    
    client = CryptoManager()
    client.set_session_key(os.urandom(32))
    
    data_sizes = [100, 1000, 10000, 100000]
    for size in data_sizes:
        test_data = "A" * size
        
        start_time = time.time()
        encrypted = client.encrypt_data(test_data)
        encrypt_time = time.time() - start_time
        
        start_time = time.time()
        decrypted = client.decrypt_data(encrypted)
        decrypt_time = time.time() - start_time
        
        logger.info(f"数据大小: {size} 字节")
        logger.info(f"加密时间: {encrypt_time:.6f} 秒")
        logger.info(f"解密时间: {decrypt_time:.6f} 秒")
        logger.info(f"加密后数据大小: {len(encrypted)} 字符")

def main():
    logger.info("开始测试 CryptoManager")
    
    try:
        test_key_generation_and_loading()
        client, server = test_rsa_encryption()
        test_aes_encryption(client, server)
        test_error_handling()
        test_performance()
        logger.info("所有测试通过")
    except Exception as e:
        logger.error(f"测试失败: {e}", exc_info=True)
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())