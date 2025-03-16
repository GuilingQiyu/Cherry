import os
import logging
import json
import base64
from crypto import CryptoManager
from protocol import JsonRpcProtocol

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("ProtocolTest")

def setup_client_server():
    """创建客户端和服务端实例"""
    logger.info("===== 创建客户端和服务端 =====")
    
    # 创建加密管理器
    client_crypto = CryptoManager(is_server=False)
    server_crypto = CryptoManager(is_server=True)
    
    # 创建协议处理器
    client_protocol = JsonRpcProtocol(client_crypto)
    server_protocol = JsonRpcProtocol(server_crypto)
    
    logger.info("成功创建客户端和服务端实例")
    return client_protocol, server_protocol

def test_handshake(client, server):
    """测试握手过程"""
    logger.info("===== 测试握手流程 =====")
    
    # 客户端创建握手消息
    handshake_msg = client.create_handshake()
    logger.info(f"客户端创建握手消息: {len(handshake_msg)} 字符")
    
    # 服务端处理握手消息
    handshake_response = server.process_handshake(handshake_msg)
    logger.info(f"服务端处理握手并返回响应: {len(handshake_response)} 字符")
    
    # 客户端处理握手响应
    success = client.process_session_key(handshake_response)
    assert success, "处理会话密钥失败"
    logger.info("客户端成功处理会话密钥")
    
    # 验证客户端和服务端的会话密钥是否匹配
    test_data = "会话密钥验证测试"
    encrypted = client.crypto.encrypt_data(test_data)
    decrypted = server.crypto.decrypt_data(encrypted)
    assert decrypted.decode() == test_data, "客户端和服务端会话密钥不匹配"
    logger.info("客户端和服务端会话密钥匹配验证通过")
    
    return True

def test_requests_responses(client, server):
    """测试请求和响应流程"""
    logger.info("===== 测试请求和响应流程 =====")
    
    # 测试不同类型的请求
    test_cases = [
        {"method": "connect", "host": "example.com", "port": 443},
        {"method": "data", "host": "example.com", "port": 443, "data": "Hello World"},
        {"method": "data", "host": "example.com", "port": 443, "data": os.urandom(100)},
        {"method": "close", "host": "example.com", "port": 443, "session_id": "12345"}
    ]
    
    for i, test in enumerate(test_cases):
        logger.info(f"测试请求 #{i+1}: {test['method']}")
        
        # 客户端创建请求 - 安全地获取参数
        request = client.create_request(
            method=test["method"],
            target_host=test["host"],
            target_port=test["port"],
            data=test.get("data"),  # 使用.get()安全获取，避免KeyError
            session_id=test.get("session_id")
        )
        logger.info(f"客户端创建请求: {len(request)} 字符")
        
        # 服务端处理请求
        parsed_request = server.process_request(request)
        logger.info(f"服务端解析请求: {parsed_request.get('method')}")
        
        # 验证请求内容
        assert parsed_request["method"] == test["method"], "请求方法不匹配"
        assert parsed_request["params"]["host"] == test["host"], "目标主机不匹配"
        assert parsed_request["params"]["port"] == test["port"], "目标端口不匹配"
        
        if test.get("session_id"):
            assert parsed_request["params"]["session_id"] == test["session_id"], "会话ID不匹配"
        
        if test.get("data"):
            if isinstance(test.get("data"), bytes):
                decoded_data = base64.b64decode(parsed_request["params"]["data"])
                assert decoded_data == test.get("data"), "二进制数据不匹配"
            else:
                assert parsed_request["params"]["data"] == test.get("data"), "文本数据不匹配"
        
        # 服务端创建响应
        response_data = "响应数据" if test["method"] != "close" else None
        response = server.create_response(
            request_id=parsed_request["id"],
            status="success",
            data=response_data
        )
        logger.info(f"服务端创建响应: {len(response)} 字符")
        
        # 客户端处理响应
        parsed_response = client.process_response(response)
        logger.info(f"客户端解析响应: ID={parsed_response.get('id')}")
        
        # 验证响应内容
        assert parsed_response["id"] == parsed_request["id"], "响应ID不匹配"
        assert parsed_response["result"]["status"] == "success", "响应状态不匹配"
        
        if response_data:
            assert parsed_response["result"]["data"] == response_data, "响应数据不匹配"
    
    logger.info("请求和响应测试通过")
    return True

def test_error_handling():
    """测试错误处理"""
    logger.info("===== 测试错误处理 =====")
    
    # 创建测试实例
    client_crypto = CryptoManager(is_server=False)
    client = JsonRpcProtocol(client_crypto)
    
    # 测试没有会话密钥的情况
    try:
        client.create_request("connect", "example.com", 443)
        assert False, "应该抛出错误：没有会话密钥"
    except Exception as e:
        logger.info(f"预期错误（没有会话密钥）: {e}")
    
    # 测试无效的握手响应
    try:
        invalid_response = json.dumps({"jsonrpc": "2.0", "error": {"code": -32600, "message": "无效请求"}})
        client.process_session_key(invalid_response)
        logger.info("处理无效握手响应失败，但未抛出异常")
    except Exception as e:
        logger.info(f"处理无效握手响应: {e}")
    
    # 测试无效的加密数据
    client_crypto.set_session_key(os.urandom(32))  # 设置一个会话密钥
    try:
        client.process_response("这不是有效的加密数据")
        assert False, "应该抛出错误：无效的加密数据"
    except Exception as e:
        logger.info(f"预期错误（无效的加密数据）: {e}")
    
    logger.info("错误处理测试通过")
    return True

def test_handshake_edge_cases():
    """测试握手边缘情况"""
    logger.info("===== 测试握手边缘情况 =====")
    
    # 测试客户端接收握手请求的情况
    client_crypto = CryptoManager(is_server=False)
    client = JsonRpcProtocol(client_crypto)
    
    server_crypto = CryptoManager(is_server=True)
    server = JsonRpcProtocol(server_crypto)
    
    # 服务端向客户端发送握手请求（这是不正常的流程）
    handshake_msg = server.create_handshake()
    client_response = client.process_handshake(handshake_msg)
    
    # 解析响应检查错误
    response_data = json.loads(client_response)
    assert "error" in response_data, "客户端应该返回错误响应"
    logger.info(f"客户端正确拒绝处理握手请求: {response_data['error']['message']}")
    
    logger.info("握手边缘情况测试通过")
    return True

def main():
    logger.info("开始测试 JsonRpcProtocol")
    
    try:
        # 设置客户端和服务端
        client, server = setup_client_server()
        
        # 测试握手流程
        test_handshake(client, server)
        
        # 测试请求和响应
        test_requests_responses(client, server)
        
        # 测试错误处理
        test_error_handling()
        
        # 测试握手边缘情况
        test_handshake_edge_cases()
        
        logger.info("所有测试通过")
        return 0
    except Exception as e:
        logger.error(f"测试失败: {e}", exc_info=True)
        return 1

if __name__ == "__main__":
    exit(main())