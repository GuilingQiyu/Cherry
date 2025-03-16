import json
import base64
import logging
import os

logger = logging.getLogger(__name__)

class JsonRpcProtocol:
    def __init__(self, crypto_manager):
        self.crypto = crypto_manager
        self.request_id = 0
        
    def _get_next_id(self):
        """获取下一个请求ID"""
        self.request_id += 1
        return self.request_id
    
    def create_handshake(self):
        """创建握手消息，包含公钥"""
        try:
            public_key = self.crypto.get_public_key_pem()
            
            handshake_data = {
                "jsonrpc": "2.0",
                "method": "handshake",
                "params": {
                    "public_key": public_key,
                    "version": "1.0",
                    "client_id": os.urandom(8).hex()  # 添加唯一客户端ID
                },
                "id": self._get_next_id()
            }
            
            logger.debug(f"创建握手消息: {handshake_data['id']}")
            return json.dumps(handshake_data)
        except Exception as e:
            logger.error(f"创建握手消息失败: {e}")
            raise
    
    def process_handshake(self, data):
        """处理握手消息"""
        try:
            handshake_data = json.loads(data)
            
            if handshake_data.get("method") != "handshake":
                raise ValueError("无效的握手消息")
            
            # 提取对方的公钥
            peer_public_key = handshake_data["params"]["public_key"]
            self.crypto.load_peer_public_key(peer_public_key)
            logger.debug("已加载对方公钥")
            
            # 返回握手响应
            if self.crypto.is_server:
                # 服务端生成会话密钥并加密
                session_key = self.crypto.generate_session_key()
                encrypted_key = self.crypto.encrypt_with_rsa(session_key)
                
                response_data = {
                    "jsonrpc": "2.0",
                    "result": {
                        "status": "ok",
                        "session_key": base64.b64encode(encrypted_key).decode('utf-8'),
                        "server_id": os.urandom(8).hex()  # 添加唯一服务器ID
                    },
                    "id": handshake_data["id"]
                }
                logger.info("服务端已生成会话密钥并加密")
                return json.dumps(response_data)
            else:
                # 客户端不应该收到握手请求
                logger.error("客户端收到握手请求")
                response_data = {
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32600,
                        "message": "客户端不处理握手请求"
                    },
                    "id": handshake_data["id"]
                }
                return json.dumps(response_data)
        except Exception as e:
            logger.error(f"处理握手消息失败: {e}")
            raise
    
    def process_session_key(self, data):
        """客户端处理收到的会话密钥"""
        try:
            if self.crypto.is_server:
                logger.error("服务端不需要处理会话密钥响应")
                return False
                
            response_data = json.loads(data)
            
            if "result" not in response_data or "session_key" not in response_data["result"]:
                logger.error(f"无效的会话密钥响应: {response_data}")
                return False
            
            # 解码并解密会话密钥
            encrypted_key = base64.b64decode(response_data["result"]["session_key"])
            logger.debug(f"收到加密的会话密钥，长度: {len(encrypted_key)}字节")
            
            session_key = self.crypto.decrypt_with_rsa(encrypted_key)
            logger.debug(f"成功解密会话密钥，长度: {len(session_key)}字节")
            
            # 设置解密后的会话密钥
            self.crypto.set_session_key(session_key)
            logger.info("会话密钥设置成功")
            
            # 进行测试加密/解密以验证密钥是否正确
            test_data = "test_session_key"
            encrypted = self.crypto.encrypt_data(test_data)
            decrypted = self.crypto.decrypt_data(encrypted)
            if decrypted.decode('utf-8') != test_data:
                logger.error("会话密钥验证失败")
                return False
                
            logger.debug("会话密钥验证成功")
            return True
        except Exception as e:
            logger.error(f"处理会话密钥失败: {e}")
            return False
    
    def create_request(self, method, target_host, target_port, data=None, session_id=None):
        """创建请求消息"""
        try:
            request_data = {
                "jsonrpc": "2.0",
                "method": method,
                "params": {
                    "host": target_host,
                    "port": target_port,
                },
                "id": self._get_next_id()
            }
            
            # 添加会话ID
            if session_id:
                request_data["params"]["session_id"] = session_id
            
            # 处理数据
            if data:
                if isinstance(data, bytes):
                    request_data["params"]["data"] = base64.b64encode(data).decode('utf-8')
                else:
                    request_data["params"]["data"] = data
            
            # 先转换为JSON字符串
            json_str = json.dumps(request_data)
            
            # 使用会话密钥加密消息
            encrypted = self.crypto.encrypt_data(json_str)
            logger.debug(f"加密请求: {request_data['method']}, ID={request_data['id']}")
            
            return encrypted
        except Exception as e:
            logger.error(f"创建请求失败: {e}")
            raise
    
    def process_request(self, data):
        """处理请求消息"""
        try:
            # 使用会话密钥解密
            decrypted = self.crypto.decrypt_data(data)
            
            # 解析JSON
            request_data = json.loads(decrypted)
            logger.debug(f"解析请求: {request_data.get('method')}, ID={request_data.get('id')}")
            
            # 返回解析后的请求
            return request_data
        except Exception as e:
            logger.error(f"处理请求失败: {e}")
            raise
    
    def create_response(self, request_id, status, data=None):
        """创建响应消息"""
        try:
            response_data = {
                "jsonrpc": "2.0",
                "result": {
                    "status": status,
                },
                "id": request_id
            }
            
            if data:
                if isinstance(data, bytes):
                    response_data["result"]["data"] = base64.b64encode(data).decode('utf-8')
                else:
                    response_data["result"]["data"] = data
            
            # 先转换为JSON字符串
            json_str = json.dumps(response_data)
            
            # 使用会话密钥加密消息
            encrypted = self.crypto.encrypt_data(json_str)
            logger.debug(f"加密响应: ID={request_id}")
            
            return encrypted
        except Exception as e:
            logger.error(f"创建响应失败: {e}")
            raise
    
    def process_response(self, data):
        """处理响应消息"""
        try:
            # 使用会话密钥解密
            decrypted = self.crypto.decrypt_data(data)
            
            # 解析JSON
            response_data = json.loads(decrypted)
            logger.debug(f"解析响应: ID={response_data.get('id')}")
            
            # 返回解析后的响应
            return response_data
        except Exception as e:
            logger.error(f"处理响应失败: {e}")
            raise