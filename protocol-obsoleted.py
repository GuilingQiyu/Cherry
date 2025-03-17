import json
import base64
import logging


class JsonRpcProtocol:
    def __init__(self, crypto_manager):
        self.crypto = crypto_manager
        self.request_id = 0
    
    def create_handshake(self):
        """创建握手消息，包含公钥"""
        public_key = self.crypto.get_public_key_pem()
        
        handshake_data = {
            "jsonrpc": "2.0",
            "method": "handshake",
            "params": {
                "public_key": public_key,
                "version": "1.0"
            },
            "id": self._get_next_id()
        }
        
        return json.dumps(handshake_data)
    
    def process_handshake(self, data):
        """处理握手消息"""
        handshake_data = json.loads(data)
        
        if handshake_data.get("method") != "handshake":
            raise ValueError("无效的握手消息")
        
        # 提取对方的公钥
        peer_public_key = handshake_data["params"]["public_key"]
        self.crypto.load_peer_public_key(peer_public_key)
        
        # 返回握手响应
        if self.crypto.is_server:
            # 服务端生成会话密钥并使用客户端的公钥加密
            session_key = self.crypto.generate_session_key()
            encrypted_key = self.crypto.encrypt_with_rsa(session_key)
            
            response = {
                "jsonrpc": "2.0",
                "result": {
                    "status": "ok",
                    "session_key": base64.b64encode(encrypted_key).decode(),
                },
                "id": handshake_data["id"]
            }
            
            return json.dumps(response)
        else:
            # 客户端仅返回确认
            response = {
                "jsonrpc": "2.0",
                "result": {
                    "status": "ok",
                },
                "id": handshake_data["id"]
            }
            
            return json.dumps(response)
    
    def process_session_key(self, data):
        """客户端处理收到的会话密钥"""
        if self.crypto.is_server:
            print("服务端不需要处理会话密钥响应")
            return None
                
        try:

            response_data = json.loads(data)
            
            if "result" not in response_data or "session_key" not in response_data["result"]:
                print(f"无效的会话密钥响应: {response_data}")
                raise ValueError("无效的会话密钥响应")
            
            # 解码并解密会话密钥
            encrypted_key = base64.b64decode(response_data["result"]["session_key"])
            print(f"收到加密的会话密钥，长度: {len(encrypted_key)}字节")
            
            session_key = self.crypto.decrypt_with_rsa(encrypted_key)
            print(f"成功解密会话密钥，长度: {len(session_key)}字节")
            
            # 设置解密后的会话密钥
            self.crypto.set_session_key(session_key)
            print("会话密钥设置成功")
            
            return True
        except Exception as e:
            print(f"处理会话密钥失败: {str(e)}")
            raise
    
    def create_request(self, method, target_host, target_port, data=None, session_id=None):
        """创建请求消息"""
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
        
        # 使用会话密钥加密消息
        encrypted = self.crypto.encrypt_data(json.dumps(request_data))
        
        return encrypted
    
    def process_request(self, data):
        

        """处理请求消息"""
        # 使用会话密钥解密
        decrypted = self.crypto.decrypt_data(data)

        request_data = json.loads(decrypted)

        # 返回解析后的请求
        return request_data
    
    def create_response(self, request_id, status, data=None):
        """创建响应消息"""
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
        
        # 使用会话密钥加密消息
        encrypted = self.crypto.encrypt_data(json.dumps(response_data))
        
        return encrypted
    
    def process_response(self, data):
        """处理响应消息"""
        # 使用会话密钥解密
        decrypted = self.crypto.decrypt_data(data)
        
        response_data = json.loads(decrypted)
        
        # 返回解析后的响应
        return response_data
    
    def _get_next_id(self):
        """获取下一个请求ID"""
        self.request_id += 1
        return self.request_id
