import socket
import select
import threading
import logging
import argparse
import requests
import base64
import json
import uuid
import time
from urllib.parse import urlparse

# 配置日志
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class HTTPSTunnelProxy:
    def __init__(self, server_url, host='0.0.0.0', port=8080, verify_ssl=True):
        self.host = host
        self.port = port
        self.server_url = server_url  # 服务端API地址
        self.verify_ssl = verify_ssl  # 是否验证SSL证书
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sessions = {}  # 存储客户端会话信息
        
    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        logger.info(f"隧道代理客户端已在 {self.host}:{self.port} 启动")
        logger.info(f"连接到服务端: {self.server_url}")
        
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f"接收到来自 {client_address[0]}:{client_address[1]} 的连接")
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            logger.info("正在关闭代理客户端...")
        finally:
            self.server_socket.close()
    
    def encode_data(self, data):
        """将数据编码为Base64"""
        json_str = json.dumps(data)
        return base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
    
    def decode_data(self, encoded_data):
        """解码Base64数据"""
        json_str = base64.b64decode(encoded_data).decode('utf-8')
        return json.loads(json_str)
    
    def handle_client(self, client_socket):
        request = client_socket.recv(4096)
        
        if not request:
            client_socket.close()
            return
        
        try:
            # 解析请求获取目标主机和端口
            first_line = request.split(b'\r\n')[0].decode('utf-8')
            method, url, _ = first_line.split()
            
            if method == 'CONNECT':
                # HTTPS连接
                host, port = url.split(':')
                port = int(port)
                logger.info(f"HTTPS CONNECT 到 {host}:{port}")
                self.handle_https_tunnel(client_socket, host, port)
            else:
                # HTTP请求 (目前不处理，仅支持HTTPS)
                logger.warning(f"不支持的方法: {method}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
        except Exception as e:
            logger.error(f"处理客户端请求时出错: {e}")
            client_socket.send(b'HTTP/1.1 500 Internal Server Error\r\n\r\n')
            client_socket.close()
    
    def handle_https_tunnel(self, client_socket, host, port):
        # 生成会话ID
        session_id = str(uuid.uuid4())
        
        try:
            # 向服务端发起连接请求
            establish_data = {
                "host": host,
                "port": port,
                "session_id": session_id
            }
            
            response = requests.post(
                f"{self.server_url}/establish",
                json={"data": self.encode_data(establish_data)},
                verify=self.verify_ssl
            )
            
            if response.status_code != 200:
                logger.error(f"无法建立连接: {response.text}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
                return
            
            # 解析响应
            response_data = self.decode_data(response.json()["data"])
            
            if response_data["status"] != "success":
                logger.error(f"连接请求被拒绝: {response_data['message']}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
                return
            
            # 发送连接成功响应给客户端
            client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            
            # 设置客户端socket为非阻塞
            client_socket.setblocking(False)
            
            # 存储会话信息
            self.sessions[session_id] = {
                "client_socket": client_socket,
                "host": host,
                "port": port,
                "last_activity": time.time()
            }
            
            # 启动数据传输
            self.tunnel_data(client_socket, session_id)
            
        except Exception as e:
            logger.error(f"建立隧道连接时出错: {e}")
            client_socket.send(b'HTTP/1.1 500 Internal Server Error\r\n\r\n')
            client_socket.close()
            
            # 尝试关闭服务端连接
            try:
                close_data = {"session_id": session_id}
                requests.post(
                    f"{self.server_url}/close",
                    json={"data": self.encode_data(close_data)},
                    verify=self.verify_ssl
                )
            except:
                pass
    
    def tunnel_data(self, client_socket, session_id):
        try:
            while True:
                # 使用select监听客户端socket
                readable, _, exceptional = select.select([client_socket], [], [client_socket], 1)
                
                if exceptional:
                    logger.info(f"连接出现异常，结束会话 {session_id}")
                    break
                
                if client_socket in readable:
                    # 从客户端读取数据
                    try:
                        client_data = client_socket.recv(8192)
                        if not client_data:
                            logger.info(f"客户端连接已关闭，结束会话 {session_id}")
                            break
                        
                        # 编码数据并发送到服务端
                        transfer_data = {
                            "session_id": session_id,
                            "direction": "to_server",
                            "payload": base64.b64encode(client_data).decode('utf-8')
                        }
                        
                        response = requests.post(
                            f"{self.server_url}/transfer",
                            json={"data": self.encode_data(transfer_data)},
                            verify=self.verify_ssl
                        )
                        
                        if response.status_code != 200:
                            logger.error(f"数据传输失败: {response.text}")
                            break
                        
                        # 解析服务端响应
                        response_data = self.decode_data(response.json()["data"])
                        
                        if response_data["status"] != "success":
                            logger.error(f"服务端报告错误: {response_data.get('message', 'Unknown error')}")
                            break
                        
                        # 将服务端响应发送给客户端
                        server_response = base64.b64decode(response_data["payload"])
                        if server_response:
                            client_socket.sendall(server_response)
                    
                    except ConnectionError:
                        logger.info(f"客户端连接已关闭，结束会话 {session_id}")
                        break
                
                # 定期从服务端检查是否有数据
                else:
                    try:
                        poll_data = {
                            "session_id": session_id,
                            "direction": "from_server",
                            "payload": ""
                        }
                        
                        response = requests.post(
                            f"{self.server_url}/transfer",
                            json={"data": self.encode_data(poll_data)},
                            verify=self.verify_ssl
                        )
                        
                        if response.status_code == 200:
                            response_data = self.decode_data(response.json()["data"])
                            
                            if response_data["status"] == "success" and response_data.get("payload"):
                                server_data = base64.b64decode(response_data["payload"])
                                if server_data:
                                    client_socket.sendall(server_data)
                    
                    except Exception as e:
                        logger.error(f"从服务端轮询数据时出错: {e}")
                        # 轮询出错不终止连接
        
        except Exception as e:
            logger.error(f"隧道数据传输时出错: {e}")
        
        finally:
            # 关闭连接
            try:
                client_socket.close()
            except:
                pass
            
            # 通知服务端关闭连接
            try:
                close_data = {"session_id": session_id}
                requests.post(
                    f"{self.server_url}/close",
                    json={"data": self.encode_data(close_data)},
                    verify=self.verify_ssl
                )
            except Exception as e:
                logger.error(f"通知服务端关闭连接时出错: {e}")
            
            # 清理会话
            if session_id in self.sessions:
                del self.sessions[session_id]
                logger.info(f"已清理会话 {session_id}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTPS隧道代理客户端')
    parser.add_argument('-s', '--server', required=True, help='服务端API地址 (例如: https://server.example.com)')
    parser.add_argument('-p', '--port', type=int, default=8080, help='客户端监听端口 (默认: 8080)')
    parser.add_argument('-b', '--bind', default='0.0.0.0', help='绑定地址 (默认: 0.0.0.0)')
    parser.add_argument('--no-verify', action='store_true', help='不验证服务端SSL证书')
    
    args = parser.parse_args()
    
    proxy = HTTPSTunnelProxy(
        server_url=args.server,
        host=args.bind,
        port=args.port,
        verify_ssl=not args.no_verify
    )
    proxy.start()