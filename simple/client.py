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
import concurrent.futures
import queue

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
        self.session_locks = {}  # 会话锁，确保并发安全
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=100)  # 线程池
        cleanup_thread = threading.Thread(target=self.cleanup_sessions, daemon=True)
        cleanup_thread.start()
    def cleanup_sessions(self):
        while True:
            time.sleep(60)  # 每分钟检查一次
            try:
                current_time = time.time()
                expired_sessions = []
                
                # 获取会话ID列表的副本避免并发修改
                session_ids = list(self.sessions.keys())
                
                for session_id in session_ids:
                    try:
                        if session_id in self.sessions:
                            with self.session_locks.get(session_id, threading.Lock()):
                                # 如果会话超过5分钟没有活动，则关闭
                                if current_time - self.sessions[session_id]["last_activity"] > 300:
                                    expired_sessions.append(session_id)
                    except Exception as e:
                        logger.error(f"检查会话 {session_id} 过期时出错: {e}")
                
                # 关闭过期会话
                for session_id in expired_sessions:
                    self.close_session(session_id)
                    
            except Exception as e:
                logger.error(f"清理会话时出错: {e}")
        
    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(100)  # 增加监听队列大小
        logger.info(f"隧道代理客户端已在 {self.host}:{self.port} 启动")
        logger.info(f"连接到服务端: {self.server_url}")
        
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f"接收到来自 {client_address[0]}:{client_address[1]} 的连接")
                # 使用线程池处理新连接
                self.executor.submit(self.handle_client, client_socket)
        except KeyboardInterrupt:
            logger.info("正在关闭代理客户端...")
        finally:
            self.server_socket.close()
            self.executor.shutdown(wait=False)  # 关闭线程池
    
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
            # 设置客户端socket为非阻塞
            client_socket.setblocking(False)
            
            # 优化socket参数
            client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            # 向服务端发起连接请求
            establish_data = {
                "host": host,
                "port": port,
                "session_id": session_id
            }
            
            # 设置连接超时
            session = requests.Session()
            session.timeout = (5, 30)  # 连接超时和读超时
            
            response = session.post(
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
            
            # 创建会话锁
            self.session_locks[session_id] = threading.Lock()
            
            # 存储会话信息
            self.sessions[session_id] = {
                "client_socket": client_socket,
                "host": host,
                "port": port,
                "last_activity": time.time(),
                "buffer": bytearray()
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
            # 创建两个线程分别处理双向数据流
            client_to_server = threading.Thread(
                target=self.handle_client_to_server,
                args=(client_socket, session_id)
            )
            server_to_client = threading.Thread(
                target=self.handle_server_to_client,
                args=(client_socket, session_id)
            )
            
            client_to_server.daemon = True
            server_to_client.daemon = True
            
            client_to_server.start()
            server_to_client.start()
            
            # 等待任意一个线程结束
            while client_to_server.is_alive() and server_to_client.is_alive():
                time.sleep(0.1)
                
        except Exception as e:
            logger.error(f"隧道数据传输时出错: {e}")
        
        finally:
            # 关闭连接
            self.close_session(session_id)
    
    def handle_client_to_server(self, client_socket, session_id):
        """处理从客户端到服务端的数据流"""
        buffer_size = 16384  # 增大缓冲区
        
        try:
            while session_id in self.sessions:
                # 使用select监听客户端socket
                readable, _, exceptional = select.select([client_socket], [], [client_socket], 0.5)
                
                if exceptional:
                    logger.info(f"客户端连接异常，结束会话 {session_id}")
                    break
                    
                if client_socket in readable:
                    # 从客户端读取数据
                    try:
                        client_data = client_socket.recv(buffer_size)
                        if not client_data:
                            logger.info(f"客户端连接已关闭，结束会话 {session_id}")
                            break
                        
                        # 加锁确保安全
                        with self.session_locks[session_id]:
                            self.sessions[session_id]["last_activity"] = time.time()
                        
                        # 编码数据并发送到服务端
                        transfer_data = {
                            "session_id": session_id,
                            "direction": "to_server",
                            "payload": base64.b64encode(client_data).decode('utf-8')
                        }
                        
                        # 使用Session对象提高连接复用
                        session = requests.Session()
                        response = session.post(
                            f"{self.server_url}/transfer",
                            json={"data": self.encode_data(transfer_data)},
                            verify=self.verify_ssl,
                            timeout=(5, 30)
                        )
                        
                        if response.status_code != 200:
                            logger.error(f"数据传输失败: {response.text}")
                            break
                        
                        # 解析服务端响应
                        response_data = self.decode_data(response.json()["data"])
                        
                        if response_data["status"] != "success":
                            logger.error(f"服务端报告错误: {response_data.get('message')}")
                            break
                        
                        # 将服务端响应发送给客户端
                        if response_data.get("payload"):
                            server_response = base64.b64decode(response_data["payload"])
                            if server_response and session_id in self.sessions:
                                client_socket.sendall(server_response)
                    
                    except ConnectionError:
                        logger.info(f"客户端连接已关闭，结束会话 {session_id}")
                        break
                    except Exception as e:
                        logger.error(f"处理客户端数据时出错: {e}")
                        break
        except Exception as e:
            logger.error(f"客户端到服务端数据传输线程出错: {e}")
    
    def handle_server_to_client(self, client_socket, session_id):
        """处理从服务端到客户端的数据流"""
        try:
            while session_id in self.sessions:
                try:
                    # 加锁确保安全
                    with self.session_locks[session_id]:
                        self.sessions[session_id]["last_activity"] = time.time()
                    
                    # 从服务端轮询数据
                    poll_data = {
                        "session_id": session_id,
                        "direction": "from_server",
                        "payload": base64.b64encode(b"").decode('utf-8')  # 发送空数据
                    }
                    
                    # 使用Session对象提高连接复用
                    session = requests.Session()
                    response = session.post(
                        f"{self.server_url}/transfer",
                        json={"data": self.encode_data(poll_data)},
                        verify=self.verify_ssl,
                        timeout=(2, 10)  # 较短的超时
                    )
                    
                    if response.status_code == 200:
                        response_data = self.decode_data(response.json()["data"])
                        
                        if response_data["status"] == "success" and response_data.get("payload"):
                            server_data = base64.b64decode(response_data["payload"])
                            if server_data and session_id in self.sessions:
                                client_socket.sendall(server_data)
                    
                    # 轮询间隔，避免过于频繁
                    time.sleep(0.05)
                
                except requests.Timeout:
                    # 超时不是致命错误，继续尝试
                    continue
                except Exception as e:
                    logger.error(f"从服务端轮询数据时出错: {e}")
                    # 轮询出错不终止连接，但增加延迟
                    time.sleep(1)
        except Exception as e:
            logger.error(f"服务端到客户端数据传输线程出错: {e}")

    def close_session(self, session_id):
        """安全地关闭一个会话"""
        if session_id in self.sessions:
            try:
                # 加锁确保并发安全
                if session_id in self.session_locks:
                    with self.session_locks[session_id]:
                        client_socket = self.sessions[session_id]["client_socket"]
                        try:
                            client_socket.close()
                        except:
                            pass
                        del self.sessions[session_id]
                        
                    # 删除会话锁
                    del self.session_locks[session_id]
                    
                # 通知服务端关闭连接
                close_data = {"session_id": session_id}
                requests.post(
                    f"{self.server_url}/close",
                    json={"data": self.encode_data(close_data)},
                    verify=self.verify_ssl,
                    timeout=5
                )
                
                logger.info(f"已关闭会话 {session_id}")
                
            except Exception as e:
                logger.error(f"关闭会话 {session_id} 时出错: {e}")

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