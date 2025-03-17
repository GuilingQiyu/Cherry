import socket
import select
import threading
import logging
import argparse
from urllib.parse import urlparse
import requests
import ssl
import time
import sys
import os

from crypto import CryptoManager
from protocol import JsonRpcProtocol

# 配置日志
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class SecureProxyClient:
    def __init__(self, server_host, server_port, local_host='127.0.0.1', local_port=8080, key_path='./client_key'):
        self.server_host = server_host
        self.server_port = server_port
        self.local_host = local_host
        self.local_port = local_port
        
        # 初始化加密管理器
        self.crypto_manager = CryptoManager(key_path, is_server=False)
        self.protocol = JsonRpcProtocol(self.crypto_manager)
        
        # 初始化本地代理服务器
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # 建立与远程服务器的连接并进行握手
        self.established = self.perform_handshake()
        if not self.established:
            raise Exception("无法与远程服务器建立安全连接")
    
    def perform_handshake(self):
        """与远程服务器执行握手流程"""
        try:
            # 创建握手消息
            handshake_data = self.protocol.create_handshake()
            
            # 发送握手请求
            response = requests.post(
                f"http://{self.server_host}:{self.server_port}/",
                headers={
                    'Content-Type': 'application/json',
                    'X-Proxy-Protocol': '1.0',
                    'X-Proxy-Action': 'handshake'
                },
                data=handshake_data.encode()
            )
            
            # 处理握手响应
            if response.status_code != 200:
                logger.error(f"握手失败: 服务器返回 {response.status_code}")
                return False
                
            # 处理服务器发送的会话密钥
            self.protocol.process_session_key(response.content)
            
            logger.info("握手成功，已建立安全连接")
            return True
        except Exception as e:
            logger.error(f"握手过程中出错: {e}")
            return False
    
    def start(self):
        self.server_socket.bind((self.local_host, self.local_port))
        self.server_socket.listen(5)
        logger.info(f"本地代理服务器已在 {self.local_host}:{self.local_port} 启动")
        
        try:
            while True:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f"接收到来自 {client_address[0]}:{client_address[1]} 的连接")
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            logger.info("正在关闭代理服务器...")
        finally:
            self.server_socket.close()
    
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
                self.handle_https(client_socket, host, port)
            else:
                # HTTP请求
                self.handle_http(client_socket, request)
        except Exception as e:
            logger.error(f"处理客户端请求时出错: {e}")
            client_socket.send(b'HTTP/1.1 500 Internal Server Error\r\n\r\n')
            client_socket.close()
    
    def handle_https(self, client_socket, host, port):
        try:
            # 创建加密通道请求
            request_data = self.protocol.create_request('connect', host, port)
            
            # 发送到远程服务器
            response = requests.post(
                f"http://{self.server_host}:{self.server_port}/",
                headers={
                    'Content-Type': 'application/json',
                    'X-Proxy-Protocol': '1.0'
                },
                data=request_data.encode()
            )
            
            if response.status_code != 200:
                logger.error(f"建立HTTPS隧道失败: {response.status_code}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
                return
                
            # 处理响应
            response_data = self.protocol.process_response(response.content)
            
            # 检查响应状态
            if response_data.get('result', {}).get('status') != 'ok':
                logger.error(f"服务端返回错误: {response_data}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
                return
                
            # 向客户端发送连接成功响应
            client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            
            # 开始双向代理
            self.tunnel_connection(client_socket, host, port)
            
        except Exception as e:
            logger.error(f"处理HTTPS请求时出错: {e}")
            try:
                client_socket.send(b'HTTP/1.1 500 Internal Server Error\r\n\r\n')
            except:
                pass
            client_socket.close()
            
    def tunnel_connection(self, client_socket, host, port):
        """建立加密隧道进行双向数据传输"""
        client_socket.setblocking(False)
        
        try:
            while True:
                # 等待客户端数据
                ready_to_read, _, _ = select.select([client_socket], [], [], 0.1)
                
                if client_socket in ready_to_read:
                    data = client_socket.recv(8192)
                    if not data:
                        # 连接已关闭
                        break
                    
                    # 加密并发送数据到服务端
                    request_data = self.protocol.create_request('data', host, port, data)
                    response = requests.post(
                        f"http://{self.server_host}:{self.server_port}/",
                        headers={
                            'Content-Type': 'application/json',
                            'X-Proxy-Protocol': '1.0'
                        },
                        data=request_data.encode()
                    )
                    
                    if response.status_code != 200:
                        logger.error(f"发送数据到服务端失败: {response.status_code}")
                        break
                    
                    # 处理服务端响应
                    response_data = self.protocol.process_response(response.content)
                    
                    # 检查服务端响应的数据
                    if 'data' in response_data.get('result', {}):
                        import base64
                        resp_data = base64.b64decode(response_data['result']['data'])
                        if resp_data:
                            client_socket.send(resp_data)
        
        except Exception as e:
            logger.error(f"隧道连接出错: {e}")
        finally:
            # 关闭隧道
            try:
                request_data = self.protocol.create_request('close', host, port)
                requests.post(
                    f"http://{self.server_host}:{self.server_port}/",
                    headers={
                        'Content-Type': 'application/json',
                        'X-Proxy-Protocol': '1.0'
                    },
                    data=request_data.encode()
                )
            except:
                pass
                
            client_socket.close()
            
    def handle_http(self, client_socket, request):
        """处理HTTP请求"""
        try:
            # 解析请求获取目标主机和端口
            first_line = request.split(b'\r\n')[0].decode('utf-8')
            method, url, _ = first_line.split()
            
            # 解析URL
            parsed_url = urlparse(url)
            host = parsed_url.netloc
            
            # 如果URL中没有指定主机，从Host头中获取
            if not host:
                for line in request.split(b'\r\n')[1:]:
                    if not line:
                        break
                    header_line = line.decode('utf-8', errors='ignore')
                    if header_line.lower().startswith('host:'):
                        host = header_line[5:].strip()
                        break
            
            # 从主机中提取端口
            port = 80
            if ':' in host:
                host, port_str = host.split(':', 1)
                port = int(port_str)
            
            logger.info(f"HTTP {method} 到 {host}:{port}")
            
            # 创建加密请求
            request_data = self.protocol.create_request('request', host, port, request)
            
            # 发送到远程服务器
            response = requests.post(
                f"http://{self.server_host}:{self.server_port}/",
                headers={
                    'Content-Type': 'application/json',
                    'X-Proxy-Protocol': '1.0'
                },
                data=request_data.encode()
            )
            
            if response.status_code != 200:
                logger.error(f"HTTP请求失败: {response.status_code}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
                return
                
            # 处理响应
            response_data = self.protocol.process_response(response.content)
            
            # 检查响应状态
            if response_data.get('result', {}).get('status') != 'ok':
                logger.error(f"服务端返回错误: {response_data}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
                return
                
            # 将响应数据发送给客户端
            if 'data' in response_data.get('result', {}):
                import base64
                resp_data = base64.b64decode(response_data['result']['data'])
                client_socket.send(resp_data)
            else:
                client_socket.send(b'HTTP/1.1 200 OK\r\n\r\nNo Content')
                
            client_socket.close()
            
        except Exception as e:
            logger.error(f"处理HTTP请求时出错: {e}")
            try:
                client_socket.send(b'HTTP/1.1 500 Internal Server Error\r\n\r\n')
            except:
                pass
            client_socket.close()
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='加密代理客户端')
    parser.add_argument('-s', '--server', required=True, help='远程服务器地址')
    parser.add_argument('-p', '--server-port', type=int, default=8888, help='远程服务器端口 (默认: 8888)')
    parser.add_argument('-l', '--local-port', type=int, default=8080, help='本地监听端口 (默认: 8080)')
    parser.add_argument('-b', '--bind', default='127.0.0.1', help='本地绑定地址 (默认: 127.0.0.1)')
    parser.add_argument('-k', '--key', default='./client_key', help='密钥文件路径 (默认: ./client_key)')
    
    args = parser.parse_args()
    
    try:
        client = SecureProxyClient(
            args.server, 
            args.server_port, 
            local_host=args.bind, 
            local_port=args.local_port,
            key_path=args.key
        )
        client.start()
    except KeyboardInterrupt:
        logger.info("用户中断，正在退出...")
    except Exception as e:
        logger.error(f"启动客户端失败: {e}")
        sys.exit(1)