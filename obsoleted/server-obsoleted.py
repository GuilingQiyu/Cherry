import socket
import logging
import threading
import argparse
import requests
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse
import time
import ssl

from crypto import CryptoManager
from protocol import JsonRpcProtocol

# 配置日志
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# 禁用不安全连接警告
import urllib3
urllib3.disable_warnings()

class ProxyRequestHandler(BaseHTTPRequestHandler):
    crypto_manager = None  # 将作为类变量被设置
    
    def do_GET(self):
        # 检查是否有特定的请求头，如果没有则返回Hello World
        if 'X-Proxy-Protocol' not in self.headers:
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"<h1>Hello, World!</h1>")
            return
            
        # 处理加密代理请求
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b''
        
        try:
            # 创建协议处理器
            protocol = JsonRpcProtocol(self.crypto_manager)
            
            # 如果是握手请求
            if self.headers.get('X-Proxy-Action') == 'handshake':
                response_data = protocol.process_handshake(post_data)
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(response_data.encode())
                return
            
            # 正常的代理请求
            logger.info(f"收到请求: {self.path}, 内容长度: {content_length}字节")
            request_data = protocol.process_request(post_data)
            logger.info(f"处理请求: {request_data}")
            method = request_data.get('method', '')
            params = request_data.get('params', {})
            request_id = request_data.get('id', 0)
            
            host = params.get('host', '')
            port = params.get('port', 80)
            data = params.get('data', None)
            
            if data and isinstance(data, str):
                import base64
                data = base64.b64decode(data)
            
            response = None
            status = 'error'
            
            if method == 'connect':
                # 处理HTTPS连接
                response, status = self.handle_connect(host, port, data)
            elif method == 'request':
                # 处理HTTP请求
                response, status = self.handle_request(host, port, data)
            elif method == 'data':
                # 处理数据传输
                response, status = self.handle_data(host, port, data)
            elif method == 'close':
                # 处理连接关闭
                response, status = b'', 'ok'
            
            # 创建响应
            response_data = protocol.create_response(request_id, status, response)
            print(response_data)
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            self.wfile.write(response_data.encode())
            
        except Exception as e:
            logger.error(f"处理请求时出错: {e}")
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"Error: {str(e)}".encode())
    
    # 将POST请求重定向到GET处理
    do_POST = do_GET
    
    def handle_connect(self, host, port, data):
        """处理HTTPS连接请求"""
        try:
            # 创建到目标服务器的连接
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((host, port))
            
            if data:
                server_socket.send(data)
                
            # 读取响应
            response_data = server_socket.recv(8192)
            server_socket.close()
            
            return response_data, 'ok'
        except Exception as e:
            logger.error(f"处理CONNECT请求失败: {e}")
            return str(e).encode(), 'error'
    
    def handle_data(self, host, port, data):
        """处理数据传输请求"""
        try:
            # 这里应该实现使用持久连接的逻辑
            # 简化版本直接创建新连接
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((host, port))
            
            if data:
                server_socket.send(data)
                
            # 读取响应
            response_data = server_socket.recv(8192)
            server_socket.close()
            
            return response_data, 'ok'
        except Exception as e:
            logger.error(f"处理数据传输请求失败: {e}")
            return str(e).encode(), 'error'
    
    def handle_request(self, host, port, data):
        """处理HTTP请求"""
        try:
            if not data:
                return b'', 'error'
                
            # 模拟HTTP请求
            headers = {}
            method = "GET"
            path = "/"
            
            # 解析HTTP请求头
            lines = data.split(b'\r\n')
            if lines and lines[0]:
                request_line = lines[0].decode('utf-8', errors='ignore')
                parts = request_line.split(' ')
                if len(parts) >= 3:
                    method, path, _ = parts
            
            # 解析其他头
            for i in range(1, len(lines)):
                if not lines[i]:
                    break
                    
                try:
                    header_line = lines[i].decode('utf-8', errors='ignore')
                    if ': ' in header_line:
                        name, value = header_line.split(': ', 1)
                        headers[name] = value
                except:
                    pass
            
            # 构建完整URL
            schema = 'https' if port == 443 else 'http'
            url = f"{schema}://{host}:{port}{path}"
            
            # 发送请求
            if method == 'GET':
                response = requests.get(url, headers=headers, verify=False)
            elif method == 'POST':
                # 查找请求体
                body = b''
                for i, line in enumerate(lines):
                    if not line and i+1 < len(lines):
                        body = b'\r\n'.join(lines[i+1:])
                        break
                
                response = requests.post(url, headers=headers, data=body, verify=False)
            else:
                # 其他HTTP方法
                response = requests.request(
                    method, 
                    url, 
                    headers=headers, 
                    verify=False
                )
            
            # 构建响应
            status_line = f"HTTP/1.1 {response.status_code} {response.reason}"
            headers_lines = [f"{name}: {value}" for name, value in response.headers.items()]
            
            response_data = status_line.encode() + b'\r\n'
            response_data += b'\r\n'.join([line.encode() for line in headers_lines])
            response_data += b'\r\n\r\n'
            response_data += response.content
            
            return response_data, 'ok'
        except Exception as e:
            logger.error(f"处理HTTP请求失败: {e}")
            return str(e).encode(), 'error'
    
    def log_message(self, format, *args):
        """重写日志方法，使用我们自己的日志格式"""
        logger.info(f"{self.client_address[0]} - {format%args}")

class ProxyServer:
    def __init__(self, host='0.0.0.0', port=8888, key_path='./server_key'):
        self.host = host
        self.port = port
        
        # 初始化加密管理器
        self.crypto_manager = CryptoManager(key_path, is_server=True)
        
        # 设置处理器的加密管理器
        ProxyRequestHandler.crypto_manager = self.crypto_manager
        
        # 创建HTTP服务器
        self.server = HTTPServer((host, port), ProxyRequestHandler)
    
    def start(self):
        logger.info(f"代理服务器已在 {self.host}:{self.port} 启动")
        
        try:
            self.server.serve_forever()
        except KeyboardInterrupt:
            logger.info("正在关闭代理服务器...")
        finally:
            self.server.server_close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='加密代理服务器')
    parser.add_argument('-p', '--port', type=int, default=8888, help='代理服务器监听端口 (默认: 8888)')
    parser.add_argument('-b', '--bind', default='0.0.0.0', help='绑定地址 (默认: 0.0.0.0)')
    parser.add_argument('-k', '--key', default='./server_key', help='密钥文件路径 (默认: ./server_key)')
    
    args = parser.parse_args()
    
    server = ProxyServer(host=args.bind, port=args.port, key_path=args.key)
    server.start()