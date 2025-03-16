import socket
import logging
import threading
import argparse
import requests
import json
import base64
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

from crypto import CryptoManager
from protocol import JsonRpcProtocol

# 配置日志
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# 禁用不安全连接警告
import urllib3
urllib3.disable_warnings()

# 会话管理
class SessionManager:
    def __init__(self):
        self.sessions = {}
        self.lock = threading.Lock()
        
        # 启动会话清理线程
        self.cleanup_thread = threading.Thread(target=self._cleanup_task)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()
    
    def create_session(self, session_id, host, port):
        with self.lock:
            # 关闭已存在的会话
            if session_id in self.sessions:
                self.close_session(session_id)
                
            try:
                # 创建到目标服务器的连接
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)  # 设置超时
                sock.connect((host, port))
                
                self.sessions[session_id] = {
                    'socket': sock,
                    'host': host,
                    'port': port,
                    'last_active': time.time()
                }
                logger.info(f"创建到 {host}:{port} 的会话 {session_id}")
                return True
            except Exception as e:
                logger.error(f"无法连接到 {host}:{port}: {e}")
                return False
    
    def get_session(self, session_id):
        with self.lock:
            if session_id in self.sessions:
                # 更新活跃时间
                self.sessions[session_id]['last_active'] = time.time()
                return self.sessions[session_id]
            return None
    
    def close_session(self, session_id):
        with self.lock:
            if session_id in self.sessions:
                try:
                    logger.info(f"关闭会话 {session_id}")
                    self.sessions[session_id]['socket'].close()
                except Exception as e:
                    logger.error(f"关闭会话 {session_id} 时出错: {e}")
                finally:
                    del self.sessions[session_id]
    
    def _cleanup_task(self):
        """定期清理过期会话的后台任务"""
        while True:
            time.sleep(30)  # 每30秒检查一次
            self._cleanup_expired_sessions()
    
    def _cleanup_expired_sessions(self):
        """清理超过5分钟不活跃的会话"""
        now = time.time()
        expired_sessions = []
        
        with self.lock:
            for session_id, session in self.sessions.items():
                if now - session['last_active'] > 300:  # 5分钟
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                try:
                    logger.info(f"清理过期会话 {session_id}")
                    self.sessions[session_id]['socket'].close()
                except Exception:
                    pass
                finally:
                    del self.sessions[session_id]

class ProxyRequestHandler(BaseHTTPRequestHandler):
    crypto_manager = None  # 将作为类变量被设置
    session_manager = None  # 将作为类变量被设置
    
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
                logger.info("处理握手请求")
                response_data = protocol.process_handshake(post_data)
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(response_data.encode())
                return
            
            # 正常的代理请求
            try:
                logger.info(f"处理代理请求，数据长度: {len(post_data)}字节")
                request_data = protocol.process_request(post_data)
                
                method = request_data.get('method', '')
                params = request_data.get('params', {})
                request_id = request_data.get('id', 0)
                session_id = params.get('session_id', f"{params.get('host')}:{params.get('port')}")
                
                logger.info(f"请求: {method} 到 {params.get('host')}:{params.get('port')}")
                
                host = params.get('host', '')
                port = params.get('port', 80)
                data = params.get('data', None)
                
                if data and isinstance(data, str):
                    data = base64.b64decode(data)
                
                response = None
                status = 'error'
                
                if method == 'connect':
                    # 创建新的会话
                    if self.session_manager.create_session(session_id, host, port):
                        response, status = b'', 'ok'
                    else:
                        response, status = b'Unable to connect to the target server', 'error'
                
                elif method == 'data':
                    # 处理数据传输
                    session = self.session_manager.get_session(session_id)
                    if session:
                        response, status = self.handle_data(session, data)
                    else:
                        response, status = b'No Such Seesion', 'error'
                
                elif method == 'close':
                    # 关闭会话
                    self.session_manager.close_session(session_id)
                    response, status = b'', 'ok'
                
                elif method == 'request':
                    # 处理HTTP请求
                    response, status = self.handle_http_request(host, port, data)
                
                # 创建响应
                response_data = protocol.create_response(request_id, status, response)
                
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(response_data.encode())
            
            except Exception as e:
                logger.error(f"处理请求数据时出错: {str(e)}")
                # 返回错误响应
                error_response = {
                    "jsonrpc": "2.0", 
                    "error": {"message": str(e)},
                    "id": 0
                }
                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(error_response).encode())
        
        except Exception as e:
            logger.error(f"处理请求时出错: {str(e)}")
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"Error: {str(e)}".encode())
    
    # 将POST请求重定向到GET处理
    do_POST = do_GET
    
    def handle_data(self, session, data):
        """处理数据传输请求"""
        try:
            socket = session['socket']
            
            if data:
                socket.sendall(data)
            
            # 设置非阻塞以便快速检查响应
            socket.setblocking(False)
            
            try:
                # 尝试接收响应，但不要永久阻塞
                response_chunks = []
                while True:
                    try:
                        chunk = socket.recv(8192)
                        if not chunk:
                            break
                        response_chunks.append(chunk)
                    except BlockingIOError:
                        # 没有更多数据可读
                        break
                
                # 恢复阻塞模式
                socket.setblocking(True)
                
                if response_chunks:
                    return b''.join(response_chunks), 'ok'
                else:
                    return b'', 'ok'  # 没有响应数据也是正常的
            
            except Exception as e:
                logger.error(f"接收数据时出错: {e}")
                return str(e).encode(), 'error'
        
        except Exception as e:
            logger.error(f"处理数据传输请求失败: {e}")
            return str(e).encode(), 'error'
    
    def handle_http_request(self, host, port, data):
        """处理HTTP请求"""
        try:
            if not data:
                return b'', 'error'
                
            # 解析HTTP请求
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
                response = requests.get(url, headers=headers, verify=False, timeout=10)
            elif method == 'POST':
                # 查找请求体
                body = b''
                for i, line in enumerate(lines):
                    if not line and i+1 < len(lines):
                        body = b'\r\n'.join(lines[i+1:])
                        break
                
                response = requests.post(url, headers=headers, data=body, verify=False, timeout=10)
            else:
                # 其他HTTP方法
                response = requests.request(
                    method, 
                    url, 
                    headers=headers, 
                    verify=False,
                    timeout=10
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
        
        # 初始化会话管理器
        self.session_manager = SessionManager()
        
        # 设置处理器的变量
        ProxyRequestHandler.crypto_manager = self.crypto_manager
        ProxyRequestHandler.session_manager = self.session_manager
        
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