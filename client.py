import socket
import select
import threading
import logging
import argparse
import json
import base64
import time
import sys
import os
from urllib.parse import urlparse
import requests

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
        
        # 会话计数器
        self.session_counter = 0
        self.session_lock = threading.Lock()
        
        # 建立与远程服务器的连接并进行握手
        self.established = self.perform_handshake()
        if not self.established:
            raise Exception("无法与远程服务器建立安全连接")
    
    def get_next_session_id(self):
        """获取唯一会话ID"""
        with self.session_lock:
            self.session_counter += 1
            return f"session_{self.session_counter}"
    
    def perform_handshake(self):
        """与远程服务器执行握手流程"""
        try:
            logger.info(f"开始与服务器 {self.server_host}:{self.server_port} 进行握手")
            
            # 创建握手消息
            handshake_data = self.protocol.create_handshake()
            logger.debug("已创建握手消息")
            
            # 发送握手请求
            response = requests.post(
                f"http://{self.server_host}:{self.server_port}/",
                headers={
                    'Content-Type': 'application/json',
                    'X-Proxy-Protocol': '1.0',
                    'X-Proxy-Action': 'handshake'
                },
                data=handshake_data.encode(),
                timeout=10
            )
            
            # 处理握手响应
            if response.status_code != 200:
                logger.error(f"握手失败: 服务器返回 {response.status_code}")
                return False
            
            logger.debug(f"收到握手响应，开始处理会话密钥")
            # 处理服务器发送的会话密钥
            result = self.protocol.process_session_key(response.content)
            if not result:
                logger.error("处理会话密钥失败")
                return False
            
            logger.info("握手成功，已建立安全连接")
            return True
        except Exception as e:
            logger.error(f"握手过程中出错: {e}")
            return False
    
    def start(self):
        """启动代理服务器"""
        try:
            self.server_socket.bind((self.local_host, self.local_port))
            self.server_socket.listen(5)
            logger.info(f"本地代理服务器已在 {self.local_host}:{self.local_port} 启动")
            
            while True:
                client_socket, client_address = self.server_socket.accept()
                logger.info(f"接收到来自 {client_address[0]}:{client_address[1]} 的连接")
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_thread.daemon = True
                client_thread.start()
        except KeyboardInterrupt:
            logger.info("正在关闭代理服务器...")
        except Exception as e:
            logger.error(f"代理服务器出错: {e}")
        finally:
            self.server_socket.close()
    
    def handle_client(self, client_socket):
        """处理客户端连接"""
        try:
            request = client_socket.recv(4096)
            
            if not request:
                client_socket.close()
                return
            
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
                logger.info(f"HTTP {method} 请求")
                self.handle_http(client_socket, request)
        except Exception as e:
            logger.error(f"处理客户端请求时出错: {e}")
            try:
                client_socket.send(b'HTTP/1.1 500 Internal Server Error\r\n\r\n')
            except:
                pass
            client_socket.close()
    
    def handle_https(self, client_socket, host, port):
        """处理HTTPS连接请求"""
        try:
            # 生成会话ID
            session_id = self.get_next_session_id()
            logger.debug(f"为 {host}:{port} 创建会话 {session_id}")
            
            # 创建加密通道请求
            request_data = self.protocol.create_request('connect', host, port, session_id=session_id)
            
            # 发送到远程服务器
            response = requests.post(
                f"http://{self.server_host}:{self.server_port}/",
                headers={
                    'Content-Type': 'application/json',
                    'X-Proxy-Protocol': '1.0'
                },
                data=request_data.encode(),
                timeout=10
            )
            
            if response.status_code != 200:
                logger.error(f"建立HTTPS隧道失败: {response.status_code}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
                return
                
            # 处理响应
            try:
                response_data = self.protocol.process_response(response.content)
                
                # 检查响应状态
                if response_data.get('result', {}).get('status') != 'ok':
                    error_msg = response_data.get('result', {}).get('message', 'Unknown error')
                    logger.error(f"服务端返回错误: {error_msg}")
                    client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                    client_socket.close()
                    return
                    
                # 向客户端发送连接成功响应
                client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
                logger.info(f"HTTPS隧道已建立: {host}:{port}")
                
                # 开始双向代理
                self.tunnel_connection(client_socket, host, port, session_id)
            except Exception as e:
                logger.error(f"处理服务端响应时出错: {e}")
                client_socket.send(b'HTTP/1.1 500 Internal Server Error\r\n\r\n')
                client_socket.close()
            
        except Exception as e:
            logger.error(f"处理HTTPS请求时出错: {e}")
            try:
                client_socket.send(b'HTTP/1.1 500 Internal Server Error\r\n\r\n')
            except:
                pass
            client_socket.close()
            
    def tunnel_connection(self, client_socket, host, port, session_id):
        """建立加密隧道进行双向数据传输"""
        client_socket.setblocking(False)
        running = True
        last_activity = time.time()
        
        try:
            while running:
                # 设置超时时间，避免无限循环
                current_time = time.time()
                if current_time - last_activity > 300:  # 5分钟无活动超时
                    logger.info(f"会话 {session_id} 超时，关闭连接")
                    break
                
                # 等待客户端数据
                ready_to_read, _, ready_to_error = select.select([client_socket], [], [client_socket], 0.1)
                
                if client_socket in ready_to_error:
                    logger.info("客户端连接错误，关闭隧道")
                    break
                
                if client_socket in ready_to_read:
                    try:
                        data = client_socket.recv(8192)
                        if not data:
                            # 连接已关闭
                            logger.info("客户端连接关闭")
                            break
                        
                        last_activity = time.time()
                        
                        # 加密并发送数据到服务端
                        request_data = self.protocol.create_request(
                            'data', 
                            host, 
                            port, 
                            data=data, 
                            session_id=session_id
                        )
                        
                        response = requests.post(
                            f"http://{self.server_host}:{self.server_port}/",
                            headers={
                                'Content-Type': 'application/json',
                                'X-Proxy-Protocol': '1.0'
                            },
                            data=request_data.encode(),
                            timeout=30
                        )
                        
                        if response.status_code != 200:
                            logger.error(f"发送数据到服务端失败: {response.status_code}")
                            break
                        
                        # 处理服务端响应
                        response_data = self.protocol.process_response(response.content)
                        
                        if response_data.get('result', {}).get('status') != 'ok':
                            error_msg = response_data.get('result', {}).get('message', 'Unknown error')
                            logger.error(f"服务端返回错误: {error_msg}")
                            break
                        
                        # 检查服务端响应的数据
                        if 'data' in response_data.get('result', {}):
                            resp_data = base64.b64decode(response_data['result']['data'])
                            if resp_data:
                                client_socket.send(resp_data)
                                last_activity = time.time()
                    
                    except Exception as e:
                        if not isinstance(e, (BlockingIOError, TimeoutError)):
                            logger.error(f"处理客户端数据时出错: {e}")
                            running = False
                            break
                
                # 轮询服务端是否有数据需要发送给客户端
                # 不频繁请求，避免服务器负担过重
                else:
                    try:
                        # 每5秒轮询一次，避免过多请求
                        if time.time() - last_activity > 0.5:  # 如果0.5秒内没有活动才发送轮询请求
                            request_data = self.protocol.create_request(
                                'data', 
                                host, 
                                port, 
                                data=None, 
                                session_id=session_id
                            )
                            
                            response = requests.post(
                                f"http://{self.server_host}:{self.server_port}/",
                                headers={
                                    'Content-Type': 'application/json',
                                    'X-Proxy-Protocol': '1.0'
                                },
                                data=request_data.encode(),
                                timeout=1
                            )
                            
                            if response.status_code == 200:
                                response_data = self.protocol.process_response(response.content)
                                
                                if 'data' in response_data.get('result', {}):
                                    resp_data = base64.b64decode(response_data['result']['data'])
                                    if resp_data:
                                        client_socket.send(resp_data)
                                        last_activity = time.time()
                    
                    except requests.exceptions.Timeout:
                        # 超时是正常的，不算错误
                        pass
                    except Exception as e:
                        if not isinstance(e, (requests.exceptions.RequestException, TimeoutError)):
                            logger.error(f"轮询服务端数据时出错: {e}")
        
        except Exception as e:
            logger.error(f"隧道连接出错: {e}")
        finally:
            # 关闭隧道
            try:
                logger.info(f"关闭会话 {session_id}")
                request_data = self.protocol.create_request('close', host, port, session_id=session_id)
                requests.post(
                    f"http://{self.server_host}:{self.server_port}/",
                    headers={
                        'Content-Type': 'application/json',
                        'X-Proxy-Protocol': '1.0'
                    },
                    data=request_data.encode(),
                    timeout=5
                )
            except:
                pass
                
            try:
                client_socket.close()
            except:
                pass
            
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
            
            logger.info(f"HTTP {method} 到 {host}:{port}{parsed_url.path}")
            
            # 创建一个新的会话ID
            session_id = self.get_next_session_id()
            
            # 创建加密请求
            request_data = self.protocol.create_request(
                'request', 
                host, 
                port, 
                data=request, 
                session_id=session_id
            )
            
            # 发送到远程服务器
            response = requests.post(
                f"http://{self.server_host}:{self.server_port}/",
                headers={
                    'Content-Type': 'application/json',
                    'X-Proxy-Protocol': '1.0'
                },
                data=request_data.encode(),
                timeout=30  # HTTP请求可能需要更长的超时时间
            )
            
            if response.status_code != 200:
                logger.error(f"HTTP请求失败: {response.status_code}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
                return
                
            # 处理响应
            try:
                response_data = self.protocol.process_response(response.content)
                
                # 检查响应状态
                if response_data.get('result', {}).get('status') != 'ok':
                    error_msg = response_data.get('result', {}).get('message', 'Unknown error')
                    logger.error(f"服务端返回错误: {error_msg}")
                    client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n' + error_msg.encode())
                    client_socket.close()
                    return
                
                # 将响应数据发送给客户端
                if 'data' in response_data.get('result', {}):
                    resp_data = base64.b64decode(response_data['result']['data'])
                    client_socket.send(resp_data)
                else:
                    client_socket.send(b'HTTP/1.1 204 No Content\r\n\r\n')
            except Exception as e:
                logger.error(f"处理HTTP响应时出错: {e}")
                client_socket.send(b'HTTP/1.1 500 Internal Server Error\r\n\r\n')
            finally:
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
    parser.add_argument('-d', '--debug', action='store_true', help='启用调试日志')
    
    args = parser.parse_args()
    
    # 如果启用了调试模式，设置更详细的日志级别
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
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