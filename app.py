import socket
import select
import threading
import logging
import argparse

# 配置日志
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class HTTPSProxy:
    def __init__(self, host='0.0.0.0', port=8080):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
    def start(self):
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        logger.info(f"代理服务器已在 {self.host}:{self.port} 启动")
        
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
                # HTTP请求 (目前不处理，仅支持HTTPS)
                logger.warning(f"不支持的方法: {method}")
                client_socket.send(b'HTTP/1.1 502 Bad Gateway\r\n\r\n')
                client_socket.close()
        except Exception as e:
            logger.error(f"处理客户端请求时出错: {e}")
            client_socket.send(b'HTTP/1.1 500 Internal Server Error\r\n\r\n')
            client_socket.close()
    
    def handle_https(self, client_socket, host, port):
        try:
            # 连接到目标服务器
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((host, port))
            
            # 发送连接成功响应给客户端
            client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            
            # 设置两个socket为非阻塞
            client_socket.setblocking(False)
            server_socket.setblocking(False)
            
            # 双向转发数据
            while True:
                # 等待数据传输
                read_sockets, _, error_sockets = select.select([client_socket, server_socket], [], [client_socket, server_socket], 30)
                
                if error_sockets:
                    break
                
                for sock in read_sockets:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            return
                        
                        if sock is client_socket:
                            server_socket.send(data)
                        else:
                            client_socket.send(data)
                    except Exception as e:
                        logger.error(f"转发数据时出错: {e}")
                        return
        except Exception as e:
            logger.error(f"处理HTTPS连接时出错: {e}")
        finally:
            # 关闭连接
            if 'server_socket' in locals():
                server_socket.close()
            client_socket.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='HTTPS正向代理服务器')
    parser.add_argument('-p', '--port', type=int, default=8080, help='代理服务器监听端口 (默认: 8080)')
    parser.add_argument('-b', '--bind', default='0.0.0.0', help='绑定地址 (默认: 0.0.0.0)')
    
    args = parser.parse_args()
    
    proxy = HTTPSProxy(host=args.bind, port=args.port)
    proxy.start()