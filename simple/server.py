
import base64
import json
import socket
import threading
import logging
import asyncio
import time
from typing import Dict
import concurrent.futures
from contextlib import asynccontextmanager
import uvicorn
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# 配置日志
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# 创建FastAPI应用
app = FastAPI(title="HTTPS隧道代理服务端")

# 创建会话存储
sessions = {}
session_locks = {}
executor = concurrent.futures.ThreadPoolExecutor(max_workers=100)  # 用于处理IO操作

class ProxyRequest(BaseModel):
    data: str  # Base64编码的数据

class ProxyResponse(BaseModel):
    data: str  # Base64编码的数据

def decode_data(encoded_data: str) -> Dict:
    """解码Base64数据"""
    try:
        # 解码Base64得到JSON字符串
        json_str = base64.b64decode(encoded_data).decode('utf-8')
        # 解析JSON
        return json.loads(json_str)
    except Exception as e:
        logger.error(f"数据解码失败: {e}")
        raise ValueError("无效的数据格式")

def encode_data(data: Dict) -> str:
    """编码数据为Base64"""
    try:
        # 将字典转换为JSON字符串
        json_str = json.dumps(data)
        # 编码为Base64
        return base64.b64encode(json_str.encode('utf-8')).decode('utf-8')
    except Exception as e:
        logger.error(f"数据编码失败: {e}")
        raise ValueError("无法编码数据")

@app.post("/establish")
async def establish_connection(proxy_request: ProxyRequest):
    """建立到目标服务器的连接"""
    try:
        # 解码请求数据
        request_data = decode_data(proxy_request.data)
        host = request_data.get("host")
        port = request_data.get("port")
        session_id = request_data.get("session_id")
        
        if not all([host, port, session_id]):
            raise ValueError("缺少必要参数")
        
        # 使用线程池异步连接到目标服务器
        def create_connection():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # 禁用Nagle算法提高实时性
            s.connect((host, int(port)))
            return s
            
        server_socket = await asyncio.get_event_loop().run_in_executor(
            executor, create_connection
        )
        
        # 存储会话并创建会话锁
        sessions[session_id] = {
            "socket": server_socket,
            "host": host,
            "port": port,
            "last_activity": int(time.time()),
            "buffer": bytearray()
        }
        session_locks[session_id] = asyncio.Lock()
        
        logger.info(f"已建立到 {host}:{port} 的连接，会话ID: {session_id}")
        
        # 返回成功响应
        response_data = {
            "status": "success",
            "message": "连接已建立"
        }
        
        return ProxyResponse(data=encode_data(response_data))
    
    except Exception as e:
        logger.error(f"建立连接失败: {e}")
        response_data = {
            "status": "error",
            "message": str(e)
        }
        return JSONResponse(
            status_code=400,
            content={"data": encode_data(response_data)}
        )

@app.post("/transfer")
async def transfer_data(proxy_request: ProxyRequest):
    """在客户端和目标服务器之间传输数据"""
    try:
        # 解码请求数据
        request_data = decode_data(proxy_request.data)
        session_id = request_data.get("session_id")
        direction = request_data.get("direction")  # 'to_server' 或 'from_server'
        payload = request_data.get("payload")  # Base64编码的实际请求/响应数据
        
        if not all([session_id, direction, payload]):
            raise ValueError("缺少必要参数")
        
        if session_id not in sessions:
            raise ValueError(f"会话ID无效: {session_id}")
        
        session = sessions[session_id]
        server_socket = session["socket"]
        
        # 更新最后活动时间
        session["last_activity"] = int(time.time())
        
        # 使用会话锁确保并发安全
        async with session_locks[session_id]:
            if direction == "to_server":
                # 解码负载并发送到目标服务器
                raw_data = base64.b64decode(payload)
                
                # 使用线程池执行IO操作
                def send_to_server():
                    server_socket.sendall(raw_data)
                    # 从服务器读取响应
                    response_data = bytearray()
                    server_socket.settimeout(2.0)  # 设置较短的超时
                    try:
                        while True:
                            chunk = server_socket.recv(16384)  # 增加缓冲区大小
                            if not chunk:
                                break
                            response_data.extend(chunk)
                            if len(chunk) < 16384:
                                break
                    except socket.timeout:
                        pass
                    return bytes(response_data)
                
                response_data = await asyncio.get_event_loop().run_in_executor(
                    executor, send_to_server
                )
                
                # 编码响应数据
                encoded_response = base64.b64encode(response_data).decode('utf-8')
                
                return ProxyResponse(data=encode_data({
                    "status": "success",
                    "session_id": session_id,
                    "payload": encoded_response
                }))
            
            elif direction == "from_server":
                # 仅从服务器读取数据
                def receive_from_server():
                    response_data = bytearray()
                    server_socket.settimeout(0.2)  # 设置非常短的超时以提高响应速度
                    try:
                        while True:
                            chunk = server_socket.recv(16384)
                            if not chunk:
                                break
                            response_data.extend(chunk)
                            if len(chunk) < 16384:
                                break
                    except socket.timeout:
                        pass
                    return bytes(response_data)
                
                response_data = await asyncio.get_event_loop().run_in_executor(
                    executor, receive_from_server
                )
                
                # 编码响应数据
                encoded_response = base64.b64encode(response_data).decode('utf-8')
                
                return ProxyResponse(data=encode_data({
                    "status": "success",
                    "session_id": session_id,
                    "payload": encoded_response
                }))
            
            else:
                raise ValueError(f"无效的传输方向: {direction}")
    
    except Exception as e:
        logger.error(f"数据传输失败: {e}")
        response_data = {
            "status": "error",
            "message": str(e)
        }
        return JSONResponse(
            status_code=400,
            content={"data": encode_data(response_data)}
        )
        

@app.post("/close")
async def close_connection(proxy_request: ProxyRequest):
    """关闭到目标服务器的连接"""
    try:
        # 解码请求数据
        request_data = decode_data(proxy_request.data)
        session_id = request_data.get("session_id")
        
        if not session_id:
            raise ValueError("缺少必要参数")
        
        if session_id in sessions:
            # 加锁确保并发安全
            if session_id in session_locks:
                async with session_locks[session_id]:
                    session = sessions[session_id]
                    server_socket = session["socket"]
                    await asyncio.get_event_loop().run_in_executor(
                        executor, lambda: server_socket.close()
                    )
                    del sessions[session_id]
                    logger.info(f"已关闭会话: {session_id}")
                # 删除会话锁
                del session_locks[session_id]
        
        return ProxyResponse(data=encode_data({
            "status": "success",
            "message": "连接已关闭"
        }))
    
    except Exception as e:
        logger.error(f"关闭连接失败: {e}")
        response_data = {
            "status": "error",
            "message": str(e)
        }
        return JSONResponse(
            status_code=400,
            content={"data": encode_data(response_data)}
        )

# 清理过期会话的后台任务
import time

def cleanup_sessions():
    """清理过期的会话"""
    while True:
        time.sleep(60)  # 每分钟检查一次
        current_time = int(time.time())
        expired_sessions = []
        
        # 复制会话信息避免并发修改
        current_sessions = dict(sessions)
        
        for session_id, session in current_sessions.items():
            # 如果会话超过10分钟没有活动，则关闭
            if current_time - session["last_activity"] > 600:
                expired_sessions.append(session_id)
        
        for session_id in expired_sessions:
            try:
                if session_id in sessions:
                    sessions[session_id]["socket"].close()
                    del sessions[session_id]
                    # 同时删除对应的锁
                    if session_id in session_locks:
                        del session_locks[session_id]
                    logger.info(f"已清理过期会话: {session_id}")
            except Exception as e:
                logger.error(f"清理会话 {session_id} 时出错: {e}")
# 启动清理任务
cleanup_thread = threading.Thread(target=cleanup_sessions, daemon=True)
cleanup_thread.start()

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)