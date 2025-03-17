from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# 定义请求数据模型
class DataRequest(BaseModel):
    data: str  # 使用str类型接收base64编码的数据

# 创建FastAPI实例
app = FastAPI(title="简单POST API")

@app.post("/")
async def post_api(request: DataRequest):
    try:
        # 解码base64数据
        decoded_data = base64.b64decode(request.data)
        decoded_data = json.loads(decoded_data)
        print(decoded_data)
        # 将字节转换为字符串以便JSON序列化
        return {"data": decoded_data.decode('utf-8', errors='replace')}
    except Exception as e:
        return {"error": str(e)}

# 直接运行此文件时启动服务器
if __name__ == "__main__":
    uvicorn.run("fastapi-exam:app", host="0.0.0.0", port=8000, reload=True)