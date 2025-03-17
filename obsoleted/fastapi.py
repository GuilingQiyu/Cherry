from fastapi import FastAPI
from pydantic import BaseModel
import uvicorn
import json
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# 创建FastAPI实例
app = FastAPI(title="简单POST API")

@app.post("/")
async def post_api(data: json):
    data = json.loads(data)
    data = base64.b64decode(data["data"])
    print(data)
    return {"data": data}



# 直接运行此文件时启动服务器
if __name__ == "__main__":
    uvicorn.run("fastapi_post_example:app", host="0.0.0.0", port=8000, reload=True)