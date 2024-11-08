from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import httpx
import asyncio
from datetime import datetime, timedelta
import time
from collections import defaultdict
import ipaddress
import random

app = FastAPI()

# 添加 CORS 中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 在生产环境中应该设置具体的域名
    allow_methods=["*"],
    allow_headers=["*"],
)

# 速率限制配置
RATE_LIMIT_DURATION = 60  # 60秒时间窗口
MAX_REQUESTS = 1000  # 每个IP每分钟最多1000个请求
MAX_TOKENS_PER_REQUEST = 5  # 每次请求最多验证5个令牌
MAX_CONCURRENT_CONNECTIONS = 5000  # 最大并发连接数
TOKEN_BUCKETS = defaultdict(lambda: {"count": 0, "reset_time": time.time()})

class TokenRequest(BaseModel):
    tokens: List[str]

def is_rate_limited(ip: str) -> bool:
    bucket = TOKEN_BUCKETS[ip]
    current_time = time.time()
    
    # 重置计数器
    if current_time - bucket["reset_time"] >= RATE_LIMIT_DURATION:
        bucket["count"] = 0
        bucket["reset_time"] = current_time
    
    # 检查是否超过限制
    if bucket["count"] >= MAX_REQUESTS:
        return True
    
    bucket["count"] += 1
    return False

async def check_token(token: str, semaphore: asyncio.Semaphore) -> dict:
    async with semaphore:
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                token = token.strip()
                if not token:
                    return {
                        "status": "invalid",
                        "message": "Token为空",
                        "access_token": None,
                        "refresh_token": None
                    }

                # 使用 token.oaifree.com API 验证
                try:
                    refresh_response = await client.post(
                        "https://token.oaifree.com/api/auth/refresh",
                        headers={
                            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"
                        },
                        data={
                            "refresh_token": token
                        },
                        timeout=30.0
                    )

                    if refresh_response.status_code == 200:
                        response_data = refresh_response.json()
                        if "access_token" in response_data:
                            return {
                                "status": "valid",
                                "message": "Token有效",
                                "access_token": response_data["access_token"],
                                "refresh_token": token
                            }
                
                    return {
                        "status": "invalid",
                        "message": "Token无效或已过期",
                        "access_token": None,
                        "refresh_token": None
                    }

                except httpx.TimeoutException:
                    return {
                        "status": "invalid",
                        "message": "请求超时",
                        "access_token": None,
                        "refresh_token": None
                    }
                except Exception as e:
                    return {
                        "status": "invalid",
                        "message": f"Token验证失败: {str(e)}",
                        "access_token": None,
                        "refresh_token": None
                    }

            except Exception as e:
                return {
                    "status": "invalid",
                    "message": f"验证出错: {str(e)}",
                    "access_token": None,
                    "refresh_token": None
                }

# 添加清理过期记录的函数
def cleanup_token_buckets():
    current_time = time.time()
    expired_ips = [
        ip for ip, bucket in TOKEN_BUCKETS.items()
        if current_time - bucket["reset_time"] >= RATE_LIMIT_DURATION * 2
    ]
    for ip in expired_ips:
        del TOKEN_BUCKETS[ip]

@app.post("/api/check-tokens")
async def check_tokens(request: Request, token_request: TokenRequest):
    # 每100次请求执行一次清理
    if random.random() < 0.01:  # 1% 的概率执行清理
        cleanup_token_buckets()
    # 获取客户端IP
    client_ip = request.client.host
    
    # 检查速率限制
    if is_rate_limited(client_ip):
        raise HTTPException(
            status_code=429,
            detail="请求过于频繁，请稍后再试"
        )
    
    # 检查令牌数量限制
    if len(token_request.tokens) > MAX_TOKENS_PER_REQUEST:
        raise HTTPException(
            status_code=400,
            detail=f"每次请求最多验证 {MAX_TOKENS_PER_REQUEST} 个令牌"
        )
    
    # 创建信号量控制并发
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_CONNECTIONS)  # 增加并发连接数
    
    # 批量处理令牌
    tasks = []
    for token in token_request.tokens:
        if not token.strip():
            continue
        
        tasks.append(asyncio.create_task(check_token(token.strip(), semaphore)))
    
    try:
        results = await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail="服务器内部错误")
    
    # 处理结果
    processed_results = []
    for result in results:
        if isinstance(result, Exception):
            processed_results.append({
                "status": "invalid",
                "message": "Invalid token format",
                "access_token": None,
                "refresh_token": None
            })
        else:
            processed_results.append(result)
    
    return processed_results
