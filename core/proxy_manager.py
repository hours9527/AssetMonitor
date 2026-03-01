from typing import Dict, Optional
import random
from config import Config

def get_random_proxy() -> Optional[Dict[str, str]]:
    """
    分布式行为打散：随机代理获取引擎
    优先从 Config 读取配置，支持 .env 文件配置 PROXY_POOL

    返回:
        代理字典或None（表示本机直连）
    """
    # 1. 检查开关
    if not Config.ENABLE_PROXY:
        return None

    # 2. 获取代理池 (从Config中读取列表)
    pool = Config.PROXY_POOL
    
    # 如果池为空，回退到本机
    if not pool:
        return None

    selected = random.choice(pool)
    if selected:
        # 适配 curl_cffi 和 requests 的代理格式
        return {"http": selected, "https": selected}
    return None