from typing import Dict, Optional

def get_random_proxy() -> Optional[Dict[str, str]]:
    """
    分布式行为打散：随机代理获取引擎
    实战中，你可以把这里的静态列表换成通过 requests 实时请求动态代理 API 的逻辑。

    返回:
        代理字典或None（表示本机直连）
    """
    import random
    # 这里填入你未来购买或白嫖的代理 IP 列表。目前用 None 代表本机直连作为容错。
    PROXY_POOL = [
        # "http://114.231.45.67:8080",
        # "http://221.122.33.44:9000",
        None
    ]

    selected = random.choice(PROXY_POOL)
    if selected:
        # 适配 curl_cffi 和 requests 的代理格式
        return {"http": selected, "https": selected}
    return None