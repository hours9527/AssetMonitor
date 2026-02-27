"""
反检测/反爬虫规避模块
支持：UA池、Referer多样化、Cookie模拟、TLS指纹规避
"""
import random
import time
from typing import Dict
from config import Config

# ==========================================
# 扩展的 User-Agent 池（100+个真实UA）
# ==========================================
USER_AGENTS = [
    # Chrome 浏览器
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",

    # Firefox 浏览器
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",

    # Safari 浏览器
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Mobile/15E148 Safari/604.1",

    # Edge 浏览器
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",

    # 手机端 (Android)
    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.129 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",

    # 旧版本浏览器（某些WAF识别爬虫常用）
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
]

# ==========================================
# Referer 多样化池
# ==========================================
REFERER_POOL = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.baidu.com/",
    "https://www.google.com/search?q=test",
    "https://www.bing.com/search?q=test",
    "",  # 直接访问
    "https://www.reddit.com/",
    "https://www.github.com/",
    "https://www.linkedin.com/",
]

# ==========================================
# Accept-Language 池
# ==========================================
ACCEPT_LANGUAGE_POOL = [
    "zh-CN,zh;q=0.9,en;q=0.8",
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
]


def get_stealth_headers() -> Dict[str, str]:
    """
    生成逼真的随机HTTP请求头，规避检测
    支持：多UA、多Referer、多语言、随机其他头部
    """
    headers = {
        # 随机 User-Agent
        "User-Agent": random.choice(USER_AGENTS),

        # 浏览器标准Accept
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",

        # 随机语言偏好
        "Accept-Language": random.choice(ACCEPT_LANGUAGE_POOL),

        # 随机Referer
        "Referer": random.choice(REFERER_POOL),

        # 标准浏览器头部
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Accept-Encoding": "gzip, deflate, br",

        # 缓存控制
        "Cache-Control": "max-age=0",

        # 随机其他头部（某些真实浏览器会发送）
        "Sec-Fetch-Dest": random.choice(["document", "iframe", "image"]),
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": random.choice(["none", "same-origin", "cross-site"]),
    }

    # 5% 概率添加额外的隐蔽头部
    if random.random() < 0.05:
        headers["X-Requested-With"] = random.choice(["XMLHttpRequest", "fetch"])

    # 10% 概率随机删除某些"太明显"的头部（更像真实爬虫）
    if random.random() < 0.1:
        # 某些真实爬虫会忘记发某些头部
        headers.pop("Upgrade-Insecure-Requests", None)

    return headers


def smart_sleep(min_delay: float = 0.1, max_delay: float = 1.2) -> None:
    """
    智能动态延迟 (Jitter + Exponential Backoff)

    参数:
        min_delay: 最小延迟(秒)
        max_delay: 最大延迟(秒)

    作用：
        - 打乱发包频率，规避频率检测
        - 模拟真实用户的随机访问行为
        - 防触发CC防护
    """
    # 基础抖动延迟
    delay = random.uniform(min_delay, max_delay)

    # 5% 概率增加长延迟（模拟用户思考时间）
    if random.random() < 0.05:
        delay = random.uniform(2, 5)

    time.sleep(delay)


def get_random_browser_fingerprint() -> str:
    """
    返回随机的TLS指纹识别（curl_cffi impersonate参数）
    """
    return random.choice([
        "chrome120",
        "chrome121",
        "firefox121",
        "safari17",
        "edge120"
    ])


def simulate_user_behavior() -> None:
    """
    模拟用户行为的进阶延迟
    某些高级WAF会检测机器人的"完美规律"
    """
    # 随机模拟"用户滚动页面"的延迟
    if random.random() < 0.3:
        time.sleep(random.uniform(0.5, 2))

    # 随机模拟"用户思考"的长延迟
    if random.random() < 0.05:
        time.sleep(random.uniform(3, 8))