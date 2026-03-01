"""
HTTP探测引擎：指纹识别、存活检测、漏洞验证一体化
支持高级泛域名检测、重定向追踪、编码自动处理
P3-08改进：Circuit Breaker防止重复请求失败端点
"""
from curl_cffi import requests
import urllib3
import re
import concurrent.futures
import random
import string
import time
import threading
from typing import Dict, List, Optional, Tuple

from datetime import datetime, timedelta
from core.evasion import get_stealth_headers, smart_sleep
from core.proxy_manager import get_random_proxy
from core.poc_engine import run_pocs
from core.models import Asset, Vulnerability
from config import Config
from logger import get_logger

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logger = get_logger("httpx_probe")


# ==========================================
# P3-08: Circuit Breaker 模式 (防止无谓重试)
# ==========================================
class CircuitBreaker:
    """P3-08: Circuit Breaker 防止重复请求失败的端点"""

    def __init__(self, failure_threshold: int = None, timeout: int = None):
        """
        初始化Circuit Breaker
        failure_threshold: 失败多少次后打开熔断器 (默认从Config读取)
        timeout: 熔断后多少秒尝试恢复 (默认从Config读取)
        """
        self.failure_threshold = failure_threshold or Config.CIRCUIT_BREAKER_FAILURE_THRESHOLD
        self.timeout = timeout or Config.CIRCUIT_BREAKER_TIMEOUT
        self.circuits = {}  # {url: {'failures': int, 'last_failure': timestamp, 'state': 'closed'|'open'|'half_open'}}

    def record_failure(self, url: str) -> None:
        """
        记录一次失败，并在失败次数达到阈值后打开熔断器

        Args:
            url: 失败的URL
        """
        if url not in self.circuits:
            self.circuits[url] = {'failures': 0, 'last_failure': None, 'state': 'closed'}

        circuit = self.circuits[url]
        circuit['failures'] += 1
        circuit['last_failure'] = time.time()

        if circuit['failures'] >= self.failure_threshold:
            circuit['state'] = 'open'
            logger.warning(f"[⚠️] Circuit Breaker开启: {url} (失败{circuit['failures']}次)")

    def record_success(self, url: str) -> None:
        """
        记录一次成功，重置熔断器状态

        Args:
            url: 成功的URL
        """
        if url in self.circuits:
            self.circuits[url]['failures'] = 0
            self.circuits[url]['state'] = 'closed'

    def is_available(self, url: str) -> bool:
        """
        判断端点是否可用

        Circuit Breaker状态机:
        - closed: 端点正常，接受请求
        - open: 端点故障，拒绝请求
        - half_open: 端点恢复中，允许测试请求

        Args:
            url: 要检查的URL

        Returns:
            bool: 如果端点可用返回True，否则返回False
        """
        if url not in self.circuits:
            return True

        circuit = self.circuits[url]

        # 如果是closed状态，直接可用
        if circuit['state'] == 'closed':
            return True

        # 如果是open状态，检查是否可以尝试恢复
        if circuit['state'] == 'open':
            elapsed = time.time() - circuit['last_failure']
            if elapsed > self.timeout:
                circuit['state'] = 'half_open'
                circuit['failures'] = 0
                logger.info(f"[↻] Circuit Breaker半开: {url} (尝试恢复)")
                return True
            else:
                return False

        # half_open状态，允许一次请求来测试
        return circuit['state'] == 'half_open'

    def get_stats(self) -> Dict[str, int]:
        """获取熔断器统计"""
        open_count = len([c for c in self.circuits.values() if c['state'] == 'open'])
        return {'total': len(self.circuits), 'open': open_count}


# 全局Circuit Breaker实例
circuit_breaker = CircuitBreaker(failure_threshold=5, timeout=300)


# ==========================================
# 指纹识别规则库（带权重）
# ==========================================
FINGERPRINTS = [
    # Spring Boot
    {"name": "Spring Boot", "location": "body", "keyword": "Whitelabel Error Page", "weight": 0.90},
    {"name": "Spring Boot", "location": "body", "keyword": "timestamp", "weight": 0.50},
    {"name": "Spring Boot", "location": "header", "keyword": "X-Application-Context", "weight": 0.95},

    # Apache Shiro
    {"name": "Apache Shiro", "location": "header", "keyword": "rememberMe=", "weight": 0.85},
    {"name": "Apache Shiro", "location": "header", "keyword": "JSESSIONID", "weight": 0.75},  # Shiro应用的会话标识

    # ThinkPHP
    {"name": "ThinkPHP", "location": "header", "keyword": "X-Powered-By: ThinkPHP", "weight": 0.90},

    # JBoss
    {"name": "JBoss", "location": "header", "keyword": "X-Powered-By: JBoss", "weight": 0.85},

    # Nginx
    {"name": "Nginx", "location": "header", "keyword": "Server: nginx", "weight": 0.95},

    # IIS
    {"name": "IIS", "location": "header", "keyword": "Server: Microsoft-IIS", "weight": 0.95},

    # Vue.js
    {"name": "Vue.js", "location": "body", "keyword": "__NUXT__", "weight": 0.85},
    {"name": "Vue.js", "location": "body", "keyword": "app.js", "weight": 0.40},
]

# 全局风控状态（线程安全优化版）
CONSECUTIVE_BLOCKS = 0
DYNAMIC_DELAY_BASE = Config.SMART_SLEEP_MIN
risk_lock = threading.Lock()
# 优化: 使用Event和时间戳避免阻塞睡眠
waf_backoff_until = 0  # Unix时间戳，标记WAF退避截止时间


# ==========================================
# 指纹识别函数（带权重计算）
# ==========================================
def identify_fingerprint(headers: Dict, body: str) -> Tuple[List[str], float]:
    """
    识别应用指纹（返回指纹列表和平均置信度）

    Args:
        headers: HTTP响应头字典
        body: HTTP响应体内容

    Returns:
        (指纹名称列表, 平均置信度) 元组

    Example:
        >>> names, confidence = identify_fingerprint({}, "Whitelabel Error Page")
        >>> "Spring Boot" in names
        True
    """
    detected = {}  # {name: max_weight}
    headers_str = str(headers).lower()
    body_lower = body.lower()

    for rule in FINGERPRINTS:
        keyword_lower = rule['keyword'].lower()
        matched = False

        if rule['location'] == 'header' and keyword_lower in headers_str:
            matched = True
        elif rule['location'] == 'body' and keyword_lower in body_lower:
            matched = True

        if matched:
            name = rule['name']
            weight = rule['weight']
            detected[name] = max(detected.get(name, 0), weight)

    if not detected:
        return ["未知"], 0.0

    # 计算平均权重作为整体置信度
    names = list(detected.keys())
    avg_weight = sum(detected.values()) / len(detected)

    return names, avg_weight


# ==========================================
# HTML 解析辅助函数
# ==========================================
def get_title(html_content: str) -> str:
    """
    安全地提取HTML标题，避免正则表达式DoS

    Args:
        html_content: HTML内容字符串

    Returns:
        页面标题，若提取失败返回"无标题"

    Note:
        - 限制标题长度为100字符
        - 清理换行符和控制字符
        - 捕获所有异常避免影响扫描流程
    """
    try:
        # 使用更安全的正则表达式（限制匹配长度）
        match = re.search(
            r'<title>(.*?)</title>',
            html_content,
            re.IGNORECASE | re.DOTALL
        )
        if match:
            title = match.group(1).strip()
            # 清理换行符和控制字符
            title = re.sub(r'\s+', ' ', title)
            return title[:100]  # 限制长度
    except Exception as e:
        logger.debug(f"[-] 标题提取失败: {e}")

    return "无标题"


# ==========================================
# 泛域名检测（高级）
# ==========================================
def generate_random_subdomain(domain: str) -> str:
    """
    生成随机子域名用于泛域名检测

    Args:
        domain: 主域名 (e.g., "example.com")

    Returns:
        生成的随机子域名 (e.g., "abc123def45.example.com")

    Note:
        使用10个随机大小写字母和数字组成子域名前缀
    """
    random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    return f"{random_str}.{domain}"


def get_wildcard_signature(domain: str) -> Dict:
    """
    高级泛域名检测：测试多个随机子域名对比

    Args:
        domain: 目标主域名

    Returns:
        泛域名签名字典，包含以下字段:
        - is_wildcard (bool): 是否检测到泛解析
        - signatures (List[Dict]): 响应特征列表
        - status_codes (List[int]): HTTP状态码列表

    Note:
        如果返回的内容相同，说明存在泛解析
        支持HTTP和HTTPS两种协议检测
    """
    logger.info(f"[*] 检测泛域名配置...")

    signature = {
        "is_wildcard": False,
        "signatures": [],  # 多个签名
        "status_codes": []
    }

    test_count = Config.WILDCARD_TEST_COUNT
    urls_tested = []

    for protocol in ["http", "https"]:
        for i in range(test_count):
            fake_sub = generate_random_subdomain(domain)
            url = f"{protocol}://{fake_sub}"
            urls_tested.append(url)

            try:
                res = requests.get(
                    url,
                    verify=Config.VERIFY_SSL_CERTIFICATE,
                    timeout=Config.REQUEST_TIMEOUT,
                    impersonate="chrome120"
                )

                signature["status_codes"].append(res.status_code)

                # 记录响应签名（用于对比）
                sig = {
                    "status_code": res.status_code,
                    "content_length": len(res.content),
                    "title": get_title(res.text)
                }
                signature["signatures"].append(sig)

                if res.status_code == 200:
                    signature["is_wildcard"] = True
                    logger.info(f"  [!] 检测到泛解析: {protocol}://{domain}")
                    return signature

            except Exception as e:
                logger.debug(f"  [-] 泛域名检测失败 {url}: {e}")

    logger.debug(f"  [√] 无泛解析配置")
    return signature


def is_wildcard_response(response_sig: Dict, wildcard_sig: Dict) -> bool:
    """
    判断响应是否来自泛解析

    通过比对响应特征和泛解析签名来判断

    Args:
        response_sig: 当前响应特征字典，包含:
            - status_code: HTTP状态码
            - content_length: 响应体长度
            - title: 页面标题
        wildcard_sig: 泛解析签名（来自 get_wildcard_signature()）

    Returns:
        bool: 如果判断为泛解析响应返回True，否则返回False

    Note:
        使用内容长度阈值（Config.WILDCARD_THRESHOLD）来判断
    """
    if not wildcard_sig.get("is_wildcard"):
        return False

    threshold = Config.WILDCARD_THRESHOLD

    # 与记录的泛解析签名比对
    for sig in wildcard_sig.get("signatures", []):
        if (
            response_sig.get("status_code") == sig.get("status_code")
            and abs(response_sig.get("content_length", 0) - sig.get("content_length", 0)) < threshold
            and response_sig.get("title") == sig.get("title")
        ):
            logger.debug(f"  [*] 判断为泛解析: 特征匹配")
            return True

    return False


# ==========================================
# 重定向链追踪
# ==========================================
def follow_redirects(url: str, max_redirects: int = Config.MAX_REDIRECTS) -> Tuple[str, List[str]]:
    """
    追踪HTTP重定向链，返回最终URL和重定向链

    Args:
        url: 初始URL
        max_redirects: 最大重定向跟踪次数 (默认: Config.MAX_REDIRECTS)

    Returns:
        (最终URL, 重定向链列表) 元组
        重定向链列表包含初始URL和所有重定向URL

    Raises:
        捕获所有网络异常并记录日志，不会抛出异常

    Example:
        >>> final, chain = follow_redirects("http://example.com")
        >>> final in chain  # final URL在chain列表中
        True
    """
    final_url = url
    redirect_chain = [url]
    redirects_followed = 0

    while redirects_followed < max_redirects:
        try:
            headers = get_stealth_headers()
            proxies = get_random_proxy()

            # 不自动跟踪重定向
            res = requests.get(
                final_url,
                headers=headers,
                proxies=proxies,
                verify=Config.VERIFY_SSL_CERTIFICATE,
                timeout=Config.REQUEST_TIMEOUT,
                impersonate="chrome120",
                allow_redirects=False  # 手动处理重定向
            )

            # 检查是否有重定向
            if res.status_code in [301, 302, 303, 307, 308]:
                location = res.headers.get('Location')
                if location:
                    # 处理相对URL
                    if location.startswith('/'):
                        from urllib.parse import urlparse, urljoin
                        final_url = urljoin(final_url, location)
                    else:
                        final_url = location

                    redirect_chain.append(final_url)
                    redirects_followed += 1
                    logger.debug(f"  [→] 重定向: {final_url}")
                    time.sleep(0.5)  # 避免频繁请求
                else:
                    break
            else:
                # 没有重定向，停止跟踪
                break

        except Exception as e:
            logger.debug(f"  [-] 重定向追踪异常: {e}")
            break

    return final_url, redirect_chain


# ==========================================
# 主探测函数
# ==========================================
def probe_subdomain(subdomain: str, wildcard_sig: Dict, max_retries: int = 2) -> Optional[Asset]:
    """
    探测单个子域名：存活检测、指纹识别、漏洞验证
    P3-08改进：Circuit Breaker防止重复请求失败的端点

    参数:
        subdomain: 要探测的子域名
        wildcard_sig: 泛域名签名
        max_retries: 网络错误最多重试次数

    返回:
        Asset对象（如果存活），否则None
    """
    global CONSECUTIVE_BLOCKS, DYNAMIC_DELAY_BASE, waf_backoff_until

    if '@' in subdomain:
        return None

    urls = [f"http://{subdomain}", f"https://{subdomain}"]
    retry_count = 0

    for url in urls:
        # P3-08: Circuit Breaker检查 - 如果端点熔断了，跳过
        if not circuit_breaker.is_available(url):
            logger.debug(f"  [⊘] 跳过熔断端点: {url}")
            continue

        # 单个URL的重试循环
        response = None
        for attempt in range(max_retries + 1):
            try:
                # [新增] 检查全局WAF退避状态
                # 如果其他线程触发了WAF防护，当前线程应主动暂停
                if waf_backoff_until > time.time():
                    wait_time = waf_backoff_until - time.time()
                    if wait_time > 0:
                        logger.warning(f"  [!] 全局WAF退避生效中，暂停 {wait_time:.1f}s ...")
                        time.sleep(wait_time)

                stealth_headers = get_stealth_headers()

                # 动态延迟（带线程锁）
                with risk_lock:
                    current_delay = DYNAMIC_DELAY_BASE
                smart_sleep(current_delay, current_delay + 0.6)

                current_proxy = get_random_proxy()

                # 发送请求
                start_perf = time.perf_counter()

                # 先做一个不跟随重定向的请求以捕获初始响应头（包括Set-Cookie）
                initial_response = requests.get(
                    url,
                    headers=stealth_headers,
                    proxies=current_proxy,
                    verify=Config.VERIFY_SSL_CERTIFICATE,
                    timeout=Config.REQUEST_TIMEOUT,
                    impersonate="chrome120",
                    allow_redirects=False
                )

                # 如果是重定向，继续跟随重定向获取最终内容
                if initial_response.status_code in [301, 302, 303, 307, 308]:
                    response = requests.get(
                        url,
                        headers=stealth_headers,
                        proxies=current_proxy,
                        verify=Config.VERIFY_SSL_CERTIFICATE,
                        timeout=Config.REQUEST_TIMEOUT,
                        impersonate="chrome120",
                        allow_redirects=True
                    )
                    # 合并初始响应头到最终响应（用于指纹识别）
                    # 将初始响应的Set-Cookie等重要头部添加到最终响应
                    for key, value in initial_response.headers.items():
                        if key.lower() in ['set-cookie', 'server', 'x-powered-by']:
                            if key not in response.headers:
                                response.headers[key] = value
                else:
                    response = initial_response

                # 记录耗时 (ms)
                response.elapsed_ms = int((time.perf_counter() - start_perf) * 1000)

                # P3-08: 请求成功，重置circuit breaker状态
                circuit_breaker.record_success(url)
                break  # 请求成功，跳出重试循环

            except requests.exceptions.Timeout:
                if attempt < max_retries:
                    logger.debug(f"  [↻] 超时重试 ({attempt + 1}/{max_retries}): {url}")
                    time.sleep(1)
                else:
                    logger.debug(f"  [-] 请求超时 (放弃): {url}")
                    # 修复: 超时也应计入熔断器失败次数
                    circuit_breaker.record_failure(url)
            except requests.exceptions.ConnectionError:
                if attempt < max_retries:
                    logger.debug(f"  [↻] 连接重试 ({attempt + 1}/{max_retries}): {url}")
                    time.sleep(2)
                else:
                    logger.debug(f"  [-] 连接失败 (放弃): {url}")
                    circuit_breaker.record_failure(url)
            except Exception as e:
                logger.error(f"  [!] 未知异常 {url}: {e}")
                circuit_breaker.record_failure(url)
                break  # 未知异常通常不重试

        if not response:
            continue

        # 编码处理
        if hasattr(response, 'apparent_encoding') and response.apparent_encoding:
            response.encoding = response.apparent_encoding
        elif response.encoding is None:
            response.encoding = 'utf-8'

        # ===== 风控自适应（优化版：避免阻塞） =====
        if response.status_code in [403, 429]:
            with risk_lock:
                CONSECUTIVE_BLOCKS += 1
                # 如果连续拦截>=3次，触发退避
                if CONSECUTIVE_BLOCKS >= 3:
                    logger.warning(f"\n[!!!] 检测到WAF防护 (连续拦截{CONSECUTIVE_BLOCKS}次)，采用指数退避策略")
                    import time as t
                    waf_backoff_until = t.time() + 15
                    DYNAMIC_DELAY_BASE += 0.5
                    CONSECUTIVE_BLOCKS = 0
        else:
            with risk_lock:
                CONSECUTIVE_BLOCKS = 0

            # ===== 内容提取 =====
            content_length = len(response.content)
            title = get_title(response.text)

            # ===== 泛解析过滤 =====
            response_sig = {
                "status_code": response.status_code,
                "content_length": content_length,
                "title": title
            }

            if is_wildcard_response(response_sig, wildcard_sig):
                logger.debug(f"  [·] 过滤泛解析: {url}")
                continue

            # ===== 指纹识别 =====
            tech_stack, confidence = identify_fingerprint(response.headers, response.text)
            tech_str = ", ".join(tech_stack)

            # ===== 漏洞检测 =====
            # 无论是否识别出指纹，都调用POC引擎（引擎内部会处理通用POC）
            vulns = run_pocs(url, tech_stack)

            # ===== 输出格式化 =====
            if vulns:
                marker = "[💥 漏洞!!!]"
            elif tech_stack != ["未知"]:
                marker = "[★]"
            else:
                marker = "[+]"

            result = f"{marker} 存活: {url:<35} | 状态: {response.status_code} | 指纹: [{tech_str}] | 标题: {title}"
            logger.info(result)

            response_time_ms = getattr(response, 'elapsed_ms', 0)

            return Asset(
                url=url,
                status=response.status_code,
                fingerprint=tech_str,
                confidence=confidence,
                title=title,
                vulns=vulns,
                response_time=response_time_ms
            )

    return None


# ==========================================
# 批量探测函数
# ==========================================
def batch_probe(subdomains: List[str], target_domain: str, threads: int = Config.THREADS_DEFAULT) -> List[Asset]:
    """
    批量探测子域名

    参数:
        subdomains: 子域名列表
        target_domain: 目标主域名
        threads: 线程数

    返回:
        存活资产列表
    """
    wildcard_sig = get_wildcard_signature(target_domain)
    logger.info(f"\n[*] 开始并发探测，共 {len(subdomains)} 个目标（线程数: {threads}）...")

    alive_assets: List[Asset] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(probe_subdomain, sub, wildcard_sig)
            for sub in subdomains
        ]
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            if res:
                alive_assets.append(res)

    logger.info(f"[√] 探测完成！发现 {len(alive_assets)} 个存活资产")
    return alive_assets
