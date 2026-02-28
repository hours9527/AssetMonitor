import requests
import socket
import json
import concurrent.futures
from typing import Set, List, Dict
from datetime import datetime
from config import Config
from logger import get_logger
from core.evasion import get_stealth_headers

logger = get_logger("subdomain")


class SubdomainCollector:
    """企业级多源子域名收集器"""

    def __init__(self):
        # 使用evasion模块的综合请求头，替代简单的User-Agent
        self.headers = get_stealth_headers()
        self.sources_result = {}

    def collect(self, domain: str) -> List[str]:
        """
        多源子域名聚合收集
        """
        logger.info(f"[*] 开始多源子域名收集: {domain}")

        subdomains = set()
        sources = Config.SUBDOMAIN_SOURCES

        # 按优先级调用各数据源
        if "hackertarget" in sources:
            subs = self._hackertarget(domain)
            subdomains.update(subs)

        if "crtsh" in sources:
            subs = self._crtsh(domain)
            subdomains.update(subs)

        if "dnsdumpster" in sources:
            subs = self._dnsdumpster(domain)
            subdomains.update(subs)

        # DNS 验证 (可选，耗时但准确)
        if Config.DNS_VERIFY_ENABLED:
            logger.info(f"[*] 开始DNS验证，过滤假子域名...")
            subdomains = self._dns_verify(subdomains)

        # 基础清理
        subdomains = self._clean_subdomains(subdomains)

        logger.info(
            f"[√] 子域名收集完成！共 {len(subdomains)} 个唯一子域 "
            f"(来源: {', '.join(self.sources_result.keys())})"
        )

        return list(subdomains)

    def _hackertarget(self, domain: str) -> Set[str]:
        """数据源1: HackerTarget API"""
        logger.info("  [>] 调用 HackerTarget 接口...")
        subdomains = set()

        try:
            url = Config.HACKERTARGET_URL.format(domain=domain)
            response = requests.get(url, headers=self.headers, timeout=10)

            if response.status_code == 200:
                for line in response.text.split('\n'):
                    if ',' in line:
                        subdomain = line.split(',')[0].strip()
                        if subdomain:
                            subdomains.add(subdomain)
                logger.info(f"  [+] HackerTarget 收集成功: {len(subdomains)} 个")
                self.sources_result["HackerTarget"] = len(subdomains)
            else:
                logger.warning(
                    f"  [-] HackerTarget API 响应异常: {response.status_code}"
                )
        except requests.Timeout:
            logger.warning("  [-] HackerTarget 请求超时")
        except Exception as e:
            logger.error(f"  [-] HackerTarget 请求失败: {e}")

        return subdomains

    def _crtsh(self, domain: str) -> Set[str]:
        """数据源2: crt.sh (证书透明度日志)"""
        logger.info("  [>] 调用 crt.sh 接口 (可能需要20秒)...")
        subdomains = set()

        try:
            url = Config.CRTSH_URL.format(domain=domain)
            response = requests.get(url, headers=self.headers, timeout=30)

            if response.status_code == 200:
                for item in response.json():
                    name_value = item.get('name_value', '')
                    for name in name_value.split('\n'):
                        # 移除泛域名前缀
                        clean_name = name.replace('*.', '').strip()
                        if clean_name:
                            subdomains.add(clean_name)
                logger.info(f"  [+] crt.sh 收集成功: {len(subdomains)} 个")
                self.sources_result["crt.sh"] = len(subdomains)
            else:
                logger.warning(f"  [-] crt.sh 响应异常: {response.status_code}")
        except requests.Timeout:
            logger.warning("  [-] crt.sh 请求超时")
        except Exception as e:
            logger.error(f"  [-] crt.sh 请求失败: {e}")

        return subdomains

    def _dnsdumpster(self, domain: str) -> Set[str]:
        """数据源3: DNSDumpster (网络爬虫，无API限制)"""
        logger.info("  [>] 调用 DNSDumpster 接口...")
        subdomains = set()

        try:
            # DNSDumpster 需要特殊处理，这是一个简化版本
            # 实战中可以集成如 dnsdumpster 库
            logger.warning("  [!] DNSDumpster 需要额外配置，已跳过")
        except Exception as e:
            logger.error(f"  [-] DNSDumpster 失败: {e}")

        return subdomains

    def _dns_verify(self, subdomains: Set[str]) -> Set[str]:
        """
        DNS验证：移除无法解析的子域名
        这能有效过滤扫描器生成的假域名
        P3-01改进：DNS查询超时保护
        P3-06改进：并行DNS验证 (ThreadPoolExecutor)
        """
        # P3-01: 使用Config中的DNS_TIMEOUT配置
        dns_timeout = Config.DNS_TIMEOUT if hasattr(Config, 'DNS_TIMEOUT') else 2
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(dns_timeout)

        # P3-06: 使用ThreadPoolExecutor并行验证DNS，加速20个域的验证
        # 性能优化：动态调整DNS并发数，最多THREADS_DEFAULT个
        dns_workers = min(max(20, Config.THREADS_DEFAULT), len(subdomains))
        verified = set()
        failed_count = 0
        timeout_count = 0

        def _verify_single(subdomain: str) -> tuple:
            """单个DNS验证"""
            try:
                socket.gethostbyname(subdomain)
                return (True, subdomain, None)
            except socket.timeout:
                return (False, subdomain, "timeout")
            except socket.gaierror:
                return (False, subdomain, "failed")
            except Exception:
                return (True, subdomain, None)  # 保守起见，其他异常保留

        # 使用线程池并行验证
        with concurrent.futures.ThreadPoolExecutor(max_workers=dns_workers) as executor:
            futures = {executor.submit(_verify_single, sub): sub for sub in subdomains}

            for future in concurrent.futures.as_completed(futures):
                success, subdomain, error_type = future.result()
                if success:
                    verified.add(subdomain)
                elif error_type == "timeout":
                    timeout_count += 1
                    verified.add(subdomain)  # 保守起见，超时的也保留
                elif error_type == "failed":
                    failed_count += 1

        # 恢复全局超时设置，避免影响其他模块
        socket.setdefaulttimeout(old_timeout)

        if failed_count > 0 or timeout_count > 0:
            logger.info(
                f"  [*] DNS验证: 移除 {failed_count} 个无效域名"
                f"{f', {timeout_count} 个超时' if timeout_count > 0 else ''} "
                f"(并行: {dns_workers}个worker)"
            )

        return verified

    @staticmethod
    def _clean_subdomains(subdomains: Set[str]) -> Set[str]:
        """清理和规范化子域名"""
        cleaned = set()

        for sub in subdomains:
            # 转小写
            sub = sub.lower().strip()

            # 移除重复的*符号
            if sub.startswith('*.'):
                sub = sub[2:]

            # 移除特殊字符和无效域名
            if sub and sub.count('.') > 0 and len(sub) < 253:
                cleaned.add(sub)

        return cleaned


# 兼容旧版本 API
def get_subdomains(domain: str) -> List[str]:
    """
    获取域名的所有子域名（多源聚合）

    Args:
        domain: 目标主域名 (e.g., "example.com")

    Returns:
        子域名列表

    Note:
        - 使用多个数据源进行聚合（DNS、HTTP、爬虫等）
        - 自动去重和验证
        - 返回已过滤和验证的子域名

    Example:
        >>> subdomains = get_subdomains("example.com")
        >>> isinstance(subdomains, list)
        True
    """
    collector = SubdomainCollector()
    return collector.collect(domain)