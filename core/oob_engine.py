import requests
import random
import string
import time
import json
from config import Config
from logger import get_logger

logger = get_logger("oob_engine")


class OOBEngine:
    def __init__(self):
        """
        企业级 OOB 盲打引擎 (支持 Ceye.io 和 DNS-log 双服务)
        优先使用主服务，失败时自动切换到备用服务
        """
        self.service_type = None  # 'ceye' or 'dnslog'
        self.api_token = ""
        self.domain_identifier = ""
        self.is_configured = False

        # Detect available service
        self._detect_available_service()

        if not self.is_configured:
            logger.warning("[OOB] 未配置可用的OOB服务(Ceye或DNS-log)，OOB漏洞检测将被跳过")

    def _check_service_health(self, service: str) -> bool:
        """
        检查OOB服务是否可访问

        Args:
            service: 'ceye' or 'dnslog'

        Returns:
            bool: 服务是否健康
        """
        try:
            if service == 'ceye':
                # Ceye健康检查
                if not Config.CEYE_DOMAIN:
                    return False
                test_url = f"http://api.ceye.io/v1/records?token={Config.CEYE_TOKEN}&type=dns&filter=health_check"
                res = requests.get(test_url, timeout=3)
                return res.status_code == 200

            elif service == 'dnslog':
                # DNS-log health check
                if not Config.DNSLOG_DOMAIN:
                    return False
                test_url = f"http://api.dnslog.cn/query?token={Config.DNSLOG_TOKEN}&latest=true"
                res = requests.get(test_url, timeout=3)
                return res.status_code == 200
        except Exception as e:
            logger.debug(f"[OOB] {service} 健康检查失败: {e}")
            return False

    def _detect_available_service(self):
        """
        检测并配置可用的OOB服务
        优先使用主服务 (默认Ceye)，失败时切换到备用服务 (DNS-log)
        """
        primary = Config.OOB_PRIMARY_SERVICE.lower()

        # Try primary service first
        if primary == 'ceye' and Config.CEYE_TOKEN and Config.CEYE_DOMAIN:
            if self._check_service_health('ceye'):
                self.service_type = 'ceye'
                self.api_token = Config.CEYE_TOKEN
                self.domain_identifier = Config.CEYE_DOMAIN
                self.is_configured = True
                logger.info("[OOB] 使用Ceye.io服务")
                return

        elif primary == 'dnslog' and Config.DNSLOG_TOKEN and Config.DNSLOG_DOMAIN:
            if self._check_service_health('dnslog'):
                self.service_type = 'dnslog'
                self.api_token = Config.DNSLOG_TOKEN
                self.domain_identifier = Config.DNSLOG_DOMAIN
                self.is_configured = True
                logger.info("[OOB] 使用DNS-log服务")
                return

        # Try fallback service if enabled
        if Config.OOB_FALLBACK_ENABLED:
            fallback = 'dnslog' if primary == 'ceye' else 'ceye'

            if fallback == 'ceye' and Config.CEYE_TOKEN and Config.CEYE_DOMAIN:
                if self._check_service_health('ceye'):
                    self.service_type = 'ceye'
                    self.api_token = Config.CEYE_TOKEN
                    self.domain_identifier = Config.CEYE_DOMAIN
                    self.is_configured = True
                    logger.warning("[OOB] 主服务不可用，使用备用服务Ceye.io")
                    return

            elif fallback == 'dnslog' and Config.DNSLOG_TOKEN and Config.DNSLOG_DOMAIN:
                if self._check_service_health('dnslog'):
                    self.service_type = 'dnslog'
                    self.api_token = Config.DNSLOG_TOKEN
                    self.domain_identifier = Config.DNSLOG_DOMAIN
                    self.is_configured = True
                    logger.warning("[OOB] 主服务不可用，使用备用服务DNS-log")
                    return

    def generate_payload(self):
        """
        每次发包前，生成一个唯一的子域名，用于精准追踪是哪个资产触发了漏洞
        例如: f8a9b2.xxxxx.ceye.io 或 f8a9b2.xxxxx.dnslog.cn

        Returns:
            tuple: (unique_id, oob_url) 或 (None, None) if not configured
        """
        if not self.is_configured:
            return None, None

        unique_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))

        if self.service_type == 'ceye':
            oob_url = f"{unique_id}.{self.domain_identifier}"
        elif self.service_type == 'dnslog':
            oob_url = f"{unique_id}.{self.domain_identifier}"
        else:
            return None, None

        return unique_id, oob_url

    def verify(self, unique_id: str) -> bool:
        """
        静默查询接口：去盲打平台看看，目标服务器有没有偷偷访问我们的域名
        支持Ceye.io和DNS-log服务

        Args:
            unique_id: 要查询的unique_id

        Returns:
            bool: 是否验证到回调
        """
        if not self.is_configured:
            logger.debug("[OOB] OOB未配置，跳过验证")
            return False

        if not unique_id:
            logger.debug("[OOB] unique_id为空，跳过验证")
            return False

        try:
            if self.service_type == 'ceye':
                return self._verify_ceye(unique_id)
            elif self.service_type == 'dnslog':
                return self._verify_dnslog(unique_id)
            else:
                return False

        except Exception as e:
            logger.error(f"[OOB] 验证异常: {type(e).__name__}: {e}")
            return False

    def _verify_ceye(self, unique_id: str) -> bool:
        """Verify callback on Ceye.io"""
        api_url = f"http://api.ceye.io/v1/records?token={self.api_token}&type=dns&filter={unique_id}"
        try:
            res = requests.get(api_url, timeout=5)
            res.raise_for_status()

            try:
                data = res.json()
            except json.JSONDecodeError as e:
                logger.warning(f"[OOB] Ceye API响应格式错误: {e}")
                return False

            if data.get('data'):
                logger.debug(f"[OOB] Ceye验证成功，检测到回调: {unique_id}")
                return True

            logger.debug(f"[OOB] Ceye未检测到回调: {unique_id}")
            return False

        except requests.exceptions.Timeout:
            logger.warning("[OOB] Ceye API查询超时 (5s)")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"[OOB] Ceye连接失败: {e}")
            return False
        except requests.exceptions.HTTPError as e:
            logger.warning(f"[OOB] Ceye HTTP错误: {e.response.status_code}")
            return False

    def _verify_dnslog(self, unique_id: str) -> bool:
        """Verify callback on DNS-log.cn"""
        api_url = f"http://api.dnslog.cn/query?token={self.api_token}&latest=true"
        try:
            res = requests.get(api_url, timeout=5)
            res.raise_for_status()

            try:
                data = res.json()
            except json.JSONDecodeError as e:
                logger.warning(f"[OOB] DNS-log API响应格式错误: {e}")
                return False

            # Check if unique_id appears in DNS records
            if isinstance(data, list):
                for record in data:
                    if isinstance(record, dict) and unique_id in record.get('subdomain', ''):
                        logger.debug(f"[OOB] DNS-log验证成功，检测到回调: {unique_id}")
                        return True

            logger.debug(f"[OOB] DNS-log未检测到回调: {unique_id}")
            return False

        except requests.exceptions.Timeout:
            logger.warning("[OOB] DNS-log API查询超时 (5s)")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"[OOB] DNS-log连接失败: {e}")
            return False
        except requests.exceptions.HTTPError as e:
            logger.warning(f"[OOB] DNS-log HTTP错误: {e.response.status_code}")
            return False