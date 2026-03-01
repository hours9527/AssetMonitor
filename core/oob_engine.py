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
        企业级 OOB 盲打引擎 (基于 Ceye.io 架构)
        优先从 Config 读取配置
        """
        self.api_token = Config.CEYE_TOKEN or ""
        self.domain_identifier = Config.CEYE_DOMAIN or ""
        self.is_configured = bool(self.api_token and self.domain_identifier)

        if not self.is_configured:
            logger.warning("[OOB] Ceye.io未配置，OOB漏洞检测将被跳过")

    def generate_payload(self):
        """
        每次发包前，生成一个唯一的子域名，用于精准追踪是哪个资产触发了漏洞
        例如: f8a9b2.xxxxx.ceye.io
        """
        if not self.is_configured:
            return None, None

        unique_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        oob_url = f"{unique_id}.{self.domain_identifier}"
        return unique_id, oob_url

    def verify(self, unique_id: str) -> bool:
        """
        静默查询接口：去盲打平台看看，目标服务器有没有偷偷访问我们的域名
        [修复] 改进异常处理，明确区分各种错误情形

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

        api_url = f"http://api.ceye.io/v1/records?token={self.api_token}&type=dns&filter={unique_id}"
        try:
            res = requests.get(api_url, timeout=5)
            res.raise_for_status()  # 检查HTTP状态码

            try:
                data = res.json()
            except json.JSONDecodeError as e:
                logger.warning(f"[OOB] API响应格式错误（非JSON）: {e}")
                return False

            # 如果 data 数组有内容，说明服务器中招并向外发起了请求！
            if data.get('data'):
                logger.debug(f"[OOB] 验证成功，检测到OOB回调: {unique_id}")
                return True

            logger.debug(f"[OOB] 未检测到回调: {unique_id}")
            return False

        except requests.exceptions.Timeout:
            logger.warning("[OOB] API查询超时 (5s)")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"[OOB] 连接失败（无法访问Ceye API）: {e}")
            return False
        except requests.exceptions.HTTPError as e:
            logger.warning(f"[OOB] HTTP错误: {e.response.status_code}")
            return False
        except Exception as e:
            logger.error(f"[OOB] 未预期的异常: {type(e).__name__}: {e}")
            return False