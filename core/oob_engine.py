import requests
import random
import string
import time
from config import Config
from logger import get_logger

logger = get_logger("oob_engine")


class OOBEngine:
    def __init__(self):
        """
        企业级 OOB 盲打引擎 (基于 Ceye.io 架构)
        优先从 Config 读取配置
        """
        self.api_token = Config.CEYE_TOKEN or "YOUR_CEYE_TOKEN"
        self.domain_identifier = Config.CEYE_DOMAIN or "YOUR_IDENTIFIER.ceye.io"

    def generate_payload(self):
        """
        每次发包前，生成一个唯一的子域名，用于精准追踪是哪个资产触发了漏洞
        例如: f8a9b2.xxxxx.ceye.io
        """
        unique_id = ''.join(random.choices(string.ascii_lowercase + string.digits, k=6))
        oob_url = f"{unique_id}.{self.domain_identifier}"
        return unique_id, oob_url

    def verify(self, unique_id):
        """
        静默查询接口：去盲打平台看看，目标服务器有没有偷偷访问我们的域名
        """
        if self.api_token == "YOUR_CEYE_TOKEN" or not self.api_token:
            # 如果没配置真实 Token，直接返回 False 防报错
            logger.warning("[OOB] 未配置真实 Ceye API，跳过无回显漏洞验证。")
            return False

        api_url = f"http://api.ceye.io/v1/records?token={self.api_token}&type=dns&filter={unique_id}"
        try:
            res = requests.get(api_url, timeout=5).json()
            # 如果 data 数组有内容，说明服务器中招并向外发起了请求！
            if res.get('data'):
                return True
        except Exception:
            pass
        return False