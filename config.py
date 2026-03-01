"""
统一配置管理模块
支持.env文件、环境变量覆盖和YAML配置文件
"""
import os
import yaml
from typing import Optional, Dict, Any
from pathlib import Path

# 加载 .env 文件
def _load_dotenv():
    """
    加载.env文件到环境变量（带有验证）
    仅允许白名单中的配置键，防止注入攻击
    """
    import re

    # 允许的配置键白名单
    ALLOWED_KEYS = {
        # 基础设置
        'THREADS', 'REQUEST_TIMEOUT', 'SMART_SLEEP_MIN', 'SMART_SLEEP_MAX',
        # 子域名收集
        'DNS_VERIFY', 'DNS_TIMEOUT',
        # POC配置
        'POC_TIMEOUT',
        # 熔断器
        'CIRCUIT_BREAKER_THRESHOLD', 'CIRCUIT_BREAKER_TIMEOUT',
        # 反检测
        'ENABLE_PROXY', 'PROXY_POOL',
        # OOB配置
        'OOB_ENABLED', 'OOB_PLATFORM', 'OOB_TIMEOUT', 'CEYE_TOKEN', 'CEYE_DOMAIN',
        'OOB_PRIMARY_SERVICE', 'OOB_FALLBACK_ENABLED', 'OOB_HEALTH_CHECK_INTERVAL',
        'DNSLOG_TOKEN', 'DNSLOG_DOMAIN',
        # 数据库
        'DB_FILE', 'DB_POOL_SIZE', 'DB_TIMEOUT',
        # 通知
        'NOTIFY_ENABLED', 'NOTIFY_CHANNELS',
        'TG_BOT_TOKEN', 'TG_CHAT_ID',
        'DINGTALK_WEBHOOK', 'DINGTALK_SECRET', 'WECHAT_WEBHOOK',
        'EMAIL_ENABLED', 'EMAIL_HOST', 'EMAIL_PORT', 'EMAIL_USER', 'EMAIL_PASSWORD', 'EMAIL_FROM', 'EMAIL_TO',
        'NOTIFY_DEDUP_HOURS', 'NOTIFY_RATE_LIMIT', 'DEDUP_EXPIRE_DAYS', 'SMTP_POOL_SIZE',
        # 输出
        'OUTPUT_DIR', 'HTML_REPORT',
        # 日志
        'LOG_LEVEL', 'LOG_DIR', 'LOG_MAX_BYTES', 'LOG_BACKUP_COUNT',
        # 断点续传
        'CHECKPOINT_ENABLED', 'CHECKPOINT_DIR', 'CHECKPOINT_AUTO_SAVE_INTERVAL',
        # SSL
        'VERIFY_SSL',
        # 高级选项
        'DRY_RUN', 'DEBUG'
    }

    env_file = Path(__file__).parent / ".env"
    if env_file.exists():
        try:
            with open(env_file, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    # 跳过空行和注释
                    if not line or line.startswith('#'):
                        continue
                    # 检查格式
                    if '=' not in line:
                        print(f"[!] .env 第 {line_num} 行格式错误，跳过")
                        continue

                    key, value = line.split('=', 1)
                    key = key.strip()
                    value = value.strip()

                    # 检查键是否在白名单中
                    if key not in ALLOWED_KEYS:
                        print(f"[!] 未知配置键被忽略: {key}")
                        continue

                    # 基础值验证（防止明显的恶意值）
                    if not value:
                        print(f"[!] 配置 {key} 的值为空，被忽略")
                        continue

                    # 检查值是否包含可疑的shell程序
                    if any(dangerous in value for dangerous in ['&&', '|', ';', '`', '$(']):
                        print(f"[!] 配置 {key} 包含可疑字符，被忽略")
                        continue

                    # 数值类型配置的验证
                    numeric_keys = {
                        'THREADS', 'REQUEST_TIMEOUT', 'SMART_SLEEP_MIN', 'SMART_SLEEP_MAX',
                        'DNS_TIMEOUT', 'POC_TIMEOUT', 'CIRCUIT_BREAKER_THRESHOLD',
                        'CIRCUIT_BREAKER_TIMEOUT', 'OOB_TIMEOUT', 'OOB_HEALTH_CHECK_INTERVAL',
                        'DB_POOL_SIZE', 'DB_TIMEOUT',
                        'LOG_MAX_BYTES', 'LOG_BACKUP_COUNT', 'CHECKPOINT_AUTO_SAVE_INTERVAL',
                        'NOTIFY_DEDUP_HOURS', 'NOTIFY_RATE_LIMIT', 'DEDUP_EXPIRE_DAYS',
                        'SMTP_POOL_SIZE', 'EMAIL_PORT'
                    }

                    if key in numeric_keys:
                        if not re.match(r'^-?\d+(\.\d+)?$', value):
                            print(f"[!] 配置 {key} 期望数值，得到: {value}")
                            continue

                    # 设置环境变量
                    os.environ.setdefault(key, value)
        except Exception as e:
            print(f"[!] 加载.env文件失败: {e}")

_load_dotenv()


class Config:
    """全局配置类"""

    # ==================== 基础设置 ====================
    PROJECT_NAME = "AssetMonitor"
    VERSION = "2.1"  # 更新到v2.1+ (含P3优化)

    # ==================== 扫描参数 ====================
    THREADS_DEFAULT = int(os.getenv("THREADS", "15"))
    REQUEST_TIMEOUT = int(os.getenv("REQUEST_TIMEOUT", "5"))
    SMART_SLEEP_MIN = float(os.getenv("SMART_SLEEP_MIN", "0.2"))
    SMART_SLEEP_MAX = float(os.getenv("SMART_SLEEP_MAX", "0.8"))

    # ==================== 子域名收集 ====================
    SUBDOMAIN_SOURCES = ["hackertarget", "crtsh", "alienvault", "rapiddns"]  # 增加更多源
    HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
    CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
    SUBDOMAIN_CACHE_HOURS = 12  # 子域名缓存时间
    DNS_VERIFY_ENABLED = os.getenv("DNS_VERIFY", "true").lower() == "true"
    DNS_TIMEOUT = int(os.getenv("DNS_TIMEOUT", "2"))  # P3-01: DNS查询超时（秒）

    # ==================== 探测配置 ====================
    WILDCARD_TEST_COUNT = 3  # 泛域名检测测试数
    WILDCARD_THRESHOLD = 500  # content_length偏差阈值
    MAX_REDIRECTS = 5  # 最大重定向跟踪数
    CERTIFICATE_INFO_ENABLED = True  # 提取证书信息
    VERIFY_SSL_CERTIFICATE = os.getenv("VERIFY_SSL", "false").lower() == "true"  # 验证SSL证书（默认关闭，可在.env开启）

    # ==================== POC引擎 ====================
    POC_TIMEOUT = int(os.getenv("POC_TIMEOUT", "3"))
    POC_CACHE_HOURS = 24  # POC结果缓存（避免重复测试）
    VULN_DEDUP_HOURS = 1  # 漏洞去重时间窗口
    POC_MAX_WORKERS = 3  # POC并发数

    # ==================== 熔断器配置 ====================
    CIRCUIT_BREAKER_FAILURE_THRESHOLD = int(os.getenv("CIRCUIT_BREAKER_THRESHOLD", "5"))  # 失败多少次后打开
    CIRCUIT_BREAKER_TIMEOUT = int(os.getenv("CIRCUIT_BREAKER_TIMEOUT", "300"))  # 熔断后多久尝试恢复（秒）

    # ==================== 反检测配置 ====================
    ENABLE_PROXY = os.getenv("ENABLE_PROXY", "false").lower() == "true"
    PROXY_POOL = os.getenv("PROXY_POOL", "").split(",") if os.getenv("PROXY_POOL") else []
    USER_AGENT_POOL_SIZE = 100  # UA池大小（将从实时源更新）
    REFERER_POOL = [
        "https://www.google.com/",
        "https://www.bing.com/",
        "https://duckduckgo.com/",
        "https://www.baidu.com/",
        "",  # 直接访问
    ]

    # ==================== OOB/盲打 ====================
    OOB_ENABLED = os.getenv("OOB_ENABLED", "false").lower() == "true"
    OOB_PLATFORM = os.getenv("OOB_PLATFORM", "ceye")  # ceye, dnslog, http-callbacks
    OOB_TIMEOUT = int(os.getenv("OOB_TIMEOUT", "15"))
    CEYE_TOKEN = os.getenv("CEYE_TOKEN", "")
    CEYE_DOMAIN = os.getenv("CEYE_DOMAIN", "")

    # OOB Service Fallback (M1 improvement)
    OOB_PRIMARY_SERVICE = os.getenv("OOB_PRIMARY_SERVICE", "ceye")  # ceye or dnslog
    OOB_FALLBACK_ENABLED = os.getenv("OOB_FALLBACK_ENABLED", "true").lower() == "true"
    OOB_HEALTH_CHECK_INTERVAL = int(os.getenv("OOB_HEALTH_CHECK_INTERVAL", "300"))  # seconds
    DNSLOG_TOKEN = os.getenv("DNSLOG_TOKEN", "")
    DNSLOG_DOMAIN = os.getenv("DNSLOG_DOMAIN", "")

    # ==================== 数据库配置 ====================
    DB_FILE = os.getenv("DB_FILE", "secbot_memory.db")
    DB_POOL_SIZE = int(os.getenv("DB_POOL_SIZE", str(max(10, THREADS_DEFAULT // 2))))  # 动态调整：至少10，约为线程数的一半
    DB_TIMEOUT = int(os.getenv("DB_TIMEOUT", "10"))

    # ==================== 通知配置 ====================
    NOTIFY_ENABLED = os.getenv("NOTIFY_ENABLED", "true").lower() == "true"
    NOTIFY_CHANNELS = os.getenv("NOTIFY_CHANNELS", "").split(",") or ["console"]

    # Telegram
    TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "")
    TG_CHAT_ID = os.getenv("TG_CHAT_ID", "")

    # DingTalk (钉钉)
    DINGTALK_WEBHOOK = os.getenv("DINGTALK_WEBHOOK", "")
    DINGTALK_SECRET = os.getenv("DINGTALK_SECRET", "")

    # WeChat (企业微信)
    WECHAT_WEBHOOK = os.getenv("WECHAT_WEBHOOK", "")

    # Email
    EMAIL_ENABLED = os.getenv("EMAIL_ENABLED", "false").lower() == "true"
    EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
    EMAIL_PORT = int(os.getenv("EMAIL_PORT", "587"))
    EMAIL_USER = os.getenv("EMAIL_USER", "")
    EMAIL_PASSWORD = os.getenv("EMAIL_PASSWORD", "")
    EMAIL_FROM = os.getenv("EMAIL_FROM", "")
    EMAIL_TO = os.getenv("EMAIL_TO", "").split(",") or []
    SMTP_POOL_SIZE = int(os.getenv("SMTP_POOL_SIZE", "2"))  # P3-04: SMTP连接池大小

    # 通知限流
    NOTIFY_DEDUP_HOURS = int(os.getenv("NOTIFY_DEDUP_HOURS", "1"))
    NOTIFY_RATE_LIMIT = int(os.getenv("NOTIFY_RATE_LIMIT", "10"))  # 每分钟最多推送数
    DEDUP_EXPIRE_DAYS = int(os.getenv("DEDUP_EXPIRE_DAYS", "7"))  # P3-03: 去重数据过期天数

    # ==================== 输出配置 ====================
    OUTPUT_DIR = os.getenv("OUTPUT_DIR", "data")
    OUTPUT_FORMATS = ["txt", "json", "csv"]  # 支持的格式
    HTML_REPORT_ENABLED = os.getenv("HTML_REPORT", "true").lower() == "true"

    # ==================== 日志配置 ====================
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    LOG_DIR = os.getenv("LOG_DIR", "logs")
    LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    LOG_MAX_BYTES = int(os.getenv("LOG_MAX_BYTES", "10485760"))  # 10MB
    LOG_BACKUP_COUNT = int(os.getenv("LOG_BACKUP_COUNT", "10"))

    # ==================== 断点续传配置 ====================
    CHECKPOINT_ENABLED = os.getenv("CHECKPOINT_ENABLED", "true").lower() == "true"
    CHECKPOINT_DIR = os.getenv("CHECKPOINT_DIR", "checkpoints")
    CHECKPOINT_AUTO_SAVE_INTERVAL = int(os.getenv("CHECKPOINT_AUTO_SAVE_INTERVAL", "300"))  # 每5分钟保存一次

    # ==================== 高级选项 ====================
    DRY_RUN = os.getenv("DRY_RUN", "false").lower() == "true"  # 测试模式
    DEBUG = os.getenv("DEBUG", "false").lower() == "true"

    @classmethod
    def load_from_yaml(cls, yaml_path: str) -> Dict[str, Any]:
        """从YAML文件加载配置"""
        if not os.path.exists(yaml_path):
            return {}

        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f) or {}

            # 环境变量覆盖YAML中的值
            for key, value in os.environ.items():
                if key.startswith("ASSET_"):
                    config_key = key[6:].lower()  # 去掉ASSET_前缀
                    config_data[config_key] = value

            return config_data
        except Exception as e:
            print(f"[!] 加载YAML配置失败: {e}")
            return {}

    @classmethod
    def to_dict(cls, include_secrets: bool = False) -> Dict[str, Any]:
        """
        将配置转为字典
        [修复] 默认不包含敏感信息，防止意外泄露

        Args:
            include_secrets: 是否包含敏感信息（令牌、密码等）

        Returns:
            配置字典
        """
        # 敏感键白名单 - 不应该在日志或调试输出中出现
        SENSITIVE_KEYS = {
            'CEYE_TOKEN', 'CEYE_DOMAIN',
            'TG_BOT_TOKEN', 'TG_CHAT_ID',
            'DINGTALK_WEBHOOK', 'DINGTALK_SECRET',
            'WECHAT_WEBHOOK',
            'EMAIL_PASSWORD', 'EMAIL_USER',
            'PROXY_POOL'
        }

        result = {}
        for k, v in cls.__dict__.items():
            if k.startswith('_') or not k.isupper():
                continue

            # 如果是敏感键且未明确请求，用***代替
            if k in SENSITIVE_KEYS and not include_secrets:
                result[k] = "***" if v else ""
            else:
                result[k] = v

        return result


# 快速访问
def get_config(key: str, default: Any = None) -> Any:
    """获取配置值"""
    return getattr(Config, key, default)


if __name__ == "__main__":
    # 打印当前配置（敏感信息白名单方式）
    print("当前配置:")
    SAFE_KEYS = {
        'PROJECT_NAME', 'VERSION', 'THREADS_DEFAULT', 'REQUEST_TIMEOUT',
        'WILDCARD_TEST_COUNT', 'WILDCARD_THRESHOLD', 'MAX_REDIRECTS',
        'POC_TIMEOUT', 'POC_CACHE_HOURS', 'VULN_DEDUP_HOURS', 'POC_MAX_WORKERS',
        'ENABLE_PROXY', 'USER_AGENT_POOL_SIZE', 'OOB_ENABLED', 'OOB_PLATFORM', 'OOB_TIMEOUT',
        'DB_FILE', 'DB_POOL_SIZE', 'DB_TIMEOUT',
        'NOTIFY_ENABLED', 'NOTIFY_CHANNELS', 'SMTP_POOL_SIZE',
        'NOTIFY_DEDUP_HOURS', 'NOTIFY_RATE_LIMIT', 'DEDUP_EXPIRE_DAYS',
        'OUTPUT_DIR', 'OUTPUT_FORMATS', 'HTML_REPORT_ENABLED',
        'LOG_LEVEL', 'LOG_DIR', 'LOG_MAX_BYTES', 'LOG_BACKUP_COUNT',
        'CHECKPOINT_ENABLED', 'CHECKPOINT_DIR', 'CHECKPOINT_AUTO_SAVE_INTERVAL',
        'DRY_RUN', 'DEBUG'
    }
    for key, value in Config.to_dict().items():
        if key in SAFE_KEYS:
            print(f"  {key}: {value}")
