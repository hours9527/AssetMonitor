"""
通知告警系统：多渠道、去重、限流
支持 Telegram/钉钉/企业微信/Email/自定义Webhook
"""
import requests
import json
import time
import hashlib
import smtplib
import threading
from typing import List, Dict, Optional
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from config import Config
from logger import get_logger

logger = get_logger("notify")


class NotificationDedup:
    """通知去重和限流（支持持久化，P3-05：内存上限保护）"""

    def __init__(self):
        """初始化去重管理"""
        # P3-05: 使用OrderedDict限制内存中的去重记录条数
        from collections import OrderedDict
        self.sent_notifications = OrderedDict()  # 内存缓存
        self.max_memory_entries = 10000  # 最多保留10000条内存记录
        self.rate_limiter = {"last_send": None, "count": 0}

        # 尝试使用数据库持久化
        self.use_db = False
        try:
            from core.database import get_db_manager
            self.db_manager = get_db_manager()
            self.use_db = True
            logger.debug("[*] 使用数据库进行通知去重")
        except Exception as e:
            logger.warning(f"[!] 无法使用数据库去重，回退到内存模式: {e}")
            self.db_manager = None

    def _hash_notification(self, domain: str, vuln_name: str) -> str:
        """计算通知哈希值（用于去重）"""
        key = f"{domain}_{vuln_name}"
        return hashlib.md5(key.encode()).hexdigest()

    def should_send(self, domain: str, vuln_name: str) -> bool:
        """判断是否应该发送通知（支持数据库和内存模式）"""
        notif_hash = self._hash_notification(domain, vuln_name)
        now = datetime.now()

        # ===== 去重检查 =====
        if self.use_db and self.db_manager:
            # 使用数据库进行持久化去重
            last_sent_str = self.db_manager.get_notification_time(notif_hash)
            if last_sent_str:
                try:
                    last_sent = datetime.fromisoformat(last_sent_str)
                    delta = now - last_sent
                    dedup_hours = Config.NOTIFY_DEDUP_HOURS

                    if delta.total_seconds() < dedup_hours * 3600:
                        logger.debug(
                            f"  [·] 通知已在数据库中,{delta.total_seconds():.0f}秒前发送过，跳过"
                        )
                        return False
                except Exception as e:
                    logger.warning(f"[!] 数据库去重检查失败: {e}")
        else:
            # 回退到内存模式
            if notif_hash in self.sent_notifications:
                last_send = self.sent_notifications[notif_hash]
                delta = now - last_send
                dedup_hours = Config.NOTIFY_DEDUP_HOURS

                if delta.total_seconds() < dedup_hours * 3600:
                    logger.debug(
                        f"  [·] 通知已在内存中,{delta.total_seconds():.0f}秒前发送过，跳过"
                    )
                    return False

        # ===== 限流检查 =====
        if self.rate_limiter["last_send"]:
            last_send = self.rate_limiter["last_send"]
            delta = now - last_send

            if delta.total_seconds() < 60:  # 每分钟统计
                self.rate_limiter["count"] += 1

                if self.rate_limiter["count"] > Config.NOTIFY_RATE_LIMIT:
                    logger.warning(
                        f"  [!] 通知频率过高 ({self.rate_limiter['count']}/{Config.NOTIFY_RATE_LIMIT})，跳过此条"
                    )
                    return False
            else:
                # 重置计数器
                self.rate_limiter["last_send"] = now
                self.rate_limiter["count"] = 1
        else:
            self.rate_limiter["last_send"] = now
            self.rate_limiter["count"] = 1

        # ===== 记录通知 =====
        if self.use_db and self.db_manager:
            # 数据库持久化
            try:
                self.db_manager.record_notification(notif_hash, domain, vuln_name)
                logger.debug(f"  [✓] 通知已记录到数据库: {vuln_name}")
            except Exception as e:
                logger.warning(f"[!] 记录通知失败: {e}")
                # 降级到内存
                self._add_to_memory(notif_hash, now)
        else:
            # 内存模式
            self._add_to_memory(notif_hash, now)

        return True

    def _add_to_memory(self, notif_hash: str, timestamp: datetime):
        """P3-05: 将通知添加到内存缓存，并维护上限"""
        self.sent_notifications[notif_hash] = timestamp

        # 如果超过上限，删除最旧的条目
        if len(self.sent_notifications) > self.max_memory_entries:
            oldest_key = next(iter(self.sent_notifications))
            del self.sent_notifications[oldest_key]
            logger.debug(f"  [*] 内存去重缓存已满，删除最旧条目，当前: {len(self.sent_notifications)}/{self.max_memory_entries}")


# 全局去重实例
dedup = NotificationDedup()


# ==========================================
# SMTP连接池（P3-04改进）
# ==========================================
class SMTPPool:
    """P3-04: SMTP连接池，避免频繁创建连接"""

    def __init__(self, host: str, port: int, user: str, password: str, pool_size: int = 2):
        """
        初始化SMTP连接池
        pool_size: 连接池大小，默认2个连接
        """
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.pool_size = pool_size
        self.connections = []
        self.available = []
        self._init_pool()

    def _init_pool(self):
        """初始化连接池"""
        for _ in range(self.pool_size):
            try:
                conn = smtplib.SMTP(self.host, self.port)
                conn.starttls()
                conn.login(self.user, self.password)
                self.connections.append(conn)
                self.available.append(True)
                logger.debug(f"[*] SMTP连接 #{len(self.connections)} 创建成功")
            except Exception as e:
                logger.warning(f"[-] SMTP连接创建失败: {e}")

    def get_connection(self) -> Optional[smtplib.SMTP]:
        """获取可用的SMTP连接"""
        for i, available in enumerate(self.available):
            if available:
                self.available[i] = False
                return self.connections[i]
        # 如果没有可用连接，尝试创建新连接（应急）
        try:
            conn = smtplib.SMTP(self.host, self.port)
            conn.starttls()
            conn.login(self.user, self.password)
            logger.debug("[!] SMTP应急创建额外连接")
            return conn
        except Exception as e:
            logger.error(f"[-] SMTP应急连接失败: {e}")
            return None

    def release_connection(self, conn: smtplib.SMTP):
        """释放连接回池"""
        if conn in self.connections:
            idx = self.connections.index(conn)
            self.available[idx] = True

    def close_all(self):
        """关闭所有连接"""
        for conn in self.connections:
            try:
                conn.quit()
            except:
                pass
        self.connections.clear()
        self.available.clear()

    def __del__(self):
        """析构时清理连接"""
        self.close_all()


# ==========================================
# 通知告警系统
# ==========================================
class NotificationChannel:
    """通知渠道基础类"""

    def send(self, title: str, content: str) -> bool:
        """发送通知，返回success/failure"""
        raise NotImplementedError


class ConsoleChannel(NotificationChannel):
    """控制台输出（内置）"""

    def send(self, title: str, content: str) -> bool:
        logger.info("\n" + "="*50)
        logger.info(f"📢 {title}")
        logger.info("="*50)
        logger.info(content)
        logger.info("="*50 + "\n")
        return True


class TelegramChannel(NotificationChannel):
    """Telegram机器人"""

    def __init__(self, token: str, chat_id: str):
        self.token = token
        self.chat_id = chat_id
        self.api_url = f"https://api.telegram.org/bot{token}/sendMessage"

    def send(self, title: str, content: str) -> bool:
        if not self.token or self.token.startswith("YOUR"):
            logger.warning("  [-] Telegram未配置，跳过")
            return False

        try:
            message = f"*{title}*\n\n{content}"
            payload = {
                "chat_id": self.chat_id,
                "text": message,
                "parse_mode": "Markdown"
            }
            response = requests.post(
                self.api_url,
                json=payload,
                timeout=10
            )
            if response.status_code == 200:
                logger.info("  [✓] Telegram通知已发送")
                return True
            else:
                logger.warning(f"  [-] Telegram API错误: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"  [-] Telegram发送失败: {e}")
            return False


class DingTalkChannel(NotificationChannel):
    """钉钉机器人"""

    def __init__(self, webhook: str, secret: str = ""):
        self.webhook = webhook
        self.secret = secret

    def send(self, title: str, content: str) -> bool:
        if not self.webhook or self.webhook.startswith("YOUR"):
            logger.warning("  [-] 钉钉未配置，跳过")
            return False

        try:
            message = {
                "msgtype": "markdown",
                "markdown": {
                    "title": title,
                    "text": content
                }
            }
            response = requests.post(
                self.webhook,
                json=message,
                timeout=10
            )
            if response.status_code == 200:
                logger.info("  [✓] 钉钉通知已发送")
                return True
            else:
                logger.warning(f"  [-] 钉钉API错误: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"  [-] 钉钉发送失败: {e}")
            return False


class WeChatChannel(NotificationChannel):
    """企业微信"""

    def __init__(self, webhook: str):
        self.webhook = webhook

    def send(self, title: str, content: str) -> bool:
        if not self.webhook or self.webhook.startswith("YOUR"):
            logger.warning("  [-] 企业微信未配置，跳过")
            return False

        try:
            message = {
                "msgtype": "markdown",
                "markdown": {
                    "content": f"**{title}**\n\n{content}"
                }
            }
            response = requests.post(
                self.webhook,
                json=message,
                timeout=10
            )
            if response.status_code == 200:
                logger.info("  [✓] 企业微信通知已发送")
                return True
            else:
                logger.warning(f"  [-] 企业微信API错误: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"  [-] 企业微信发送失败: {e}")
            return False


class EmailChannel(NotificationChannel):
    """P3-04: 邮件通知（使用SMTP连接池）"""

    def __init__(self, host: str, port: int, user: str, password: str, from_addr: str, to_addrs: List[str]):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.from_addr = from_addr
        self.to_addrs = to_addrs

        # P3-04: 初始化SMTP连接池
        self.smtp_pool = None
        if self.user and not self.user.startswith("YOUR"):
            try:
                # 使用Config中的SMTP_POOL_SIZE配置
                pool_size = Config.SMTP_POOL_SIZE if hasattr(Config, 'SMTP_POOL_SIZE') else 2
                self.smtp_pool = SMTPPool(host, port, user, password, pool_size=pool_size)
                logger.debug("[*] SMTP连接池初始化成功")
            except Exception as e:
                logger.warning(f"[-] SMTP连接池初始化失败: {e}")

    def send(self, title: str, content: str) -> bool:
        if not Config.EMAIL_ENABLED or not self.user:
            logger.warning("  [-] 邮件未配置，跳过")
            return False

        try:
            msg = MIMEMultipart()
            msg['From'] = self.from_addr
            msg['To'] = ','.join(self.to_addrs)
            msg['Subject'] = title
            msg.attach(MIMEText(content, 'html'))

            # P3-04: 使用连接池发送
            if self.smtp_pool:
                conn = self.smtp_pool.get_connection()
                if conn:
                    try:
                        conn.sendmail(self.from_addr, self.to_addrs, msg.as_string())
                        self.smtp_pool.release_connection(conn)
                        logger.info(f"  [✓] 邮件通知已发送到 {','.join(self.to_addrs)}")
                        return True
                    except Exception as e:
                        logger.error(f"  [-] 邮件发送失败: {e}")
                        # 连接出错，标记为不可用
                        self.smtp_pool.release_connection(conn)
                        return False
                else:
                    logger.error("  [-] 无可用SMTP连接")
                    return False
            else:
                # 备用方案：直接连接（低效但可靠）
                conn = smtplib.SMTP(self.host, self.port)
                try:
                    conn.starttls()
                    conn.login(self.user, self.password)
                    conn.sendmail(self.from_addr, self.to_addrs, msg.as_string())
                    logger.info(f"  [✓] 邮件通知已发送到 {','.join(self.to_addrs)}")
                    return True
                finally:
                    conn.quit()

        except Exception as e:
            logger.error(f"  [-] 邮件发送失败: {e}")
            return False


class WebhookChannel(NotificationChannel):
    """自定义Webhook"""

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, title: str, content: str) -> bool:
        try:
            payload = {
                "title": title,
                "content": content,
                "timestamp": datetime.now().isoformat()
            }
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=10
            )
            if response.status_code in [200, 201]:
                logger.info("  [✓] Webhook通知已发送")
                return True
            else:
                logger.warning(f"  [-] Webhook API错误: {response.status_code}")
                return False
        except Exception as e:
            logger.error(f"  [-] Webhook发送失败: {e}")
            return False


# ==========================================
# 通知管理器
# ==========================================
class NotificationManager:
    """统一通知管理"""

    def __init__(self):
        self.channels: Dict[str, NotificationChannel] = {}
        self._init_channels()

    def _init_channels(self):
        """初始化所有通知渠道"""
        if "console" in Config.NOTIFY_CHANNELS:
            self.channels["console"] = ConsoleChannel()

        if "telegram" in Config.NOTIFY_CHANNELS:
            self.channels["telegram"] = TelegramChannel(
                Config.TG_BOT_TOKEN,
                Config.TG_CHAT_ID
            )

        if "dingtalk" in Config.NOTIFY_CHANNELS:
            self.channels["dingtalk"] = DingTalkChannel(
                Config.DINGTALK_WEBHOOK,
                Config.DINGTALK_SECRET
            )

        if "wechat" in Config.NOTIFY_CHANNELS:
            self.channels["wechat"] = WeChatChannel(
                Config.WECHAT_WEBHOOK
            )

        if "email" in Config.NOTIFY_CHANNELS:
            self.channels["email"] = EmailChannel(
                Config.EMAIL_HOST,
                Config.EMAIL_PORT,
                Config.EMAIL_USER,
                Config.EMAIL_PASSWORD,
                Config.EMAIL_FROM,
                Config.EMAIL_TO
            )

    def send(self, title: str, content: str, domain: str = "", vuln_name: str = "") -> bool:
        """
        发送通知到所有配置的渠道
        """
        # 去重和限流检查
        if vuln_name and not dedup.should_send(domain, vuln_name):
            return False

        success_count = 0
        logger.info(f"\n[!] 发送告警通知: {title}")

        for channel_name, channel in self.channels.items():
            try:
                if channel.send(title, content):
                    success_count += 1
            except Exception as e:
                logger.error(f"  [-] {channel_name}发送失败: {e}")

        logger.info(f"[√] 通知发送完成 ({success_count}/{len(self.channels)}个渠道成功)")
        return success_count > 0


# 全局通知管理器
notify_manager = NotificationManager()


# ==========================================
# 兼容性函数
# ==========================================
def send_alert(target_domain: str, assets: List[Dict]):
    """
    原有API兼容函数
    """
    if not Config.NOTIFY_ENABLED or not assets:
        return

    # 过滤高价值资产
    high_value_assets = [
        a for a in assets
        if a.get('fingerprint', '') != "未知" and a.get('fingerprint', '') != ""
    ]

    if not high_value_assets:
        logger.info("\n[*] 本次扫描未发现高价值框架指纹，暂不发送通知")
        return

    # 构造内容
    title = f"🚨 {target_domain} 资产巡航高价值报警"

    content = f"### {target_domain} 资产巡航结果\n"
    content += f"**扫描时间**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    content += f"**发现资产**: {len(high_value_assets)} 个\n\n"

    content += "#### 高价值目标清单\n\n"
    for asset in high_value_assets[:10]:  # 最多显示10个
        content += f"- **{asset['url']}**\n"
        content += f"  - 状态: {asset['status']}\n"
        content += f"  - 指纹: `{asset['fingerprint']}`\n"
        content += f"  - 标题: {asset.get('title', '无')}\n\n"

    if len(high_value_assets) > 10:
        content += f"\n*...还有 {len(high_value_assets) - 10} 个资产，请登录系统查看*\n"

    # 处理漏洞
    all_vulns = []
    for asset in high_value_assets:
        all_vulns.extend(asset.get('vulns', []))

    if all_vulns:
        content += f"\n#### 发现漏洞\n\n"
        for vuln in all_vulns[:5]:
            content += f"- **{vuln['vuln_name']}** (严重等级: {vuln.get('severity', 'UNKNOWN')})\n"
            content += f"  URL: `{vuln.get('payload_url', 'N/A')}`\n\n"

            # 逐个漏洞发送通知（启用去重）
            notify_manager.send(
                title=f"💥 {vuln['vuln_name']}",
                content=f"找到漏洞: {asset['url']}\n{str(vuln)}",
                domain=target_domain,
                vuln_name=vuln['vuln_name']
            )

    # 发送综合报警
    notify_manager.send(
        title=title,
        content=content,
        domain=target_domain,
        vuln_name="asset_discovery"  # 作为去重标识
    )
