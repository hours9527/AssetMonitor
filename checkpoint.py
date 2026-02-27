"""
断点续传系统
支持中断后继续扫描，避免重复工作
新增：批处理优化（P3-02）减少I/O次数
"""
import os
import json
import hashlib
import time
from datetime import datetime
from typing import Set, Dict, List
from config import Config
from logger import get_logger

logger = get_logger("checkpoint")


class CheckpointManager:
    """检查点管理器"""

    def __init__(self, scan_id: str):
        """
        初始化检查点管理器
        scan_id: 扫描任务ID (通常是domain_timestamp)
        """
        self.scan_id = scan_id
        self.checkpoint_dir = Config.CHECKPOINT_DIR
        os.makedirs(self.checkpoint_dir, exist_ok=True)

        self.checkpoint_file = os.path.join(
            self.checkpoint_dir,
            f"{scan_id}.checkpoint.json"
        )

        self.data = self._load_checkpoint()

        # P3-02: 批处理缓冲机制
        self.pending_saves = 0
        self.last_save_time = time.time()
        self.batch_threshold = 10  # 每10个更新批处理一次
        self.time_threshold = 10   # 或每10秒批处理一次

    def _load_checkpoint(self) -> Dict:
        """加载已保存的检查点"""
        if os.path.exists(self.checkpoint_file):
            try:
                with open(self.checkpoint_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                logger.info(f"[√] 加载检查点: {self.scan_id}")
                return data
            except Exception as e:
                logger.warning(f"[-] 检查点加载失败: {e}，创建新检查点")
                return self._init_checkpoint()
        else:
            return self._init_checkpoint()

    def _init_checkpoint(self) -> Dict:
        """初始化新检查点"""
        return {
            "scan_id": self.scan_id,
            "started_at": datetime.now().isoformat(),
            "last_updated": datetime.now().isoformat(),
            "stages": {
                "subdomain_collection": {"status": "pending", "count": 0, "items": []},
                "wildcard_detection": {"status": "pending", "data": None},
                "probing": {"status": "pending", "count": 0, "items": []},
                "poc_testing": {"status": "pending", "count": 0, "vulns": []},
            },
            "results": {
                "subdomains": [],
                "alive_assets": [],
                "vulnerabilities": []
            }
        }

    def save(self, force: bool = False):
        """
        保存检查点到文件（支持批处理）
        force: True时立即保存，False时使用批处理缓冲
        """
        if not Config.CHECKPOINT_ENABLED:
            return

        self.data["last_updated"] = datetime.now().isoformat()

        # P3-02: 批处理逻辑
        self.pending_saves += 1
        current_time = time.time()

        # 判断是否需要保存
        should_save = (
            force or
            self.pending_saves >= self.batch_threshold or
            (current_time - self.last_save_time) >= self.time_threshold
        )

        if not should_save:
            return

        # 执行文件写入
        try:
            with open(self.checkpoint_file, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
            logger.debug(f"[√] 检查点已保存 (批处理: {self.pending_saves}个更新)")
            self.pending_saves = 0
            self.last_save_time = current_time
        except Exception as e:
            logger.error(f"[-] 保存检查点失败: {e}")

    def mark_stage_started(self, stage: str):
        """标记某个阶段开始"""
        if stage in self.data["stages"]:
            self.data["stages"][stage]["status"] = "in_progress"
            self.save()

    def mark_stage_completed(self, stage: str):
        """标记某个阶段完成"""
        if stage in self.data["stages"]:
            self.data["stages"][stage]["status"] = "completed"
            self.save(force=True)  # 强制保存以确保阶段状态持久化

    def add_subdomain(self, subdomain: str, source: str):
        """添加发现的子域名"""
        if subdomain not in self.data["results"]["subdomains"]:
            self.data["results"]["subdomains"].append(subdomain)
            self.data["stages"]["subdomain_collection"]["count"] += 1
            self.save()

    def get_pending_subdomains(self) -> List[str]:
        """获取还未探测的子域名"""
        all_subs = set(self.data["results"]["subdomains"])
        probed_subs = set(
            item["url"].split("://")[1].split("/")[0]
            for item in self.data["results"]["alive_assets"]
        )
        return list(all_subs - probed_subs)

    def add_alive_asset(self, asset: Dict):
        """添加发现的存活资产"""
        url = asset["url"]
        # 检查是否已存在
        if not any(a["url"] == url for a in self.data["results"]["alive_assets"]):
            self.data["results"]["alive_assets"].append(asset)
            self.data["stages"]["probing"]["count"] += 1
            self.save()

    def add_vulnerability(self, vuln: Dict):
        """添加发现的漏洞"""
        vuln_hash = self._hash_vuln(vuln)
        if not any(
            self._hash_vuln(v) == vuln_hash
            for v in self.data["results"]["vulnerabilities"]
        ):
            self.data["results"]["vulnerabilities"].append(vuln)
            self.data["stages"]["poc_testing"]["count"] += 1
            self.save()

    @staticmethod
    def _hash_vuln(vuln: Dict) -> str:
        """计算漏洞哈希值（用于去重）"""
        key = f"{vuln.get('url', '')}_{vuln.get('vuln_name', '')}"
        return hashlib.md5(key.encode()).hexdigest()

    def set_wildcard_signature(self, signature: Dict):
        """保存泛域名签名"""
        self.data["stages"]["wildcard_detection"]["data"] = signature
        self.save(force=True)  # 强制保存以确保签名不丢失

    def get_wildcard_signature(self) -> Dict:
        """获取泛域名签名"""
        return self.data["stages"]["wildcard_detection"]["data"]

    def is_stage_completed(self, stage: str) -> bool:
        """判断某个阶段是否已完成"""
        return self.data["stages"].get(stage, {}).get("status") == "completed"

    def get_results(self) -> Dict:
        """获取最终结果"""
        return self.data["results"]

    def cleanup(self):
        """清理检查点文件（扫描完成后）"""
        if os.path.exists(self.checkpoint_file):
            try:
                os.remove(self.checkpoint_file)
                logger.info(f"[√] 检查点已清理: {self.scan_id}")
            except Exception as e:
                logger.error(f"[-] 清理检查点失败: {e}")


class DedupManager:
    """去重管理器（避免重复扫描相同目标，P3-03：支持自动过期）"""

    def __init__(self):
        self.db_file = os.path.join(Config.CHECKPOINT_DIR, "dedup.json")
        os.makedirs(Config.CHECKPOINT_DIR, exist_ok=True)
        self.data = self._load()
        # P3-03: 使用Config中的DEDUP_EXPIRE_DAYS配置
        self.dedup_days = Config.DEDUP_EXPIRE_DAYS if hasattr(Config, 'DEDUP_EXPIRE_DAYS') else 7

    def _load(self) -> Dict[str, Dict]:
        """加载去重数据库"""
        if os.path.exists(self.db_file):
            try:
                with open(self.db_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except:
                return {}
        return {}

    def _save(self):
        """保存去重数据库"""
        try:
            with open(self.db_file, 'w', encoding='utf-8') as f:
                json.dump(self.data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            logger.error(f"[-] 保存去重表失败: {e}")

    def cleanup_expired(self, days: int = None):
        """
        P3-03: 清理过期的去重数据（防止无限增长）
        days: 多少天前的数据视为过期，默认为init时的设置值
        """
        if days is None:
            days = self.dedup_days

        from datetime import timedelta
        cutoff_time = datetime.now() - timedelta(days=days)
        expired_domains = []

        for domain, timestamp_str in self.data.items():
            try:
                record_time = datetime.fromisoformat(timestamp_str)
                if record_time < cutoff_time:
                    expired_domains.append(domain)
            except (ValueError, TypeError):
                # 无法解析时间戳，删除该条目
                expired_domains.append(domain)

        if expired_domains:
            for domain in expired_domains:
                del self.data[domain]
            self._save()
            logger.info(f"[*] Dedup清理: 删除 {len(expired_domains)} 条过期记录 (>={days}天)")

    def mark_scanned(self, domain: str):
        """标记域名已扫描"""
        self.data[domain] = datetime.now().isoformat()
        self._save()

    def is_scanned(self, domain: str) -> bool:
        """判断域名是否已扫描过"""
        return domain in self.data

    def mark_probed(self, url: str):
        """标记URL已探测"""
        key = f"url_{url}"
        self.data[key] = datetime.now().isoformat()
        self._save()

    def is_probed(self, url: str) -> bool:
        """判断URL是否已探测过"""
        key = f"url_{url}"
        return key in self.data

    def clear(self):
        """清空去重表"""
        self.data = {}
        self._save()
