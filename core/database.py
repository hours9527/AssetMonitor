"""
数据库管理层：连接池、事务管理、模型定义
解决sqlite3高并发和资源泄漏问题
"""
import sqlite3
import threading
import logging
from typing import Optional, List, Dict, Any, Callable
from contextlib import contextmanager
from config import Config

logger = logging.getLogger("database")


class DatabaseConnectionPool:
    """SQLite连接池管理（线程安全）"""

    def __init__(self, db_file: str = Config.DB_FILE, pool_size: int = Config.DB_POOL_SIZE):
        """
        初始化数据库连接池

        参数:
            db_file: 数据库文件路径
            pool_size: 最大连接数
        """
        self.db_file = db_file
        self.pool_size = pool_size
        self.connections = []
        self.available = []
        self.lock = threading.Lock()
        self.timeout = Config.DB_TIMEOUT

        # 初始化连接池
        self._init_pool()

    def _init_pool(self):
        """初始化连接池中的连接"""
        with self.lock:
            for _ in range(self.pool_size):
                try:
                    conn = sqlite3.connect(
                        self.db_file,
                        timeout=self.timeout,
                        check_same_thread=False  # 允许跨线程使用
                    )
                    self.connections.append(conn)
                    self.available.append(True)
                except Exception as e:
                    logger.error(f"[-] 创建数据库连接失败: {e}")

    @contextmanager
    def get_connection(self):
        """
        获取连接上下文管理器
        使用方式:
            with db_pool.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(...)
        """
        conn = None
        try:
            # 获取可用连接
            with self.lock:
                for i, available in enumerate(self.available):
                    if available:
                        self.available[i] = False
                        conn = self.connections[i]
                        break

            if conn is None:
                raise Exception("无可用数据库连接（连接池已满）")

            yield conn

        except Exception as e:
            logger.error(f"[-] 数据库操作错误: {e}")
            # 关键修复: 发生异常时回滚事务，防止脏连接回到连接池
            if conn:
                try:
                    conn.rollback()
                except Exception:
                    pass
            raise
        finally:
            # 归还连接
            if conn:
                with self.lock:
                    idx = self.connections.index(conn)
                    self.available[idx] = True

    def execute(self, query: str, params: tuple = ()) -> sqlite3.Cursor:
        """
        执行单条查询并自动提交

        参数:
            query: SQL语句
            params: 参数元组

        返回:
            cursor对象
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor

    def execute_many(self, query: str, seq: List[tuple]) -> None:
        """
        执行批量插入/更新

        参数:
            query: SQL语句
            seq: 参数列表
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(query, seq)
            conn.commit()

    def execute_transaction(self, func: Callable) -> Any:
        """
        执行事务（确保all-or-nothing）

        参数:
            func: 接收cursor的函数

        使用方式:
            def insert_data(cursor):
                cursor.execute("INSERT INTO ...", (...))
                cursor.execute("UPDATE ...", (...))
                return result

            result = db_pool.execute_transaction(insert_data)
        """
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                result = func(cursor)
                conn.commit()
                return result
            except Exception as e:
                conn.rollback()
                logger.error(f"[-] 事务执行失败: {e}")
                raise

    def fetchone(self, query: str, params: tuple = ()) -> Optional[tuple]:
        """获取单条结果"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchone()

    def fetchall(self, query: str, params: tuple = ()) -> List[tuple]:
        """获取所有结果"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor.fetchall()

    def close_all(self):
        """关闭所有连接"""
        with self.lock:
            for conn in self.connections:
                try:
                    conn.close()
                except Exception as e:
                    logger.warning(f"[-] 关闭连接失败: {e}")
            self.connections.clear()
            self.available.clear()

    def __del__(self):
        """析构时关闭所有连接"""
        self.close_all()


class DatabaseInitializer:
    """数据库初始化和模式管理"""

    def __init__(self, pool: DatabaseConnectionPool):
        self.pool = pool

    def init_db(self):
        """初始化数据库表"""
        logger.info("[*] 初始化数据库...")

        with self.pool.get_connection() as conn:
            cursor = conn.cursor()

            # 创建资产表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS assets (
                    url TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    status INTEGER,
                    fingerprint TEXT,
                    confidence REAL DEFAULT 0,
                    title TEXT,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 创建漏洞表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    vuln_hash TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    domain TEXT NOT NULL,
                    vuln_name TEXT NOT NULL,
                    vuln_type TEXT,
                    severity TEXT,
                    payload_url TEXT,
                    confidence REAL DEFAULT 0,
                    alert_sent INTEGER DEFAULT 0,
                    discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(url) REFERENCES assets(url)
                )
            ''')

            # 创建通知去重表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS notification_history (
                    notif_hash TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    vuln_name TEXT NOT NULL,
                    last_sent DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # 创建扫描历史表
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    scan_id TEXT PRIMARY KEY,
                    domain TEXT NOT NULL,
                    started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    completed_at DATETIME,
                    status TEXT,
                    total_subdomains INTEGER,
                    alive_assets INTEGER,
                    vulnerabilities INTEGER
                )
            ''')

            # 创建索引（加速查询）
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain ON assets(domain)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_url ON assets(url)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_url ON vulnerabilities(url)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_vuln_domain ON vulnerabilities(domain)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_notif_hash ON notification_history(notif_hash)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_scan_domain ON scan_history(domain)')

            conn.commit()

        logger.info("[✓] 数据库初始化完成")

    def add_asset(self, url: str, domain: str, status: int, fingerprint: str, confidence: float, title: str) -> bool:
        """添加或更新资产"""
        def _insert(cursor):
            cursor.execute('''
                INSERT OR REPLACE INTO assets
                (url, domain, status, fingerprint, confidence, title, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ''', (url, domain, status, fingerprint, confidence, title))
            return cursor.lastrowid

        try:
            result = self.pool.execute_transaction(_insert)
            return result > 0
        except Exception as e:
            logger.error(f"[-] 添加资产失败: {e}")
            return False

    def add_vulnerability(self, vuln_hash: str, url: str, domain: str, vuln_data: Dict[str, Any]) -> bool:
        """添加漏洞"""
        def _insert(cursor):
            cursor.execute('''
                INSERT OR IGNORE INTO vulnerabilities
                (vuln_hash, url, domain, vuln_name, vuln_type, severity, payload_url, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln_hash,
                url,
                domain,
                vuln_data.get('vuln_name', ''),
                vuln_data.get('type', 'Unknown'),
                vuln_data.get('severity', 'UNKNOWN'),
                vuln_data.get('payload_url', ''),
                vuln_data.get('confidence', 0)
            ))
            return cursor.rowcount

        try:
            result = self.pool.execute_transaction(_insert)
            return result > 0
        except Exception as e:
            logger.error(f"[-] 添加漏洞失败: {e}")
            return False

    def record_notification(self, notif_hash: str, domain: str, vuln_name: str) -> bool:
        """记录已发送的通知"""
        try:
            self.pool.execute('''
                INSERT OR REPLACE INTO notification_history
                (notif_hash, domain, vuln_name, last_sent)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ''', (notif_hash, domain, vuln_name))
            return True
        except Exception as e:
            logger.error(f"[-] 记录通知失败: {e}")
            return False

    def get_notification_time(self, notif_hash: str) -> Optional[str]:
        """获取通知最后发送时间"""
        try:
            result = self.pool.fetchone(
                'SELECT last_sent FROM notification_history WHERE notif_hash=?',
                (notif_hash,)
            )
            return result[0] if result else None
        except Exception as e:
            logger.error(f"[-] 查询通知时间失败: {e}")
            return None

    def start_scan(self, scan_id: str, domain: str) -> bool:
        """记录扫描开始"""
        try:
            self.pool.execute('''
                INSERT INTO scan_history
                (scan_id, domain, status)
                VALUES (?, ?, 'started')
            ''', (scan_id, domain))
            return True
        except Exception as e:
            logger.error(f"[-] 记录扫描开始失败: {e}")
            return False

    def complete_scan(self, scan_id: str, total_subs: int, alive: int, vulns: int) -> bool:
        """记录扫描完成"""
        try:
            self.pool.execute('''
                UPDATE scan_history
                SET status='completed',
                    completed_at=CURRENT_TIMESTAMP,
                    total_subdomains=?,
                    alive_assets=?,
                    vulnerabilities=?
                WHERE scan_id=?
            ''', (total_subs, alive, vulns, scan_id))
            return True
        except Exception as e:
            logger.error(f"[-] 记录扫描完成失败: {e}")
            return False


# 全局数据库实例
_db_pool: Optional[DatabaseConnectionPool] = None
_db_manager: Optional[DatabaseInitializer] = None


def init_database() -> DatabaseInitializer:
    """初始化全局数据库连接池"""
    global _db_pool, _db_manager

    if _db_pool is None:
        _db_pool = DatabaseConnectionPool()
        _db_manager = DatabaseInitializer(_db_pool)
        _db_manager.init_db()

    return _db_manager


def get_db_manager() -> DatabaseInitializer:
    """获取全局数据库管理器"""
    if _db_manager is None:
        raise RuntimeError("数据库未初始化，请先调用 init_database()")
    return _db_manager


def get_db_pool() -> DatabaseConnectionPool:
    """获取全局数据库连接池"""
    if _db_pool is None:
        raise RuntimeError("数据库未初始化，请先调用 init_database()")
    return _db_pool
