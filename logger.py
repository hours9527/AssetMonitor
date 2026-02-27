"""
统一日志管理系统
替代原有的 print() 输出
"""
import os
import logging
import logging.handlers
from config import Config


class LogManager:
    """日志管理器（单例模式）"""
    _instance = None
    _loggers = {}

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return

        self._initialized = True
        os.makedirs(Config.LOG_DIR, exist_ok=True)

    @staticmethod
    def get_logger(name: str) -> logging.Logger:
        """获取或创建logger"""
        if name in LogManager._loggers:
            return LogManager._loggers[name]

        # 确保日志目录存在
        os.makedirs(Config.LOG_DIR, exist_ok=True)

        logger = logging.getLogger(name)
        logger.setLevel(Config.LOG_LEVEL)

        # 避免重复处理
        if not logger.handlers:
            # 控制台处理器
            console_handler = logging.StreamHandler()
            console_handler.setLevel(Config.LOG_LEVEL)

            # 文件处理器（日志轮转）
            log_file = os.path.join(Config.LOG_DIR, f"{name}.log")
            file_handler = logging.handlers.RotatingFileHandler(
                log_file,
                maxBytes=Config.LOG_MAX_BYTES,
                backupCount=Config.LOG_BACKUP_COUNT,
                encoding='utf-8'
            )
            file_handler.setLevel(Config.LOG_LEVEL)

            # 格式化器
            formatter = logging.Formatter(Config.LOG_FORMAT)
            console_handler.setFormatter(formatter)
            file_handler.setFormatter(formatter)

            logger.addHandler(console_handler)
            logger.addHandler(file_handler)

        LogManager._loggers[name] = logger
        return logger


def get_logger(module_name: str) -> logging.Logger:
    """快速获取logger"""
    return LogManager.get_logger(module_name)


# 便捷别名
logger = get_logger("AssetMonitor")
