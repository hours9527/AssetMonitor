"""
统一的异常处理工具模块
提供装饰器和工具函数，规范化异常处理逻辑
"""
import functools
import logging
from typing import Callable, Any, Optional, Type
from logger import get_logger

logger = get_logger("error_handler")


def safe_execute(func: Callable) -> Callable:
    """
    装饰器：统一的异常处理
    自动捕获并记录异常，而不是吞掉它们
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs) -> Any:
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.error(f"[!] {func.__name__}执行失败: {type(e).__name__}: {e}", exc_info=True)
            raise
    return wrapper


def safe_execute_with_default(default: Any = None) -> Callable:
    """
    装饰器：异常处理并返回默认值
    用于非关键操作，失败时返回默认值
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs) -> Any:
            try:
                return func(*args, **kwargs)
            except Exception as e:
                logger.warning(f"[!] {func.__name__}执行失败，返回默认值: {type(e).__name__}: {e}")
                return default
        return wrapper
    return decorator


def handle_exception(
    logger_obj,
    operation: str,
    exception: Exception,
    log_level: str = "error"
) -> None:
    """
    集中处理异常日志记录

    Args:
        logger_obj: logger实例（默认为全局logger）
        operation: 操作描述（如"数据库查询"）
        exception: 异常对象
        log_level: 日志级别（debug/info/warning/error/critical）
    """
    if logger_obj is None:
        logger_obj = logger

    exc_type = type(exception).__name__
    exc_msg = str(exception)
    message = f"[!] {operation}失败 ({exc_type}): {exc_msg}"

    log_func = getattr(logger_obj, log_level.lower(), logger_obj.error)
    log_func(message, exc_info=True)


class SafeDict(dict):
    """
    安全字典：访问不存在的键时返回空值而不是抛异常
    用于替代 except: pass 的模式
    """
    def __init__(self, *args, default_factory=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.default_factory = default_factory or (lambda: {})

    def __getitem__(self, key):
        try:
            return super().__getitem__(key)
        except KeyError:
            return self.default_factory()


def safe_json_load(file_path: str, logger_obj = None) -> dict:
    """
    安全加载JSON文件，失败时返回空字典

    Args:
        file_path: JSON文件路径
        logger_obj: logger实例（可选）

    Returns:
        字典对象，失败时返回空字典
    """
    import json
    import os

    if logger_obj is None:
        logger_obj = logger

    if not os.path.exists(file_path):
        logger_obj.warning(f"[!] 文件不存在: {file_path}")
        return {}

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger_obj.error(f"[!] JSON解析失败 ({file_path}): {e}")
        return {}
    except Exception as e:
        logger_obj.error(f"[!] 读取文件失败 ({file_path}): {type(e).__name__}: {e}")
        return {}
