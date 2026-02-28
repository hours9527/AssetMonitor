"""
AssetMonitor 核心模块

统一导出常用的类、函数和常量，便于快速导入。
"""

__version__ = "2.1"
__author__ = "AssetMonitor Team"

# 数据模型
from core.models import (
    Asset,
    Vulnerability,
    Severity,
    VulnType,
    ScanResult,
)

# 数据库
from core.database import (
    get_db_manager,
    init_database,
)

# DI容器
from core.di_container import (
    DIContainer,
    initialize_di_container,
    get_di_container,
)

# 异常处理
from core.error_handler import (
    safe_execute,
    safe_execute_with_default,
    handle_exception,
    SafeDict,
    safe_json_load,
)

__all__ = [
    # 模型
    "Asset",
    "Vulnerability",
    "Severity",
    "VulnType",
    "ScanResult",
    # 数据库
    "get_db_manager",
    "init_database",
    # DI
    "DIContainer",
    "initialize_di_container",
    "get_di_container",
    # 错误处理
    "safe_execute",
    "safe_execute_with_default",
    "handle_exception",
    "SafeDict",
    "safe_json_load",
]
