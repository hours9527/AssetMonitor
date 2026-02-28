"""
依赖注入容器（DI Container）
统一管理所有全局对象和配置，替代全局变量
"""
from typing import Optional, Dict, Any, TYPE_CHECKING
from logger import get_logger

if TYPE_CHECKING:
    from core.database import DatabaseInitializer

logger = get_logger(__name__)


class DIContainer:
    """单例依赖注入容器"""

    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not DIContainer._initialized:
            self._services: Dict[str, Any] = {}
            DIContainer._initialized = True

    def register(self, name: str, factory=None, instance=None):
        """
        注册服务（工厂函数或实例）

        Args:
            name: 服务名称
            factory: 工厂函数（延迟初始化）
            instance: 直接注册实例（立即初始化）
        """
        if instance is not None:
            self._services[name] = {'type': 'instance', 'value': instance}
            logger.debug(f"[*] 注册服务实例: {name}")
        elif factory is not None:
            self._services[name] = {'type': 'factory', 'value': factory}
            logger.debug(f"[*] 注册服务工厂: {name}")
        else:
            raise ValueError(f"必须提供factory或instance")

    def get(self, name: str) -> Any:
        """
        获取服务实例（自动初始化）

        Args:
            name: 服务名称

        Returns:
            服务实例
        """
        if name not in self._services:
            raise KeyError(f"服务未注册: {name}")

        service = self._services[name]

        if service['type'] == 'instance':
            return service['value']
        elif service['type'] == 'factory':
            # 延迟初始化，并缓存result
            if '_initialized_value' not in service:
                service['_initialized_value'] = service['value']()
            return service['_initialized_value']

    def has(self, name: str) -> bool:
        """检查服务是否已注册"""
        return name in self._services

    def clear(self):
        """清除所有服务（测试时使用）"""
        self._services.clear()
        DIContainer._initialized = False


def initialize_di_container():
    """初始化DI容器并注册所有服务"""
    from config import Config

    container = DIContainer()

    # 注册数据库服务
    container.register('db', factory=lambda: initialize_database())

    # 注册Config实例
    container.register('config', instance=Config)

    logger.info("[✓] DI容器初始化完成")
    return container


def initialize_database() -> Optional["DatabaseInitializer"]:
    """初始化并返回数据库管理器"""
    try:
        from core.database import init_database
        db_manager = init_database()
        logger.info("[✓] 数据库连接池初始化成功")
        return db_manager
    except Exception as e:
        logger.error(f"[!] 数据库初始化失败: {e}")
        return None


def get_di_container() -> DIContainer:
    """获取DI容器实例"""
    return DIContainer()


def get_db_from_di() -> Optional["DatabaseInitializer"]:
    """便捷函数：从DI容器获取数据库实例"""
    container = get_di_container()
    return container.get('db')


def get_config_from_di():
    """便捷函数：从DI容器获取Config"""
    container = get_di_container()
    return container.get('config')
