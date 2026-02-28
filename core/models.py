"""
数据模型定义模块
提供统一的数据结构和验证，替代混乱的dict定义
"""
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from enum import Enum
from datetime import datetime


class Severity(Enum):
    """漏洞严重程度枚举"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def _missing_(cls, value):
        """处理无效的严重程度值"""
        if isinstance(value, str):
            value = value.upper()
            for member in cls:
                if member.value == value:
                    return member
        return cls.UNKNOWN


class VulnType(Enum):
    """漏洞类型枚举"""
    INFORMATION_DISCLOSURE = "Information Disclosure"
    AUTHENTICATION_BYPASS = "Authentication Bypass"
    REMOTE_CODE_EXECUTION = "Remote Code Execution"
    SQL_INJECTION = "SQL Injection"
    CROSS_SITE_SCRIPTING = "Cross Site Scripting"
    WEAK_CONFIGURATION = "Weak Configuration"
    UNKNOWN = "Unknown"

    @classmethod
    def _missing_(cls, value):
        """处理无效的漏洞类型"""
        if isinstance(value, str):
            for member in cls:
                if member.value.lower() == value.lower():
                    return member
        return cls.UNKNOWN


@dataclass
class Vulnerability:
    """
    漏洞数据模型

    Attributes:
        vuln_name: 漏洞名称 (如: "Spring Boot Actuator Exposure")
        payload_url: 验证URL或payload地址
        severity: 严重程度 (CRITICAL/HIGH/MEDIUM/LOW)
        vuln_type: 漏洞类型 (枚举类型)
        discovered_at: 发现时间 (ISO8601格式)
        confidence: 置信度 (0.0-1.0)
        description: 漏洞描述 (可选)
    """
    vuln_name: str
    payload_url: str
    severity: Severity
    vuln_type: VulnType
    discovered_at: str
    confidence: float = 0.8
    description: Optional[str] = None

    def validate(self) -> tuple[bool, str]:
        """
        验证漏洞数据有效性

        Returns:
            (is_valid, error_message)
        """
        if not self.vuln_name or len(self.vuln_name) == 0:
            return False, "vuln_name cannot be empty"

        if not self.payload_url or len(self.payload_url) == 0:
            return False, "payload_url cannot be empty"

        if not (0.0 <= self.confidence <= 1.0):
            return False, f"confidence must be between 0.0 and 1.0, got {self.confidence}"

        # 验证时间格式
        try:
            datetime.fromisoformat(self.discovered_at)
        except (ValueError, TypeError):
            return False, f"discovered_at must be ISO8601 format, got {self.discovered_at}"

        return True, ""

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式（用于JSON序列化）"""
        return {
            "vuln_name": self.vuln_name,
            "payload_url": self.payload_url,
            "severity": self.severity.value,
            "vuln_type": self.vuln_type.value,
            "discovered_at": self.discovered_at,
            "confidence": self.confidence,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Vulnerability":
        """从字典构建漏洞对象"""
        return cls(
            vuln_name=data.get("vuln_name", ""),
            payload_url=data.get("payload_url", ""),
            severity=Severity(data.get("severity", "UNKNOWN")),
            vuln_type=VulnType(data.get("vuln_type", "Unknown")),
            discovered_at=data.get("discovered_at", datetime.now().isoformat()),
            confidence=float(data.get("confidence", 0.8)),
            description=data.get("description"),
        )


@dataclass
class Asset:
    """
    资产数据模型

    Attributes:
        url: 资产URL (如: http://example.com)
        status: HTTP状态码 (100-599)
        fingerprint: 应用指纹识别结果 (如: "Nginx 1.18")
        confidence: 指纹置信度 (0.0-1.0)
        title: 页面标题
        vulns: 发现的漏洞列表
        first_seen: 首次发现时间 (ISO8601)
        last_seen: 最后发现时间 (ISO8601)
        response_time: 响应时间(毫秒)
    """
    url: str
    status: int
    fingerprint: str
    confidence: float
    title: str
    vulns: List[Vulnerability] = field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    response_time: Optional[int] = None

    def __post_init__(self):
        """数据初始化后的验证"""
        is_valid, error = self.validate()
        if not is_valid:
            raise ValueError(f"Invalid Asset: {error}")

        # 如果没有时间戳，设置为当前时间
        if self.first_seen is None:
            self.first_seen = datetime.now().isoformat()
        if self.last_seen is None:
            self.last_seen = self.first_seen

    def validate(self) -> tuple[bool, str]:
        """
        验证资产数据有效性

        Returns:
            (is_valid, error_message)
        """
        if not self.url or len(self.url) == 0:
            return False, "url cannot be empty"

        if not (100 <= self.status < 600):
            return False, f"status must be 100-599, got {self.status}"

        if not (0.0 <= self.confidence <= 1.0):
            return False, f"confidence must be 0.0-1.0, got {self.confidence}"

        if not self.title:
            self.title = "(untitled)"

        # 验证所有漏洞
        for vuln in self.vulns:
            is_valid, error = vuln.validate()
            if not is_valid:
                return False, f"Invalid vulnerability: {error}"

        return True, ""

    def add_vulnerability(self, vuln: Vulnerability) -> None:
        """
        添加漏洞

        Args:
            vuln: Vulnerability实例

        Raises:
            ValueError: 如果漏洞无效
        """
        is_valid, error = vuln.validate()
        if not is_valid:
            raise ValueError(f"Cannot add invalid vulnerability: {error}")

        # 检查是否已存在（避免重复）
        for existing in self.vulns:
            if (existing.vuln_name == vuln.vuln_name and
                existing.payload_url == vuln.payload_url):
                return  # 已存在，跳过

        self.vulns.append(vuln)
        self.last_seen = datetime.now().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "url": self.url,
            "status": self.status,
            "fingerprint": self.fingerprint,
            "confidence": self.confidence,
            "title": self.title,
            "vulns": [v.to_dict() for v in self.vulns],
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "response_time": self.response_time,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Asset":
        """从字典构建资产对象"""
        vulns = [
            Vulnerability.from_dict(v)
            for v in data.get("vulns", [])
        ]
        return cls(
            url=data.get("url", ""),
            status=int(data.get("status", 200)),
            fingerprint=data.get("fingerprint", "Unknown"),
            confidence=float(data.get("confidence", 0.0)),
            title=data.get("title", ""),
            vulns=vulns,
            first_seen=data.get("first_seen"),
            last_seen=data.get("last_seen"),
            response_time=data.get("response_time"),
        )

    @property
    def has_vulnerabilities(self) -> bool:
        """是否有漏洞"""
        return len(self.vulns) > 0

    @property
    def critical_vulns_count(self) -> int:
        """严重漏洞数量"""
        return sum(1 for v in self.vulns if v.severity == Severity.CRITICAL)

    @property
    def high_vulns_count(self) -> int:
        """高危漏洞数量"""
        return sum(1 for v in self.vulns if v.severity == Severity.HIGH)


@dataclass
class ScanResult:
    """
    扫描结果数据模型

    Attributes:
        scan_id: 扫描ID (唯一)
        target_domain: 目标主域名
        timestamp: 扫描时间
        subdomains: 发现的子域名
        alive_assets: 存活资产
        total_vulns: 总漏洞数
    """
    scan_id: str
    target_domain: str
    timestamp: str
    subdomains: List[str] = field(default_factory=list)
    alive_assets: List[Asset] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            "scan_id": self.scan_id,
            "target_domain": self.target_domain,
            "timestamp": self.timestamp,
            "subdomains": self.subdomains,
            "alive_assets": [a.to_dict() for a in self.alive_assets],
            "total_vulns": self.total_vulns_count,
        }

    @property
    def total_vulns_count(self) -> int:
        """获取总漏洞数"""
        return sum(len(asset.vulns) for asset in self.alive_assets)

    @property
    def total_assets_count(self) -> int:
        """获取总资产数"""
        return len(self.alive_assets)
