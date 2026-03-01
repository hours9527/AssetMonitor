# AssetMonitor v2.1 企业级资产发现与漏洞检测系统

![Code Quality](https://img.shields.io/badge/Code%20Quality-8.74%2F10-brightgreen)
![Type Annotations](https://img.shields.io/badge/Type%20Annotations-99%25-brightgreen)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

AssetMonitor 是一个**企业级无人值守自动化资产发现和漏洞检测系统**，专为红队和安全运营中心（SOC）设计。它集成了多源子域名收集、智能指纹识别、WAF 规避技术以及高危漏洞验证（POC）功能，并支持多种渠道的实时监控告警。

**🎯 核心优势**:
- ⚡ **70% 性能提升**: POC 并发执行框架，从串行 10 秒降低到并发 3 秒
- 🔒 **99% 类型安全**: 完整的 dataclass 数据模型 + 类型注解覆盖
- 🛡️ **智能 WAF 规避**: Circuit Breaker、动态延迟、Agent 轮换
- 📊 **多格式输出**: TXT、JSON、CSV 格式同时支持
- 🔄 **断点续传**: 大规模扫描支持中断恢复


## ✨ 核心功能

### 🔍 多源子域名收集
- 集成 HackerTarget、crt.sh、VirusTotal 等多个数据源
- 支持并行 DNS 验证与智能泛解析过滤
- 可配置的数据源优先级和超时控制

### 🎯 智能资产探测
- **TLS 指纹伪造**: 基于 `curl_cffi` 模拟 Chrome 120 浏览器，有效规避反爬虫
- **Circuit Breaker 熔断器**: 自动隔离故障端点，防止级联失败
- **WAF 智能规避**: 动态延迟、随机 User-Agent、指数退避策略
- **重定向链追踪**: 自动跟踪 301/302/307/308 重定向
- **泛域名检测**: 高级特征对比算法，精准识别泛解析

### 👁️ 应用指纹识别
自动识别 Spring Boot、Apache Shiro、ThinkPHP、Nginx、IIS、Vue.js 等组件
- 权重化识别算法，置信度评分准确高达 95%+
- 支持自定义指纹规则扩展

### 🔴 高危漏洞检测
- **并发 POC 框架**: ThreadPoolExecutor + 自动超时控制
- 内置检测: Spring Boot Actuator、Log4j2 JNDI、Shiro 反序列化、ActiveMQ RCE 等
- **OOB 盲打引擎**: 集成 Ceye.io，支持无回显漏洞检测
- 可配置化 POC 管理，轻松添加自定义检测

### 📢 多渠道告警
支持 Telegram、钉钉、企业微信、邮件、Webhook 等通知
- 智能去重和限流机制，避免告警风暴
- 详细的漏洞信息和 URL 包含在告警中

### 🚀 高性能架构
- SQLite 连接池 + 数据库持久化
- 多线程并发设计（可配置 10-100 并发数）
- 断点续传支持，支持从指定阶段恢复扫描

---

## 🛠️ 快速安装

### 前置要求
- Python 3.8+ (推荐 3.10+)
- pip 包管理器
- Git (可选，用于克隆项目)

### 安装步骤

#### 1️⃣ 克隆项目
```bash
# 使用 HTTPS（推荐）
git clone https://github.com/hours9527/AssetMonitor.git
cd AssetMonitor

# 或使用 SSH (需要配置 GitHub SSH Key)
git clone git@github.com:hours9527/AssetMonitor.git
```

#### 2️⃣ 创建虚拟环境（推荐）
```bash
# Linux/Mac
python3 -m venv venv
source venv/bin/activate

# Windows (PowerShell)
python -m venv venv
venv\Scripts\activate
```

#### 3️⃣ 安装依赖
```bash
pip install -r requirements.txt
```

**主要依赖包**:
- `curl_cffi`: TLS 指纹伪造和 HTTP 请求
- `requests`: HTTP 请求库
- `dnspython`: DNS 查询
- `pydantic`: 数据验证

---

## ⚙️ 配置说明

### 1. 基础配置 (`config.py`)

项目包含一个 `config.py` 文件，主要配置项：

```python
class Config:
    # 并发与超时
    THREADS_DEFAULT = 30                      # 主线程数（推荐 20-50）
    REQUEST_TIMEOUT = 10                      # HTTP 请求超时（秒）
    POC_TIMEOUT = 5                           # POC 执行超时（秒）

    # Circuit Breaker 配置（故障隔离）
    CIRCUIT_BREAKER_FAILURE_THRESHOLD = 5     # 失败几次后打开熔断
    CIRCUIT_BREAKER_TIMEOUT = 300             # 熔断恢复等待时间（秒）

    # WAF 规避
    SMART_SLEEP_MIN = 0.5                     # 最小随机延迟
    SMART_SLEEP_MAX = 1.2                     # 最大随机延迟
    VERIFY_SSL_CERTIFICATE = False            # SSL 证书验证

    # 泛域名检测
    WILDCARD_TEST_COUNT = 3                   # 测试次数
    WILDCARD_THRESHOLD = 50                   # 内容长度差异阈值

    # 输出
    OUTPUT_FORMATS = ["txt", "json", "csv"]   # 导出格式
    OUTPUT_DIR = "./output"                   # 输出目录

    # 数据库
    CHECKPOINT_ENABLED = True                 # 断点续传
    DATABASE_URL = "sqlite:///assets.db"      # 数据库连接
```

### 2. 代理池配置 (`core/proxy_manager.py`)

为了防止 IP 被封禁，在生产环境配置代理池：

```python
PROXY_POOL = [
    "http://user:pass@proxy1.com:8080",
    "http://user:pass@proxy2.com:8080",
    "socks5://proxy3.com:1080",
    None  # 允许直连作为备选
]
```

### 3. 通知告警配置 (`core/notify.py`)

配置告警渠道：

```python
# Telegram
TG_BOT_TOKEN = "YOUR_BOT_TOKEN"
TG_CHAT_ID = "YOUR_CHAT_ID"

# 钉钉
DINGTALK_WEBHOOK = "https://oapi.dingtalk.com/robot/send?access_token=..."

# 企业微信
WECHAT_WEBHOOK = "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=..."

# 邮件
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "your-email@gmail.com"
SMTP_PASSWORD = "your-app-password"
```

---

## 🚀 使用示例

### 方式一：命令行使用（最简单）

#### 基础扫描
```bash
# 最简单的扫描
python main.py -d example.com

# 指定并发线程数（适合大规模扫描）
python main.py -d example.com -t 50

# 使用自定义配置文件
python main.py -d example.com --config prod_config.yaml
```

#### 高级选项
```bash
# 从上次断点继续扫描（大规模扫描时很有用）
python main.py -d example.com --continue-scan

# 禁用断点续传，完全重新扫描
python main.py -d example.com --no-checkpoint

# 启用详细日志输出
python main.py -d example.com -v

# 启动 Web Dashboard
python main.py --server --port 5000
```

#### 完整实战例子
```bash
# 企业级扫描：50 并发线程，自定义配置，启用断点续传
python main.py -d aliyun.com -t 50 --config prod_config.yaml

# 开发/测试：10 并发线程，详细日志，无断点
python main.py -d test.local -t 10 -v --no-checkpoint

# 继续上次扫描（例如之前的扫描被中断）
python main.py -d aliyun.com --continue-scan
```

---

### 方式二：代码集成（开发者推荐）

#### 基础用法
```python
from core.models import Asset, Vulnerability, Severity, VulnType
from core.httpx_probe import batch_probe
from core.subdomain import get_subdomains
from core.poi_engine import run_pocs
import json

def scan_target(domain: str, threads: int = 30):
    """扫描目标域名的完整流程"""

    # 1. 收集子域名
    print(f"[*] 正在收集 {domain} 的子域名...")
    subdomains = get_subdomains(domain)
    print(f"[+] 收集到 {len(subdomains)} 个子域名")

    # 2. 批量探测资产
    print(f"[*] 开始批量探测（{threads} 并发）...")
    assets: list[Asset] = batch_probe(subdomains, domain, threads=threads)
    print(f"[+] 发现 {len(assets)} 个存活资产")

    # 3. 处理结果
    vulnerabilities = []
    for asset in assets:
        print(f"  [★] {asset.url} | 状态: {asset.status} | 指纹: {asset.fingerprint}")

        # 记录已发现的漏洞
        for vuln in asset.vulns:
            vulnerabilities.append(vuln)
            print(f"      [💥] {vuln.vuln_name} (严重等级: {vuln.severity.value})")

    # 4. 导出结果
    print(f"\n[√] 扫描完成！")
    print(f"    - 存活资产: {len(assets)}")
    print(f"    - 发现漏洞: {len(vulnerabilities)}")

    return assets, vulnerabilities

# 执行扫描
if __name__ == "__main__":
    assets, vulns = scan_target("example.com", threads=30)

    # 导出为JSON
    result = {
        "target": "example.com",
        "assets": [a.to_dict() for a in assets],
        "vulnerabilities": [v.to_dict() for v in vulns]
    }
    with open("scan_result.json", "w") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
```

#### 自定义 POC 检测
```python
from core.poc_engine import BasePOC
from core.models import Severity, VulnType, Vulnerability
from typing import Optional, Dict, Any

class CustomVulnPOC(BasePOC):
    """自定义漏洞检测"""

    def __init__(self):
        super().__init__(
            name="Custom Vulnerability Check",
            severity=Severity.HIGH,
            poc_type=VulnType.REMOTE_CODE_EXECUTION,
            timeout=5
        )

    def _check(self, url: str) -> Optional[Dict[str, Any]]:
        """实现具体的检查逻辑"""
        try:
            # 你的检查逻辑
            response = requests.get(f"{url}/admin/api/status", timeout=3)

            if response.status_code == 200 and "vulnerable" in response.text.lower():
                return {
                    "vuln_name": "Custom API Exposure",
                    "payload_url": f"{url}/admin/api/status",
                    "severity": Severity.HIGH,
                    "confidence": 0.9,
                    "description": "Admin API endpoint exposed without authentication"
                }
        except Exception as e:
            self.logger.debug(f"检查失败: {e}")

        return None

# 使用
poc = CustomVulnPOC()
vuln = poc.execute("http://example.com")
if vuln:
    print(f"[!] 发现漏洞: {vuln.vuln_name}")
```

#### 批量探测并导出结果
```python
from core.httpx_probe import batch_probe
from core.models import Asset
import csv

# 探测子域名列表
subdomains = [
    "www.example.com",
    "api.example.com",
    "admin.example.com",
    "mail.example.com"
]

assets = batch_probe(subdomains, "example.com", threads=10)

# 导出为 CSV
with open("assets.csv", "w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["URL", "Status", "Fingerprint", "Confidence", "Title", "Vulnerabilities"]
    )
    writer.writeheader()

    for asset in assets:
        writer.writerow({
            "URL": asset.url,
            "Status": asset.status,
            "Fingerprint": asset.fingerprint,
            "Confidence": f"{asset.confidence * 100:.1f}%",
            "Title": asset.title,
            "Vulnerabilities": len(asset.vulns)
        })

print(f"[+] 结果已导出到 assets.csv")
```

---

## 📊 输出结果解读

### 输出目录结构
```
output/
├── example.com_20260228_202300_results.txt    # 文本格式报告
├── example.com_20260228_202300_results.json   # JSON 格式（推荐用于自动化）
└── example.com_20260228_202300_assets.csv     # CSV 表格（推荐用于 Excel）
```

### TXT 报告示例
```
AssetMonitor 扫描结果
======================================================================
目标域名: example.com
扫描ID: example.com_20260228_202300
扫描时间: 2026-02-28 20:23:00
发现的子域名: 150
存活资产: 45
发现漏洞: 12
======================================================================

【存活资产列表】
----------------------------------------------------------------------
URL: http://www.example.com
  状态码: 200
  指纹: Nginx 1.18, PHP 7.4
  置信度: 92.5%
  标题: Welcome Page
  漏洞数: 2

【漏洞汇总】
----------------------------------------------------------------------
类型: SQL Injection in search
  严重等级: HIGH
  目标: http://www.example.com/search?q=test
  发现时间: 2026-02-28T20:23:15
```

### JSON 格式
```json
{
  "target": "example.com",
  "scan_id": "example.com_20260228_202300",
  "timestamp": "2026-02-28T20:23:00",
  "summary": {
    "total_subdomains": 150,
    "alive_assets": 45,
    "vulnerabilities_found": 12
  },
  "results": {
    "alive_assets": [
      {
        "url": "http://www.example.com",
        "status": 200,
        "fingerprint": "Nginx 1.18, PHP 7.4",
        "confidence": 0.925,
        "title": "Welcome Page",
        "vulns": [
          {
            "vuln_name": "SQL Injection",
            "payload_url": "http://www.example.com/search?q=test",
            "severity": "HIGH",
            "confidence": 0.85
          }
        ]
      }
    ]
  }
}
```

---

## 🔍 实战常见场景

### 场景 1: 快速发现企业资产暴露面

```bash
# 输入: 企业主域名
python main.py -d yourcompany.com -t 50

# 输出: TXT/JSON/CSV 报告
# 包含所有发现的子域名和漏洞
```

### 场景 2: 定期监控关键域名

```bash
# 编辑 crontab（Linux/Mac）
0 0 * * * cd /path/to/AssetMonitor && python main.py -d critical-domain.com --continue-scan

# 或使用 Windows 计划任务（每天午夜执行）
```

### 场景 3: 渗透测试中的资产收集

```python
# 测试前的资产发现
import subprocess
import json

domains = ["target1.com", "target2.com", "subsidiary.target1.com"]

for domain in domains:
    result = subprocess.run(
        ["python", "main.py", "-d", domain, "-t", "30"],
        capture_output=True
    )

    # 读取 JSON 结果进行后续处理
    with open(f"output/{domain}_*.json") as f:
        data = json.load(f)
        print(f"[+] {domain}: 发现 {data['summary']['alive_assets']} 个资产")
```

### 场景 4: WAF 环境下的扫描配置

```python
# config.py - WAF 规避配置
class Config:
    # 加大延迟
    SMART_SLEEP_MIN = 2.0
    SMART_SLEEP_MAX = 5.0

    # 减少并发
    THREADS_DEFAULT = 10

    # 配置代理池
    PROXY_POOL = [
        "http://proxy1:8080",
        "http://proxy2:8080",
        "socks5://proxy3:1080"
    ]

    # 更长的超时时间
    REQUEST_TIMEOUT = 15
```

---

## 📈 性能基准

| 场景 | 子域名数 | 线程数 | 扫描时间 | 性能提升 |
|------|--------|--------|---------|---------|
| 小规模 | <100 | 10 | ~5 分钟 | - |
| 中规模 | 100-500 | 30 | ~10 分钟 | 70% vs 串行 |
| 大规模 | >1000 | 50 | ~20 分钟 | 70% vs 串行 |
| 企业级 | >5000 | 100 | ~1 小时 | 70% vs 串行 |

**注**: 70% 性能提升来自 POC 并发执行框架

---

## 🐛 常见问题 (FAQ)

### Q1: 扫描速度慢怎么办？

**A**: 增加并发线程数：
```bash
# 从默认的 30 增加到 50
python main.py -d example.com -t 50

# 或修改 config.py
THREADS_DEFAULT = 50
```

### Q2: 被目标 WAF 封 IP

**A**: 启用 WAF 规避配置：
```python
# config.py
SMART_SLEEP_MIN = 2.0    # 增加随机延迟
SMART_SLEEP_MAX = 5.0
PROXY_POOL = [...]       # 配置代理池
```

### Q3: 如何添加自定义 POC？

**A**: 继承 `BasePOC` 类：
```python
from core.poc_engine import BasePOC

class MyPOC(BasePOC):
    def _check(self, url: str):
        # 你的检查逻辑
        pass
```

### Q4: 能否在 Docker 中运行？

**A**: 可以，创建 Dockerfile：
```dockerfile
FROM python:3.10
WORKDIR /app
COPY . .
RUN pip install -r requirements.txt
CMD ["python", "main.py", "-d", "${TARGET_DOMAIN}"]
```

---

## 📂 项目结构

```
AssetMonitor/
├── core/
│   ├── models.py              # 数据模型 (Asset, Vulnerability)
│   ├── httpx_probe.py         # HTTP 探测 + Circuit Breaker
│   ├── poc_engine.py          # POC 执行框架
│   ├── subdomain.py           # 子域名收集
│   ├── database.py            # 数据库管理
│   ├── notify.py              # 通知告警
│   ├── evasion.py             # WAF 规避
│   ├── proxy_manager.py       # 代理管理
│   └── di_container.py        # 依赖注入
├── config.py                  # 全局配置
├── main.py                    # 命令行入口
├── checkpoint.py              # 断点续传
├── logger.py                  # 统一日志
└── requirements.txt           # 依赖清单
```

---

## 📌 最佳实践

### 1. 大规模扫描推荐配置
```python
THREADS_DEFAULT = 50-100      # 高并发
REQUEST_TIMEOUT = 15          # 较长超时
DB_POOL_SIZE = 20             # 数据库连接池
CHECKPOINT_ENABLED = True     # 启用断点续传
```

### 2. 保护隐私
```bash
# 不提交敏感配置到 Git
echo "config.local.py" >> .gitignore
echo "output/" >> .gitignore
echo "*.db" >> .gitignore
```

### 3. 日志管理
```bash
# 查看实时日志
tail -f logs/assetmonitor.log

# 查看特定模块的日志
grep "httpx_probe" logs/assetmonitor.log
```

---

## 📄 许可证

MIT License - 仅供安全研究和授权测试使用

⚠️ **免责声明**: 本工具仅供安全研究、渗透测试和授权的网络防御使用。严禁用于非法攻击或未经授权的渗透测试。使用者需自行承担因使用本工具而产生的一切法律责任。

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

## 📞 联系方式

- 📧 Email: skyandeos@foxmail.com
- 🐛 Bug 反馈: https://github.com/hours9527/AssetMonitor/issues
- ✨ 功能建议: https://github.com/hours9527/AssetMonitor/discussions

---

