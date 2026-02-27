# AssetMonitor 资产监控与漏洞扫描系统

AssetMonitor 是一个企业级的信息收集、资产监控与自动化漏洞扫描工具。它集成了多源子域名收集、智能指纹识别、WAF 规避探测以及高危漏洞验证（POC）功能，并支持多种渠道的实时告警。

## ✨ 核心功能

*   **多源子域名收集**: 集成 HackerTarget, crt.sh 等接口，支持并行 DNS 验证与泛解析过滤。
*   **智能资产探测**:
    *   基于 `curl_cffi` 的 TLS 指纹伪造（模拟 Chrome/Firefox），有效规避反爬虫。
    *   **Circuit Breaker (熔断器)**: 自动识别并跳过不稳定的端点，防止无效重试。
    *   **WAF 智能规避**: 动态延迟、随机 User-Agent/Referer、指数退避策略。
*   **指纹识别**: 自动识别 Spring Boot, Shiro, ThinkPHP, Nginx, IIS, Vue.js 等组件。
*   **漏洞验证 (POC)**:
    *   内置高危漏洞检测（如 Spring Boot Actuator, Log4j2 JNDI, Shiro 反序列化等）。
    *   **OOB (Out-of-Band) 盲打引擎**: 集成 Ceye.io，支持无回显漏洞检测。
*   **通知告警**: 支持 Telegram, 钉钉, 企业微信, 邮件, Webhook 等多渠道推送，具备去重和限流功能。
*   **高性能架构**: 采用 SQLite 连接池、SMTP 连接池和多线程并发设计。

## 🛠️ 安装与依赖

确保您的环境安装了 Python 3.8+。

1.  **克隆项目**
    ```bash
    git clone https://github.com/your-repo/AssetMonitor.git
    cd AssetMonitor
    ```

2.  **安装依赖**
    主要依赖 `curl_cffi` 和 `requests`。
    ```bash
    pip install curl_cffi requests
    ```

## ⚙️ 配置说明

在使用前，请根据您的环境修改以下配置文件。

### 1. 基础配置 (`config.py`)
请确保项目根目录下存在 `config.py` 文件（参考代码中的引用），主要配置项如下：

```python
class Config:
    # 收集源配置
    SUBDOMAIN_SOURCES = ["hackertarget", "crtsh"]
    DNS_VERIFY_ENABLED = True
    
    # 通知配置
    NOTIFY_ENABLED = True
    NOTIFY_CHANNELS = ["telegram", "console"]  # 可选: dingtalk, wechat, email
    
    # Telegram 配置
    TG_BOT_TOKEN = "YOUR_BOT_TOKEN"
    TG_CHAT_ID = "YOUR_CHAT_ID"
    
    # 数据库配置
    DB_FILE = "assets.db"
    
    # OOB 配置
    OOB_ENABLED = True
```

### 2. OOB 盲打配置 (`core/oob_engine.py`)
如果您需要检测 Log4j2 等无回显漏洞，请修改 `core/oob_engine.py`：

```python
self.api_token = "YOUR_CEYE_TOKEN"        # 替换为您的 Ceye.io Token
self.domain_identifier = "YOUR.ceye.io"   # 替换为您的 Identifier
```

### 3. 代理池配置 (`core/proxy_manager.py`)
为了防止 IP 被封禁，建议在 `core/proxy_manager.py` 中配置代理池：

```python
PROXY_POOL = [
    "http://user:pass@1.2.3.4:8080",
    None  # 允许直连作为备选
]
```

## 🚀 快速使用

### 编写启动脚本 (`main.py`)

在项目根目录下创建一个 `main.py` 来启动扫描任务：

```python
from core.subdomain import get_subdomains
from core.httpx_probe import batch_probe
from core.database import init_database
from core.notify import send_alert

def main(target_domain):
    # 1. 初始化数据库
    db = init_database()
    
    print(f"[*] 开始扫描目标: {target_domain}")
    
    # 2. 收集子域名
    subdomains = get_subdomains(target_domain)
    print(f"[+] 收集到 {len(subdomains)} 个子域名")
    
    # 3. 批量探测存活与漏洞
    # 自动进行指纹识别和 POC 扫描
    assets = batch_probe(subdomains, target_domain, threads=10)
    
    # 4. 结果入库
    for asset in assets:
        db.add_asset(
            url=asset['url'],
            domain=target_domain,
            status=asset['status'],
            fingerprint=asset['fingerprint'],
            confidence=asset['confidence'],
            title=asset['title']
        )
        
        # 记录漏洞
        for vuln in asset.get('vulns', []):
            # 生成简单的 hash
            vuln_hash = f"{asset['url']}_{vuln['vuln_name']}"
            db.add_vulnerability(vuln_hash, asset['url'], target_domain, vuln)

    # 5. 发送告警
    send_alert(target_domain, assets)

if __name__ == "__main__":
    main("example.com")
```

### 运行扫描

```bash
python main.py
```

## 📂 项目结构

*   `core/subdomain.py`: 子域名收集模块
*   `core/httpx_probe.py`: HTTP 探测、指纹识别、WAF 规避
*   `core/poc_engine.py`: 漏洞验证引擎 (POCs)
*   `core/database.py`: SQLite 数据库管理与连接池
*   `core/notify.py`: 多渠道通知系统
*   `core/evasion.py`: 反检测模块 (User-Agent, Headers)
*   `core/oob_engine.py`: OOB 盲打辅助模块

## ⚠️ 免责声明

本工具仅供安全研究和授权测试使用。严禁用于非法攻击或未经授权的渗透测试。使用者需自行承担因使用本工具而产生的一切法律责任。