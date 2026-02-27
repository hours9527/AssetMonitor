from flask import Flask, request, jsonify, render_template_string
import requests
import time
import os
import hashlib
import sys
from pathlib import Path
import json

# P3-07: 添加项目路径以导入core模块
sys.path.insert(0, str(Path(__file__).parent))

app = Flask(__name__)

# ==========================================
# ⚙️ 全局配置与数据库 (P3-07：集成连接池)
# ==========================================
TG_BOT_TOKEN = os.getenv("TG_BOT_TOKEN", "在此替换为你的_BOT_TOKEN")
TG_CHAT_ID = os.getenv("TG_CHAT_ID", "在此替换为你的_CHAT_ID")

# P3-07: 使用共享的数据库连接池而不是直接连接
db_manager = None

def init_db():
    """P3-07: 初始化数据库（使用连接池）"""
    global db_manager
    try:
        from core.database import init_database
        db_manager = init_database()
        print("[✓] 数据库连接池初始化成功 (P3-07)")
        return True
    except Exception as e:
        print(f"[!] 数据库初始化失败，使用快速模式: {e}")
        return False

def send_tg_message(text):
    if TG_BOT_TOKEN.startswith("在此替换") or TG_CHAT_ID.startswith("在此替换"):
        return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    requests.post(url, json={"chat_id": TG_CHAT_ID, "text": text, "parse_mode": "Markdown"}, timeout=10)

def playbook_critical_vuln(asset_url, target_domain, vuln):
    print(f"\n[🔥] 触发漏洞响应剧本 -> 目标: {asset_url}")
    alert_msg = f"🚨 **SecBot 新增漏洞告警** 🚨\n\n**资产**: `{asset_url}`\n**漏洞**: 💥 {vuln['vuln_name']}\n**路径**: [点击验证]({vuln['payload_url']})"
    send_tg_message(alert_msg)

def process_recon_intel(domain, assets):
    """P3-07: 处理侦察情报（使用数据库连接池）"""
    global db_manager

    if not db_manager:
        print("[!] 数据库未初始化，跳过数据保存")
        return 0

    new_vulns_count = 0

    for asset in assets:
        url, status, fingerprint, vulns = asset.get("url"), asset.get("status"), asset.get("fingerprint"), asset.get("vulns", [])

        # 添加资产到数据库
        try:
            db_manager.add_asset(url, domain, status, fingerprint, 0.8, "")
        except Exception as e:
            print(f"[-] 添加资产失败: {e}")

        # 处理漏洞
        for v in vulns:
            vuln_name, payload_url = v['vuln_name'], v['payload_url']
            vuln_hash = hashlib.md5(f"{url}_{vuln_name}".encode()).hexdigest()

            try:
                # 添加漏洞到数据库
                db_manager.add_vulnerability(vuln_hash, url, domain, {
                    'vuln_name': vuln_name,
                    'payload_url': payload_url,
                    'type': v.get('type', 'Unknown'),
                    'severity': v.get('severity', 'MEDIUM'),
                    'confidence': v.get('confidence', 0.8)
                })
                new_vulns_count += 1
                playbook_critical_vuln(url, domain, v)
            except Exception as e:
                print(f"[-] 添加漏洞失败: {e}")

    return new_vulns_count

# ==========================================
# 📡 神经中枢 (Webhook Listeners)
# ==========================================
@app.route('/api/v1/webhook/recon', methods=['POST'])
def receive_recon_intel():
    try:
        data = request.json
        domain, assets = data.get("domain", "Unknown"), data.get("assets", [])
        process_recon_intel(domain, assets)
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400

# ==========================================
# 🖥️ Web 可视化大屏 (Dashboard)
# ==========================================
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="zh-CN" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <title>SecBot-SOAR 态势感知大屏</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body { background-color: #0d1117; color: #c9d1d9; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        .card { background-color: #161b22; border: 1px solid #30363d; border-radius: 10px; }
        .text-danger-glow { color: #ff7b72; text-shadow: 0 0 10px rgba(255,123,114,0.5); }
        .text-success-glow { color: #3fb950; text-shadow: 0 0 10px rgba(63,185,80,0.5); }
        .table-dark { background-color: #161b22; }
    </style>
</head>
<body>
<div class="container-fluid py-4">
    <h2 class="mb-4 fw-bold">🛡️ SecBot-SOAR <span class="text-secondary fs-5">| 自动化威胁编排与感知中心</span></h2>
    
    <div class="row mb-4">
        <div class="col-md-6">
            <div class="card p-3 text-center">
                <h5 class="text-muted">全网存活资产总量</h5>
                <h1 class="display-4 text-success-glow fw-bold">{{ total_assets }}</h1>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card p-3 text-center">
                <h5 class="text-muted">已确认为高危漏洞</h5>
                <h1 class="display-4 text-danger-glow fw-bold">{{ total_vulns }}</h1>
            </div>
        </div>
    </div>

    <!-- 图表区域 -->
    <div class="row mb-4">
        <div class="col-md-6">
            <div class="card p-3">
                <h5 class="text-muted mb-3">📊 漏洞等级分布</h5>
                <canvas id="severityChart" style="max-height: 300px;"></canvas>
            </div>
        </div>
        <div class="col-md-6">
            <div class="card p-3">
                <h5 class="text-muted mb-3">🏆 TOP 10 脆弱资产</h5>
                <canvas id="assetChart" style="max-height: 300px;"></canvas>
            </div>
        </div>
    </div>

    <div class="row">
        <div class="col-md-12 mb-4">
            <div class="card p-4">
                <h4 class="mb-3 text-danger-glow">💥 最新漏洞战果 (Vulnerabilities)</h4>
                <div class="table-responsive">
                    <table class="table table-dark table-hover align-middle">
                        <thead>
                            <tr>
                                <th>发现时间</th>
                                <th>脆弱目标</th>
                                <th>漏洞名称</th>
                                <th>利用凭证 (Payload)</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for v in vulns %}
                            <tr>
                                <td>{{ v[5] }}</td>
                                <td class="text-warning">{{ v[1] }}</td>
                                <td class="fw-bold text-danger">{{ v[2] }}</td>
                                <td><code>{{ v[3] }}</code></td>
                            </tr>
                            {% else %}
                            <tr><td colspan="4" class="text-center text-muted">当前环境安全，暂未发现高危漏洞。</td></tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div class="col-md-12">
            <div class="card p-4">
                <h4 class="mb-3 text-success-glow">🌐 高价值资产雷达 (High-Value Assets)</h4>
                <div class="table-responsive">
                    <table class="table table-dark table-hover align-middle">
                        <thead>
                            <tr>
                                <th>最近活跃</th>
                                <th>主域名</th>
                                <th>存活 URL</th>
                                <th>状态码</th>
                                <th>技术组件指纹</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for a in assets %}
                            <tr>
                                <td>{{ a[5] }}</td>
                                <td>{{ a[1] }}</td>
                                <td><a href="{{ a[0] }}" target="_blank" class="text-decoration-none text-info">{{ a[0] }}</a></td>
                                <td><span class="badge bg-{{ 'success' if a[2]==200 else 'warning' }}">{{ a[2] }}</span></td>
                                <td><span class="badge bg-secondary">{{ a[3] }}</span></td>
                            </tr>
                            {% else %}
                            <tr><td colspan="5" class="text-center text-muted">探针正在巡航中，暂无资产数据。</td></tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<script>
    // 漏洞等级分布图
    const severityCtx = document.getElementById('severityChart').getContext('2d');
    new Chart(severityCtx, {
        type: 'doughnut',
        data: {
            labels: {{ severity_labels | tojson }},
            datasets: [{
                data: {{ severity_counts | tojson }},
                backgroundColor: [
                    '#ff7b72', // Critical - Red
                    '#d2a8ff', // High - Purple
                    '#f2cc60', // Medium - Yellow
                    '#58a6ff', // Low - Blue
                    '#8b949e'  // Unknown - Grey
                ],
                borderWidth: 0,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'right', labels: { boxWidth: 12, padding: 20 } }
            },
            cutout: '70%'
        }
    });

    // TOP 10 资产图
    const assetCtx = document.getElementById('assetChart').getContext('2d');
    new Chart(assetCtx, {
        type: 'bar',
        data: {
            labels: {{ top_asset_labels | tojson }},
            datasets: [{
                label: '漏洞数量',
                data: {{ top_asset_counts | tojson }},
                backgroundColor: 'rgba(35, 134, 54, 0.7)',
                borderColor: '#238636',
                borderWidth: 1,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, grid: { borderDash: [2, 4] } },
                x: { grid: { display: false } }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
</script>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def dashboard():
    """P3-07: Web UI 路由：从数据库读取数据并渲染HTML大屏（使用连接池）"""
    global db_manager

    total_assets = 0
    total_vulns = 0
    vulns = []
    assets = []
    severity_labels = []
    severity_counts = []
    top_asset_labels = []
    top_asset_counts = []

    if db_manager:
        try:
            # 获取统计数据
            total_assets_result = db_manager.fetchone("SELECT COUNT(*) FROM assets")
            total_assets = total_assets_result[0] if total_assets_result else 0

            total_vulns_result = db_manager.fetchone("SELECT COUNT(*) FROM vulnerabilities")
            total_vulns = total_vulns_result[0] if total_vulns_result else 0

            # 获取详细列表 (按时间倒序排)
            vulns_result = db_manager.fetchall(
                "SELECT * FROM vulnerabilities ORDER BY discovered_at DESC LIMIT 20"
            )
            vulns = vulns_result if vulns_result else []

            # 只展示识别出指纹的高价值资产
            assets_result = db_manager.fetchall(
                "SELECT * FROM assets WHERE fingerprint != '未知' ORDER BY last_seen DESC LIMIT 50"
            )
            assets = assets_result if assets_result else []

            # 图表数据1: 漏洞等级分布
            sev_result = db_manager.fetchall(
                "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"
            )
            if sev_result:
                for row in sev_result:
                    severity_labels.append(row[0] or "Unknown")
                    severity_counts.append(row[1])

            # 图表数据2: TOP 10 脆弱资产
            top_result = db_manager.fetchall(
                "SELECT url, COUNT(*) as cnt FROM vulnerabilities GROUP BY url ORDER BY cnt DESC LIMIT 10"
            )
            if top_result:
                for row in top_result:
                    # 简化URL显示
                    short_url = row[0].replace('http://', '').replace('https://', '').split('/')[0]
                    top_asset_labels.append(short_url)
                    top_asset_counts.append(row[1])

        except Exception as e:
            print(f"[-] 数据库查询失败: {e}")

    # 将数据注入到 HTML 模板中并渲染
    return render_template_string(
        HTML_TEMPLATE, total_assets=total_assets, total_vulns=total_vulns, vulns=vulns, assets=assets,
        severity_labels=severity_labels, severity_counts=severity_counts,
        top_asset_labels=top_asset_labels, top_asset_counts=top_asset_counts
    )

# ==========================================
# 🏁 引擎启动
# ==========================================
if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=5000, debug=False)