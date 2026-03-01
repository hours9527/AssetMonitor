"""
资产监控巡航引擎 v2.1
企业级无人值守自动化资产发现和漏洞检测系统
新增：数据库连接池、POC配置化管理、持久化去重
"""
import os
import time
import argparse
import json
import csv
import hashlib
from typing import Dict, List, Any
from datetime import datetime

from config import Config
from logger import get_logger
from checkpoint import CheckpointManager, DedupManager
from core.database import init_database  # 新增数据库导入
from core.di_container import initialize_di_container
from core.subdomain import get_subdomains
from core.httpx_probe import batch_probe
from core.models import Asset, Vulnerability
from core.notify import send_alert

logger = get_logger("main")


def create_output_directory() -> None:
    """创建输出目录"""
    os.makedirs(Config.OUTPUT_DIR, exist_ok=True)


def export_results(results: Dict[str, Any], target_domain: str, scan_id: str) -> Dict[str, str]:
    """
    导出扫描结果为多种格式
    支持: TXT, JSON, CSV

    参数:
        results: 扫描结果字典
        target_domain: 目标域名
        scan_id: 扫描ID

    返回:
        导出文件路径字典
    """
    exported = {}
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_filename = f"{target_domain}_{timestamp}"

    # ===== 导出为 TXT =====
    if "txt" in Config.OUTPUT_FORMATS:
        txt_file = os.path.join(Config.OUTPUT_DIR, f"{base_filename}_results.txt")
        try:
            with open(txt_file, 'w', encoding='utf-8') as f:
                f.write(f"AssetMonitor 扫描结果\n")
                f.write("=" * 70 + "\n")
                f.write(f"目标域名: {target_domain}\n")
                f.write(f"扫描ID: {scan_id}\n")
                f.write(f"扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"发现的子域名: {len(results['subdomains'])}\n")
                f.write(f"存活资产: {len(results['alive_assets'])}\n")
                f.write(f"发现漏洞: {len(results['vulnerabilities'])}\n")
                f.write("=" * 70 + "\n\n")

                f.write("【存活资产列表】\n")
                f.write("-" * 70 + "\n")
                for asset in results['alive_assets']:
                    f.write(f"URL: {asset.url}\n")
                    f.write(f"  状态码: {asset.status}\n")
                    f.write(f"  指纹: {asset.fingerprint}\n")
                    f.write(f"  置信度: {asset.confidence*100:.1f}%\n")
                    f.write(f"  标题: {asset.title}\n")
                    f.write(f"  漏洞数: {len(asset.vulns)}\n\n")

                if results['vulnerabilities']:
                    f.write("【漏洞汇总】\n")
                    f.write("-" * 70 + "\n")
                    for vuln in results['vulnerabilities']:
                        f.write(f"类型: {vuln.vuln_name}\n")
                        f.write(f"  严重等级: {vuln.severity.value}\n")
                        f.write(f"  目标: {vuln.payload_url}\n")
                        f.write(f"  发现时间: {vuln.discovered_at}\n\n")

            logger.info(f"  [✓] TXT导出成功: {txt_file}")
            exported["txt"] = txt_file
        except Exception as e:
            logger.error(f"  [-] TXT导出失败: {e}")

    # ===== 导出为 JSON =====
    if "json" in Config.OUTPUT_FORMATS:
        json_file = os.path.join(Config.OUTPUT_DIR, f"{base_filename}_results.json")
        try:
            # 转换对象为字典以便JSON序列化
            serializable_results = {
                "subdomains": results['subdomains'],
                "alive_assets": [a.to_dict() for a in results['alive_assets']],
                "vulnerabilities": [v.to_dict() for v in results['vulnerabilities']]
            }

            json_result = {
                "target": target_domain,
                "scan_id": scan_id,
                "timestamp": datetime.now().isoformat(),
                "summary": {
                    "total_subdomains": len(results['subdomains']),
                    "alive_assets": len(results['alive_assets']),
                    "vulnerabilities_found": len(results['vulnerabilities'])
                },
                "results": serializable_results
            }
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(json_result, f, ensure_ascii=False, indent=2)

            logger.info(f"  [✓] JSON导出成功: {json_file}")
            exported["json"] = json_file
        except Exception as e:
            logger.error(f"  [-] JSON导出失败: {e}")

    # ===== 导出为 CSV =====
    if "csv" in Config.OUTPUT_FORMATS:
        csv_file = os.path.join(Config.OUTPUT_DIR, f"{base_filename}_assets.csv")
        try:
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(
                    f,
                    fieldnames=['url', 'status', 'fingerprint', 'confidence', 'title', 'vulnerabilities']
                )
                writer.writeheader()

                for asset in results['alive_assets']:
                    writer.writerow({
                        'url': asset.url,
                        'status': asset.status,
                        'fingerprint': asset.fingerprint,
                        'confidence': f"{asset.confidence*100:.1f}%",
                        'title': asset.title,
                        'vulnerabilities': len(asset.vulns)
                    })

            logger.info(f"  [✓] CSV导出成功: {csv_file}")
            exported["csv"] = csv_file
        except Exception as e:
            logger.error(f"  [-] CSV导出失败: {e}")

    return exported


def main() -> None:
    """主函数"""
    parser = argparse.ArgumentParser(
        description="企业级资产暴露面自动化巡航系统 v2.1 (无人值守版)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py -d aliyun.com
  python main.py -d aliyun.com -t 20 --no-checkpoint
  python main.py -d aliyun.com --continue-scan
  python main.py --server  (启动可视化大屏)
        """
    )

    parser.add_argument(
        "-d", "--domain",
        help="目标主域名 (如: aliyun.com)"
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=Config.THREADS_DEFAULT,
        help=f"并发线程数 (默认: {Config.THREADS_DEFAULT})"
    )
    parser.add_argument(
        "--continue-scan",
        action="store_true",
        help="从上次断点继续扫描"
    )
    parser.add_argument(
        "--no-checkpoint",
        action="store_true",
        help="禁用断点续传功能"
    )
    parser.add_argument(
        "--config",
        help="配置文件路径 (YAML格式)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="详细输出"
    )
    parser.add_argument(
        "--server",
        action="store_true",
        help="启动可视化Web大屏 (Dashboard)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5000,
        help="Web服务端口 (默认: 5000)"
    )

    args = parser.parse_args()

    # 模式1: 启动Web服务器
    if args.server:
        from soar_engine import app
        logger.info("[*] 正在启动可视化大屏...")
        logger.info(f"[*] 请访问: http://127.0.0.1:{args.port}")
        initialize_di_container()
        app.run(host='0.0.0.0', port=args.port)
        return

    # 模式2: 执行扫描 (必须提供域名)
    if not args.domain:
        parser.error("未指定目标域名 (-d/--domain)，且未选择启动服务模式 (--server)")

    # [新增] 动态加载配置文件 (YAML)
    # 这确保了命令行指定的配置文件能真正覆盖默认配置
    if args.config and os.path.exists(args.config):
        cfg = Config.load_from_yaml(args.config)
        if cfg:
            logger.info(f"[*] 已加载配置文件: {args.config}")
            for k, v in cfg.items():
                setattr(Config, k.upper(), v)
    elif os.path.exists("config.yaml"):
        cfg = Config.load_from_yaml("config.yaml")
        if cfg:
            for k, v in cfg.items():
                setattr(Config, k.upper(), v)

    target_domain = args.domain.lower()
    threads = args.threads
    enable_checkpoint = Config.CHECKPOINT_ENABLED and not args.no_checkpoint

    # ===== 初始化数据库（通过DI容器）=====
    try:
        logger.info("[*] 初始化数据库连接池...")
        initialize_di_container()
        db_manager = init_database()
        if db_manager:
            logger.info("[✓] 数据库初始化成功")
        else:
            logger.warning("[!] 数据库初始化失败，仅使用文件输出")
    except Exception as e:
        logger.warning(f"[!] 数据库初始化失败: {e}，仅使用文件输出")
        db_manager = None

    # ===== 打印启动信息 =====
    startup_info = f"""
╔════════════════════════════════════════════════════════════╗
║  AssetMonitor v2.1 - 企业级资产巡航引擎                    ║
║  自动化无人值守资产发现 & 漏洞检测系统                     ║
║  [新增] 数据库连接池 / POC配置化 / 持久化去重              ║
╚════════════════════════════════════════════════════════════╝

【扫描参数】
  目标域名: {target_domain}
  并发线程: {threads}
  断点续传: {'启用' if enable_checkpoint else '禁用'}
  数据库: {'✓ 已连接' if db_manager else '✗ 未连接'}
  配置文件: {args.config or 'config.yaml'}
  输出格式: {', '.join(Config.OUTPUT_FORMATS)}

"""
    logger.info(startup_info)

    # ===== 初始化 =====
    create_output_directory()

    # 生成扫描ID (用于断点续传)
    scan_id = f"{target_domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # 记录扫描开始
    if db_manager:
        db_manager.start_scan(scan_id, target_domain)

    checkpoint = CheckpointManager(scan_id) if enable_checkpoint else None
    dedup = DedupManager()

    # ===== 判断是否继续扫描 =====
    if enable_checkpoint and args.continue_scan and checkpoint.is_stage_completed("subdomain_collection"):
        logger.info("[*] 检测到断点数据，继续从上次中断处扫描...")
        subdomains = checkpoint.get_pending_subdomains()

        if not subdomains:
            logger.info("[√] 上次扫描已完成所有子域名探测")
            subdomains = checkpoint.data["results"]["subdomains"]
    else:
        # ===== 阶段一：子域名收集 =====
        if enable_checkpoint:
            checkpoint.mark_stage_started("subdomain_collection")

        logger.info(f"\n[>>>] 阶段一：开始多源子域名收集...")
        subdomains = get_subdomains(target_domain)

        if not subdomains:
            logger.error("[-] 未收集到任何子域名，扫描结束")
            return

        if enable_checkpoint:
            for sub in subdomains:
                checkpoint.add_subdomain(sub, "multi_source")
            checkpoint.mark_stage_completed("subdomain_collection")

    # ===== 阶段二：存活探测与指纹识别 =====
    if enable_checkpoint:
        checkpoint.mark_stage_started("probing")

    logger.info(f"\n[>>>] 阶段二：HTTP存活探测与指纹识别 (线程: {threads})...")
    alive_assets = batch_probe(subdomains, target_domain, threads=threads)

    if enable_checkpoint:
        for asset in alive_assets:
            checkpoint.add_alive_asset(asset)
        checkpoint.mark_stage_completed("probing")

    # ===== 漏洞汇总 =====
    all_vulnerabilities: List[Vulnerability] = []
    for asset in alive_assets:
        for vuln in asset.vulns:
            all_vulnerabilities.append(vuln)
            if enable_checkpoint:
                checkpoint.add_vulnerability(vuln)

    # ===== 阶段三：数据持久化 =====
    logger.info(f"\n[>>>] 阶段三：结果导出与持久化...")

    # 同步数据到数据库
    if db_manager:
        logger.info("[*] 正在同步数据到数据库...")
        try:
            save_count = 0
            for asset in alive_assets:
                # 保存资产
                db_manager.add_asset(
                    asset.url,
                    target_domain,
                    asset.status,
                    asset.fingerprint,
                    asset.confidence,
                    asset.title
                )
                save_count += 1
                
                # 保存漏洞
                for vuln in asset.vulns:
                    v_key = f"{asset.url}_{vuln.vuln_name}"
                    v_hash = hashlib.md5(v_key.encode()).hexdigest()
                    db_manager.add_vulnerability(
                        v_hash, asset.url, target_domain, vuln.to_dict()
                    )
            
            db_manager.complete_scan(scan_id, len(subdomains), len(alive_assets), len(all_vulnerabilities))
            logger.info(f"[✓] 数据库同步完成 (已保存 {save_count} 个资产)")
        except Exception as e:
            logger.error(f"[-] 数据库同步失败: {e}")

    results = {
        "subdomains": subdomains,
        "alive_assets": alive_assets,
        "vulnerabilities": all_vulnerabilities
    }

    exported = export_results(results, target_domain, scan_id)

    # ===== 阶段四：通知告警 =====
    logger.info(f"\n[>>>] 阶段四：触发通知规则引擎...")

    # Convert Asset objects to dicts for send_alert
    alert_assets = []
    for asset in alive_assets:
        alert_assets.append({
            "url": asset.url,
            "status": asset.status,
            "fingerprint": asset.fingerprint,
            "confidence": asset.confidence,
            "title": asset.title,
            "vulns": [v.to_dict() for v in asset.vulns]
        })
    send_alert(target_domain, alert_assets)

    # ===== 清理检查点 =====
    if enable_checkpoint:
        checkpoint.cleanup()

    # ===== 完成统计 =====
    logger.info(f"""
╔════════════════════════════════════════════════════════════╗
║                     🎉 扫描全链路完成！                     ║
╚════════════════════════════════════════════════════════════╝

【扫描统计】
  收集子域名: {len(subdomains)}
  发现存活资产: {len(alive_assets)}
  发现漏洞: {len(all_vulnerabilities)}

【导出格式】
{chr(10).join(f"  - {fmt}: {exported.get(fmt, 'N/A')}" for fmt in Config.OUTPUT_FORMATS)}

【下一步行动】
  1. 查看导出的扫描报告
  2. 登录系统仪表板审视详细信息
  3. 根据漏洞等级优先修复关键漏洞

""")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.warning("\n[!] 用户中断扫描任务")
    except Exception as e:
        logger.error(f"[!] 发生致命错误: {e}", exc_info=True)
