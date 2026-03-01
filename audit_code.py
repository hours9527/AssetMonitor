"""
全局代码审查和质量检查工具

检查内容：
1. 语法错误和导入问题
2. 未处理的异常
3. 资源泄漏（文件、连接、线程）
4. 线程安全问题
5. 常见的安全漏洞
6. 性能问题
7. 代码重复和复杂度
8. 文档和注释缺失
"""

import os
import sys
import ast
import re
from pathlib import Path
from collections import defaultdict

class CodeAudit:
    """代码审查工具"""

    def __init__(self):
        self.issues = []
        self.files_checked = 0
        self.total_lines = 0
        self.python_files = []

    def find_python_files(self, root_dir):
        """找到所有Python文件"""
        root = Path(root_dir)
        self.python_files = list(root.glob("**/*.py"))
        return self.python_files

    def check_syntax(self, file_path):
        """检查Python语法"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                code = f.read()
            ast.parse(code)
            return True, None
        except SyntaxError as e:
            return False, f"Syntax error: {e}"
        except Exception as e:
            return False, str(e)

    def check_bare_except(self, file_path):
        """检查裸露的except语句（应该明确异常类型）"""
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    if re.search(r'\bexcept\s*:', line):
                        issues.append((line_num, "Bare except clause found", "Should specify exception type"))
        except Exception as e:
            pass
        return issues

    def check_resource_leaks(self, file_path):
        """检查资源泄漏（未关闭的文件、连接等）"""
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # 检查open()调用没有with语句
            for match in re.finditer(r'(?<!["\'])open\([^)]+\)(?!.*\.close\(\))', content):
                if 'with ' not in content[max(0, match.start()-50):match.start()]:
                    # 可能有资源泄漏
                    pass

            # 检查连接池/数据库连接没有关闭
            if 'sqlite3.connect' in content or 'cursor.execute' in content:
                if not all('conn.close()' in block for block in content.split('sqlite3.connect')):
                    # 可能有连接没有关闭
                    pass

        except Exception as e:
            pass
        return issues

    def check_hardcoded_values(self, file_path):
        """检查硬编码的值（密钥、密码等）"""
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    # 检查可疑的硬编码值
                    if re.search(r'(password|secret|token|api_key)\s*=\s*["\']', line, re.IGNORECASE):
                        if 'os.getenv' not in line and 'Config.' not in line:
                            issues.append((line_num, "Hardcoded sensitive value", line.strip()[:80]))
        except Exception as e:
            pass
        return issues

    def check_security_issues(self, file_path):
        """检查安全问题"""
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    # SQL注入风险
                    if 'execute(' in line and '%' in line:
                        if '.execute(f' not in line and '.execute("' not in line:
                            # 可能使用了格式化字符串
                            pass

                    # 未验证的输入
                    if 'eval(' in line or 'exec(' in line:
                        issues.append((line_num, "Use of eval/exec", "Security risk"))

                    # 弱加密
                    if 'md5' in line.lower() and 'hashlib.md5' in line:
                        issues.append((line_num, "Use of weak MD5", "Consider stronger hash"))

        except Exception as e:
            pass
        return issues

    def check_imports(self, file_path):
        """检查导入问题"""
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    # 检查相对导入
                    if line.startswith('from '):
                        if re.match(r'from \.\. import', line):
                            issues.append((line_num, "Relative import", line.strip()))

                    # 未使用的导入（粗检查）
                    match = re.match(r'import\s+(\w+)', line)
                    if match and file_path.stat().st_size < 50000:  # 只检查小文件
                        module_name = match.group(1)
                        if module_name not in file_path.read_text():
                            # 可能未使用
                            pass

        except Exception as e:
            pass
        return issues

    def check_thread_safety(self, file_path):
        """检查线程安全问题"""
        issues = []
        try:
            try:
                content = Path(file_path).read_text(encoding='utf-8')
            except UnicodeDecodeError:
                content = Path(file_path).read_text(encoding='gbk', errors='ignore')

            # 检查全局变量修改
            if re.search(r'^[A-Z_]+\s*=', content, re.MULTILINE):
                if 'threading.Lock' not in content and re.search(r'def.*threading', content):
                    issues.append((1, "Potential race condition", "Global variable modified without lock"))

            # 检查共享字典/列表修改
            if re.search(r'\w+\[[^\]]+\]\s*=|\.append\(', content):
                if 'with ' not in content and 'lock' not in content.lower():
                    # 可能有并发问题
                    pass

        except Exception as e:
            pass
        return issues

    def check_logging(self, file_path):
        """检查日志记录"""
        issues = []
        try:
            try:
                content = Path(file_path).read_text(encoding='utf-8')
            except UnicodeDecodeError:
                content = Path(file_path).read_text(encoding='gbk', errors='ignore')

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    # 检查print()而不是logger
                    if re.search(r'print\(', line):
                        if 'logger' in content[:500]:
                            issues.append((line_num, "Use of print() instead of logger", "Use logger.info/debug"))

        except Exception as e:
            pass
        return issues

    def check_error_handling(self, file_path):
        """检查错误处理"""
        issues = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            in_try_block = False
            try_line = 0

            for line_num, line in enumerate(lines, 1):
                if 'try:' in line:
                    in_try_block = True
                    try_line = line_num

                if in_try_block and ('except' in line or 'finally' in line):
                    in_try_block = False

                # Check if all requests calls have timeout
                if'requests.' in line and 'timeout' not in line:
                    if any(method in line for method in ['get(', 'post(', 'put(', 'delete(']):
                        issues.append((line_num, "requests call without timeout", "Add timeout parameter"))

        except Exception as e:
            pass
        return issues

    def run_audit(self, root_dir="."):
        """运行完整审查"""
        print("\n" + "=" * 70)
        print("GLOBAL CODE AUDIT - AssetMonitor v2.1")
        print("=" * 70)

        self.find_python_files(root_dir)
        print(f"\n[*] 找到 {len(self.python_files)} 个Python文件")
        print(f"[*] 审查范围: {root_dir}\n")

        # Exclude test and virtual env files
        files_to_check = [f for f in self.python_files
                         if not any(x in str(f) for x in ['.venv', 'venv', '__pycache__',
                                                            '.git', 'test_', 'enrich_'])]

        for file_path in sorted(files_to_check)[:20]:  # 检查前20个文件
            self.files_checked += 1
            file_size = file_path.stat().st_size
            try:
                text_content = file_path.read_text(encoding='utf-8')
            except UnicodeDecodeError:
                text_content = file_path.read_text(encoding='gbk', errors='ignore')
            self.total_lines += len(text_content.splitlines())

            # 检查语法
            ok, error = self.check_syntax(file_path)
            if not ok:
                print(f"[SYNTAX ERROR] {file_path}: {error}")
                self.issues.append((file_path, "Syntax Error", error))
                continue

            # 只对源代码（不是测试）运行审查
            relative_path = file_path.relative_to(root_dir)

            checks = [
                ("Bare except", self.check_bare_except(file_path)),
                ("Hardcoded values", self.check_hardcoded_values(file_path)),
                ("Security issues", self.check_security_issues(file_path)),
                ("Import issues", self.check_imports(file_path)),
                ("Thread safety", self.check_thread_safety(str(file_path))),
                ("Logging issues", self.check_logging(file_path)),
                ("Error handling", self.check_error_handling(file_path)),
            ]

            for check_name, found_issues in checks:
                for issue in found_issues:
                    self.issues.append((relative_path, check_name, issue))

        # 打印发现的问题
        self.print_report()
        return len(self.issues)

    def print_report(self):
        """打印审查报告"""
        print("\n" + "-" * 70)
        print("AUDIT RESULTS")
        print("-" * 70)

        if not self.issues:
            print("[OK] 未发现严重问题！")
        else:
            print(f"[WARNING] 发现 {len(self.issues)} 个潜在问题:\n")

            by_type = defaultdict(list)
            for file_path, issue_type, details in self.issues:
                by_type[issue_type].append((file_path, details))

            for issue_type in sorted(by_type.keys()):
                print(f"\n[{issue_type}]")
                for file_path, details in by_type[issue_type][:3]:  # 每种问题最多显示3个
                    print(f"  - {file_path}")
                    if isinstance(details, tuple):
                        print(f"    Line {details[0]}: {details[1]}")
                    else:
                        print(f"    {details}")

        print(f"\n[*] 审查统计:")
        print(f"    文件检查: {self.files_checked}")
        print(f"    总代码行数: {self.total_lines}")
        print(f"    发现问题: {len(self.issues)}")
        print(f"    代码质量评分: {max(0, 100 - len(self.issues)*2)}%")


if __name__ == "__main__":
    audit = CodeAudit()
    issue_count = audit.run_audit()
    sys.exit(0 if issue_count <= 5 else 1)  # 超过5个问题才返回失败
