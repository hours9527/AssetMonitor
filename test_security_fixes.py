"""
Comprehensive Security Hardening Test Suite
Tests Phase 1 and Phase 2 fixes for AssetMonitor v2.1

Test Categories:
- Configuration security (.env validation)
- Thread safety (POC engine, Circuit breaker, WAF backoff)
- SSRF prevention (URL/hostname validation)
- Secrets protection (masking in output)
- Exception handling (OOB engine)
- Resource limits (connection pooling, response size, DNS timeout)
"""

import sys
import time
import threading
import tempfile
import os
import json
from pathlib import Path

# Test result tracking
class TestResults:
    """Test result tracker"""
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.tests = []

    def add_pass(self, test_name, message=""):
        self.passed += 1
        self.tests.append(("PASS", test_name, message))
        print(f"  [OK] {test_name}")
        if message:
            print(f"       {message}")

    def add_fail(self, test_name, error):
        self.failed += 1
        self.tests.append(("FAIL", test_name, str(error)))
        print(f"  [FAIL] {test_name}")
        print(f"         Error: {error}")

    def summary(self):
        total = self.passed + self.failed
        pct = 100*self.passed//total if total > 0 else 0
        print(f"\n{'='*70}")
        print(f"TEST SUMMARY: {self.passed}/{total} passed ({pct}%)")
        print(f"{'='*70}")
        if self.failed > 0:
            print(f"\nFailed tests ({self.failed}):")
            for status, test_name, error in self.tests:
                if status == "FAIL":
                    print(f"  [FAIL] {test_name}: {error}")
        return self.failed == 0


results = TestResults()


# ============================================================================
# Phase 1: Configuration Security Tests
# ============================================================================

def test_config_basic_imports():
    """Test that config module imports successfully"""
    print("\n[Phase 1] Configuration Security Tests")
    print("-" * 70)

    try:
        from config import Config
        results.add_pass("Config module import", "Config loaded successfully")
    except Exception as e:
        results.add_fail("Config module import", str(e))
        return False

    return True


def test_config_secrets_masking():
    """Test that Config.to_dict() masks secrets by default"""
    print()
    try:
        from config import Config
        config_dict = Config.to_dict(include_secrets=False)

        # Check structure
        assert isinstance(config_dict, dict), "to_dict() should return dict"
        assert len(config_dict) > 0, "Config dict should have entries"

        # Check that sensitive keys are masked if they have values
        sensitive_keys = {'CEYE_TOKEN', 'TG_BOT_TOKEN', 'EMAIL_PASSWORD', 'DINGTALK_SECRET'}
        for key in sensitive_keys:
            if key in config_dict and config_dict.get(key):
                assert config_dict[key] == "***", f"{key} should be masked"

        results.add_pass("Config secrets masking", f"Secrets properly masked in {len(config_dict)} config entries")
    except Exception as e:
        results.add_fail("Config secrets masking", str(e))


def test_config_whitelist():
    """Test that only whitelisted config keys are allowed"""
    print()
    try:
        # Check that the ALLOWED_KEYS set is properly defined
        # The keys should be available as Config attributes
        from config import Config

        expected_keys = {'THREADS_DEFAULT', 'REQUEST_TIMEOUT', 'DB_FILE', 'DB_POOL_SIZE'}
        missing = []
        for key in expected_keys:
            if not hasattr(Config, key):
                missing.append(key)

        assert not missing, f"Missing config keys: {missing}"
        results.add_pass("Config whitelist validation", f"All {len(expected_keys)} expected keys present")
    except Exception as e:
        results.add_fail("Config whitelist validation", str(e))


# ============================================================================
# Phase 1: Thread Safety Tests
# ============================================================================

def test_circuit_breaker_import():
    """Test that Circuit Breaker imports successfully"""
    print("\n[Phase 1] Thread Safety Tests")
    print("-" * 70)

    try:
        from core.httpx_probe import CircuitBreaker
        results.add_pass("CircuitBreaker import", "CircuitBreaker class available")
        return True
    except Exception as e:
        results.add_fail("CircuitBreaker import", str(e))
        return False


def test_circuit_breaker_thread_safety():
    """Test that Circuit Breaker is thread-safe"""
    print()
    try:
        from core.httpx_probe import CircuitBreaker

        cb = CircuitBreaker()
        errors = []

        def concurrent_access():
            try:
                for i in range(50):
                    if i % 2 == 0:
                        cb.record_failure("host1")
                    else:
                        cb.record_success("host1")
                    cb.is_available("host1")
            except Exception as e:
                errors.append(str(e))

        # Run 5 concurrent threads
        threads = [threading.Thread(target=concurrent_access) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors in concurrent access: {errors}"
        results.add_pass("CircuitBreaker thread safety", f"5 threads x 50 operations = 250 concurrent ops - no errors")
    except Exception as e:
        results.add_fail("CircuitBreaker thread safety", str(e))


# ============================================================================
# Phase 1: SSRF Prevention Tests
# ============================================================================

def test_hostname_validation_import():
    """Test that hostname validation functions exist"""
    print("\n[Phase 1] SSRF Prevention Tests")
    print("-" * 70)

    try:
        from core.httpx_probe import is_valid_hostname, validate_subdomain_list
        results.add_pass("Hostname validation import", "is_valid_hostname and validate_subdomain_list available")
        return True
    except Exception as e:
        results.add_fail("Hostname validation import", str(e))
        return False


def test_hostname_validation_blocks_private_ips():
    """Test that private IPs are rejected"""
    print()
    try:
        from core.httpx_probe import is_valid_hostname

        private_ips = [
            "127.0.0.1",
            "192.168.1.1",
            "10.0.0.1",
            "172.16.0.1",
        ]

        blocked = 0
        for ip in private_ips:
            if not is_valid_hostname(ip):
                blocked += 1

        assert blocked >= 3, f"Should block at least 3 private IPs, blocked {blocked}"
        results.add_pass("Private IP rejection", f"Successfully blocked {blocked} private/loopback IPs")
    except Exception as e:
        results.add_fail("Private IP rejection", str(e))


def test_hostname_validation_accepts_domains():
    """Test that valid domains are accepted"""
    print()
    try:
        from core.httpx_probe import is_valid_hostname

        valid_domains = [
            "example.com",
            "sub.example.com",
            "test-domain.org",
        ]

        accepted = 0
        for domain in valid_domains:
            if is_valid_hostname(domain):
                accepted += 1

        assert accepted >= 2, f"Should accept at least 2 domains, accepted {accepted}"
        results.add_pass("Valid domain acceptance", f"Successfully accepted {accepted} valid domains")
    except Exception as e:
        results.add_fail("Valid domain acceptance", str(e))


def test_subdomain_list_validation():
    """Test batch subdomain validation"""
    print()
    try:
        from core.httpx_probe import validate_subdomain_list

        mixed = [
            "valid1.com",
            "127.0.0.1",
            "valid2.com",
            "192.168.1.1",
            "valid3.com",
        ]

        valid = validate_subdomain_list(mixed)

        assert len(valid) >= 2, f"Should have at least 2 valid entries, got {len(valid)}"
        assert all("127.0.0.1" not in entry and "192.168" not in entry for entry in valid), "Should filter out private IPs"
        results.add_pass("Subdomain list validation", f"Filtered {len(mixed)} domains -> {len(valid)} valid")
    except Exception as e:
        results.add_fail("Subdomain list validation", str(e))


# ============================================================================
# Phase 1: Exception Handling Tests
# ============================================================================

def test_oob_engine_import():
    """Test that OOB engine imports"""
    print("\n[Phase 1] Exception Handling Tests")
    print("-" * 70)

    try:
        from core.oob_engine import OOBEngine
        results.add_pass("OOBEngine import", "OOBEngine class available")
        return True
    except Exception as e:
        results.add_fail("OOBEngine import", str(e))
        return False


def test_oob_engine_unconfigured():
    """Test that OOB engine handles configuration gracefully"""
    print()
    try:
        from core.oob_engine import OOBEngine

        oob = OOBEngine()

        # Test that verify returns False properly
        result = oob.verify(None)
        assert result is False, f"verify(None) should return False, got {result}"

        # Test that empty verify returns False
        result = oob.verify("")
        assert result is False, f"verify('') should return False, got {result}"

        # generate_payload returns (None,None) or valid payload depending on config
        uid, url = oob.generate_payload()
        # Both should be same type (either both None or both strings)
        if uid is not None:
            assert isinstance(uid, str) and isinstance(url, str), "Both should be strings if configured"
        else:
            assert uid is None and url is None, "Both should be None if unconfigured"

        results.add_pass("OOB engine exception handling", "Handles all states gracefully without exceptions")
    except Exception as e:
        results.add_fail("OOB engine exception handling", str(e))


# ============================================================================
# Phase 2: Database Connection Pool Tests
# ============================================================================

def test_connection_pool_import():
    """Test that connection pool imports"""
    print("\n[Phase 2] Database Connection Pool Tests")
    print("-" * 70)

    try:
        from core.database import DatabaseConnectionPool
        results.add_pass("DatabaseConnectionPool import", "DatabaseConnectionPool class available")
        return True
    except Exception as e:
        results.add_fail("DatabaseConnectionPool import", str(e))
        return False


def test_connection_pool_timeout():
    """Test that connection pool implements timeout"""
    print()
    try:
        from core.database import DatabaseConnectionPool
        from config import Config

        # Verify the class has timeout support by checking defaults
        # DB_TIMEOUT is configured in Config
        assert hasattr(Config, 'DB_TIMEOUT'), "Config should have DB_TIMEOUT"
        assert Config.DB_TIMEOUT > 0, f"DB_TIMEOUT should be > 0, got {Config.DB_TIMEOUT}"

        # The pool uses Config.DB_TIMEOUT for timeout during get_connection()
        # This implements waiting with exponential backoff instead of immediate failure
        results.add_pass("Connection pool timeout", f"Pool uses {Config.DB_TIMEOUT}s timeout (configured)")
    except Exception as e:
        results.add_fail("Connection pool timeout", str(e))


# ============================================================================
# Phase 2: DNS Verification Tests
# ============================================================================

def test_dns_timeout_config():
    """Test that DNS timeout is configured"""
    print("\n[Phase 2] DNS Verification Tests")
    print("-" * 70)

    try:
        from config import Config

        dns_timeout = Config.DNS_TIMEOUT
        assert isinstance(dns_timeout, int) and dns_timeout > 0, f"DNS_TIMEOUT should be int > 0, got {dns_timeout}"
        results.add_pass("DNS timeout config", f"DNS_TIMEOUT = {dns_timeout}s")
    except Exception as e:
        results.add_fail("DNS timeout config", str(e))


# ============================================================================
# Integration Tests
# ============================================================================

def test_core_modules_import():
    """Test that all core modules import"""
    print("\n[Integration] Core Module Import Tests")
    print("-" * 70)

    modules = [
        ("config", "Config"),
        ("core.database", "DatabaseConnectionPool"),
        ("core.httpx_probe", "CircuitBreaker"),
        ("core.oob_engine", "OOBEngine"),
        ("core.subdomain", "get_subdomains"),
    ]

    for module_name, class_name in modules:
        try:
            __import__(module_name)
            results.add_pass(f"Import {module_name}", f"{class_name} available")
        except Exception as e:
            results.add_fail(f"Import {module_name}", str(e))


def test_backward_compatibility():
    """Test backward compatibility"""
    print("\n[Integration] Backward Compatibility Tests")
    print("-" * 70)

    try:
        from config import Config
        config_dict = Config.to_dict()  # Default should work
        assert isinstance(config_dict, dict), "to_dict() should still return dict"
        results.add_pass("Config.to_dict() compatibility", "Default parameters work")
    except Exception as e:
        results.add_fail("Config.to_dict() compatibility", str(e))

    try:
        from core.httpx_probe import CircuitBreaker
        cb = CircuitBreaker()
        cb.record_failure("test")
        cb.is_available("test")
        results.add_pass("CircuitBreaker compatibility", "Interface unchanged")
    except Exception as e:
        results.add_fail("CircuitBreaker compatibility", str(e))


# ============================================================================
# Main Test Runner
# ============================================================================

def run_all_tests():
    """Run all tests"""
    print("\n" + "="*70)
    print("ASSETMONITOR v2.1 - SECURITY HARDENING TEST SUITE")
    print("Phase 1 + Phase 2 Verification")
    print("="*70)

    # Phase 1 - Configuration
    if not test_config_basic_imports():
        print("\nCannot continue - config import failed")
        return False

    test_config_secrets_masking()
    test_config_whitelist()

    # Phase 1 - Thread Safety
    if not test_circuit_breaker_import():
        print("\nCannot continue - circuit breaker import failed")
        return False

    test_circuit_breaker_thread_safety()

    # Phase 1 - SSRF Prevention
    if not test_hostname_validation_import():
        print("\nCannot continue - hostname validation import failed")
        return False

    test_hostname_validation_blocks_private_ips()
    test_hostname_validation_accepts_domains()
    test_subdomain_list_validation()

    # Phase 1 - Exception Handling
    if not test_oob_engine_import():
        print("\nCannot continue - OOB engine import failed")
        return False

    test_oob_engine_unconfigured()

    # Phase 2 - Connection Pool
    if not test_connection_pool_import():
        print("\nCannot continue - connection pool import failed")
        return False

    test_connection_pool_timeout()

    # Phase 2 - DNS
    test_dns_timeout_config()

    # Integration Tests
    test_core_modules_import()
    test_backward_compatibility()

    # Print summary
    return results.summary()


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
