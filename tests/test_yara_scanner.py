"""Tests for YARA Scanner"""

import os
import sys
import tempfile
import shutil
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from yara_scanner import YaraScanner


@pytest.fixture
def temp_rules_dir():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d)


@pytest.fixture
def scanner(temp_rules_dir):
    return YaraScanner(rules_dir=temp_rules_dir)


class TestYaraScanner:
    def test_creates_sample_rules(self, temp_rules_dir):
        scanner = YaraScanner(rules_dir=temp_rules_dir)
        yar_files = [f for f in os.listdir(temp_rules_dir) if f.endswith(".yar")]
        assert len(yar_files) >= 1

    def test_get_stats(self, scanner):
        stats = scanner.get_stats()
        assert "files_scanned" in stats
        assert "matches_found" in stats
        assert "yara_available" in stats
        assert "rules_compiled" in stats

    def test_scan_nonexistent_file(self, scanner):
        results = scanner.scan_file("/nonexistent/file.exe")
        assert results == []

    def test_scan_empty_directory(self, scanner):
        d = tempfile.mkdtemp()
        results = scanner.scan_directory(d)
        shutil.rmtree(d)
        assert results == []

    def test_scan_nonexistent_directory(self, scanner):
        results = scanner.scan_directory("/nonexistent/dir")
        assert results == []

    def test_get_recent_results(self, scanner):
        results = scanner.get_recent_results()
        assert isinstance(results, list)

    def test_hash_file(self):
        f = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        f.write(b"test content")
        f.close()
        h = YaraScanner._hash_file(f.name)
        assert len(h) == 64  # SHA-256 hex
        os.unlink(f.name)

    def test_hash_nonexistent_file(self):
        h = YaraScanner._hash_file("/nonexistent")
        assert h == ""

    def test_reload_rules(self, scanner):
        scanner.reload_rules()
        stats = scanner.get_stats()
        assert "rules_compiled" in stats
