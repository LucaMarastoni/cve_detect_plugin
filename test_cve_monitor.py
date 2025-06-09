import os
import json
import sys
import subprocess
import pytest
from pathlib import Path

import cve_monitor as cs

# costanti per comodità
OK = cs.OK
WARNING = cs.WARNING
CRITICAL = cs.CRITICAL
UNKNOWN = cs.UNKNOWN

# Dummy runner per subprocess.run
class DummyRun:
    def __init__(self):
        self.calls = []

    def __call__(self, args, check):
        self.calls.append((args, check))


# 1) clone_or_update_repo

def test_clone_or_update_repo_clone(monkeypatch, tmp_path):
    dummy = DummyRun()
    monkeypatch.setattr(cs, "LOCAL_REPO", str(tmp_path / "repo"))
    monkeypatch.setattr(subprocess, "run", dummy)
    # directory non esiste ancora
    assert not (tmp_path / "repo").exists()
    cs.clone_or_update_repo()
    assert dummy.calls == [(["git", "clone", cs.REPO_URL, str(tmp_path / "repo")], True)]


def test_clone_or_update_repo_pull(monkeypatch, tmp_path):
    dummy = DummyRun()
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    monkeypatch.setattr(cs, "LOCAL_REPO", str(repo_dir))
    monkeypatch.setattr(subprocess, "run", dummy)
    cs.clone_or_update_repo()
    assert dummy.calls == [(["git", "-C", str(repo_dir), "pull"], True)]


# 2) load_tech_keywords

def test_load_tech_keywords_no_file(monkeypatch, tmp_path):
    monkeypatch.setattr(cs, "TECH_FILE", str(tmp_path / "nonexistent.md"))
    assert cs.load_tech_keywords() == []


def test_load_tech_keywords_table_and_plain(monkeypatch, tmp_path):
    content = """| Tech | Version | Company |
|------|---------|---------|
| Foo  | 1.2.3   | Bar     |
| Baz  |         |         |
"""
    tf = tmp_path / "tech_list.md"
    tf.write_text(content, encoding="utf-8")
    monkeypatch.setattr(cs, "TECH_FILE", str(tf))
    techs = cs.load_tech_keywords()
    assert ("foo", "1.2.3", "Bar") in techs
    assert ("baz", None, None) in techs


# 3) get_highest_cvss_score

def test_get_highest_cvss_score_empty():
    assert cs.get_highest_cvss_score([]) == 0.0


def test_get_highest_cvss_score_various():
    metrics = [
        {"cvssV3_1": {"baseScore": 5.0}},
        {"cvssV2_0": {"baseScore": 3.2}},
        {"cvssV4_0": {"baseScore": 9.1}}
    ]
    assert cs.get_highest_cvss_score(metrics) == pytest.approx(9.1)


# 4) is_version_affected

def test_is_version_affected_exact_and_less():
    vc = [
        {"status": "affected", "version": "2.0"},
        {"status": "affected", "lessThan": "3.0"},
        {"status": "unaffected", "version": "1.0"}
    ]
    assert cs.is_version_affected("2.0", vc)
    assert cs.is_version_affected("2.5", vc)
    assert not cs.is_version_affected("4.0", vc)


def test_is_version_affected_bad_input():
    assert not cs.is_version_affected("notav", [{"status": "affected", "lessThan": "1.0"}])
    assert not cs.is_version_affected("1.0", [{"status": "affected", "lessThan": "notav"}])


# 5) find_recent_json_files

def test_find_recent_json_files_error(monkeypatch):
    def raise_cp(cmd, text):
        raise subprocess.CalledProcessError(1, cmd)
    monkeypatch.setattr(subprocess, "check_output", raise_cp)
    assert cs.find_recent_json_files() == []


def test_find_recent_json_files_success(monkeypatch, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "a.json").write_text("{}", encoding="utf-8")
    (repo / "b.txt").write_text("ignore", encoding="utf-8")
    (repo / "c.json").write_text("{}", encoding="utf-8")
    monkeypatch.setattr(cs, "LOCAL_REPO", str(repo))
    out = "a.json\nb.txt\nc.json\n"
    monkeypatch.setattr(subprocess, "check_output", lambda *args, **kwargs: out)
    files = cs.find_recent_json_files()
    names = sorted([p.name for p in files])
    assert names == ["a.json", "c.json"]


# 6) scan_file

def make_json(tmp_path, data):
    p = tmp_path / "test.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def test_scan_file_no_score(tmp_path):
    data = {"containers": {"cna": {"metrics": [], "affected": [], "title": "t"}}}
    p = make_json(tmp_path, data)
    assert cs.scan_file(p, [("foo", None, None)]) is None


def test_scan_file_match(tmp_path):
    metrics = [{"cvssV3_1": {"baseScore": 5.0}}]
    affected = [{
        "vendor": "Foo",
        "product": "App",
        "versions": [{"status": "affected", "lessThan": "2.0"}]
    }]
    data = {
        "containers": {
            "cna": {
                "metrics": metrics,
                "affected": affected,
                "title": "Example CVE"
            }
        }
    }
    p = make_json(tmp_path, data)
    res = cs.scan_file(p, [("foo app", None, "SomeCo")])
    assert res == ("foo app", None, "SomeCo", "Example CVE", 5.0)


# 7) main()

def run_main(capsys, monkeypatch, args, techs, files, scans):
    monkeypatch.setattr(cs, "clone_or_update_repo", lambda: None)
    monkeypatch.setattr(cs, "load_tech_keywords", lambda: techs)
    monkeypatch.setattr(cs, "find_recent_json_files", lambda: files)
    monkeypatch.setattr(cs, "scan_file", lambda jf, ts: scans.get(jf, None))
    monkeypatch.setattr(sys, "argv", ["prog"] + args)
    with pytest.raises(SystemExit) as se:
        cs.main()
    return se.value.code, capsys.readouterr().out.strip()


def test_main_no_techs(capsys, monkeypatch):
    code, out = run_main(capsys, monkeypatch, [], [], [], {})
    assert code == UNKNOWN
    assert "UNKNOWN - tech_list.md mancante o vuoto" in out


def test_main_no_matches(capsys, monkeypatch):
    code, out = run_main(capsys, monkeypatch, [], [("t", None, None)], [], {})
    assert code == OK
    assert "OK - nessuna CVE critica trovata" in out


def test_main_company_filter_no_matches(capsys, monkeypatch):
    code, out = run_main(capsys, monkeypatch, ["-c", "X"], [("t", None, "X")], [], {})
    assert code == OK
    assert "OK - nessuna CVE critica trovata per azienda: X" in out


def test_main_with_matches(capsys, monkeypatch, tmp_path):
    f1 = tmp_path / "f1.json"
    f2 = tmp_path / "f2.json"
    scans = {
        f1: ("tech1", "1.0", "Co1", "T1", 8.0),
        f2: ("tech2", None, "Co2", "T2", 9.5)
    }
    code, out = run_main(
        capsys, monkeypatch,
        [], [("t", None, None)], [f1, f2], scans
    )
    assert code == CRITICAL
    assert "WARNING - TECH1 1.0" in out
    assert "CRITICAL - TECH2" in out


def test_main_with_company_filter_match(capsys, monkeypatch, tmp_path):
    f1 = tmp_path / "f1.json"
    f2 = tmp_path / "f2.json"
    scans = {
        f1: ("tech1", None, "CoA", "T1", 5.0),
        f2: ("tech2", None, "CoB", "T2", 5.0)
    }
    code, out = run_main(
        capsys, monkeypatch,
        ["-c", "CoA"], [("t", None, None)], [f1, f2], scans
    )
    # rimane solo CoA, baseScore < 9 => WARNING
    assert code == WARNING
    assert "WARNING" in out
    assert "T1" in out
