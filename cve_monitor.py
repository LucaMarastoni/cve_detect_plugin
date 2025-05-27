import os
import subprocess
import json
import sys
from packaging import version
from pathlib import Path
from datetime import datetime, timedelta

REPO_URL = "https://github.com/CVEProject/cvelistV5.git"
LOCAL_REPO = "cvelistV5"
TECH_FILE = "tech_list.txt"

# Codici di Nagios
OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3

def clone_or_update_repo():
    if not os.path.exists(LOCAL_REPO):
        subprocess.run(["git", "clone", REPO_URL, LOCAL_REPO], check=True)
    else:
        subprocess.run(["git", "-C", LOCAL_REPO, "pull"], check=True)

def load_tech_keywords():
    if not os.path.exists(TECH_FILE):
        return []
    keywords = []
    with open(TECH_FILE) as f:
        for line in f:
            parts = line.strip().lower().split()
            if len(parts) == 2:
                keywords.append((parts[0], parts[1]))
            elif len(parts) == 1:
                keywords.append((parts[0], None))
    return keywords

def find_recent_json_files():
    cmd = [
        "git", "-C", LOCAL_REPO,
        "log",
        "--since=24 hours ago",
        "--diff-filter=A",
        "--name-only",
        "--pretty="
    ]
    try:
        out = subprocess.check_output(cmd, text=True)
    except subprocess.CalledProcessError:
        return []
    files = set()
    for line in out.splitlines():
        if line.strip().endswith(".json"):
            path = Path(LOCAL_REPO) / line.strip()
            if path.exists():
                files.add(path)
    return list(files)

def get_highest_cvss_score(metrics):
    scores = []
    for m in metrics:
        for key in ("cvssV4_0","cvssV3_1","cvssV3_0","cvssV2_0"):
            if key in m and "baseScore" in m[key]:
                scores.append(m[key]["baseScore"])
    return max(scores) if scores else 0.0

def get_affected(cna):
    affected = []
    for a in cna.get("affected", []):
        vendor = a.get("vendor", "").strip()
        product = a.get("product", "").strip()
        versions = a.get("versions", [])
        is_affected = any(v.get("status") == "affected" for v in versions)

        if vendor and product and is_affected:
            affected.append(f"{vendor} {product}")
    return affected


def scan_file(json_path, techs):
    with open(json_path) as f:
        data = json.load(f)
    cna = data.get("containers", {}).get("cna", {})
    score = get_highest_cvss_score(cna.get("metrics", []))
    if score < 1.0:
        return None

    for a in cna.get("affected", []):
        vendor = a.get("vendor", "").lower()
        product = a.get("product", "").lower()
        joined = f"{vendor} {product}".strip()
        versions = a.get("versions", [])

        for tech_name, tech_version in techs:
            if tech_name in joined:
                if tech_version is None or is_version_affected(tech_version, versions):
                    title = cna.get("title", "")
                    return tech_name, tech_version, title, score

    return None


def is_version_affected(version_str, version_constraints):

    try:
        user_version = version.parse(version_str)
    except Exception:
        return False

    for v in version_constraints:
        status = v.get("status", "")
        if status != "affected":
            continue
        v_exact = v.get("version")
        v_less = v.get("lessThan")

        if v_exact and v_exact != "0":
            try:
                if user_version == version.parse(v_exact):
                    return True
            except Exception:
                continue
        if v_less:
            try:
                if user_version < version.parse(v_less):
                    return True
            except Exception:
                continue
    return False



def main():
    clone_or_update_repo()
    techs = load_tech_keywords()
    if not techs:
        print("UNKNOWN - tech_list.txt mancante o vuoto")
        sys.exit(UNKNOWN)

    files = find_recent_json_files()
    matches = []
    for jf in files:
        res = scan_file(jf, techs)
        if res:
            matches.append((jf, *res)) 

    if not matches:
        print("OK - nessuna CVE critica trovata")
        sys.exit(OK)

    exit_code = OK
    formatted_output = []
    for path, tech, version, title, score in matches:
        sev = CRITICAL if score >= 9 else WARNING
        exit_code = max(exit_code, sev)
        version_str = f" {version}" if version else ""
        formatted_output.append(
            f"- {tech.upper()}{version_str} | CVSS: {score} | {title.strip()} | File: {path.name}"
        )

    status_str = "CRITICAL" if exit_code == CRITICAL else "WARNING"
    print(f"{status_str} - {len(matches)} CVE critiche trovate:")
    print("\n".join(formatted_output))
    sys.exit(exit_code)

main()