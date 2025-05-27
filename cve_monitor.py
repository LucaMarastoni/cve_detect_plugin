import os
import subprocess
import json
import sys
import argparse
from packaging import version
from pathlib import Path

REPO_URL = "https://github.com/CVEProject/cvelistV5.git"
LOCAL_REPO = "cvelistV5"
TECH_FILE = "tech_list.md"


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
    techs = []
    with open(TECH_FILE, encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]
    if len(lines) >= 2 and lines[0].startswith("|") and lines[1].startswith("|"):
        lines = lines[2:]
    for line in lines:
        parts = [p.strip() for p in line.strip('|').split('|')]
        if len(parts) >= 2:
            tech_name = parts[0].lower()
            tech_version = parts[1] or None
            company = parts[2] if len(parts) >= 3 and parts[2] else None
            techs.append((tech_name, tech_version, company))
    return techs

def find_recent_json_files():
    cmd = [
        "git", "-C", LOCAL_REPO,
        "log",
        "--since=7 days ago",
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
        for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
            if key in m and "baseScore" in m[key]:
                scores.append(m[key]["baseScore"])
    return max(scores) if scores else 0.0

def is_version_affected(version_str, version_constraints):
    try:
        user_version = version.parse(version_str)
    except Exception:
        return False
    for v in version_constraints:
        if v.get("status") != "affected":
            continue
        v_exact = v.get("version")
        v_less = v.get("lessThan")
        if v_exact and v_exact != "0":
            try:
                if user_version == version.parse(v_exact):
                    return True
            except Exception:
                pass
        if v_less:
            try:
                if user_version < version.parse(v_less):
                    return True
            except Exception:
                pass
    return False

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
        for tech_name, tech_version, company in techs:
            if tech_name in joined:
                if tech_version is None or is_version_affected(tech_version, versions):
                    title = cna.get("title", "")
                    return tech_name, tech_version, company, title, score
    return None

def main():
    parser = argparse.ArgumentParser(description="Scan CVE recenti filtrando per tecnologia e azienda.")
    parser.add_argument('-c', '--company', help='Filtra le CVE per nome azienda (case-insensitive)')
    args = parser.parse_args()

    clone_or_update_repo()
    techs = load_tech_keywords()
    if not techs:
        print("UNKNOWN - tech_list.md mancante o vuoto")
        sys.exit(UNKNOWN)
    files = find_recent_json_files()
    matches = []
    for jf in files:
        res = scan_file(jf, techs)
        if res:
            matches.append((jf, *res))

    if args.company:
        filtered = []
        for path, tech, version_val, company, title, score in matches:
            if company and company.lower() == args.company.lower():
                filtered.append((path, tech, version_val, company, title, score))
        matches = filtered

    if not matches:
        if args.company:
            print(f"OK - nessuna CVE critica trovata per azienda: {args.company}")
        else:
            print("OK - nessuna CVE critica trovata")
        sys.exit(OK)

    exit_code = OK
    for path, tech, version_val, company, title, score in matches:
        sev = CRITICAL if score >= 9 else WARNING
        exit_code = max(exit_code, sev)
        version_str = f" {version_val}" if version_val else ""
        company_str = f"Azienda: {company}" if company else "Azienda: N/D"
        status_str = "CRITICAL" if sev == CRITICAL else "WARNING"
        print(f"{status_str} - {tech.upper()}{version_str} | {company_str} | CVSS: {score} | {title.strip()} | File: {path.name}")
        sys.exit(exit_code)

if __name__ == "__main__":
    main()
