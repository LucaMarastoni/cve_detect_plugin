# cve\_detect\_plugin

**Script**: `cve_monitor.py`

CVE Detector is a Python script that daily monitors new critical vulnerabilities (CVEs) published in the [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) repository. It filters alerts by technology and version of interest, and outputs results in a Nagios-compatible format.

---

## 🚀 Features

* **Clone & update** the `CVEProject/cvelistV5` repository locally.
* Detect JSON files **added** in the last 24 hours using `git log --diff-filter=A`.
* Extract from each CVE record:

  * The **highest CVSS score** available (V4.0 → V3.1 → V3.0 → V2.0).
  * The list of **affected vendor/product combinations** and their version constraints.
  * The CVE **title** and metadata.
* Compare each CVE’s affected versions against the **technology/version pairs** defined in `tech_list.txt`:

  * If a version is specified, only CVEs impacting that version are reported.
  * If no version is given, all CVEs for that technology are considered.
* Produce a **Nagios-style** summary with exit codes:

  * `0 (OK)`: no critical CVEs found
  * `1 (WARNING)`: CVSS ≥ 7.0 and < 9.0
  * `2 (CRITICAL)`: CVSS ≥ 9.0
  * `3 (UNKNOWN)`: configuration error or missing files

---

## 📋 Requirements

* **Python** 3.6 or higher
* **Git** CLI installed and in `$PATH`
* Python package **`packaging`** (for version comparison)
* UNIX-like environment (Linux or macOS)

Dependencies are listed in `requirements.txt`:

```text
packaging
```

---

## 📂 Repository Structure

```
cve_detect_plugin/             # Root folder
├── cve_monitor.py        # Main monitoring script
├── tech_list.txt         # Technology and version list (one per line)
├── requirements.txt      # Python dependencies
└── README.md             # Documentation (this file)
```

* **`tech_list.txt`** format:

  ```text
  <technology> [version]
  ```

  Examples:

  ```text
  nginx 1.1.3
  apache 2.4.52
  log4j
  ```

---

## 🔧 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/LucaMarastoni/cve_detect_plugin.git
cd cve_detector
python3 -m pip install --user -r requirements.txt
chmod +x cve_monitor.py
```

---

## ⚙️ Configuration

1. Edit **`tech_list.txt`** and list each technology on its own line. Optionally append a specific version separated by a space.
2. (Optional) Adjust CVSS thresholds in `cve_monitor.py` if you need different sensitivity:

   * Minimum CVSS to report: `score < 1.0` in code (default filters out only score < 1)
   * `WARNING` range: `7.0 ≤ score < 9.0`
   * `CRITICAL` range: `score ≥ 9.0`

---

## ▶️ Usage

Run the script manually or via scheduler:

```bash
./cve_monitor.py
```

### Sample Outputs

* **OK** (no critical CVEs):

  ```text
  OK - no critical CVEs found
  ```

* **WARNING** (CVSS 7–8.9):

  ```text
  WARNING - 2 CVEs detected:
  - NGINX 1.1.3 | CVSS: 7.2 | HTTP/2 RCE vulnerability | File: CVE-2025-48210.json
  - LOG4J | CVSS: 8.0 | Remote code execution | File: CVE-2025-48300.json
  ```

* **CRITICAL** (CVSS ≥ 9.0):

  ```text
  CRITICAL - 1 CVE detected:
  - APACHE 2.4.52 | CVSS: 9.1 | Directory traversal in mod_proxy | File: CVE-2025-48222.json
  ```

---

## ⏰ Scheduling with Cron

To run daily at 00:10 and log output:

```cron
10 0 * * * /usr/bin/env python3 /path/to/cve_detector/cve_monitor.py \
    >> /var/log/cve_monitor.log 2>&1
```

Ensure the cron user has read/write permissions on the log path.

---

## 📊 Exit Codes

| Code | Meaning                                      |
| ---: | -------------------------------------------- |
|    0 | OK: no critical CVEs found                   |
|    1 | WARNING: CVSS ≥ 7.0 and < 9.0                |
|    2 | CRITICAL: CVSS ≥ 9.0                         |
|    3 | UNKNOWN: configuration error or missing file |

---

## 🛠 Troubleshooting

* Validate new files with:

  ```bash
  git -C cvelistV5 log --since="24 hours ago" --diff-filter=A
  ```
* Run `cve_monitor.py` with debug prints by editing the script.

---

## 📝 License

This project is licensed under the MIT License. © 2025 Luca Marastoni
