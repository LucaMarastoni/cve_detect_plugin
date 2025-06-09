# cve\_detect\_plugin

**Script**: `cve_monitor.py`

CVE Detector is a Python script that periodically monitors new critical vulnerabilities published in the [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5) repository. It filters alerts based on technology, version, and optionally company, and provides output compatible with Nagios.

---

## 🚀 Features

* **Clone & update** the `CVEProject/cvelistV5` repository locally.
* Detect JSON files **added in the last 7 days** using `git log --diff-filter=A --since="7 days ago"`.
* From each CVE record, extract:

  * The **highest CVSS score** available (V4.0 → V3.1 → V3.0 → V2.0).
  * The list of **affected vendor/product** combinations with their version constraints.
  * The CVE **title** and metadata.
* Compare affected versions against the **technology/version** pairs defined in `tech_list.md`:

  * If a version is specified, only CVEs impacting that version are reported.
  * If no version is given, all CVEs for that technology are considered.
* Support for **company filtering** via `-c`/`--company` (case-insensitive).
* Generates a **Nagios-style** summary with exit codes:

  * `0 (OK)`: no critical CVEs found
  * `1 (WARNING)`: CVSS ≥ 7.0 and < 9.0
  * `2 (CRITICAL)`: CVSS ≥ 9.0
  * `3 (UNKNOWN)`: configuration error or missing files

---

## 📋 Requirements

* **Python** 3.6 or higher
* **Git** CLI installed and available in `$PATH`
* Python package **`packaging`** (for version comparison)
* UNIX-like environment (Linux or macOS)

Dependencies are listed in `requirements.txt`:

```text
packaging
```

---

## 📂 Repository Structure

```plaintext
cve_detect_plugin/           # Plugin root folder
├── cve_monitor.py            # Main monitoring script
├── tech_list.md              # Technology/version list (Markdown)
├── requirements.txt          # Python dependencies
└── README.md                 # Documentation (this file)
```

---

## 📝 tech\_list.md Format

The `tech_list.md` file uses a simple Markdown table format. The parser automatically skips the first two header rows if they start with `|`.

```markdown
| Technology | Version | Company |
|------------|---------|---------|
| nginx      | 1.1.3   |         |
| apache     | 2.4.52  |         |
| log4j      |         |         |
| mylib      | 3.0     | MyCorp  |
```

* **Technology**: name of the technology (case-insensitive substring match)
* **Version** (optional): specific version to monitor
* **Company** (optional): company name for additional filtering

---

## 🔧 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/LucaMarastoni/cve_detect_plugin.git
cd cve_detect_plugin
python3 -m pip install --user -r requirements.txt
chmod +x cve_monitor.py
```

---

## ⚙️ Configuration

1. Edit **`tech_list.md`** according to the format above.
2. (Optional) Adjust CVSS thresholds in `cve_monitor.py` if different sensitivity is required:

   * Minimum score to report: `score < 1.0` filters out only scores below 1 by default.
   * **WARNING** range: `7.0 ≤ score < 9.0`
   * **CRITICAL** range: `score ≥ 9.0`

---

## ▶️ Usage

Run the script manually or via a scheduler:

```bash
./cve_monitor.py [-c COMPANY_NAME]
```

* `-c`, `--company`: (optional) filter CVEs by company name (case-insensitive).

### Sample Outputs

* **OK** (no critical CVEs found):

  ```text
  OK - no critical CVEs found
  ```

* **WARNING** (CVSS 7.0–8.9):

  ```text
  WARNING - 2 CVEs detected:
  - NGINX 1.1.3 | Company: N/A | CVSS: 7.2 | HTTP/2 RCE vulnerability | File: CVE-2025-48210.json
  - LOG4J | Company: N/A | CVSS: 8.0 | Remote code execution | File: CVE-2025-48300.json
  ```

* **CRITICAL** (CVSS ≥ 9.0):

  ```text
  CRITICAL - 1 CVE detected:
  - APACHE 2.4.52 | Company: N/A | CVSS: 9.1 | Directory traversal in mod_proxy | File: CVE-2025-48222.json
  ```

* **Company filter**:

  ```text
  OK - no critical CVEs found for company: MyCorp
  ```

---

## ⏰ Scheduling with Cron

To run daily at 00:10 and log output:

```cron
10 0 * * * /usr/bin/env python3 /path/to/cve_detect_plugin/cve_monitor.py \
    >> /var/log/cve_monitor.log 2>&1
```

Ensure the cron user has read/write permissions on the log path.

---

## 📊 Exit Codes

| Code | Meaning                                       |
| ---: | --------------------------------------------- |
|    0 | OK: no critical CVEs found                    |
|    1 | WARNING: CVSS ≥ 7.0 and < 9.0                 |
|    2 | CRITICAL: CVSS ≥ 9.0                          |
|    3 | UNKNOWN: configuration error or missing files |

---

## 🛠 Troubleshooting

* Check new files with:

  ```bash
  git -C cvelistV5 log --since="7 days ago" --diff-filter=A
  ```
  
* Run `cve_monitor.py` with debug prints by editing the script.
