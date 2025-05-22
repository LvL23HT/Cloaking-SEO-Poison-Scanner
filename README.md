# 🕵️ Cloaking & SEO Poison Scanner v1.3

A powerful forensic tool to detect cloaking, blackhat SEO tricks, malware-laced redirections and risky file downloads — with automatic VirusTotal integration.

---

## ✨ Features

- 🔎 Detects **cloaking** via content comparison (Googlebot vs Real UA)
- 🔁 Detects suspicious **redirects** to external sites or malicious filetypes
- 📜 Flags **JavaScript obfuscation**: `eval`, `setTimeout`, `window.location`, etc.
- 🧪 Identifies **base64 encoded payloads** (decoded preview shown)
- 🪟 Finds **hidden iframes** and `<meta refresh>` redirects
- 📥 Automatically downloads risky files: `.exe`, `.apk`, `.sh`, `.ipa`, etc.
- 🔐 Calculates SHA256 hash and checks file with **VirusTotal API**
- ⚠️ Copies confirmed malicious files to a dedicated quarantine folder
- 📁 Exports structured reports: `report.txt`, `report.json`, `exports/report.csv`

---

## 🧪 Example Terminal Output

```
🔐 Cloaking & SEO POISON SCANNER - v1.3
--------------------------------------------
▸ Detects: cloaking, redirections, malware
▸ Flags: obfuscation, JS, iframes, base64
▸ Downloads risky files, VT integration

🌐 URL: http://example.com/cloaked-page
🔍 Similarity: 7.8% → 🛑 CLOAKING
🔁 Redirected to: http://example.com/cloaked-page → ✅ Normal
🧠 BlackHat Keywords: crack, patch
📜 Suspicious JS: setTimeout(, window.location
🧪 Base64 Decoded Snippet:
   ↳ <script src='http://malicious[.]site/load.js'>
🪟 Hidden <iframe> detected!
🔄 Meta Refresh redirection found!
🚨 HIGH-RISK FILE DETECTED & DOWNLOADED!
🔗 URL: http://malicious.site/dropper.exe
📁 Saved as: malicious_downloads/ab34cd...7e.exe
🔐 SHA256: ab34cd...7e
📦 MIME: application/x-dosexec, Size: 183412 bytes
🧪 VT Scan: 12/71 detections → https://virustotal.com/gui/file/ab34cd...

⚠️ Copied to: malicious_confirmed/ab34cd...7e.exe (VT confirmed malicious)
--------------------------------------------

🌐 URL: https://safe-site.org/
🔍 Similarity: 99.8% → ✅ OK
🔁 Redirected to: https://safe-site.org/ → ✅ Normal
--------------------------------------------

=== Summary Report ===
🔎 Total URLs scanned:       2
🛑 Cloaking detected:        1
⚠️ Suspicious redirections: 0
📜 JS Obfuscation found:     2
🧪 Base64 threats detected:  1
🪟 Hidden iframes:           1
🔄 Meta refresh tags:        1
📥 Files downloaded:         1
🔥 Confirmed malicious files: 1
🪟 Windows files:            1
🐧 Linux files:              0
🍏 macOS files:              0
📱 Android files:            0
🍎 iOS files:                0
🧪 VT flagged files:         1
[✓] Reports saved to 'report.txt' and 'report.json'
```

---

## 📂 Output Files

| File                   | Description                          |
| ---------------------- | ------------------------------------ |
| `report.txt`           | Human-readable terminal summary      |
| `report.json`          | Structured results for SIEM/analysis |
| `exports/report.csv`   | Clean CSV for Excel or threat feeds  |
| `vt_cache.json`        | Cached VT hashes to reduce queries   |
| `malicious_downloads/` | Folder for risky file captures       |
| `malicious_confirmed/` | Files flagged by VirusTotal          |

---

## ⚙️ Requirements

- Python 3.8+
- `requests`, `hashlib`, `csv`, `json`, `re`

---

## 🔐 VirusTotal API

To enable VT integration, export your API key:

```bash
export VT_API_KEY="your_virustotal_api_key"
```

If not set, the tool will skip VT checks.

---

## Screeshots

![Captura-de-pantalla-2025-05-23-011157.png](https://i.postimg.cc/FKVP8RpJ/Captura-de-pantalla-2025-05-23-011157.png)
![2025-05-23-011249.png](https://i.postimg.cc/Bv0YmDT0/Captura-de-pantalla-2025-05-23-011249.png)
![Captura-de-pantalla-2025-05-23-011324.png](https://i.postimg.cc/VL2Hb255/Captura-de-pantalla-2025-05-23-011324.png)

---

## ⚠️ Disclaimer

This tool is for **educational and research purposes only**. Use it responsibly to protect and audit your own infrastructure or for ethical threat hunting.

---

## 📬 Contact

Maintained by [@dEEpEst_23](https://github.com/LvL23HT) — contributions welcome!



