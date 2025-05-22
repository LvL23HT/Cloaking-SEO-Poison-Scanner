import requests, re, os, csv, json, hashlib
from difflib import SequenceMatcher
from urllib.parse import urlparse
from base64 import b64decode
import datetime

# === COLOR CODES ===
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"

# === CONFIG ===
BLACKHAT_KEYWORDS = ["crack", "keygen", "serial", "download free", "activation", "patch", "nulled"]
SUSPICIOUS_JS = ["eval(", "atob(", "unescape(", "document.write(", "setTimeout(", "window.location", "location.href", "location.replace"]
SUSPICIOUS_EXT = (
    ".exe", ".scr", ".js", ".bat", ".vbs", ".ps1", ".cmd", ".msi", ".hta", ".wsf", ".dll",
    ".sh", ".run", ".elf", ".bin", ".dmg", ".pkg", ".app", ".command", ".apk", ".xapk", ".ipa"
)
VT_API_KEY = os.getenv("VT_API_KEY")

# === BANNER ===
def banner():
    print(f"""{BOLD}{CYAN}
┌────────────────────────────────────────────┐
│ 🕵️  CLOAKING & SEO POISON SCANNER - v1.3   │
│--------------------------------------------│
│  ▸ Detects: cloaking, redirections, malware│
│  ▸ Flags: obfuscation, JS, iframes, base64 │
│  ▸ Downloads risky files, VT integration   │
│                                            │
│  🔧 Coded by:     {RESET}@dEEpEst_23{CYAN}              │
└────────────────────────────────────────────┘
{RESET}""")

# === DETECTION HELPERS ===
def fetch(url, ua):
    try:
        res = requests.get(url, headers={"User-Agent": ua}, timeout=10, allow_redirects=True)
        return res.text, res.url
    except Exception as e:
        return f"[ERROR] {e}", url

def compare(a, b):
    return round(SequenceMatcher(None, a, b).ratio() * 100, 2)

def is_suspicious_redirect(original, final):
    if final.startswith("[ERROR]"):
        return False
    po, pf = urlparse(original), urlparse(final)
    return (po.netloc != pf.netloc) or pf.path.endswith(SUSPICIOUS_EXT)

def detect_base64(content):
    matches = re.findall(r"[A-Za-z0-9+/=]{50,}", content)
    decoded = []
    for m in matches:
        try:
            if len(m) % 4 == 0:
                b64 = b64decode(m).decode("utf-8", errors="ignore")
                if any(x in b64.lower() for x in ["<script", "http", "exe"]):
                    decoded.append(b64[:200])
        except: 
            continue
    return decoded

def keyword_hits(content, keywords):
    return [kw for kw in keywords if kw.lower() in content.lower()]

def js_suspicious(content):
    return [k for k in SUSPICIOUS_JS if k in content]

def detect_iframe_hidden(content):
    return bool(re.search(r"<iframe[^>]*(display\s*:\s*none|visibility\s*:\s*hidden|width=['\"]?0|height=['\"]?0)", content, re.IGNORECASE))

def detect_meta_refresh(content):
    return bool(re.search(r'<meta[^>]*http-equiv=["\']refresh["\']', content, re.IGNORECASE))

def download_file(url):
    os.makedirs("malicious_downloads", exist_ok=True)
    try:
        ext = os.path.splitext(urlparse(url).path)[1]
        r = requests.get(url, stream=True, timeout=15)
        if r.status_code == 200:
            content = r.content
            sha256 = hashlib.sha256(content).hexdigest()
            filename = f"malicious_downloads/{sha256}{ext}"

            if os.path.exists(filename):
                file_size = os.path.getsize(filename)
                mime_type = r.headers.get('Content-Type', 'unknown')
                print(f"{YELLOW}[!] File already downloaded: {filename}{RESET}")
            else:
                with open(filename, "wb") as f:
                    f.write(content)
                file_size = len(content)
                mime_type = r.headers.get('Content-Type', 'unknown')
                print(f"{RED}{BOLD}🚨 HIGH-RISK FILE DETECTED & DOWNLOADED!{RESET}")
                print(f"{YELLOW}🔗 URL: {url}{RESET}")
                print(f"{CYAN}📁 Saved as: {filename}{RESET}")
                print(f"{MAGENTA}🔐 SHA256: {sha256}{RESET}")
                print(f"{YELLOW}📦 MIME: {mime_type}, Size: {file_size} bytes{RESET}")

            return sha256, filename, mime_type, file_size
    except Exception as e:
        print(f"{RED}[ERROR] Could not download {url}: {e}{RESET}")
    return None, None, None, None

def vt_scan(sha256):
    cache_file = "vt_cache.json"
    cache = {}
    if os.path.exists(cache_file):
        with open(cache_file, "r", encoding="utf-8") as f:
            try:
                cache = json.load(f)
            except json.JSONDecodeError:
                cache = {}

    if sha256 in cache:
        return cache[sha256]

    if not VT_API_KEY:
        return None

    headers = {"x-apikey": VT_API_KEY}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    try:
        res = requests.get(url, headers=headers)
        if res.status_code == 200:
            data = res.json()
            stats = data['data']['attributes']['last_analysis_stats']
            link = f"https://www.virustotal.com/gui/file/{sha256}"
            result = {
                "positives": stats['malicious'],
                "total": sum(stats.values()),
                "permalink": link
            }
            cache[sha256] = result
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(cache, f, indent=2)
            return result
    except Exception as e:
        print(f"{RED}[ERROR] VT lookup failed: {e}{RESET}")
    return None

def print_and_write(text, out, color=RESET):
    print(color + text + RESET)
    out.write(text + "\n")

def load_urls():
    urls = []
    if os.path.exists("urls.txt"):
        with open("urls.txt", "r") as f:
            urls = [line.strip() for line in f if line.strip()]
    elif os.path.exists("urls.csv"):
        with open("urls.csv", newline='', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if "url" in row and row["url"].strip():
                    urls.append(row["url"].strip())
    else:
        print(f"{RED}[!] No input file found. Please use urls.txt or urls.csv{RESET}")
        return []
    return urls

# === MAIN ===
def main():
    banner()
    urls = load_urls()
    if not urls:
        return

    total = len(urls)
    stats = {"cloaking": 0, "redirects": 0, "js_flags": 0, "base64": 0, "iframe": 0, "meta": 0}
    json_output = []

    with open("report.txt", "w", encoding="utf-8") as out:
        for url in urls:
            g_ua = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
            r_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0"

            g_content, g_final = fetch(url, g_ua)
            r_content, r_final = fetch(url, r_ua)

            similarity = compare(g_content, r_content)
            cloaking = similarity < 90
            redirect = is_suspicious_redirect(url, r_final)
            b64 = detect_base64(r_content)[:2]
            keywords = keyword_hits(r_content, BLACKHAT_KEYWORDS)
            js_flags = js_suspicious(r_content)
            iframe_hidden = detect_iframe_hidden(r_content)
            meta_refresh = detect_meta_refresh(r_content)

            if cloaking: stats["cloaking"] += 1
            if redirect: stats["redirects"] += 1
            if js_flags: stats["js_flags"] += len(js_flags)
            if b64: stats["base64"] += len(b64)
            if iframe_hidden: stats["iframe"] += 1
            if meta_refresh: stats["meta"] += 1

            print_and_write(f"🌐 URL: {url}", out, CYAN)
            print_and_write(f"🔍 Similarity: {similarity}% → {'🛑 CLOAKING' if cloaking else '✅ OK'}", out, RED if cloaking else GREEN)
            print_and_write(f"🔁 Redirected to: {r_final} → {'⚠️ SUSPICIOUS' if redirect else '✅ Normal'}", out, YELLOW if redirect else GREEN)
            if keywords:
                print_and_write(f"🧠 BlackHat Keywords: {', '.join(keywords)}", out, MAGENTA)
            if js_flags:
                print_and_write(f"📜 Suspicious JS: {', '.join(js_flags)}", out, MAGENTA)
            if b64:
                print_and_write("🧪 Base64 Decoded Snippet:", out, YELLOW)
                for b in b64:
                    print_and_write(f"   ↳ {b.strip()[:100]}", out, YELLOW)
            if iframe_hidden:
                print_and_write("🪟 Hidden <iframe> detected!", out, RED)
            if meta_refresh:
                print_and_write("🔄 Meta Refresh redirection found!", out, RED)

            entry = {
                "url": url,
                "similarity": similarity,
                "cloaking": cloaking,
                "redirect": redirect,
                "final_url": r_final,
                "blackhat_keywords": keywords,
                "suspicious_js": js_flags,
                "base64_snippets": b64,
                "iframe_hidden": iframe_hidden,
                "meta_refresh": meta_refresh,
                "timestamp": datetime.datetime.now().isoformat()
            }

            if r_final.lower().endswith(SUSPICIOUS_EXT):
                sha256, fname, mime_type, file_size = download_file(r_final)
                if sha256:
                    entry["downloaded_file"] = {
                        "sha256": sha256,
                        "filename": os.path.basename(fname),
                        "from_url": r_final,
                        "mime_type": mime_type,
                        "size_bytes": file_size,
                        "timestamp": datetime.datetime.now().isoformat()
                    }
                    if VT_API_KEY:
                        vt = vt_scan(sha256)
                        if vt:
                            entry["downloaded_file"]["virustotal"] = vt
                            if vt['positives'] > 0:
                                entry["downloaded_file"]["confirmed_malicious"] = True
                                os.makedirs("malicious_confirmed", exist_ok=True)
                                dest_path = os.path.join("malicious_confirmed", os.path.basename(fname))
                                try:
                                    with open(fname, "rb") as src, open(dest_path, "wb") as dst:
                                        dst.write(src.read())
                                    print(f"{RED}{BOLD}⚠️ Copied to: {dest_path} (VT confirmed malicious){RESET}")
                                except Exception as copy_error:
                                    print(f"{RED}[ERROR] Could not copy to malicious_confirmed/: {copy_error}{RESET}")

            json_output.append(entry)
            print_and_write("─" * 60, out, CYAN)

    with open("report.json", "w", encoding="utf-8") as jf:
        json.dump(json_output, jf, indent=2)

    # Write CSV export
    os.makedirs("exports", exist_ok=True)
    with open("exports/report.csv", "w", newline="", encoding="utf-8") as csvf:
        writer = csv.writer(csvf)
        writer.writerow(["sha256", "filename", "mime_type", "size", "platform", "vt_positives", "vt_total", "from_url", "timestamp"])
        for entry in json_output:
            f = entry.get("downloaded_file")
            if f:
                platform = ""
                name = f["filename"].lower()
                if name.endswith((".exe", ".scr", ".dll", ".msi", ".bat", ".cmd")): platform = "Windows"
                elif name.endswith((".sh", ".run", ".elf", ".bin")): platform = "Linux"
                elif name.endswith((".dmg", ".pkg", ".app", ".command")): platform = "macOS"
                elif name.endswith((".apk", ".xapk")): platform = "Android"
                elif name.endswith((".ipa",)): platform = "iOS"

                vt = f.get("virustotal", {})
                writer.writerow([
                    f["sha256"], 
                    f["filename"], 
                    f.get("mime_type", ""), 
                    f.get("size_bytes", ""),
                    platform, 
                    vt.get("positives", 0), 
                    vt.get("total", 0), 
                    f.get("from_url", ""), 
                    f.get("timestamp", "")
                ])

    print(f"\n{BOLD}{CYAN}=== Summary Report ==={RESET}")
    print(f"🔎 Total URLs scanned:       {total}")
    print(f"🛑 Cloaking detected:        {RED}{stats['cloaking']}{RESET}")
    print(f"⚠️  Suspicious redirections: {YELLOW}{stats['redirects']}{RESET}")
    print(f"📜 JS Obfuscation found:     {MAGENTA}{stats['js_flags']}{RESET}")
    print(f"🧪 Base64 threats detected:  {YELLOW}{stats['base64']}{RESET}")
    print(f"🪟 Hidden iframes:           {RED}{stats['iframe']}{RESET}")
    print(f"🔄 Meta refresh tags:        {RED}{stats['meta']}{RESET}")

    # Count downloaded files
    file_downloads = sum(1 for entry in json_output if 'downloaded_file' in entry)
    print(f"📥 Files downloaded:         {YELLOW}{file_downloads}{RESET}")

    vt_confirmed = sum(1 for entry in json_output if entry.get('downloaded_file', {}).get('confirmed_malicious', False))
    print(f"🔥 Confirmed malicious files: {RED}{vt_confirmed}{RESET}")

    # Count by platform
    win_ext = (".exe", ".scr", ".dll", ".msi", ".bat", ".cmd")
    lin_ext = (".sh", ".run", ".elf", ".bin")
    mac_ext = (".dmg", ".pkg", ".app", ".command")
    and_ext = (".apk", ".xapk")
    ios_ext = (".ipa",)

    def count_by_ext(exts):
        return sum(1 for e in json_output if e.get("downloaded_file", {}).get("filename", "").lower().endswith(exts))

    print(f"🪟 Windows files:            {count_by_ext(win_ext)}")
    print(f"🐧 Linux files:              {count_by_ext(lin_ext)}")
    print(f"🍏 macOS files:              {count_by_ext(mac_ext)}")
    print(f"📱 Android files:            {count_by_ext(and_ext)}")
    print(f"🍎 iOS files:                {count_by_ext(ios_ext)}")

    # Count VirusTotal detections
    vt_hits = sum(1 for entry in json_output if entry.get('downloaded_file', {}).get('virustotal', {}).get('positives', 0) > 0)
    print(f"🧪 VT flagged files:         {RED}{vt_hits}{RESET}")

    print(f"{GREEN}[✓] Reports saved to 'report.txt' and 'report.json'{RESET}")
    input(f"\n{CYAN}Press Enter to exit...{RESET}")

if __name__ == "__main__":
    main()
