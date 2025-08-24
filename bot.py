#!/usr/bin/env python3

import logging
import requests
import re
import io
import time
from datetime import datetime
from urllib.parse import urlparse, quote
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes

# --- تنظیمات لاگ ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# --- وضعیت‌ها ---
CHOOSING, GET_URL, GET_PAYLOAD_FILE = range(3)

# --- منو ---
menu_keyboard = [
    ['🛡️ Detect WAF & Server'],
    ['🧨 Test Vulnerabilities']
]
reply_markup = [[button] for row in menu_keyboard for button in row]
reply_markup = ReplyKeyboardMarkup(menu_keyboard, resize_keyboard=True, one_time_keyboard=False)

# --- WAF Signatures ---
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare", "cf-request-id"],
    "Sucuri": ["sucuri", "x-sucuri-id"],
    "Imperva": ["imperva", "incapsula", "x-iinfo"],
    "Akamai": ["akamai", "x-akamai"],
    "AWS WAF": ["awswaf", "x-amzn-requestid"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "F5 BIG-IP": ["f5", "bigip"],
    "FortiWeb": ["fortiwaf"]
}

# --- Server Signatures ---
SERVER_SIGNATURES = {
    "Apache": [r"Apache(?:/([\d.]+))?"],
    "Nginx": [r"Nginx(?:/([\d.]+))?|nginx(?:/([\d.]+))?"],
    "Microsoft-IIS": [r"Microsoft-IIS(?:/([\d.]+))?"]
}

# --- /start ---
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ Security Testing Bot\n"
        "Choose an option:",
        reply_markup=reply_markup
    )
    return CHOOSING

# --- انتخاب گزینه ---
async def handle_choice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()

    if text == "🛡️ Detect WAF & Server":
        await update.message.reply_text("Enter target URL (e.g., https://example.com):")
        return GET_URL

    elif text == "🧨 Test Vulnerabilities":
        msg = (
            "Select vulnerability to test:\n"
            "1 → SQL Injection\n"
            "2 → XSS\n"
            "3 → LFI\n"
            "4 → Command Injection\n"
            "5 → Open Redirect\n"
            "6 → SSRF\n"
            "7 → IDOR\n"
            "8 → File Upload Bypass\n"
            "9 → Missing Security Headers\n"
            "10 → Clickjacking\n"
            "Enter number (1-10):"
        )
        context.user_data['test_mode'] = 'vuln'
        await update.message.reply_text(msg)
        return GET_URL

    else:
        await update.message.reply_text("Use the menu.")
        return CHOOSING

# --- دریافت URL یا شماره آسیب‌پذیری ---
async def get_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()

    # اگر داریم تست آسیب‌پذیری انجام می‌دیم
    if context.user_data.get('test_mode') == 'vuln':
        try:
            vuln_id = int(text)
            if vuln_id not in range(1, 11):
                await update.message.reply_text("❌ Invalid number. Choose 1-10.")
                return GET_URL
            context.user_data['vuln_id'] = vuln_id
            await update.message.reply_text("Enter target URL (e.g., https://site.com/page?id=1):")
            return GET_URL
        except:
            await update.message.reply_text("❌ Please enter a number (1-10).")
            return GET_URL

    # دریافت URL برای تشخیص WAF/Server
    url = text
    if not url.startswith("http"):
        await update.message.reply_text("❌ Invalid URL. Must start with http:// or https://")
        return GET_URL

    parsed = urlparse(url)
    if not parsed.netloc:
        await update.message.reply_text("❌ Invalid domain.")
        return GET_URL

    context.user_data['target_url'] = url
    return await run_scan(update, context)

# --- دریافت فایل پیلود ---
async def get_payload_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    document = update.message.document

    if not document or not document.file_name.endswith(".txt"):
        await update.message.reply_text("❌ Please send a .txt file.")
        return GET_PAYLOAD_FILE

    try:
        file = await document.get_file()
        content = await file.download_as_bytearray()
        payloads = [line.strip() for line in content.decode("utf-8", errors="ignore").splitlines() if line.strip()]

        if not payloads:
            await update.message.reply_text("❌ File is empty.")
            return GET_PAYLOAD_FILE

        context.user_data['payloads'] = payloads
        await update.message.reply_text("✅ Payloads loaded. Running test...")
        return await run_vulnerability_test(update, context)

    except Exception as e:
        await update.message.reply_text(f"❌ Failed to read file: {str(e)}")
        return GET_PAYLOAD_FILE

# --- اسکن WAF و وب سرور ---
async def run_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = context.user_data['target_url']
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) SecurityBot"})
    session.verify = False

    result = ""
    result += "🔍 SCAN REPORT\n"
    result += "=" * 60 + "\n"
    result += f"Target: {url}\n"
    result += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    result += "-" * 60 + "\n"

    try:
        r = session.get(url, timeout=10)
        result += f"Status: {r.status_code}\n"
        result += f"Final URL: {r.url}\n\n"
        headers = dict(r.headers)
        header_text = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        body = r.text.lower()
    except Exception as e:
        result += f"❌ Connection failed: {str(e)}"
        await update.message.reply_text(result)
        await update.message.reply_text("Choose an option:", reply_markup=reply_markup)
        return CHOOSING

    # تشخیص وب سرور
    result += "🖥️ WEB SERVER\n"
    server_header = headers.get("Server", "Not found")
    result += f"Header: {server_header}\n"
    server_name = server_version = "Unknown"
    for serv, patterns in SERVER_SIGNATURES.items():
        for pattern in patterns:
            match = re.search(pattern, server_header, re.IGNORECASE)
            if match:
                server_name = serv
                server_version = match.group(1) or "Unknown"
                break
        if server_name != "Unknown":
            break
    result += f"Detected: {server_name} v{server_version}\n\n"

    # تشخیص WAF
    result += "🛡️ WAF DETECTION\n"
    waf_name = "None"
    waf_version = "Unknown"
    for waf, sigs in WAF_SIGNATURES.items():
        if any(sig in header_text or sig in body for sig in sigs):
            waf_name = waf
            if "cf-ray" in headers:
                waf_version = headers["cf-ray"].split('-')[1] if '-' in headers["cf-ray"] else "Detected"
            break
    result += f"Detected: {waf_name} v{waf_version}\n"

    # ارسال نتیجه
    await update.message.reply_text(result)

    # ارسال فایل TXT
    txt_buffer = io.BytesIO()
    txt_buffer.write(result.encode("utf-8"))
    txt_buffer.seek(0)
    txt_buffer.name = f"scan_{update.effective_user.id}.txt"
    await update.message.reply_document(document=txt_buffer, filename=txt_buffer.name, caption="📄 WAF & Server Report")

    await update.message.reply_text("Choose another test:", reply_markup=reply_markup)
    return CHOOSING

# --- تست آسیب‌پذیری (با پیلود کاربر برای همه تست‌ها) ---
# --- تست آسیب‌پذیری (اصلاح شده برای 9 و 10) ---
async def run_vulnerability_test(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = context.user_data['target_url']
    vuln_id = context.user_data['vuln_id']
    payloads = context.user_data['payloads']
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) SecurityBot"})
    session.verify = False

    # --- تعیین نوع آسیب‌پذیری ---
    vuln_map = {
        1: "SQLi",
        2: "XSS",
        3: "LFI",
        4: "RCE",
        5: "Open Redirect",
        6: "SSRF",
        7: "IDOR",
        8: "File Upload Bypass",
        9: "Security Headers",
        10: "Clickjacking"
    }

    if vuln_id not in vuln_map:
        await update.message.reply_text("❌ Invalid vulnerability number.")
        return CHOOSING

    vuln_name = vuln_map[vuln_id]
    result = ""
    result += "🧨 VULNERABILITY TEST\n"
    result += "=" * 60 + "\n"
    result += f"Target: {url}\n"
    result += f"Test: {vuln_name}\n"
    result += f"Payloads: {len(payloads)}\n"
    result += f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
    result += "-" * 60 + "\n"

    found = []
    base = url.split('=')[0] + '=' if '=' in url else url + '?test='

    try:
        r_base = session.get(url, timeout=10)
        headers = dict(r_base.headers)
    except:
        headers = {}

    # --- تست‌ها ---
    for payload in payloads:
        try:
            test_url = base + quote(payload)

            # --- 1. SQLi ---
            if vuln_id == 1:
                r = session.get(test_url, timeout=10)
                if any(k in r.text.lower() for k in ["sql", "syntax", "mysql"]):
                    found.append(f"SQLi: {payload}")

            # --- 2. XSS ---
            elif vuln_id == 2:
                r = session.get(test_url, timeout=10)
                if payload in r.text:
                    found.append(f"XSS: {payload}")

            # --- 3. LFI ---
            elif vuln_id == 3:
                r = session.get(test_url, timeout=10)
                if "root:x" in r.text or "bin/bash" in r.text:
                    found.append(f"LFI: {payload}")

            # --- 4. RCE ---
            elif vuln_id == 4:
                r = session.get(test_url, timeout=10)
                if "root:x" in r.text or "id=" in r.text:
                    found.append(f"RCE: {payload}")

            # --- 5. Open Redirect ---
            elif vuln_id == 5:
                for param in ['url', 'redirect', 'next']:
                    if param in url:
                        redir_url = url.replace(f"{param}=", f"{param}={payload}")
                        r = session.get(redir_url, allow_redirects=False, timeout=10)
                        location = r.headers.get("Location", "")
                        if r.status_code in [301, 302] and payload in location:
                            found.append(f"Open Redirect: {location}")

            # --- 6. SSRF ---
            elif vuln_id == 6:
                r = session.get(test_url, timeout=15)
                if "127.0.0.1" in r.text or "localhost" in r.text:
                    found.append(f"SSRF: {payload}")

            # --- 7. IDOR ---
            elif vuln_id == 7 and re.search(r'id=\d+', url):
                idor_url = re.sub(r'id=\d+', f'id={payload}', url)
                r = session.get(idor_url, timeout=10)
                if r.status_code == 200:
                    found.append(f"IDOR: Access to id={payload}")

            # --- 8. File Upload Bypass ---
            elif vuln_id == 8:
                for param in ['file', 'upload', 'avatar']:
                    if param in url:
                        upload_url = url.replace(f"{param}=", f"{param}={payload}")
                        r = session.get(upload_url, timeout=10)
                        if "uploaded" in r.text or "success" in r.text:
                            found.append(f"File Upload: {payload}")

            # --- 9. Missing Security Headers ---
            elif vuln_id == 9:
                required_headers = {
                    "Strict-Transport-Security": "HSTS missing",
                    "Content-Security-Policy": "CSP missing",
                    "X-Frame-Options": "Clickjacking protection missing",
                    "X-Content-Type-Options": "MIME sniffing protection missing"
                }
                for header, desc in required_headers.items():
                    if header not in headers:
                        found.append(desc)

            # --- 10. Clickjacking ---
            elif vuln_id == 10:
                # تست روی چند endpoint
                endpoints = ["/", "/login", "/admin", f"/profile?id={payload}"]
                for ep in endpoints:
                    ep_url = url.rstrip("/") + ep
                    try:
                        r = session.get(ep_url, timeout=10)
                        hdrs = dict(r.headers)
                        if "X-Frame-Options" not in hdrs and "Content-Security-Policy" not in hdrs:
                            found.append(f"Vulnerable to Clickjacking: {ep_url}")
                    except:
                        continue

        except Exception as e:
            continue  # ادامه به پیلود بعدی

    # --- نمایش نتایج ---
    if found:
        result += "✅ Vulnerabilities found:\n"
        for item in found:
            result += f"  → {item}\n"
    else:
        result += "❌ No vulnerabilities detected.\n"

    # --- ارسال نتیجه و فایل ---
    await update.message.reply_text(result)

    txt_buffer = io.BytesIO()
    txt_buffer.write(result.encode("utf-8"))
    txt_buffer.seek(0)
    txt_buffer.name = f"test_{update.effective_user.id}.txt"

    await update.message.reply_document(
        document=txt_buffer,
        filename=txt_buffer.name,
        caption="📄 Full Test Results"
    )

    await update.message.reply_text("Choose another test:", reply_markup=reply_markup)
    return CHOOSING

# --- اصلی ---
def main():
    TOKEN = "8263277491:AAExcpTTrKzHCguB-UYBRHHGun-VKqbkPBI"  # ← توکن خودت رو وارد کن
    app = Application.builder().token(TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_choice))
    app.add_handler(MessageHandler(filters.Document.FileExtension("txt"), get_payload_file))

    print("✅ Security Bot is running...")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
