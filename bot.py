#!/usr/bin/env python3

import logging
import requests
import re
import io
from datetime import datetime
from urllib.parse import urlparse, quote
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes, ConversationHandler

# --- تنظیمات لاگ ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# --- وضعیت‌ها ---
CHOOSING, GET_URL, GET_PAYLOAD = range(3)

# --- منو ---
menu_keyboard = [
    ['🛡️ Detect WAF & Server'],
    ['🧨 Test Vulnerabilities']
]
reply_markup = ReplyKeyboardMarkup(menu_keyboard, resize_keyboard=True, one_time_keyboard=False)

# --- WAF Signatures ---
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare"],
    "Sucuri": ["sucuri", "x-sucuri-id"],
    "Imperva": ["imperva", "incapsula"],
    "Akamai": ["akamai"],
    "AWS WAF": ["awswaf", "x-amzn"],
    "ModSecurity": ["mod_security", "modsecurity"],
    "F5 BIG-IP": ["f5", "bigip"]
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

# --- انتخاب تست ---
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
            "Enter number:"
        )
        context.user_data['mode'] = 'vuln'
        await update.message.reply_text(msg)
        return GET_URL

    else:
        await update.message.reply_text("Use the menu.")
        return CHOOSING

# --- دریافت URL یا شماره ---
async def get_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()

    # اگر داریم تست آسیب‌پذیری انجام می‌دیم
    if context.user_data.get('mode') == 'vuln':
        try:
            vuln_id = int(text)
            if vuln_id not in [1, 2, 3, 4]:
                await update.message.reply_text("❌ Invalid number. Choose 1-4.")
                return GET_URL
            context.user_data['vuln_id'] = vuln_id
            await update.message.reply_text("Enter target URL:")
            return GET_URL
        except:
            await update.message.reply_text("❌ Please enter a number (1-4).")
            return GET_URL

    # حالا URL وارد شده
    url = text
    if not url.startswith("http"):
        await update.message.reply_text("❌ Invalid URL. Must start with http:// or https://")
        return GET_URL

    parsed = urlparse(url)
    if not parsed.netloc:
        await update.message.reply_text("❌ Invalid domain.")
        return GET_URL

    context.user_data['target_url'] = url

    if context.user_data.get('mode') == 'vuln':
        await update.message.reply_text("📤 Send a .txt file with payloads (one per line)")
        return GET_PAYLOAD
    else:
        return await run_scan(update, context)

# --- دریافت فایل پیلود ---
async def get_payload(update: Update, context: ContextTypes.DEFAULT_TYPE):
    document = update.message.document

    if not document or not document.file_name.endswith(".txt"):
        await update.message.reply_text("❌ Please send a .txt file.")
        return GET_PAYLOAD

    try:
        file = await document.get_file()
        content = await file.download_as_bytearray()
        payloads = [line.strip() for line in content.decode("utf-8", errors="ignore").splitlines() if line.strip()]

        if not payloads:
            await update.message.reply_text("❌ File is empty.")
            return GET_PAYLOAD

        context.user_data['payloads'] = payloads
        await update.message.reply_text("✅ Payloads loaded. Running test...")
        return await run_vulnerability_test(update, context)

    except Exception as e:
        await update.message.reply_text(f"❌ Failed to read file: {str(e)}")
        return GET_PAYLOAD

# --- اسکن WAF و سرور ---
async def run_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = context.user_data['target_url']
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) SecurityBot"})
    session.verify = False

    result = f"🔍 SCAN REPORT\n{'='*50}\nTarget: {url}\n\n"

    try:
        r = session.get(url, timeout=10)
        headers = dict(r.headers)
        header_text = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        body = r.text.lower()
    except Exception as e:
        result += f"❌ Connection failed: {str(e)}"
        await update.message.reply_text(result)
        await update.message.reply_text("Choose an option:", reply_markup=reply_markup)
        return CHOOSING

    # تشخیص سرور
    server_header = headers.get("Server", "Not found")
    result += f"🖥️ Server: {server_header}\n"

    for serv, patterns in SERVER_SIGNATURES.items():
        for pattern in patterns:
            if re.search(pattern, server_header, re.IGNORECASE):
                version = re.search(pattern, server_header).group(1) or "Unknown"
                result += f"   → Detected: {serv} v{version}\n"
                break

    # تشخیص WAF
    result += "\n🛡️ WAF:\n"
    for waf, sigs in WAF_SIGNATURES.items():
        if any(sig in header_text or sig in body for sig in sigs):
            result += f"   → {waf}\n"

    await update.message.reply_text(result)

    # ارسال فایل TXT
    txt_buffer = io.BytesIO(result.encode("utf-8"))
    txt_buffer.name = "scan.txt"
    await update.message.reply_document(document=txt_buffer, filename="scan.txt")

    await update.message.reply_text("Choose another test:", reply_markup=reply_markup)
    return CHOOSING

# --- تست آسیب‌پذیری ---
async def run_vulnerability_test(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = context.user_data['target_url']
    vuln_id = context.user_data['vuln_id']
    payloads = context.user_data['payloads']
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) SecurityBot"})
    session.verify = False

    vuln_names = {1: "SQLi", 2: "XSS", 3: "LFI", 4: "RCE"}
    result = f"🧨 TESTING: {vuln_names[vuln_id]}\nURL: {url}\n\nFound:\n"

    found = []
    base = url.split('=')[0] + '=' if '=' in url else url + '?test='

    for payload in payloads:
        test_url = base + quote(payload)
        try:
            r = session.get(test_url, timeout=10)
            text = r.text.lower()

            if vuln_id == 1 and "'" in payload and any(k in text for k in ["sql", "syntax"]):
                found.append(f"SQLi: {payload}")
            elif vuln_id == 2 and "<script>" in payload and payload in r.text:
                found.append(f"XSS: {payload}")
            elif vuln_id == 3 and "etc/passwd" in payload and "root:x" in r.text:
                found.append(f"LFI: {payload}")
            elif vuln_id == 4 and (";" in payload or "|" in payload) and "bin/bash" in r.text:
                found.append(f"RCE: {payload}")

        except:
            continue

    if found:
        for item in found:
            result += f"✅ {item}\n"
    else:
        result += "❌ No match found.\n"

    await update.message.reply_text(result)

    txt_buffer = io.BytesIO(result.encode("utf-8"))
    txt_buffer.name = "test.txt"
    await update.message.reply_document(document=txt_buffer, filename="test.txt")

    await update.message.reply_text("Choose another test:", reply_markup=reply_markup)
    return CHOOSING

# --- اصلی ---
def main():
    TOKEN = "8263277491:AAExcpTTrKzHCguB-UYBRHHGun-VKqbkPBI"
    app = Application.builder().token(TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start)],
        states={
            CHOOSING: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_choice)],
            GET_URL: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_url)],
            GET_PAYLOAD: [MessageHandler(filters.Document.FileExtension("txt"), get_payload)]
        },
        fallbacks=[CommandHandler("start", start)],
        per_user=True
    )

    app.add_handler(conv_handler)
    print("✅ Bot is running...")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()
