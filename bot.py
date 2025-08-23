#!/usr/bin/env python3

# --- تنظیمات ---
import logging
import requests
import re
import io
from urllib.parse import urlparse, urljoin, quote
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ConversationHandler, ContextTypes

# --- تنظیمات لاگ ---
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# --- وضعیت‌ها ---
START_OVER, GET_URL, GET_PAYLOAD_FILE = range(3)

# --- منو ---
menu_keyboard = [
    ['🔍 Detect Web Server & WAF'],
    ['🧨 Test OWASP Vulnerabilities']
]
reply_markup = [[button] for row in menu_keyboard for button in row]  # تبدیل به لیست درست
reply_markup = ReplyKeyboardMarkup(menu_keyboard, resize_keyboard=True, one_time_keyboard=False)

# --- WAF Signatures ---
WAF_SIGNATURES = {
    "Cloudflare": ["cf-ray", "cloudflare"],
    "Sucuri": ["sucuri", "x-sucuri"],
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
    return START_OVER

# --- انتخاب تست ---
async def handle_choice(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.strip()

    if text == "🔍 Detect Web Server & WAF":
        await update.message.reply_text("Enter target URL (e.g., https://example.com):")
        return GET_URL

    elif text == "🧨 Test OWASP Vulnerabilities":
        await update.message.reply_text("Enter target URL (e.g., https://site.com/page?id=1):")
        return GET_URL

    else:
        await update.message.reply_text("Use the menu.")
        return START_OVER

# --- دریافت URL ---
async def get_url(update: Update, context: ContextTypes.DEFAULT_TYPE):
    url = update.message.text.strip()
    if not url.startswith("http"):
        await update.message.reply_text("❌ Invalid URL. Must start with http:// or https://")
        return GET_URL

    parsed = urlparse(url)
    if not parsed.netloc:
        await update.message.reply_text("❌ Invalid domain.")
        return GET_URL

    context.user_data['target_url'] = url
    context.user_data['test_type'] = update.message.text.strip()

    if context.user_data['test_type'] == "🧨 Test OWASP Vulnerabilities":
        await update.message.reply_text("📤 Send a .txt file with payloads (one per line)")
        return GET_PAYLOAD_FILE
    else:
        return await run_test(update, context)

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
        await update.message.reply_text(f"✅ Loaded {len(payloads)} payloads. Starting test...")
        return await run_test(update, context)

    except Exception as e:
        await update.message.reply_text(f"❌ Failed to read file: {str(e)}")
        return GET_PAYLOAD_FILE

# --- اجرای تست ---
async def run_test(update: Update, context: ContextTypes.DEFAULT_TYPE):
    test_type = context.user_data['test_type']
    url = context.user_data['target_url']
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) SecurityBot"})
    session.verify = False

    result = f"🎯 Target: {url}\n"
    result += "="*50 + "\n"

    try:
        r = session.get(url, timeout=10)
        result += f"Status: {r.status_code}\n"
        headers = dict(r.headers)
        header_text = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        body = r.text.lower()
    except Exception as e:
        result += f"❌ Failed to connect: {str(e)}"
        await update.message.reply_text(result)
        await update.message.reply_text("Choose an option:", reply_markup=reply_markup)
        return START_OVER

    # --- تشخیص وب سرور و WAF ---
    if test_type == "🔍 Detect Web Server & WAF":
        # Web Server
        server_header = headers.get("Server", "Not found")
        result += f"\n🖥️ Server Header: {server_header}\n"
        server_name = "Unknown"
        server_version = "Unknown"

        for serv, patterns in SERVER_SIGNATURES.items():
            for pattern in patterns:
                match = re.search(pattern, server_header, re.IGNORECASE)
                if match:
                    server_name = serv
                    server_version = match.group(1) or "Unknown"
                    break
            if server_name != "Unknown":
                break

        result += f"✅ Server: {server_name} v{server_version}\n"

        # WAF
        waf_name = "None"
        waf_version = "Unknown"
        for waf, sigs in WAF_SIGNATURES.items():
            if any(sig in header_text or sig in body for sig in sigs):
                waf_name = waf
                if "cf-ray" in header_text:
                    ray = headers.get("cf-ray", "")
                    waf_version = ray.split('-')[1] if '-' in ray else "Detected"
                break

        result += f"\n🛡️ WAF: {waf_name} v{waf_version}"

    # --- تست آسیب‌پذیری OWASP ---
    elif test_type == "🧨 Test OWASP Vulnerabilities":
        payloads = context.user_data.get('payloads', [])
        parsed = urlparse(url)
        param = parsed.query.split('=')[0] if '=' in parsed.query else 'id'
        base = url.split('=')[0] + '=' if '=' in url else url + '?test='
        found = []

        result += f"\n🔧 Testing {len(payloads)} payloads on param: {param}\n\n"

        for payload in payloads:
            try:
                test_url = base + quote(payload)
                r_test = session.get(test_url, timeout=10)

                # SQLi
                if "'" in payload and any(k in r_test.text.lower() for k in ["sql", "syntax", "mysql"]):
                    found.append(f"SQLi: {payload}")

                # XSS
                elif "<script>" in payload and payload in r_test.text:
                    found.append(f"XSS: {payload}")

                # LFI
                elif "etc/passwd" in payload and "root:x" in r_test.text:
                    found.append(f"LFI: {payload}")

                # Command Injection
                elif ";" in payload and "bin/bash" in r_test.text:
                    found.append(f"RCE: {payload}")

            except Exception as e:
                continue

        if found:
            result += "⚠️ Matches found:\n"
            for item in found:
                result += f"  → {item}\n"
        else:
            result += "✅ No vulnerabilities detected."

        # Open Redirect
        if "url=" in url:
            redir_url = url.replace("url=", "url=https://google.com")
            try:
                r_redir = session.get(redir_url, allow_redirects=False, timeout=10)
                location = r_redir.headers.get("Location", "")
                if r_redir.status_code in [301, 302] and "google.com" in location:
                    result += f"\n🚨 Open Redirect: CONFIRMED! → {location}"
            except:
                pass

        # Security Headers
        sec_headers = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]
        missing = [h for h in sec_headers if h not in headers]
        if missing:
            result += f"\n\n⚠️ Missing Security Headers:\n"
            for h in missing:
                result += f"  → {h}\n"

    # --- ارسال نتیجه به صورت متن + فایل TXT ---
    await update.message.reply_text(result)

    # ارسال فایل TXT (در حافظه)
    txt_buffer = io.BytesIO()
    txt_buffer.write(result.encode("utf-8"))
    txt_buffer.seek(0)
    txt_buffer.name = f"results_{update.effective_user.id}.txt"

    await update.message.reply_document(
        document=txt_buffer,
        filename=txt_buffer.name,
        caption="📄 Full test results"
    )

    await update.message.reply_text("Choose another test:", reply_markup=reply_markup)
    return START_OVER

# --- اصلی ---
def main():
    TOKEN = "8263277491:AAExcpTTrKzHCguB-UYBRHHGun-VKqbkPBI"  # ← توکن خودت رو وارد کن

    app = Application.builder().token(TOKEN).build()

    conv_handler = ConversationHandler(
        entry_points=[CommandHandler("start", start), MessageHandler(filters.TEXT & ~filters.COMMAND, handle_choice)],
        states={
            START_OVER: [MessageHandler(filters.TEXT & ~filters.COMMAND, handle_choice)],
            GET_URL: [MessageHandler(filters.TEXT & ~filters.COMMAND, get_url)],
            GET_PAYLOAD_FILE: [MessageHandler(filters.Document.FileExtension("txt"), get_payload_file)],
        },
        fallbacks=[CommandHandler("start", start)],
        per_user=True
    )

    app.add_handler(conv_handler)
    app.add_handler(CommandHandler("start", start))

    print("✅ Security Bot is running...")
    app.run_polling(drop_pending_updates=True)

if __name__ == "__main__":
    main()

