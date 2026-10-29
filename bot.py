import os, re, html, json, base64, logging
from pathlib import Path
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, ContextTypes, filters

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)
TOKEN = os.getenv("BOT_TOKEN", "").strip()
MAX_BYTES = int(os.getenv("MAX_FILE_MB", "15")) * 1024 * 1024
TMP = Path("/tmp/fiacb_decoder")
TMP.mkdir(parents=True, exist_ok=True)

def decode_text(source):
    text = html.unescape(source)
    transforms = []
    if text != source:
        transforms.append("HTML entities")
    before = text
    text = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), text)
    text = re.sub(r'\\x([0-9a-fA-F]{2})', lambda m: chr(int(m.group(1), 16)), text)
    if text != before:
        transforms.append("JS Unicode/hex escapes")
    before = text
    pattern = re.compile(r'"([A-Za-z0-9+/]{24,}={0,2})"')
    def b64(m):
        raw = m.group(1)
        try:
            if len(raw) % 4:
                return m.group(0)
            val = base64.b64decode(raw, validate=True).decode("utf-8")
            if any(ord(c) < 9 or 13 < ord(c) < 32 for c in val):
                return m.group(0)
            return "\"" + val + "\""
        except Exception:
            return m.group(0)
    text = pattern.sub(b64, text)
    if text != before:
        transforms.append("likely Base64 text literals")
    text = re.sub(r'\r\n?', '\n', text)
    findings = []
    for pattern, label in [
        (r'\beval\s*\(', 'eval()'),
        (r'\bFunction\s*\(', 'Function constructor'),
        (r'\batob\s*\(', 'atob() Base64 decoder'),
        (r'\bfromCharCode\s*\(', 'String.fromCharCode()'),
        (r'\bfetch\s*\(', 'fetch() network request'),
        (r'\bXMLHttpRequest\b', 'XMLHttpRequest'),
        (r'\btext/plain\b', 'possible inert script wrapper'),
        (r'\bchecksum\b|\bintegrity\b', 'integrity/checksum text')
    ]:
        count = len(re.findall(pattern, text, re.I))
        if count:
            findings.append({"pattern": label, "count": count})
    report = {
        "transforms_applied": transforms,
        "input_bytes": len(source.encode("utf-8", errors="replace")),
        "output_bytes": len(text.encode("utf-8", errors="replace")),
        "patterns_found": findings,
        "limitations": [
            "Static analysis only; uploaded code is never executed.",
            "Advanced obfuscation, encrypted payloads, runtime-generated code, or integrity guards may remain unreadable.",
            "This bot does not crack passwords or bypass access controls."
        ]
    }
    return text, report

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 FIACB Static Decoder Bot চালু আছে।\n"
        "একটি .html, .htm, .js, .mjs বা .txt ফাইল পাঠান।\n"
        "পরিচিত encoding decode করার চেষ্টা করে result ও JSON report ফেরত দেব।\n"
        "⚠️ সব obfuscation 100% decode হবে—এমন নিশ্চয়তা নেই।"
    )

async def help_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        f"সমর্থিত: .html .htm .js .mjs .txt | সর্বোচ্চ {MAX_BYTES // (1024*1024)} MB\n"
        "ফাইল পাঠালেই static analysis হবে। /start"
    )

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    if not doc:
        return
    name = Path(doc.file_name or "upload.txt").name
    if Path(name).suffix.lower() not in {".html", ".htm", ".js", ".mjs", ".txt"}:
        await update.message.reply_text("শুধু .html, .htm, .js, .mjs বা .txt ফাইল পাঠান।")
        return
    if doc.file_size and doc.file_size > MAX_BYTES:
        await update.message.reply_text(f"ফাইলের সীমা {MAX_BYTES // (1024*1024)} MB।")
        return
    local = TMP / f"{update.effective_user.id}_{name}"
    try:
        tgfile = await context.bot.get_file(doc.file_id)
        await tgfile.download_to_drive(custom_path=str(local))
        raw = local.read_bytes()
        if len(raw) > MAX_BYTES:
            await update.message.reply_text("ফাইলটি নির্ধারিত সীমার চেয়ে বড়।")
            return
        source = raw.decode("utf-8", errors="replace")
        decoded, report = decode_text(source)
        out = TMP / (Path(name).stem[:70] + "_static_decoded.txt")
        rep = TMP / (Path(name).stem[:70] + "_report.json")
        out.write_text(decoded, encoding="utf-8")
        rep.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        await update.message.reply_text("✅ Static analysis শেষ। Result ও report সংযুক্ত করা হলো।")
        with out.open("rb") as f:
            await update.message.reply_document(f, filename=out.name, caption="Decoded/normalized text")
        with rep.open("rb") as f:
            await update.message.reply_document(f, filename=rep.name, caption="Analysis report")
        out.unlink(missing_ok=True)
        rep.unlink(missing_ok=True)
    except Exception:
        log.exception("Could not process file")
        await update.message.reply_text("ফাইলটি পড়া যায়নি। Text-based HTML/JS ফাইল দিয়ে আবার চেষ্টা করুন।")
    finally:
        local.unlink(missing_ok=True)

def main():
    if not TOKEN:
        raise SystemExit("BOT_TOKEN environment variable is required.")
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", help_cmd))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))
    app.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
