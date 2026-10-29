# FIACB Static Decoder Telegram Bot

A safe static-analysis Telegram bot for HTML, JavaScript, and text files. It does not execute uploaded code.

## What it tries
- Decode HTML entities
- Decode common JavaScript Unicode/hex escapes
- Decode likely Base64 text literals
- Report patterns such as `eval()`, `atob()`, `fetch()`, and integrity/checksum text

## Limitations
This is not a universal deobfuscator. Advanced obfuscation, encrypted payloads, runtime-generated code, integrity guards, and password-protected content may remain unreadable. It does not crack passwords or bypass access controls.

## Create a bot token
1. Open Telegram and search for `@BotFather`.
2. Send `/newbot` and follow the steps.
3. Keep the token secret.

## Run locally
```bash
pip install -r requirements.txt
export BOT_TOKEN="YOUR_BOT_TOKEN"
python bot.py
```
Windows PowerShell:
```powershell
$env:BOT_TOKEN="YOUR_BOT_TOKEN"
python bot.py
```

## Deploy on Render
1. Put these files in a GitHub repository.
2. In Render, select **New + → Blueprint** and connect the repository.
3. Set `BOT_TOKEN` to your BotFather token.
4. Deploy as a background worker.

Manual Render settings:
- Build command: `pip install -r requirements.txt`
- Start command: `python bot.py`
- Environment variable: `BOT_TOKEN`

Commands: `/start`, `/help`.

Uploads are temporarily processed under `/tmp` and deleted afterward. Do not upload secrets to bots you do not control.
