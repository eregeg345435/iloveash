#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Discord Bot
- PDF extract + unlock + current Epic account status
- Valorant leaderboard scraper -> streams to a configured channel
"""

import os, sys, re, io, json, time, asyncio, logging, tempfile, random, threading, traceback
from typing import Optional, Tuple, Dict, List, Union
from collections import defaultdict
import requests
import datetime

import discord
from discord.ext import commands
import PyPDF2

# =============== ENV / CONSTANTS ===============

BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
PREMIUM_PASSWORD = os.getenv("PREMIUM_PASSWORD", "ZavsMasterKey2025")
BOT_USER = os.getenv("BOT_USER", "eregeg345435")
LAST_UPDATED = "2025-09-02"

API_BASE = "https://api.proswapper.xyz/external"
_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}
_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")

# Proxies (as before)
PROXIES = [
    "45.89.53.245:3128","66.36.234.130:1339","45.167.126.1:8080","190.242.157.215:8080",
    "154.62.226.126:8888","51.159.159.73:80","176.126.103.194:44214","185.191.236.162:3128",
    "157.180.121.252:35993","157.180.121.252:16621","157.180.121.252:55503","157.180.121.252:53919",
    "175.118.246.102:3128","64.92.82.61:8081","132.145.75.68:5457","157.180.121.252:35519","77.110.114.116:8081"
]
current_proxy = None
proxy_last_checked = 0.0
proxy_check_interval = 60
proxy_lock = threading.Lock()

# Channels config
NAMES_CHANNEL_ID = 0
PRE_SEARCH_CHANNEL_ID = 0
POST_SEARCH_CHANNEL_ID = 0
server_configs: Dict[int, Dict[str, int]] = {}
authorized_users: set[int] = set()

DELETE_MESSAGES = True
MESSAGE_DELETE_DELAY = 1

# =============== DATA DIR / LOGGING ===============

def _choose_data_dir() -> str:
    cand = os.getenv("DATA_DIR", "/data").strip() or "/data"
    try:
        os.makedirs(cand, exist_ok=True)
        test = os.path.join(cand, ".write_test")
        with open(test, "w", encoding="utf-8") as f: f.write("ok")
        os.remove(test)
        return cand
    except Exception:
        pass
    cand = os.path.abspath("./data")
    os.makedirs(cand, exist_ok=True)
    return cand

DATA_DIR = _choose_data_dir()
LOG_PATH = os.path.join(DATA_DIR, "discord_bot.log")
PROCESSED_PATH = os.path.join(DATA_DIR, "processed_accounts.json")
LB_CONFIG_PATH = os.path.join(DATA_DIR, "leaderboard_config.json")

logger = logging.getLogger("discord_bot")
logger.setLevel(logging.INFO)
logger.handlers.clear()
_sh = logging.StreamHandler(sys.stdout); _sh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
_fh = logging.FileHandler(LOG_PATH, encoding="utf-8"); _fh.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
logger.addHandler(_sh); logger.addHandler(_fh)

# =============== DISCORD BOT ===============

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)
processing_lock = asyncio.Lock()

# =============== STATE LOAD/SAVE ===============

processed_account_ids: set[str] = set()
try:
    if os.path.exists(PROCESSED_PATH):
        with open(PROCESSED_PATH, "r", encoding="utf-8") as f:
            lst = json.load(f)
            if isinstance(lst, list):
                processed_account_ids = set(lst)
except Exception as e:
    logger.error(f"Error loading processed accounts: {e}")

def save_processed_account_ids():
    try:
        with open(PROCESSED_PATH, "w", encoding="utf-8") as f:
            json.dump(list(processed_account_ids), f)
    except Exception as e:
        logger.error(f"Error saving processed accounts: {e}")

def _load_lb_config():
    try:
        if os.path.exists(LB_CONFIG_PATH):
            with open(LB_CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                return {int(k): int(v) for k, v in data.items()}
    except Exception as e:
        logger.error(f"Error loading leaderboard config: {e}")
    return {}

def _save_lb_config(cfg: dict):
    try:
        with open(LB_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f)
    except Exception as e:
        logger.error(f"Error saving leaderboard config: {e}")

leaderboard_channels: Dict[int, int] = _load_lb_config()

# =============== PROXY / API ===============

def test_proxy(proxy: str, timeout: float = 3.0) -> bool:
    p = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
    try:
        r = requests.get(f"{API_BASE}/name/test", proxies=p, timeout=timeout, headers=_HEADERS)
        return r.status_code == 200
    except Exception:
        return False

def find_working_proxy(force_check: bool = False) -> Optional[str]:
    global current_proxy, proxy_last_checked
    with proxy_lock:
        now = time.time()
        if not force_check and current_proxy and (now - proxy_last_checked) < proxy_check_interval:
            return current_proxy
        if current_proxy and test_proxy(current_proxy):
            proxy_last_checked = now
            return current_proxy
        shuffled = PROXIES.copy(); random.shuffle(shuffled)
        for p in shuffled:
            if test_proxy(p):
                current_proxy = p; proxy_last_checked = now
                return p
        current_proxy = None
        return None

def get_api_response(url: str, timeout: float = 8.0) -> Union[dict, list]:
    global current_proxy, proxy_last_checked
    if not current_proxy:
        current_proxy = find_working_proxy()
    if current_proxy:
        pd = {'http': f'http://{current_proxy}', 'https': f'http://{current_proxy}'}
        try:
            resp = requests.get(url, headers=_HEADERS, proxies=pd, timeout=timeout)
            if resp.status_code == 200: return resp.json()
            if resp.status_code == 404: return {"status": "INACTIVE", "message": "Account not found or inactive"}
            if resp.status_code == 403: threading.Thread(target=lambda: find_working_proxy(True), daemon=True).start()
        except Exception:
            threading.Thread(target=lambda: find_working_proxy(True), daemon=True).start()
    for p in PROXIES:
        if p == current_proxy: continue
        pd = {'http': f'http://{p}', 'https': f'http://{p}'}
        try:
            resp = requests.get(url, headers=_HEADERS, proxies=pd, timeout=timeout)
            if resp.status_code == 200:
                current_proxy = p; proxy_last_checked = time.time()
                return resp.json()
            if resp.status_code == 404:
                return {"status": "INACTIVE", "message": "Account not found or inactive"}
        except Exception:
            continue
    try:
        resp = requests.get(url, headers=_HEADERS, timeout=timeout)
        if resp.status_code == 200: return resp.json()
        if resp.status_code == 404: return {"status": "INACTIVE", "message": "Account not found or inactive"}
        if resp.status_code == 403: return {"status": "ERROR", "message": "API access denied"}
        return {"status": "ERROR", "message": f"HTTP error: {resp.status_code}"}
    except Exception as e:
        return {"status": "ERROR", "message": f"Error: {str(e)}"}

def epic_lookup(value: str, mode: Optional[str] = None, platform: Optional[str] = None) -> Union[dict, list]:
    if not value or value.strip() == "":
        return {"status": "ERROR", "message": "Please provide a display name or account ID"}
    value = value.strip()
    if mode is None:
        mode = "id" if _HEX32.match(value) else "name"
    elif mode not in {"name", "id"}:
        return {"status": "ERROR", "message": "mode must be 'name', 'id', or None"}
    url = f"{API_BASE}/{mode}/{value}"
    resp = get_api_response(url)
    if platform and isinstance(resp, list):
        filt = []
        for acc in resp:
            if 'externalAuths' in acc and platform.lower() in acc['externalAuths']:
                filt.append(acc)
        if filt: return filt
    return resp

# =============== PDF PARSE HELPERS ===============

def detect_platform_from_transactions(text: str) -> Tuple[str, str]:
    lower = text.lower()
    if 'xbl_xtoken' in lower or any(t in lower for t in ["xbox","xbl","xb1","xsx"]): return 'Xbox (XBL)','xbl_xtoken'
    if 'psn_xtoken' in lower or any(t in lower for t in ["playstation","psn","ps4","ps5"]): return 'PlayStation (PSN)','psn_xtoken'
    if 'nintendo' in lower or 'switch' in lower: return 'Nintendo Switch','nintendo'
    if any(t in lower for t in ["pc","epic","computer","windows"]): return 'PC/Epic Games','epic'
    if any(t in lower for t in ["mobile","ios","android","phone"]): return 'Mobile (iOS/Android)','mobile'
    return 'Unknown',''

def deduplicate_accounts(accounts_list: Union[list, dict]) -> Union[list, dict]:
    if not isinstance(accounts_list, list): return accounts_list
    uniq = {}
    for acc in accounts_list:
        if isinstance(acc, dict):
            aid = acc.get('id')
            if aid: uniq[aid] = acc
    return list(uniq.values())

def extract_user_info_from_text(text: str) -> dict:
    info = {
        'display_names': [], 'email': None, 'all_emails': [],
        'account_id': None, 'creation_date': None,
        'transactions': [], 'oldest_ip': None, 'oldest_ip_date': None,
        'platform': None, 'platform_token': None,
        'account_disabled': False, 'disable_count': 0, 'disable_dates': [],
        'reactivated': False, 'reactivate_dates': [],
        'deactivated': False, 'compromised_account': False,
        'source_file': None, 'is_encrypted': False, 'account_status': None
    }

    m = re.search(r'(?:information extracted from|file|data source)[:\s]+([^\n]+\.(?:pdf|txt|json))', text, re.I)
    if m: info['source_file'] = m.group(1).strip()

    dn_pats = [
        r'(?:Display\s*Name|externalAuthDisplayName|displayName|username)[s\:]*[:\s="]+([^\r\n,;"\'][\S][^\r\n,;"\']+)',
        r'displayName\s*:?\s*["\']([^"\']+)["\']',
        r'name\s*:?\s*["\']([^"\']+)["\']',
        r'gamertag\s*:?\s*["\']([^"\']+)["\']'
    ]
    for pat in dn_pats:
        for mm in re.finditer(pat, text, re.I):
            dn = mm.group(1).strip().strip('"\'')
            if dn and dn not in info['display_names']:
                info['display_names'].append(dn)

    email_pats = [
        r'(?:Current\s*Email|Original\s*Email|email)[:\s="]+\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        r'[\w\.-]+@[\w\.-]+\.\w+',
        r'email\s*[=:]\s*"([^"]+@[^"]+\.\w+)"',
        r'email\s*[=:]\s*([^\s;,]+@[^\s;,]+\.\w+)'
    ]
    for pat in email_pats:
        for mm in re.finditer(pat, text, re.I):
            email = (mm.group(1) if mm.groups() else mm.group(0)).strip('"\'')
            if '@' in email and email not in info['all_emails']:
                info['all_emails'].append(email)
                ctx = text[max(0, mm.start()-20):mm.start()].lower()
                if 'current' in ctx: info['email'] = email
    if info['all_emails'] and not info['email']:
        info['email'] = info['all_emails'][0]

    id_pats = [r'(?:Account\s*ID|account|user|id)[\s_-]*(?:id|number|#)[\s:_-]+([^\s\n,]+)', r'Account\s*ID:?\s*([a-f0-9]+)']
    for pat in id_pats:
        mm = re.search(pat, text, re.I)
        if mm: info['account_id'] = mm.group(1).strip(); break

    date_pats = [r'Creation\s*Date:?\s*(\d{1,2}[\/\.-]\d{1,2}[\/\.-]\d{2,4})',
                 r'(?:created|registered|joined|creation|registration|date)[\s:_-]+(\d{1,2}[\/\.-]\d{1,2}[\/\.-]\d{2,4}|\d{4}[\/\.-]\d{1,2}[\/\.-]\d{1,2})']
    for pat in date_pats:
        mm = re.search(pat, text, re.I)
        if mm: info['creation_date'] = mm.group(1); break

    # platform/tokens
    auth_pats = [r'addedExternalAuth[:\s]+([^\s\n]+)', r'externalAuth[:\s]+([^\s\n]+)', r'platform[:\s]+([^\n]+)', r'\b(psn_xtoken|xbl_xtoken|epic|nintendo)\b']
    mentions = []
    for pat in auth_pats:
        for mm in re.finditer(pat, text, re.I):
            mentions.append(mm.group(1).strip().lower())
    if any('xbl_xtoken' in x for x in mentions): info['platform'], info['platform_token'] = 'Xbox (XBL)', 'xbl_xtoken'
    elif any('psn_xtoken' in x for x in mentions): info['platform'], info['platform_token'] = 'PlayStation (PSN)', 'psn_xtoken'
    elif any('nintendo' in x for x in mentions): info['platform'], info['platform_token'] = 'Nintendo Switch', 'nintendo'
    elif any(('epic' in x or 'pc' in x) for x in mentions): info['platform'], info['platform_token'] = 'PC/Epic Games', 'epic'
    else:
        mm = re.search(r'Platform:?\s*([^\n]+)', text, re.I)
        if mm:
            p,t = detect_platform_from_transactions(mm.group(1)); info['platform'], info['platform_token'] = p,t

    ip_pats = [r'Oldest\s*IP:?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
               r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[\s:_-]+(\d{1,2}/\d{1,2}/\d{2,4}))?']
    for pat in ip_pats:
        mm = re.search(pat, text, re.I)
        if mm:
            info['oldest_ip'] = mm.group(1)
            if len(mm.groups())>1 and mm.group(2): info['oldest_ip_date'] = mm.group(2); break

    sm = re.search(r'Account\s*Status:?\s*([^\n]+)', text, re.I)
    if sm:
        st = sm.group(1).lower().strip()
        if 'disabled' in st or 'disable' in st:
            info['account_disabled'] = True
            c = re.search(r'disabled\s+(\d+)\s+time', st, re.I)
            info['disable_count'] = int(c.group(1)) if c else 1
            if 'compromised' in st: info['compromised_account'] = True
            if 'deactivated' in st: info['deactivated'] = True
            if 'reactivated' in st: info['reactivated'] = True

    tx_pats = [
        r'HISTORY_ACCOUNT_([A-Z_]+)\s+(\d{1,2}/\d{1,2}/\d{2,4})\s+(.+?)(?=\n|$)',
        r'(\d{1,2}/\d{1,2}/\d{4})\s+(addedExternalAuth)\s*:\s*([^\n]+)',
        r'(\d{1,2}/\d{1,2}/\d{2,4})\s+([^\s:]+)(?:\s*:\s*|\s+)([^\n]+)'
    ]
    for pat in tx_pats:
        for mm in re.finditer(pat, text, re.I):
            if len(mm.groups()) == 3 and mm.group(1).lower() not in ['addedexternalauth']:
                ttype, date, details = mm.group(1), mm.group(2), mm.group(3).strip()
            else:
                ttype, date, details = mm.group(2).upper(), mm.group(1), mm.group(3).strip()

            if 'DISABLE' in ttype:
                info['account_disabled'] = True
                info['disable_count'] += 1
                info['disable_dates'].append(date)
                if 'meta data' in details.lower(): info['deactivated'] = True

            if any(k in ttype for k in ['REACTIVE','REENABLE','ENABLED']):
                info['reactivated'] = True; info['reactivate_dates'].append(date)

            dl = details.lower()
            if 'xbl_xtoken' in dl: info['platform'], info['platform_token'] = 'Xbox (XBL)','xbl_xtoken'
            elif 'psn_xtoken' in dl: info['platform'], info['platform_token'] = 'PlayStation (PSN)','psn_xtoken'
            elif 'nintendo' in dl: info['platform'], info['platform_token'] = 'Nintendo Switch','nintendo'
            elif any(t in dl for t in ['pc','epic']): info['platform'], info['platform_token'] = 'PC/Epic Games','epic'

            info['transactions'].append({'type': ttype,'date': date,'details': details})

    if not info['platform'] or info['platform'] == 'Unknown':
        p,t = detect_platform_from_transactions(text)
        if p != 'Unknown': info['platform'], info['platform_token'] = p,t

    return info

# =============== DISCORD HELPERS ===============

def get_channels(guild_id: int) -> Tuple[int,int,int]:
    if guild_id in server_configs:
        c = server_configs[guild_id]; return c["names_channel"], c["pre_search_channel"], c["post_search_channel"]
    return NAMES_CHANNEL_ID, PRE_SEARCH_CHANNEL_ID, POST_SEARCH_CHANNEL_ID

async def check_account_status(account_id: str) -> Optional[dict]:
    if not account_id: return None
    account_id = re.sub(r'[^a-zA-Z0-9]', '', account_id)
    if len(account_id) != 32:
        return {"status": "INVALID", "message": f"Invalid account ID format: {account_id}"}
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, lambda: epic_lookup(account_id, mode="id"))
        if result and isinstance(result, dict) and "status" not in result:
            result["status"] = "ACTIVE"
        return result
    except Exception as e:
        logger.error(f"Error checking account status: {e}")
        return {"status": "ERROR", "message": f"Error checking account status: {e}"}

async def send_pdf_analysis(ctx, info: dict):
    src = info.get('source_file', 'Unknown')
    sd = info.get('account_status')
    out = ["**📊 ACCOUNT ANALYSIS**", ""]

    def fmt_external(ext):
        if not isinstance(ext, dict) or not ext: return None
        lines = []
        for k, v in ext.items():
            if isinstance(v, dict): lines.append(f"- {k}: {v.get('externalDisplayName','N/A')}")
            else: lines.append(f"- {k}: {str(v)}")
        return "\n".join(lines) if lines else None

    if isinstance(sd, dict):
        st = sd.get("status")
        if st == "ACTIVE":
            out += ["**🟢 ACCOUNT CURRENTLY ACTIVE**"]
            dn = sd.get("displayName") or sd.get("display_name")
            if dn: out += [f"**Current Display Name:** {dn}"]
            ex = fmt_external(sd.get("externalAuths"))
            if ex: out += ["**Current Linked Accounts:**", ex, ""]
        elif st == "INACTIVE":
            out += ["**🔴 ACCOUNT CURRENTLY INACTIVE**", sd.get("message",""), "The account may have been banned, deleted, or changed username.", ""]
        elif st in {"ERROR","FORBIDDEN","INVALID"}:
            out += ["**⚠️ ACCOUNT STATUS ISSUE**", sd.get("message",""), ""]
    else:
        out += ["**⚠️ ACCOUNT STATUS UNKNOWN**", "Could not check current account status.", ""]

    out += [f"**Information extracted from:** {src}", ""]
    if info.get('display_names'):
        out += [f"**Display Names:** {', '.join(info['display_names'])}"]
        if len(info['display_names']) > 1:
            out += [f"Changed: {len(info['display_names'])-1}"]
    if info.get('email'): out += [f"**Current Email:** {info['email']}"]
    if info.get('account_id'): out += [f"**Account ID:** {info['account_id']}"]
    if info.get('creation_date'): out += [f"**Creation Date:** {info['creation_date']}"]
    if info.get('platform'):
        tok = info.get('platform_token'); out += [f"**Platform:** {info['platform']}" + (f" [{tok}]" if tok else "")]
    if info.get('oldest_ip'): out += [f"**Oldest IP:** {info['oldest_ip']}"]

    if info.get('account_disabled'):
        tail = f"Disabled {info.get('disable_count',0)} time(s)"
        if info.get('compromised_account'): tail += ", **COMPROMISED ACCOUNT DETECTED**"
        if info.get('deactivated'): tail += ", Deactivated (metadata added)"
        if info.get('reactivated'): tail += ", Reactivated (metadata removed)"
    else:
        tail = "No disable/reactivation history found"
    out += ["", f"**Account Status History:** {tail}"]

    await ctx.send("\n".join(out))
    if info.get('is_encrypted'): await ctx.send("Here is the unlocked PDF.")

# =============== PDF PROCESSOR ===============

async def process_pdf(ctx, attachment, password=None, delete_message=True):
    msg_to_delete = getattr(ctx, 'message', None)
    try:
        try:
            b = await attachment.read()
            if not b: await ctx.send("Could not read the PDF file (file is empty)."); return
        except discord.NotFound:
            await ctx.send("❌ Error: The file was not found or was deleted. Please upload it again."); return
        except discord.HTTPException as e:
            await ctx.send(f"❌ Error downloading the PDF: HTTP Error {e.status}: {e.text}"); return
        except Exception as e:
            await ctx.send(f"❌ Error downloading the PDF: {str(e)}"); logger.error(f"PDF download error: {str(e)}\n{traceback.format_exc()}"); return

        await ctx.send(f"Processing PDF: `{attachment.filename}` ({attachment.size/1024:.1f} KB)")

        if delete_message and msg_to_delete:
            try: await msg_to_delete.delete()
            except Exception: pass

        pdf_file = io.BytesIO(b)
        try:
            reader = PyPDF2.PdfReader(pdf_file)
            is_encrypted = reader.is_encrypted
            if is_encrypted:
                if not password:
                    await ctx.send("This PDF is password protected. Please provide a password with `!pdf [password]`")
                    return
                try:
                    reader.decrypt(password)
                    await ctx.send("✅ PDF successfully decrypted!")
                except Exception:
                    await ctx.send("❌ Failed to decrypt PDF. The password may be incorrect."); return

            text = ""
            try:
                for page in reader.pages:
                    try:
                        t = page.extract_text()
                        if t: text += t + "\n\n"
                    except Exception: continue
            except Exception as e:
                logger.error(f"Error extracting all pages: {str(e)}")
            if not text:
                try: text = reader.pages[0].extract_text()
                except Exception as e:
                    await ctx.send(f"Error extracting text from PDF: {str(e)}"); return

            info = extract_user_info_from_text(text)
            info['source_file'] = attachment.filename
            info['is_encrypted'] = is_encrypted

            if info.get('account_id') and info['account_id'] in processed_account_ids:
                await ctx.send(f"⚠️ This PDF has already been searched (Account ID: {info['account_id']})")
                return

            if info.get('account_id'):
                sm = await ctx.send(f"🔍 Checking current account status for ID: `{info['account_id']}`...")
                status = await check_account_status(info['account_id'])
                info['account_status'] = status
                await sm.edit(content="✅ Account status check complete.")

            await send_pdf_analysis(ctx, info)

            if info.get('account_id'):
                processed_account_ids.add(info['account_id']); save_processed_account_ids()

            if is_encrypted and password:
                writer = PyPDF2.PdfWriter()
                for p in reader.pages: writer.add_page(p)
                tmp = None
                try:
                    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tf:
                        writer.write(tf); tmp = tf.name
                    await ctx.send("Here is the unlocked PDF:", file=discord.File(tmp, f"unlocked_{attachment.filename}"))
                except Exception as e:
                    logger.error(f"Error saving unlocked PDF: {str(e)}")
                    await ctx.send("Error saving the unlocked PDF.")
                finally:
                    try:
                        if tmp and os.path.exists(tmp): os.unlink(tmp)
                    except Exception: pass

        except PyPDF2.errors.PdfReadError as e:
            await ctx.send(f"❌ Error: Cannot read the PDF file. It may be corrupted or not a valid PDF. {str(e)}")
            return
        except Exception as e:
            logger.error(f"Error processing PDF: {str(e)}\n{traceback.format_exc()}")
            await ctx.send(f"❌ Error processing PDF: {str(e)}")
            return

    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}\n{traceback.format_exc()}")
        await ctx.send(f"❌ Unexpected error: {str(e)}")
        return

# =============== LEADERBOARD (UC/SELENIUM) ===============

try:
    import undetected_chromedriver as uc
    from selenium.webdriver.common.by import By
    from selenium.webdriver.support.ui import WebDriverWait
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
except Exception:
    uc = None; By = None; WebDriverWait = None

HEADLESS_CHROME = True

def _create_uc_driver(headless: bool = True, profile_dir: Optional[str] = None):
    if uc is None: raise RuntimeError("undetected-chromedriver not installed.")
    options = uc.ChromeOptions()
    if profile_dir: options.add_argument(f"--user-data-dir={profile_dir}")
    options.binary_location = os.getenv("CHROME_BIN", "/usr/bin/google-chrome")
    options.add_argument("--disable-blink-features=AutomationControlled")
    if headless: options.add_argument("--headless=new")
    options.add_argument("--window-size=1200,900")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--enable-javascript")
    options.add_argument("--disable-infobars")
    options.add_argument("--disable-extensions")
    options.add_argument("--start-maximized")
    options.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
    driver = uc.Chrome(options=options, headless=headless)
    driver.set_window_size(1200, 900)
    try: driver.delete_all_cookies()
    except Exception: pass
    return driver

def _build_page_url(leaderboard_url: str, page: int) -> str:
    parsed = urlparse(leaderboard_url); qs = parse_qs(parsed.query)
    qs["page"] = [str(page)]
    query = urlencode({k: v if isinstance(v, list) else [v] for k, v in qs.items()}, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

def _scrape_100_users_from_page(driver, leaderboard_url: str, page: int) -> List[dict]:
    """Close to your original logic; returns only entries with Twitter."""
    page_url = _build_page_url(leaderboard_url, page)
    driver.get(page_url)
    WebDriverWait(driver, 20).until(lambda d: d.find_elements(By.CSS_SELECTOR, "div.flex.items-center.gap-4"))
    rows = driver.find_elements(By.CSS_SELECTOR, "div.flex.items-center.gap-4")
    users = []
    for row in rows:
        username_elem, discriminator_elem = None, None
        for sel in ["span.max-w-full.truncate", "span[class*='username']"]:
            try:
                el = row.find_element(By.CSS_SELECTOR, sel)
                if el.text.strip(): username_elem = el; break
            except Exception: continue
        for sel in ["span[class*='discriminator']"]:
            try:
                el = row.find_element(By.CSS_SELECTOR, sel)
                if el.text.strip(): discriminator_elem = el; break
            except Exception: continue

        username = username_elem.text.strip() if username_elem else "[unknown]"
        discriminator = discriminator_elem.text.strip().lstrip('#').strip() if discriminator_elem else ""
        # sanitize tag: keep alnum, underscore, hyphen only
        discriminator = re.sub(r'[^A-Za-z0-9_-]+', '', discriminator)

        twitter_link, twitch_link = "", ""
        for link in row.find_elements(By.CSS_SELECTOR, "a[href]"):
            href = (link.get_attribute("href") or "").strip()
            if "twitter.com/" in href and not twitter_link:
                twitter_link = href
            if "twitch.tv/" in href and not twitch_link:
                twitch_link = href

        if not twitter_link:
            continue

        users.append({
            "username": username,
            "discriminator": discriminator,
            "twitter_link": twitter_link,
            "twitch_link": twitch_link
        })
    return users

async def stream_leaderboard_to_channel(channel: discord.TextChannel, leaderboard_url: str, start_page: int = 1):
    """Iterate pages and post rows into channel. Stops after 3 empty/error pages."""
    prof = tempfile.mkdtemp(prefix="valorant_profile_")
    try:
        driver = _create_uc_driver(headless=HEADLESS_CHROME, profile_dir=prof)
    except Exception as e:
        await channel.send(f"❌ Could not start browser: {e}")
        return

    seen = set()
    page = start_page
    empty_pages = 0

    try:
        while True:
            try:
                users = _scrape_100_users_from_page(driver, leaderboard_url, page)
            except Exception as e:
                logger.info(f"LB page {page} error: {e}")
                users = []

            if not users:
                empty_pages += 1
                if empty_pages >= 3:
                    await channel.send(f"✅ Finished at page {page} (no results for {empty_pages} consecutive pages).")
                    break
                page += 1
                continue

            empty_pages = 0
            # Prepare nicely spaced + angle-bracket links (Discord-safe)
            new_lines = []
            for u in users:
                ident = f"{u['username']}#{u['discriminator']}" if u['discriminator'] else u['username']
                ident_lower = ident.lower()
                if ident_lower in seen:
                    continue
                seen.add(ident_lower)
                tw = f"<{u['twitter_link']}>" if u['twitter_link'] else ""
                tv = f"<{u['twitch_link']}>" if u['twitch_link'] else ""
                # add spaces around pipes to avoid %7C and link merge
                line = f"{ident} | {tw} | {tv}".strip()
                new_lines.append(line)

            if new_lines:
                # send in batches within Discord message limit
                buf, size = [], 0
                for line in new_lines:
                    if size + len(line) + 1 > 1900:
                        await channel.send("\n".join(buf))
                        buf, size = [], 0
                    buf.append(line); size += len(line) + 1
                if buf:
                    await channel.send("\n".join(buf))

            await channel.send(f"📄 Page {page} done. New lines: {len(new_lines)}")
            page += 1

    finally:
        try: driver.quit()
        except Exception: pass

# =============== EVENTS / BACKGROUND ===============

async def proxy_maintenance_task():
    await bot.wait_until_ready()
    while not bot.is_closed():
        try: find_working_proxy()
        except Exception: pass
        await asyncio.sleep(60)

@bot.event
async def on_ready():
    logger.info(f"Bot logged in as {bot.user.name} ({bot.user.id})")
    print(f"Bot is ready! Logged in as {bot.user.name}")
    bot.loop.create_task(proxy_maintenance_task())
    if not authorized_users:
        print("No authorized users yet. First user to interact is auto-authorized.")

@bot.event
async def on_message(message):
    if message.author == bot.user: return
    if not authorized_users and not message.author.bot:
        authorized_users.add(message.author.id)
        try: await message.author.send("✅ You've been automatically authorized for premium commands as the first user.")
        except Exception: await message.channel.send(f"✅ {message.author.mention}, you're authorized for premium commands.")
    if message.content.startswith('!lookup '):
        try: await message.delete()
        except Exception: pass
    await bot.process_commands(message)

    if message.guild and message.channel.id:
        names_channel_id, _, _ = get_channels(message.guild.id)
        if names_channel_id and message.channel.id == names_channel_id:
            for att in message.attachments:
                if att.filename.lower().endswith('.pdf'):
                    await process_pdf(message.channel, att, delete_message=False)
                    return
            try:
                await asyncio.sleep(MESSAGE_DELETE_DELAY); await message.delete()
            except Exception as e:
                logger.error(f"Error deleting message: {str(e)}")

# =============== COMMANDS ===============

async def check_premium_access(ctx) -> bool:
    if ctx.author.id not in authorized_users:
        await ctx.send("⚠️ This is a premium command. Use `!authorize [password]`.")
        try: await ctx.message.delete()
        except Exception: pass
        return False
    return True

@bot.command(name='authorize')
async def authorize_user(ctx, password=None):
    if not password:
        await ctx.send("Usage: `!authorize [password]`"); return
    if password == PREMIUM_PASSWORD:
        authorized_users.add(ctx.author.id)
        await ctx.send("✅ You are now authorized for premium commands!")
        try: await ctx.message.delete()
        except Exception: pass
    else:
        await ctx.send("❌ Invalid password.")
        try: await ctx.message.delete()
        except Exception: pass

@bot.command(name='pdf')
async def process_pdf_command(ctx, password=None):
    if not ctx.message.attachments:
        await ctx.send("Attach a PDF first."); return
    att = ctx.message.attachments[0]
    if not att.filename.lower().endswith('.pdf'):
        await ctx.send("Please attach a PDF file."); return
    await process_pdf(ctx, att, password, delete_message=True)

@bot.command(name='lookup')
async def lookup_command(ctx, *args):
    if not await check_premium_access(ctx): return
    if not args:
        await ctx.send("Usage:\n`!lookup <name/id>`\n`!lookup xbl <gamertag>`\n`!lookup psn <username>`\n`!lookup switch <username>`")
        return
    platform = None
    if args[0].lower() in ['xbl','xbox','x']:
        if len(args) < 2: await ctx.send("Usage: `!lookup xbl Ninja`"); return
        platform='xbl'; value=' '.join(args[1:]); mode='name'
    elif args[0].lower() in ['psn','playstation','ps','ps4','ps5']:
        if len(args) < 2: await ctx.send("Usage: `!lookup psn Ninja`"); return
        platform='psn'; value=' '.join(args[1:]); mode='name'
    elif args[0].lower() in ['switch','nintendo','ns']:
        if len(args) < 2: await ctx.send("Usage: `!lookup switch Ninja`"); return
        platform='nintendo'; value=' '.join(args[1:]); mode='name'
    else:
        value=' '.join(args); mode="id" if _HEX32.match(value) else "name"

    lookup_type = "account ID" if mode == "id" else "display name"
    platform_msg = f" on {platform.upper()}" if platform else ""
    msg = await ctx.send(f"🔍 Looking up Epic account by {lookup_type}{platform_msg}: `{value}`...")

    result = await asyncio.get_event_loop().run_in_executor(None, lambda: epic_lookup(value, mode, platform))
    if isinstance(result, dict) and result.get("status") in {"ERROR","INACTIVE","FORBIDDEN","INVALID"}:
        await msg.edit(content=f"❌ {result.get('message','Lookup failed')}"); return

    try:
        if mode=="name" and isinstance(result, list):
            await msg.delete()
            uniq = deduplicate_accounts(result)
            if not uniq: await ctx.send(f"❌ No results for `{value}`{platform_msg}."); return
            for acc in uniq[:5]:
                dn = acc.get("displayName","Unknown"); aid = acc.get("id","Unknown")
                emb = discord.Embed(title=f"Epic Account (name match): {dn}", color=discord.Color.green())
                emb.add_field(name="Account ID", value=aid, inline=False)
                ext = acc.get("externalAuths") or {}
                if ext:
                    lines=[]
                    for plat, data in ext.items():
                        if isinstance(data, dict): lines.append(f"{plat}: {data.get('externalDisplayName','N/A')}")
                        else: lines.append(f"{plat}: {str(data)}")
                    if lines: emb.add_field(name="Linked Accounts", value="\n".join(lines), inline=False)
                await ctx.send(embed=emb)
            if len(uniq)>5: await ctx.send(f"ℹ️ More results exist ({len(uniq)-5} more). Refine your search.")
            return
        elif mode=="id" and isinstance(result, dict):
            await msg.delete()
            dn = result.get("displayName","Unknown"); aid = result.get("id",value)
            emb = discord.Embed(title=f"Epic Account (by ID): {dn}", color=discord.Color.green())
            emb.add_field(name="Account ID", value=aid, inline=False)
            ext = result.get("externalAuths") or {}
            if ext:
                lines=[]
                for plat,data in ext.items():
                    if isinstance(data, dict): lines.append(f"{plat}: {data.get('externalDisplayName','N/A')}")
                    else: lines.append(f"{plat}: {str(data)}")
                if lines: emb.add_field(name="Linked Accounts", value="\n".join(lines), inline=False)
            await ctx.send(embed=emb); return
        elif mode=="name" and isinstance(result, dict):
            await msg.delete()
            dn = result.get("displayName","Unknown"); aid = result.get("id","Unknown")
            emb = discord.Embed(title=f"Epic Account (exact name match): {dn}", color=discord.Color.green())
            emb.add_field(name="Account ID", value=aid, inline=False)
            ext = result.get("externalAuths") or {}
            if ext:
                lines=[]
                for plat,data in ext.items():
                    if isinstance(data, dict): lines.append(f"{plat}: {data.get('externalDisplayName','N/A')}")
                    else: lines.append(f"{plat}: {str(data)}")
                if lines: emb.add_field(name="Linked Accounts", value="\n".join(lines), inline=False)
            await ctx.send(embed=emb); return
        await msg.edit(content=f"❌ No results found for `{value}`{platform_msg}.")
    except Exception as e:
        logger.error(f"Error in lookup command: {e}")
        await msg.edit(content=f"❌ Error processing API response: {str(e)}")

@bot.command(name='lbsetup')
@commands.has_permissions(administrator=True)
async def leaderboard_setup(ctx, channel: discord.TextChannel = None):
    """Pick which channel will receive leaderboard usernames."""
    if not channel:
        await ctx.send("Usage: `!lbsetup #channel`"); return
    leaderboard_channels[ctx.guild.id] = channel.id
    _save_lb_config(leaderboard_channels)
    await ctx.send(f"✅ Leaderboard output channel set to {channel.mention}. Use `!scrapelb <url> [start_page]` to begin.")

@bot.command(name='scrapelb')
async def scrape_leaderboard_command(ctx, leaderboard_url: str = None, start_page: int = 1):
    """Scrape the leaderboard and stream usernames into the configured channel."""
    if leaderboard_url is None:
        await ctx.send("Usage: `!scrapelb <leaderboard_url> [start_page]`"); return
    ch_id = leaderboard_channels.get(ctx.guild.id)
    if not ch_id:
        await ctx.send("⚠️ No leaderboard channel set. Run `!lbsetup #channel` first."); return
    channel = ctx.guild.get_channel(ch_id)
    if not channel:
        await ctx.send("⚠️ I can’t see that channel anymore. Run `!lbsetup #channel` again."); return
    await ctx.send(f"🧭 Starting scrape from page {start_page} → posting to {channel.mention}")
    bot.loop.create_task(stream_leaderboard_to_channel(channel, leaderboard_url, start_page))

@bot.command(name='testproxies')
async def test_proxies_command(ctx):
    if not await check_premium_access(ctx): return
    await ctx.send("Testing proxies... this may take a moment.")
    working, total = 0, len(PROXIES)
    prog = await ctx.send(f"Progress: 0/{total} tested")
    working_list, seen_updates = [], set()
    for i, p in enumerate(PROXIES):
        if test_proxy(p): working += 1; working_list.append(p)
        if (i+1) % 5 == 0 or i+1 == total:
            txt = f"Progress: {i+1}/{total} tested, {working} working"
            if txt not in seen_updates:
                seen_updates.add(txt); await prog.edit(content=txt)
    await ctx.send(f"✅ Found {working} working proxies out of {total}")
    if working_list:
        for i in range(0, len(working_list), 20):
            await ctx.send("```\n" + "\n".join(working_list[i:i+20]) + "\n```")

@bot.command(name='version')
async def version_info(ctx):
    if not await check_premium_access(ctx): return
    embed = discord.Embed(title="Bot Version Information", color=0x00ff00)
    embed.add_field(name="Last Updated", value=LAST_UPDATED, inline=False)
    embed.add_field(name="User", value=BOT_USER, inline=False)
    embed.add_field(name="Discord.py Version", value=discord.__version__, inline=True)
    embed.add_field(name="Python Version", value=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}", inline=True)
    if current_proxy: embed.add_field(name="API Connection", value="Active (using proxy)", inline=False)
    else: embed.add_field(name="API Connection", value="Direct connection", inline=False)
    embed.set_footer(text=f"Bot is running on {os.name.upper()} platform")
    await ctx.send(embed=embed)

@bot.command(name='commands')
async def custom_commands_help(ctx):
    if not await check_premium_access(ctx): return
    e = discord.Embed(title="Bot Commands", color=0x00ff00)
    e.set_footer(text=f"Bot Last Updated: {LAST_UPDATED}")
    e.add_field(name="!pdf [password]", value="Process attached PDF (optional password if encrypted).", inline=False)
    e.add_field(name="!lookup ...", value="Lookup Epic account by name/ID or platform.", inline=False)
    e.add_field(name="!lbsetup #channel", value="Choose channel for leaderboard usernames.", inline=False)
    e.add_field(name="!scrapelb <url> [start_page]", value="Start streaming usernames to the chosen channel.", inline=False)
    e.add_field(name="!testproxies", value="Test proxies.", inline=False)
    e.add_field(name="!version", value="Show version info.", inline=False)
    e.add_field(name="!authorize [password]", value="Authorize premium commands.", inline=False)
    await ctx.send(embed=e)

# =============== MAIN ===============

if __name__ == "__main__":
    if not BOT_TOKEN:
        print("ERROR: No bot token provided. Set DISCORD_BOT_TOKEN."); sys.exit(1)
    print("Starting bot...")
    print(f"Data dir: {DATA_DIR}")
    print(f"Last updated: {LAST_UPDATED} | User: {BOT_USER}")
    print("Testing API connection...")
    if find_working_proxy(): print("✅ API connection ready (proxy mode)")
    else: print("⚠️ No working proxy; using direct")
    try:
        bot.run(BOT_TOKEN)
    except discord.errors.LoginFailure:
        print("ERROR: Invalid bot token."); sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to start the bot: {e}"); sys.exit(1)
