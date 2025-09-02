#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Discord Bot with PDF Processing
- Extracts information from and unlocks PDF files
- Checks Epic Games account status via API
Last updated: 2025-09-02 05:47:18 (with Render worker + health webhook + DATA_DIR)
"""

import os
import json
import time
import logging
import re
import asyncio
import io
import tempfile
import sys
import random
import threading
from typing import List, Dict, Tuple, Union, Optional
from collections import defaultdict
import requests
import discord
from discord.ext import commands
import datetime
import PyPDF2
import traceback
import signal

# =========================
# ENV / CONSTANTS / PATHS
# =========================

BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()  # must be set in env
PREMIUM_PASSWORD = "ZavsMasterKey2025"

LAST_UPDATED = "2025-09-02 05:47:18"
BOT_USER = "eregeg345435"

API_BASE = "https://api.proswapper.xyz/external"
_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

# Data directory for logs and JSON persistence (mount /data on Render)
DATA_DIR = os.getenv("DATA_DIR", "/data").strip() or "/data"
os.makedirs(DATA_DIR, exist_ok=True)

LOG_PATH = os.path.join(DATA_DIR, "discord_bot.log")
PROCESSED_PATH = os.path.join(DATA_DIR, "processed_accounts.json")

# Optional health/status webhook for lifecycle pings
HEALTH_WEBHOOK_URL = os.getenv("HEALTH_WEBHOOK_URL", "").strip()

# Proxies
PROXIES = [
    "45.89.53.245:3128",
    "66.36.234.130:1339",
    "45.167.126.1:8080",
    "190.242.157.215:8080",
    "154.62.226.126:8888",
    "51.159.159.73:80",
    "176.126.103.194:44214",
    "185.191.236.162:3128",
    "157.180.121.252:35993",
    "157.180.121.252:16621",
    "157.180.121.252:55503",
    "157.180.121.252:53919",
    "175.118.246.102:3128",
    "64.92.82.61:8081",
    "132.145.75.68:5457",
    "157.180.121.252:35519",
    "77.110.114.116:8081"
]

current_proxy = None
proxy_last_checked = 0.0
proxy_check_interval = 60  # seconds
proxy_lock = threading.Lock()

# Channels + server config
NAMES_CHANNEL_ID = 0
PRE_SEARCH_CHANNEL_ID = 0
POST_SEARCH_CHANNEL_ID = 0
server_configs: Dict[int, Dict[str, int]] = {}

# Premium users
authorized_users: set[int] = set()

# Processed accounts (to avoid dup work)
processed_account_ids: set[str] = set()

# Delete messages & timing
DELETE_MESSAGES = True
MESSAGE_DELETE_DELAY = 1  # seconds

# Avoid duplicate progress lines
message_cache = set()

# =========================
# LOGGING
# =========================

logger = logging.getLogger("discord_bot")
logger.setLevel(logging.INFO)
# Ensure no duplicate handlers if reloaded
logger.handlers.clear()

_stream = logging.StreamHandler(sys.stdout)
_stream.setLevel(logging.INFO)
_stream.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

# FileHandler may fail on read-only FS; we already ensured DATA_DIR exists
_file = logging.FileHandler(LOG_PATH, encoding="utf-8")
_file.setLevel(logging.INFO)
_file.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))

logger.addHandler(_stream)
logger.addHandler(_file)

# =========================
# HEALTH WEBHOOK
# =========================

def _post_health(msg: str):
    if not HEALTH_WEBHOOK_URL:
        return
    try:
        requests.post(HEALTH_WEBHOOK_URL, json={"content": msg}, timeout=6)
    except Exception:
        # We don't want health failures to crash the bot
        pass

# Silence PyNaCl warning if not installed
try:
    import nacl  # noqa: F401
except ImportError:
    logger.warning("PyNaCl is not installed, voice will NOT be supported")

# =========================
# DISCORD SETUP
# =========================

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

processing_lock = asyncio.Lock()

# =========================
# LOAD PERSISTED STATE
# =========================

try:
    if os.path.exists(PROCESSED_PATH):
        with open(PROCESSED_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                processed_account_ids = set(data)
            else:
                processed_account_ids = set()
except Exception as e:
    logger.error(f"Error loading processed accounts: {e}")

# =========================
# PROXY HELPERS
# =========================

def test_proxy(proxy: str, timeout: float = 3.0) -> bool:
    proxy_dict = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
    try:
        r = requests.get(f"{API_BASE}/name/test", proxies=proxy_dict, timeout=timeout, headers=HEADERS)
        return r.status_code == 200
    except Exception:
        return False

def find_working_proxy(force_check: bool = False) -> Optional[str]:
    """
    Return a working proxy, refreshing if needed.
    """
    global current_proxy, proxy_last_checked
    with proxy_lock:
        now = time.time()

        # If we already have a proxy and it's fresh
        if not force_check and current_proxy and (now - proxy_last_checked) < proxy_check_interval:
            return current_proxy

        # Re-test current proxy first
        if current_proxy:
            if test_proxy(current_proxy):
                logger.info(f"Current proxy still working: {current_proxy}")
                proxy_last_checked = now
                return current_proxy
            else:
                logger.info(f"Current proxy no longer working: {current_proxy}")

        # Try a shuffled list
        shuffled = PROXIES.copy()
        random.shuffle(shuffled)
        for p in shuffled:
            if test_proxy(p):
                logger.info(f"Found working proxy: {p}")
                current_proxy = p
                proxy_last_checked = now
                return p

        # None found
        logger.warning("No working proxy found")
        current_proxy = None
        return None

def get_api_response(url: str, timeout: float = 8.0) -> Union[dict, list]:
    """
    Try current proxy, then others, then direct.
    """
    global current_proxy, proxy_last_checked

    # Ensure we have a candidate
    if not current_proxy:
        current_proxy = find_working_proxy()

    # Try current proxy
    if current_proxy:
        proxy_dict = {'http': f'http://{current_proxy}', 'https': f'http://{current_proxy}'}
        try:
            resp = requests.get(url, headers=HEADERS, proxies=proxy_dict, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {"status": "INACTIVE", "message": "Account not found or inactive"}
            elif resp.status_code == 403:
                # Refresh proxy in the background
                threading.Thread(target=lambda: find_working_proxy(force_check=True), daemon=True).start()
        except Exception:
            threading.Thread(target=lambda: find_working_proxy(force_check=True), daemon=True).start()

    # Try all other proxies
    for p in PROXIES:
        if p == current_proxy:
            continue
        proxy_dict = {'http': f'http://{p}', 'https': f'http://{p}'}
        try:
            resp = requests.get(url, headers=HEADERS, proxies=proxy_dict, timeout=timeout)
            if resp.status_code == 200:
                current_proxy = p
                proxy_last_checked = time.time()
                return resp.json()
            elif resp.status_code == 404:
                return {"status": "INACTIVE", "message": "Account not found or inactive"}
        except Exception:
            continue

    # Fallback to direct
    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
        elif resp.status_code == 404:
            return {"status": "INACTIVE", "message": "Account not found or inactive"}
        elif resp.status_code == 403:
            return {"status": "ERROR", "message": "API access denied"}
        else:
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
    response = get_api_response(url)

    # If platform provided and response is list, filter
    if platform and isinstance(response, list):
        filtered = []
        for acc in response:
            if 'externalAuths' in acc and platform.lower() in acc['externalAuths']:
                filtered.append(acc)
        if filtered:
            return filtered
    return response

# =========================
# UTIL / PDF PARSE
# =========================

def detect_platform_from_transactions(text: str) -> Tuple[str, str]:
    lower = text.lower()
    if 'xbl_xtoken' in lower or any(t in lower for t in ["xbox", "xbl", "xb1", "xsx"]):
        return 'Xbox (XBL)', 'xbl_xtoken'
    if 'psn_xtoken' in lower or any(t in lower for t in ["playstation", "psn", "ps4", "ps5"]):
        return 'PlayStation (PSN)', 'psn_xtoken'
    if 'nintendo' in lower or 'switch' in lower:
        return 'Nintendo Switch', 'nintendo'
    if any(t in lower for t in ["pc", "epic", "computer", "windows"]):
        return 'PC/Epic Games', 'epic'
    if any(t in lower for t in ["mobile", "ios", "android", "phone"]):
        return 'Mobile (iOS/Android)', 'mobile'
    return 'Unknown', ''

def deduplicate_accounts(accounts_list: Union[list, dict]) -> Union[list, dict]:
    if not isinstance(accounts_list, list):
        return accounts_list
    unique = {}
    for acc in accounts_list:
        if isinstance(acc, dict):
            aid = acc.get('id')
            if aid:
                unique[aid] = acc
    return list(unique.values())

def extract_user_info_from_text(text: str) -> dict:
    info = {
        'username': None,
        'email': None,
        'account_id': None,
        'creation_date': None,
        'transactions': [],
        'cards': [],
        'oldest_ip': None,
        'oldest_ip_date': None,
        'platform': None,
        'platform_token': None,
        'account_disabled': False,
        'disable_count': 0,
        'disable_dates': [],
        'reactivated': False,
        'reactivate_dates': [],
        'deactivated': False,
        'email_changed': False,
        'compromised_account': False,
        'display_names': [],
        'first_name': None,
        'last_name': None,
        'all_emails': [],
        'source_file': None,
        'is_encrypted': False,
        'account_status': None
    }

    # source filename hints
    filename_match = re.search(r'(?:information extracted from|file|data source)[:\s]+([^\n]+\.(?:pdf|txt|json))',
                               text, re.IGNORECASE)
    if filename_match:
        info['source_file'] = filename_match.group(1).strip()

    # display names
    display_name_patterns = [
        r'(?:Display\s*Name|externalAuthDisplayName|displayName|username)[s\:]*[:\s="]+([^\r\n,;"\'][\S][^\r\n,;"\']+)',
        r'displayName\s*:?\s*["\']([^"\']+)["\']\s*[,;]?',
        r'name\s*:?\s*["\']([^"\']+)["\']\s*[,;]?',
        r'gamertag\s*:?\s*["\']([^"\']+)["\']\s*[,;]?'
    ]
    for pat in display_name_patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            dn = m.group(1).strip().strip('"\'')
            if dn and dn not in info['display_names']:
                info['display_names'].append(dn)

    # emails
    email_patterns = [
        r'(?:Current\s*Email|Original\s*Email|email)[:\s="]+\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        r'[\w\.-]+@[\w\.-]+\.\w+',
        r'email\s*[=:]\s*"([^"]+@[^"]+\.\w+)"',
        r'email\s*[=:]\s*([^\s;,]+@[^\s;,]+\.\w+)'
    ]
    for pat in email_patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            email = (m.group(1) if m.groups() else m.group(0)).strip('"\'')
            if '@' in email and email not in info['all_emails']:
                info['all_emails'].append(email)
                ctx = text[max(0, m.start()-20):m.start()].lower()
                if 'current' in ctx:
                    info['email'] = email
    if info['all_emails'] and not info['email']:
        info['email'] = info['all_emails'][0]

    # account id
    account_id_patterns = [
        r'(?:Account\s*ID|account|user|id)[\s_-]*(?:id|number|#)[\s:_-]+([^\s\n,]+)',
        r'Account\s*ID:?\s*([a-f0-9]+)'
    ]
    for pat in account_id_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            info['account_id'] = m.group(1).strip()
            break

    # creation/registration date
    date_patterns = [
        r'Creation\s*Date:?\s*(\d{1,2}[\/\.-]\d{1,2}[\/\.-]\d{2,4})',
        r'(?:created|registered|joined|creation|registration|date)[\s:_-]+(\d{1,2}[\/\.-]\d{1,2}[\/\.-]\d{2,4}|\d{4}[\/\.-]\d{1,2}[\/\.-]\d{1,2})'
    ]
    for pat in date_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            info['creation_date'] = m.group(1)
            break

    # platform / tokens
    auth_patterns = [
        r'addedExternalAuth[:\s]+([^\s\n]+)',
        r'externalAuth[:\s]+([^\s\n]+)',
        r'platform[:\s]+([^\n]+)',
        r'\b(psn_xtoken|xbl_xtoken|epic|nintendo)\b'
    ]
    mentions = []
    for pat in auth_patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            mentions.append(m.group(1).strip().lower())

    if any('xbl_xtoken' in x for x in mentions):
        info['platform'], info['platform_token'] = 'Xbox (XBL)', 'xbl_xtoken'
    elif any('psn_xtoken' in x for x in mentions):
        info['platform'], info['platform_token'] = 'PlayStation (PSN)', 'psn_xtoken'
    elif any('nintendo' in x for x in mentions):
        info['platform'], info['platform_token'] = 'Nintendo Switch', 'nintendo'
    elif any(('epic' in x or 'pc' in x) for x in mentions):
        info['platform'], info['platform_token'] = 'PC/Epic Games', 'epic'
    else:
        m = re.search(r'Platform:?\s*([^\n]+)', text, re.IGNORECASE)
        if m:
            platform, token = detect_platform_from_transactions(m.group(1))
            info['platform'], info['platform_token'] = platform, token

    # IPs
    ip_patterns = [
        r'Oldest\s*IP:?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[\s:_-]+(\d{1,2}/\d{1,2}/\d{2,4}))?'
    ]
    for pat in ip_patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            info['oldest_ip'] = m.group(1)
            if len(m.groups()) > 1 and m.group(2):
                info['oldest_ip_date'] = m.group(2)
            break

    # status
    status_match = re.search(r'Account\s*Status:?\s*([^\n]+)', text, re.IGNORECASE)
    if status_match:
        st = status_match.group(1).lower().strip()
        if 'disabled' in st or 'disable' in st:
            info['account_disabled'] = True
            c = re.search(r'disabled\s+(\d+)\s+time', st, re.IGNORECASE)
            info['disable_count'] = int(c.group(1)) if c else 1
            if 'compromised' in st:
                info['compromised_account'] = True
            if 'deactivated' in st:
                info['deactivated'] = True
            if 'reactivated' in st:
                info['reactivated'] = True

    # transactions
    transaction_patterns = [
        r'HISTORY_ACCOUNT_([A-Z_]+)\s+(\d{1,2}/\d{1,2}/\d{2,4})\s+(.+?)(?=\n|$)',
        r'(\d{1,2}/\d{1,2}/\d{4})\s+(addedExternalAuth)\s*:\s*([^\n]+)',
        r'(\d{1,2}/\d{1,2}/\d{2,4})\s+([^\s:]+)(?:\s*:\s*|\s+)([^\n]+)'
    ]
    for pat in transaction_patterns:
        for m in re.finditer(pat, text, re.IGNORECASE):
            if len(m.groups()) == 3 and m.group(1).lower() not in ['addedexternalauth']:
                transaction_type, date, details = m.group(1), m.group(2), m.group(3).strip()
            else:
                # alt format
                transaction_type, date, details = m.group(2).upper(), m.group(1), m.group(3).strip()

            if 'DISABLE' in transaction_type:
                info['account_disabled'] = True
                info['disable_count'] += 1
                info['disable_dates'].append(date)
                if 'meta data' in details.lower():
                    info['deactivated'] = True

            if any(k in transaction_type for k in ['REACTIVE', 'REENABLE', 'ENABLED']):
                info['reactivated'] = True
                info['reactivate_dates'].append(date)

            if 'METADATA_ADD' in transaction_type and 'DISABLED_REASON' in details and 'Compromised' in details:
                info['compromised_account'] = True

            # platform from details
            detl = details.lower()
            if 'xbl_xtoken' in detl:
                info['platform'], info['platform_token'] = 'Xbox (XBL)', 'xbl_xtoken'
            elif 'psn_xtoken' in detl:
                info['platform'], info['platform_token'] = 'PlayStation (PSN)', 'psn_xtoken'
            elif 'nintendo' in detl:
                info['platform'], info['platform_token'] = 'Nintendo Switch', 'nintendo'
            elif any(t in detl for t in ['pc', 'epic']):
                info['platform'], info['platform_token'] = 'PC/Epic Games', 'epic'

            info['transactions'].append({
                'type': transaction_type,
                'date': date,
                'details': details
            })

    if not info['platform'] or info['platform'] == 'Unknown':
        platform, token = detect_platform_from_transactions(text)
        if platform != 'Unknown':
            info['platform'], info['platform_token'] = platform, token

    return info

# =========================
# DISCORD HELPERS
# =========================

def get_channels(guild_id: int) -> Tuple[int, int, int]:
    if guild_id in server_configs:
        cfg = server_configs[guild_id]
        return cfg["names_channel"], cfg["pre_search_channel"], cfg["post_search_channel"]
    return NAMES_CHANNEL_ID, PRE_SEARCH_CHANNEL_ID, POST_SEARCH_CHANNEL_ID

def save_processed_account_ids():
    try:
        with open(PROCESSED_PATH, "w", encoding="utf-8") as f:
            json.dump(list(processed_account_ids), f)
    except Exception as e:
        logger.error(f"Error saving processed accounts: {e}")

async def check_account_status(account_id: str) -> Optional[dict]:
    if not account_id:
        return None
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
    source_file = info.get('source_file', 'Unknown')
    output = "**📊 ACCOUNT ANALYSIS**\n\n"

    # Top: current status
    if info.get('account_status'):
        sd = info['account_status']
        if isinstance(sd, dict) and sd.get('status') == 'ACTIVE':
            output += "**🟢 ACCOUNT CURRENTLY ACTIVE**\n"
            if 'displayName' in sd:
                output += f"**Current Display Name:** {sd['displayName']}\n"
            elif 'display_name' in sd:
                output += f"**Current Display Name:** {sd['display_name']}\n"
            if 'externalAuths' in sd and sd['externalAuths']:
                output += "**Current Linked Accounts:**\n"
                for plat, data in sd['externalAuths'].items():
                    if isinstance(data, dict):
                        output += f"- {plat}: {data.get('externalDisplayName', 'N/A')}\n"
                    else:
                        output += f"- {plat}: {str(data)}\n"
                output += "\n"
        elif isinstance(sd, dict) and sd.get('status') == 'INACTIVE':
            output += "**🔴 ACCOUNT CURRENTLY INACTIVE**\n"
            if 'message' in sd:
                output += f"{sd['message']}\n"
            output += "The account may have been banned, deleted, or changed username.\n\n"
        elif isinstance(sd, dict) and sd.get('status') in ['ERROR', 'FORBIDDEN']:
            output += "**⚠️ ERROR CHECKING ACCOUNT STATUS**\n"
            if 'message' in sd:
                output += f"{sd['message']}\n\n"
        elif isinstance(sd, dict) and sd.get('status') == 'INVALID':
            output += "**⚠️ INVALID ACCOUNT ID FORMAT**\n"
            if 'message' in sd:
                output += f"{sd['message']}\n\n"
    else:
        output += "**⚠️ ACCOUNT STATUS UNKNOWN**\nCould not check current account status.\n\n"

    output += f"**Information extracted from:** {source_file}\n\n"

    if info['display_names']:
        output += f"**Display Names:** {', '.join(info['display_names'])}\n"
        if len(info['display_names']) > 1:
            output += f"Changed: {len(info['display_names']) - 1}\n"

    if info['email']:
        output += f"**Current Email:** {info['email']}\n"
    if info['account_id']:
        output += f"**Account ID:** {info['account_id']}\n"
    if info['creation_date']:
        output += f"**Creation Date:** {info['creation_date']}\n"

    if info['platform']:
        if info['platform_token']:
            output += f"**Platform:** {info['platform']} [{info['platform_token']}]\n"
        else:
            output += f"**Platform:** {info['platform']}\n"

    if info['oldest_ip']:
        output += f"**Oldest IP:** {info['oldest_ip']}\n"

    output += "\n**Account Status History:** "
    if info['account_disabled']:
        output += f"Disabled {info['disable_count']} time(s)"
        if info['compromised_account']:
            output += ", **COMPROMISED ACCOUNT DETECTED**"
        if info['deactivated']:
            output += ", Deactivated (metadata added)"
        if info['reactivated']:
            output += ", Reactivated (metadata removed)"
    else:
        output += "No disable/reactivation history found"

    await ctx.send(output)

    if info.get('is_encrypted', False):
        await ctx.send("Here is the unlocked PDF.")

async def process_pdf(ctx, attachment, password=None, delete_message=True):
    message_to_delete = getattr(ctx, 'message', None)
    try:
        try:
            file_bytes = await attachment.read()
            if not file_bytes:
                await ctx.send("Could not read the PDF file (file is empty).")
                return
        except discord.NotFound:
            await ctx.send("❌ Error: The file was not found or was deleted. Please upload it again.")
            return
        except discord.HTTPException as e:
            await ctx.send(f"❌ Error downloading the PDF: HTTP Error {e.status}: {e.text}")
            return
        except Exception as e:
            await ctx.send(f"❌ Error downloading the PDF: {str(e)}")
            logger.error(f"PDF download error: {str(e)}\n{traceback.format_exc()}")
            return

        initial_msg = await ctx.send(f"Processing PDF: `{attachment.filename}` ({attachment.size / 1024:.1f} KB)")

        if delete_message and message_to_delete:
            try:
                await message_to_delete.delete()
            except Exception:
                pass

        pdf_file = io.BytesIO(file_bytes)

        try:
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            is_encrypted = pdf_reader.is_encrypted

            if is_encrypted:
                if not password:
                    await ctx.send("This PDF is password protected. Please provide a password with `!pdf [password]`")
                    return
                try:
                    pdf_reader.decrypt(password)
                    await ctx.send("✅ PDF successfully decrypted!")
                except Exception:
                    await ctx.send("❌ Failed to decrypt PDF. The password may be incorrect.")
                    return

            all_text = ""
            try:
                for page in pdf_reader.pages:
                    try:
                        t = page.extract_text()
                        if t:
                            all_text += t + "\n\n"
                    except Exception:
                        continue
            except Exception as e:
                logger.error(f"Error extracting all pages: {str(e)}")

            if not all_text:
                try:
                    all_text = pdf_reader.pages[0].extract_text()
                except Exception as e:
                    await ctx.send(f"Error extracting text from PDF: {str(e)}")
                    return

            info = extract_user_info_from_text(all_text)
            info['source_file'] = attachment.filename
            info['is_encrypted'] = is_encrypted

            if info['account_id'] and info['account_id'] in processed_account_ids:
                await ctx.send(f"⚠️ This PDF has already been searched (Account ID: {info['account_id']})")
                return

            if info['account_id']:
                status_message = await ctx.send(f"🔍 Checking current account status for ID: `{info['account_id']}`...")
                account_status = await check_account_status(info['account_id'])
                info['account_status'] = account_status
                await status_message.edit(content=f"✅ Account status check complete.")

            await send_pdf_analysis(ctx, info)

            if info['account_id']:
                processed_account_ids.add(info['account_id'])
                save_processed_account_ids()

            if is_encrypted and password:
                pdf_writer = PyPDF2.PdfWriter()
                for page in pdf_reader.pages:
                    pdf_writer.add_page(page)
                try:
                    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tf:
                        pdf_writer.write(tf)
                        tmp_path = tf.name
                    await ctx.send("Here is the unlocked PDF:", file=discord.File(tmp_path, f"unlocked_{attachment.filename}"))
                except Exception as e:
                    logger.error(f"Error saving unlocked PDF: {str(e)}")
                    await ctx.send("Error saving the unlocked PDF.")
                finally:
                    try:
                        if tmp_path and os.path.exists(tmp_path):
                            os.unlink(tmp_path)
                    except Exception:
                        pass

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

# =========================
# BACKGROUND TASKS / EVENTS
# =========================

async def proxy_maintenance_task():
    await bot.wait_until_ready()
    while not bot.is_closed():
        try:
            find_working_proxy()
        except Exception:
            pass
        await asyncio.sleep(60)

@bot.event
async def on_ready():
    logger.info(f"Bot logged in as {bot.user.name} ({bot.user.id})")
    logger.info(f"Current Date: {LAST_UPDATED}")
    logger.info(f"User: {BOT_USER}")
    print(f"Bot is ready! Logged in as {bot.user.name}")
    print(f"Last updated: {LAST_UPDATED}")
    print(f"User: {BOT_USER}")
    print(f"Current Time (UTC): {LAST_UPDATED}")
    _post_health(f"✅ on_ready: logged in as {bot.user} ({bot.user.id})")

    bot.loop.create_task(proxy_maintenance_task())

    wp = find_working_proxy()
    if wp:
        print("✓ Successfully connected to proxy server")
        print("API connection ready")
    else:
        print("✗ Could not establish proxy connection")
        print("Using direct connection mode")

    global authorized_users
    if not authorized_users:
        print("No authorized users yet. The first user to interact will be automatically authorized.")

@bot.event
async def on_message(message):
    if message.author == bot.user:
        return

    # Auto-authorize the first user
    if not authorized_users and not message.author.bot:
        authorized_users.add(message.author.id)
        try:
            await message.author.send("✅ You've been automatically authorized for premium commands as the first user.")
        except Exception:
            await message.channel.send(f"✅ {message.author.mention}, you've been automatically authorized for premium commands as the first user.")

    # Hide lookup commands quickly
    if message.content.startswith('!lookup '):
        try:
            await message.delete()
        except Exception:
            pass

    await bot.process_commands(message)

    if message.guild and message.channel.id:
        names_channel_id, _, _ = get_channels(message.guild.id)
        if names_channel_id and message.channel.id == names_channel_id:
            for attachment in message.attachments:
                if attachment.filename.lower().endswith('.pdf'):
                    await process_pdf(message.channel, attachment, delete_message=False)
                    return
            try:
                await asyncio.sleep(MESSAGE_DELETE_DELAY)
                await message.delete()
            except Exception as e:
                logger.error(f"Error deleting message: {str(e)}")

# =========================
# COMMANDS
# =========================

async def check_premium_access(ctx) -> bool:
    if ctx.author.id not in authorized_users:
        await ctx.send("⚠️ This is a premium command. Please use `!authorize [password]` to access premium features.")
        try:
            await ctx.message.delete()
        except Exception:
            pass
        return False
    return True

@bot.command(name='setup')
@commands.has_permissions(administrator=True)
async def setup_channels(ctx, names_channel: discord.TextChannel = None, pre_search_channel: discord.TextChannel = None,
                         post_search_channel: discord.TextChannel = None):
    if not await check_premium_access(ctx):
        return

    if not names_channel:
        await ctx.send("Please specify channels: `!setup #names-channel #pre-search-channel #post-search-channel`")
        return

    if not pre_search_channel:
        pre_search_channel = names_channel

    if not post_search_channel:
        post_search_channel = pre_search_channel

    server_configs[ctx.guild.id] = {
        "names_channel": names_channel.id,
        "pre_search_channel": pre_search_channel.id,
        "post_search_channel": post_search_channel.id
    }

    await ctx.send(
        f"Channels set up successfully!\n"
        f"Names Channel: {names_channel.mention}\n"
        f"Pre-search Channel: {pre_search_channel.mention}\n"
        f"Post-search Channel: {post_search_channel.mention}"
    )

@bot.command(name='authorize')
async def authorize_user(ctx, password=None):
    if not password:
        await ctx.send("Please provide a password: `!authorize [password]`")
        return
    if password == PREMIUM_PASSWORD:
        authorized_users.add(ctx.author.id)
        await ctx.send("✅ You are now authorized for premium commands!")
        try:
            await ctx.message.delete()
        except Exception:
            pass
    else:
        await ctx.send("❌ Invalid password.")
        try:
            await ctx.message.delete()
        except Exception:
            pass

@bot.command(name='pdf')
async def process_pdf_command(ctx, password=None):
    if not ctx.message.attachments:
        await ctx.send("Please attach a PDF file to process.")
        return
    attachment = ctx.message.attachments[0]
    if not attachment.filename.lower().endswith('.pdf'):
        await ctx.send("Please attach a PDF file.")
        return
    await process_pdf(ctx, attachment, password, delete_message=True)

@bot.command(name='lookup')
async def lookup_command(ctx, *args):
    if not await check_premium_access(ctx):
        return

    if not args:
        await ctx.send(
            "⚠️ Please provide a display name or account ID to look up.\n"
            "Usage:\n"
            "- `!lookup <name/id>` - Look up by name or ID\n"
            "- `!lookup xbl <gamertag>` - Look up Xbox gamertag\n"
            "- `!lookup psn <username>` - Look up PlayStation username\n"
            "- `!lookup switch <username>` - Look up Nintendo Switch username"
        )
        return

    platform = None
    if args[0].lower() in ['xbl', 'xbox', 'x']:
        if len(args) < 2:
            await ctx.send("⚠️ Please provide an Xbox gamertag to look up.\nExample: `!lookup xbl Ninja`")
            return
        platform = 'xbl'
        value = ' '.join(args[1:])
        mode = 'name'
    elif args[0].lower() in ['psn', 'playstation', 'ps', 'ps4', 'ps5']:
        if len(args) < 2:
            await ctx.send("⚠️ Please provide a PlayStation username to look up.\nExample: `!lookup psn Ninja`")
            return
        platform = 'psn'
        value = ' '.join(args[1:])
        mode = 'name'
    elif args[0].lower() in ['switch', 'nintendo', 'ns']:
        if len(args) < 2:
            await ctx.send("⚠️ Please provide a Nintendo Switch username to look up.\nExample: `!lookup switch Ninja`")
            return
        platform = 'nintendo'
        value = ' '.join(args[1:])
        mode = 'name'
    else:
        value = ' '.join(args)
        mode = "id" if _HEX32.match(value) else "name"

    lookup_type = "account ID" if mode == "id" else "display name"
    platform_msg = f" on {platform.upper()}" if platform else ""
    lookup_msg = await ctx.send(f"🔍 Looking up Epic account by {lookup_type}{platform_msg}: `{value}`...")

    result = await asyncio.get_event_loop().run_in_executor(None, lambda: epic_lookup(value, mode, platform))

    if isinstance(result, dict) and result.get("status") in {"ERROR", "INACTIVE", "FORBIDDEN", "INVALID"}:
        await lookup_msg.edit(content=f"❌ {result.get('message', 'Lookup failed')}")
        return

    try:
        if mode == "name" and isinstance(result, list):
            await lookup_msg.delete()
            unique_results = deduplicate_accounts(result)
            if not unique_results:
                await ctx.send(f"❌ No results found for `{value}`{platform_msg}.")
                return
            for acc in unique_results[:5]:
                display_name = acc.get("displayName", "Unknown")
                epic_id = acc.get("id", "Unknown")
                embed = discord.Embed(title=f"Epic Account (name match): {display_name}", color=discord.Color.green())
                embed.add_field(name="Account ID", value=epic_id, inline=False)
                external = acc.get("externalAuths") or {}
                if external:
                    lines = []
                    for plat, data in external.items():
                        if isinstance(data, dict):
                            lines.append(f"{plat}: {data.get('externalDisplayName', 'N/A')}")
                        else:
                            lines.append(f"{plat}: {str(data)}")
                    if lines:
                        embed.add_field(name="Linked Accounts", value="\n".join(lines), inline=False)
                await ctx.send(embed=embed)
            if len(unique_results) > 5:
                await ctx.send(f"ℹ️ More results exist ({len(unique_results)-5} more). Refine your search.")
            return

        elif mode == "id" and isinstance(result, dict):
            await lookup_msg.delete()
            display_name = result.get("displayName", "Unknown")
            epic_id = result.get("id", value)
            embed = discord.Embed(title=f"Epic Account (by ID): {display_name}", color=discord.Color.green())
            embed.add_field(name="Account ID", value=epic_id, inline=False)
            external = result.get("externalAuths") or {}
            if external:
                lines = []
                for plat, data in external.items():
                    if isinstance(data, dict):
                        lines.append(f"{plat}: {data.get('externalDisplayName', 'N/A')}")
                    else:
                        lines.append(f"{plat}: {str(data)}")
                if lines:
                    embed.add_field(name="Linked Accounts", value="\n".join(lines), inline=False)
            await ctx.send(embed=embed)
            return

        elif mode == "name" and isinstance(result, dict):
            await lookup_msg.delete()
            display_name = result.get("displayName", "Unknown")
            epic_id = result.get("id", "Unknown")
            embed = discord.Embed(title=f"Epic Account (exact name match): {display_name}", color=discord.Color.green())
            embed.add_field(name="Account ID", value=epic_id, inline=False)
            external = result.get("externalAuths") or {}
            if external:
                lines = []
                for plat, data in external.items():
                    if isinstance(data, dict):
                        lines.append(f"{plat}: {data.get('externalDisplayName', 'N/A')}")
                    else:
                        lines.append(f"{plat}: {str(data)}")
                if lines:
                    embed.add_field(name="Linked Accounts", value="\n".join(lines), inline=False)
            await ctx.send(embed=embed)
            return

        await lookup_msg.edit(content=f"❌ No results found for `{value}`{platform_msg}.")
    except Exception as e:
        logger.error(f"Error in lookup command: {e}")
        await lookup_msg.edit(content=f"❌ Error processing API response: {str(e)}")

@bot.command(name='testproxies')
async def test_proxies_command(ctx):
    if not await check_premium_access(ctx):
        return

    await ctx.send("Testing proxies... this may take a moment.")
    working_count = 0
    total = len(PROXIES)
    progress_msg = await ctx.send(f"Progress: 0/{total} tested")
    working_list = []
    processed_counts = set()

    for i, p in enumerate(PROXIES):
        progress = i + 1
        if test_proxy(p):
            working_count += 1
            working_list.append(p)
        if progress % 5 == 0 or progress == total:
            update_text = f"Progress: {progress}/{total} tested, {working_count} working"
            if update_text not in processed_counts:
                processed_counts.add(update_text)
                await progress_msg.edit(content=update_text)

    await ctx.send(f"✅ Found {working_count} working proxies out of {total}")
    if working_list:
        batch = 20
        for i in range(0, len(working_list), batch):
            await ctx.send("```\n" + "\n".join(working_list[i:i+batch]) + "\n```")

@bot.command(name='proxyinfo')
async def proxy_info_command(ctx):
    if not await check_premium_access(ctx):
        return

    global proxy_last_checked
    if current_proxy:
        status = "✅ Connected" if test_proxy(current_proxy) else "❌ Not working (will find new proxy)"
        if not status.startswith("✅"):
            threading.Thread(target=lambda: find_working_proxy(force_check=True), daemon=True).start()
        embed = discord.Embed(
            title="API Connection Status",
            description="Using proxy connection for API requests",
            color=discord.Color.green() if status.startswith("✅") else discord.Color.red()
        )
        embed.add_field(name="Status", value=status, inline=False)
        embed.add_field(name="Connection Type", value="Proxy", inline=True)
        embed.add_field(name="Last Checked", value=f"<t:{int(proxy_last_checked)}:R>", inline=True)
        await ctx.send(embed=embed)
    else:
        wp = find_working_proxy()
        if wp:
            embed = discord.Embed(
                title="API Connection Status",
                description="Successfully established proxy connection",
                color=discord.Color.green()
            )
            embed.add_field(name="Status", value="✅ Connected", inline=False)
            embed.add_field(name="Connection Type", value="Proxy", inline=True)
            embed.add_field(name="Last Checked", value=f"<t:{int(proxy_last_checked)}:R>", inline=True)
        else:
            embed = discord.Embed(
                title="API Connection Status",
                description="Using direct connection (no working proxy)",
                color=discord.Color.red()
            )
            embed.add_field(name="Status", value="⚠️ No proxy available", inline=False)
            embed.add_field(name="Connection Type", value="Direct", inline=True)
        await ctx.send(embed=embed)

@bot.command(name='reset')
@commands.has_permissions(administrator=True)
async def reset_processed_accounts(ctx):
    if not await check_premium_access(ctx):
        return
    global processed_account_ids
    processed_account_ids = set()
    save_processed_account_ids()
    await ctx.send("✅ Processed accounts list has been reset.")

@bot.command(name='version')
async def version_info(ctx):
    if not await check_premium_access(ctx):
        return
    embed = discord.Embed(title="Bot Version Information", color=0x00ff00)
    embed.add_field(name="Last Updated", value=LAST_UPDATED, inline=False)
    embed.add_field(name="User", value=BOT_USER, inline=False)
    embed.add_field(name="Discord.py Version", value=discord.__version__, inline=True)
    embed.add_field(name="Python Version",
                    value=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                    inline=True)
    if current_proxy:
        embed.add_field(name="API Connection", value="Active (using proxy)", inline=False)
    else:
        embed.add_field(name="API Connection", value="Direct connection", inline=False)
    embed.set_footer(text=f"Bot is running on {os.name.upper()} platform")
    await ctx.send(embed=embed)

@bot.command(name='commands')
async def custom_commands_help(ctx):
    if not await check_premium_access(ctx):
        return
    embed = discord.Embed(title="Bot Commands", color=0x00ff00)
    embed.set_footer(text=f"Bot Last Updated: {LAST_UPDATED}")
    embed.add_field(name="!pdf [password]",
                    value="Process an attached PDF file to extract user information\n"
                          "(Optional password if the PDF is encrypted)",
                    inline=False)
    if ctx.author.id in authorized_users:
        embed.add_field(name="!lookup [value]",
                        value="Look up an Epic Games account by name or ID\n"
                              "Examples:\n"
                              "- `!lookup Ninja`\n"
                              "- `!lookup 1234567890abcdef1234567890abcdef`\n"
                              "- `!lookup xbl NinjaXbox`\n"
                              "- `!lookup psn NinjaPS5`",
                        inline=False)
        embed.add_field(name="!testproxies", value="Test all proxies to see which ones are working", inline=False)
        embed.add_field(name="!proxyinfo", value="Check the current API connection status", inline=False)
        embed.add_field(name="!setup #channel1 #channel2 #channel3",
                        value="Configure channels (admin only)\n"
                              "#channel1 = Names Channel\n"
                              "#channel2 = Pre-search Channel\n"
                              "#channel3 = Post-search Channel",
                        inline=False)
        embed.add_field(name="!reset", value="Reset the processed accounts list (admin only)", inline=False)
        embed.add_field(name="!version", value="Show version information for the bot", inline=False)
        embed.add_field(name="!commands", value="Show this help message", inline=False)
    embed.add_field(name="!authorize [password]", value="Authorize yourself for premium commands", inline=False)
    await ctx.send(embed=embed)

# =========================
# MAIN / STARTUP / SIGNALS
# =========================

def _graceful(sig, _frame):
    _post_health(f"🛑 Shutting down on signal {sig}")
    try:
        loop = asyncio.get_event_loop()
        loop.create_task(bot.close())
    except Exception:
        pass

if __name__ == "__main__":
    if not BOT_TOKEN:
        print("ERROR: No bot token provided. Please set the DISCORD_BOT_TOKEN environment variable.")
        sys.exit(1)

    print("Starting bot...")
    print(f"Last updated: {LAST_UPDATED}")
    print(f"User: {BOT_USER}")
    print(f"Current Time (UTC): 2025-09-02 05:54:19")
    print("Use Ctrl+C to stop")
    _post_health(
        f"🟢 Bot start: {BOT_USER} | py{sys.version_info.major}.{sys.version_info.minor} "
        f"| pid={os.getpid()} | updated={LAST_UPDATED}"
    )

    # Pre-test API/proxy before connecting bot
    print("Testing API connection...")
    wp = find_working_proxy()
    if wp:
        print("✅ API connection ready (proxy mode)")
        _post_health("🌐 API connection ready (proxy mode)")
    else:
        print("⚠️ No working proxy found, will use direct connections")
        _post_health("⚠️ No working proxy; using direct mode")

    # Signals
    try:
        signal.signal(signal.SIGTERM, _graceful)
        signal.signal(signal.SIGINT, _graceful)
    except Exception:
        # Some envs (e.g., Windows) may not support all signals
        pass

    try:
        bot.run(BOT_TOKEN)
    except discord.errors.LoginFailure:
        _post_health("❌ LoginFailure: bad token")
        print("ERROR: Invalid bot token. Please check your DISCORD_BOT_TOKEN environment variable.")
        sys.exit(1)
    except Exception as e:
        _post_health(f"❌ Fatal start error: {e}")
        print(f"ERROR: Failed to start the bot: {e}")
        sys.exit(1)
