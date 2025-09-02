#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Discord Bot: PDF Analysis + Epic Lookup + TrackerGG Leaderboard Scraper
- PDF processing (unlock + extract account info)
- Epic Games account lookup with proxies
- Leaderboard scraper with Chrome (undetected-chromedriver)
- Channel setup commands

Keep requirements.txt (minimum):
discord.py>=2.0.0
PyPDF2>=3.0.0
requests>=2.25.0
python-dotenv>=0.15.0
asyncio>=3.4.3
selenium==4.*
undetected-chromedriver==3.*

Author: you
"""

import os
import io
import re
import sys
import json
import time
import asyncio
import random
import logging
import tempfile
import traceback
from typing import Dict, List, Optional

from dotenv import load_dotenv
load_dotenv()

# ---------------- Logging ----------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("discord_bot.log", encoding="utf-8")]
)
log = logging.getLogger("bot")

# ---------------- Discord ----------------
import discord
from discord.ext import commands

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="!", intents=intents)

# ---------------- Core config ----------------
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "").strip()
if not BOT_TOKEN:
    print("ERROR: set DISCORD_BOT_TOKEN env var")
    sys.exit(1)

LAST_UPDATED = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
DATA_DIR = os.environ.get("DATA_DIR", "./data").rstrip("/")
os.makedirs(DATA_DIR, exist_ok=True)

# premium / auth
PREMIUM_PASSWORD = "ZavsMasterKey2025"
authorized_users = set()

# server configs (per guild)
# names_channel, pre_search_channel, post_search_channel, lb_channel_id
server_configs: Dict[int, Dict[str, int]] = {}

# processed Epic account IDs
PROCESSED_ACCOUNTS_PATH = os.path.join(DATA_DIR, "processed_accounts.json")
if os.path.exists(PROCESSED_ACCOUNTS_PATH):
    try:
        with open(PROCESSED_ACCOUNTS_PATH, "r", encoding="utf-8") as f:
            _loaded = json.load(f)
            processed_account_ids = set(_loaded if isinstance(_loaded, list) else [])
    except Exception:
        processed_account_ids = set()
else:
    processed_account_ids = set()

def save_processed_ids():
    try:
        with open(PROCESSED_ACCOUNTS_PATH, "w", encoding="utf-8") as f:
            json.dump(list(processed_account_ids), f)
    except Exception as e:
        log.error(f"save_processed_ids error: {e}")

# ------------------------------------------------------
#                 PDF PROCESSING
# ------------------------------------------------------
import PyPDF2

def extract_user_info_from_text(text: str) -> Dict:
    info = {
        'username': None,
        'email': None,
        'account_id': None,
        'creation_date': None,
        'transactions': [],
        'platform': None,
        'platform_token': None,
        'oldest_ip': None,
        'account_disabled': False,
        'disable_count': 0,
        'reactivated': False,
        'compromised_account': False,
        'display_names': [],
        'all_emails': [],
        'source_file': None,
        'is_encrypted': False,
        'account_status': None
    }

    # display names
    for pat in [
        r'(?:Display\s*Name|displayName|username)\s*[:="]+\s*([^\r\n,;"\']+)',
        r'displayName\s*:?\s*["\']([^"\']+)["\']'
    ]:
        for m in re.finditer(pat, text, re.IGNORECASE):
            dn = m.group(1).strip()
            if dn and dn not in info['display_names']:
                info['display_names'].append(dn)

    # emails
    for m in re.finditer(r'[\w\.-]+@[\w\.-]+\.\w+', text, re.IGNORECASE):
        em = m.group(0).strip()
        if em not in info['all_emails']:
            info['all_emails'].append(em)
    if info['all_emails'] and not info['email']:
        info['email'] = info['all_emails'][0]

    # account id
    for pat in [r'Account\s*ID:?\s*([a-f0-9]{32})', r'\b([a-f0-9]{32})\b']:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            info['account_id'] = m.group(1).strip()
            break

    # creation date (loose)
    m = re.search(r'(?:Creation|Created|Registration)[^\n:]*[: ]+(\d{1,2}[\/\.-]\d{1,2}[\/\.-]\d{2,4})', text, re.IGNORECASE)
    if m:
        info['creation_date'] = m.group(1)

    # platform hints
    low = text.lower()
    if "xbl_xtoken" in low or "xbox" in low:
        info['platform'] = "Xbox (XBL)"
        info['platform_token'] = "xbl_xtoken"
    elif "psn_xtoken" in low or "playstation" in low:
        info['platform'] = "PlayStation (PSN)"
        info['platform_token'] = "psn_xtoken"
    elif "twitch" in low or "pc" in low or "epic" in low:
        info['platform'] = "PC/Epic Games"
        info['platform_token'] = "epic"

    # oldest ip
    m = re.search(r'Oldest\s*IP:?\s*(\d{1,3}(?:\.\d{1,3}){3})', text, re.IGNORECASE)
    if m:
        info['oldest_ip'] = m.group(1)

    # status
    if "disabled" in low:
        info['account_disabled'] = True

    return info

async def send_pdf_analysis(ctx, info: Dict):
    source_file = info.get('source_file') or 'Unknown'
    out = "**📊 ACCOUNT ANALYSIS**\n\n"

    # Top — account status (if we fetched it)
    status = info.get("account_status")
    if isinstance(status, dict):
        if status.get("status") == "ACTIVE":
            out += "**🟢 ACCOUNT CURRENTLY ACTIVE**\n"
            dn = status.get("displayName") or status.get("display_name")
            if dn:
                out += f"**Current Display Name:** {dn}\n"
            ext = status.get("externalAuths") or {}
            if ext:
                out += "**Current Linked Accounts:**\n"
                for plat, data in ext.items():
                    if isinstance(data, dict):
                        out += f"- {plat}: {data.get('externalDisplayName','N/A')}\n"
                out += "\n"
        elif status.get("status") == "INACTIVE":
            out += "**🔴 ACCOUNT CURRENTLY INACTIVE**\n"
            if status.get("message"):
                out += status["message"] + "\n"
            out += "\n"
        elif status.get("status") == "INVALID":
            out += "**⚠️ INVALID ACCOUNT ID FORMAT**\n\n"
        else:
            out += "**⚠️ ACCOUNT STATUS UNKNOWN**\n\n"
    else:
        out += "**⚠️ ACCOUNT STATUS UNKNOWN**\n\n"

    out += f"**Information extracted from:** {source_file}\n\n"

    if info['display_names']:
        out += f"**Display Names:** {', '.join(info['display_names'])}\n"
        if len(info['display_names']) > 1:
            out += f"Changed: {len(info['display_names']) - 1}\n"
    if info.get('email'):
        out += f"**Current Email:** {info['email']}\n"
    if info.get('account_id'):
        out += f"**Account ID:** {info['account_id']}\n"
    if info.get('creation_date'):
        out += f"**Creation Date:** {info['creation_date']}\n"
    if info.get('platform'):
        token = f" [{info['platform_token']}]" if info.get('platform_token') else ""
        out += f"**Platform:** {info['platform']}{token}\n"
    if info.get('oldest_ip'):
        out += f"**Oldest IP:** {info['oldest_ip']}\n"

    out += "\n**Account Status History:** "
    out += "Disabled" if info.get('account_disabled') else "No disable/reactivation history found"

    await ctx.send(out)

async def process_pdf(ctx, attachment: discord.Attachment, password: Optional[str]):
    # read bytes first
    try:
        file_bytes = await attachment.read()
    except Exception as e:
        await ctx.send(f"❌ Error downloading the PDF: {e}")
        return
    await ctx.send(f"Processing PDF: `{attachment.filename}` ({attachment.size/1024:.1f} KB)")

    pdf_file = io.BytesIO(file_bytes)
    try:
        reader = PyPDF2.PdfReader(pdf_file)
        is_encrypted = reader.is_encrypted
        if is_encrypted:
            if not password:
                await ctx.send("This PDF is password-protected. Supply password: `!pdf <password>`")
                return
            try:
                reader.decrypt(password)
                await ctx.send("✅ PDF successfully decrypted!")
            except Exception:
                await ctx.send("❌ Failed to decrypt PDF. Wrong password?")
                return

        text = ""
        for p in reader.pages:
            try:
                t = p.extract_text()
                if t:
                    text += t + "\n"
            except Exception:
                continue

        if not text and reader.pages:
            try:
                text = reader.pages[0].extract_text() or ""
            except Exception as e:
                await ctx.send(f"❌ Error extracting text: {e}")
                return

        info = extract_user_info_from_text(text)
        info['source_file'] = attachment.filename
        info['is_encrypted'] = is_encrypted

        # optional account status check
        if info.get('account_id'):
            status = await check_account_status(info['account_id'])
            info['account_status'] = status

        await send_pdf_analysis(ctx, info)

        if info.get('account_id'):
            processed_account_ids.add(info['account_id'])
            save_processed_ids()

        # send unlocked if encrypted
        if is_encrypted and password:
            writer = PyPDF2.PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tf:
                writer.write(tf)
                tmp = tf.name
            await ctx.send("Unlocked PDF:", file=discord.File(tmp, f"unlocked_{attachment.filename}"))
            os.unlink(tmp)

    except Exception as e:
        log.error(f"process_pdf error: {e}\n{traceback.format_exc()}")
        await ctx.send(f"❌ Error: {e}")

@bot.command(name="pdf")
async def pdf_cmd(ctx, password: Optional[str] = None):
    if not ctx.message.attachments:
        await ctx.send("Attach a PDF and run `!pdf [password]`.")
        return
    await process_pdf(ctx, ctx.message.attachments[0], password)

# ------------------------------------------------------
#             Epic lookup (with proxies)
# ------------------------------------------------------
API_BASE = "https://api.proswapper.xyz/external"
_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}
PROXIES = [
    "45.89.53.245:3128",
    "66.36.234.130:1339",
    "45.167.126.1:8080",
    "190.242.157.215:8080",
    "154.62.226.126:8888",
    "51.159.159.73:80",
]
current_proxy = None
proxy_last_checked = 0
proxy_check_interval = 60

def test_proxy(proxy, timeout=3):
    pd = {'http': f'http://{proxy}', 'https': f'http://{proxy}'}
    try:
        r = requests.get(f"{API_BASE}/name/test", proxies=pd, timeout=timeout, headers=HEADERS)
        return r.status_code == 200
    except Exception:
        return False

def find_working_proxy(force_check=False):
    global current_proxy, proxy_last_checked
    now = time.time()
    if not force_check and current_proxy and now - proxy_last_checked < proxy_check_interval:
        return current_proxy
    if current_proxy and test_proxy(current_proxy):
        proxy_last_checked = now
        return current_proxy
    for p in random.sample(PROXIES, k=len(PROXIES)):
        if test_proxy(p):
            current_proxy = p
            proxy_last_checked = now
            return p
    current_proxy = None
    return None

import requests

def get_api_response(url, timeout=8.0):
    global current_proxy, proxy_last_checked
    if not current_proxy:
        current_proxy = find_working_proxy()
    if current_proxy:
        pd = {'http': f'http://{current_proxy}', 'https': f'http://{current_proxy}'}
        try:
            resp = requests.get(url, headers=HEADERS, proxies=pd, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code == 404:
                return {"status": "INACTIVE", "message": "Account not found or inactive"}
        except Exception:
            pass

    # fallback direct
    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout)
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            return {"status": "INACTIVE", "message": "Account not found or inactive"}
        if resp.status_code == 403:
            return {"status": "ERROR", "message": "API access denied"}
        return {"status": "ERROR", "message": f"HTTP error: {resp.status_code}"}
    except Exception as e:
        return {"status": "ERROR", "message": str(e)}

def epic_lookup(value, mode=None, platform=None):
    if not value:
        return {"status": "ERROR", "message": "Provide a display name or account ID"}
    value = value.strip()
    if mode is None:
        mode = "id" if _HEX32.match(value) else "name"
    url = f"{API_BASE}/{mode}/{value}"
    resp = get_api_response(url)
    # optional platform filter if list
    if platform and isinstance(resp, list):
        out = []
        for a in resp:
            if 'externalAuths' in a and platform.lower() in (a['externalAuths'] or {}):
                out.append(a)
        if out:
            return out
    return resp

async def check_account_status(account_id: str):
    account_id = re.sub(r'[^a-zA-Z0-9]', '', account_id or '')
    if len(account_id) != 32:
        return {"status": "INVALID", "message": f"Invalid account ID format: {account_id}"}
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(None, lambda: epic_lookup(account_id, mode="id"))
        if isinstance(result, dict) and "status" not in result:
            result["status"] = "ACTIVE"
        return result
    except Exception as e:
        return {"status": "ERROR", "message": f"{e}"}

def deduplicate_accounts(lst):
    if not isinstance(lst, list):
        return lst
    uniq = {}
    for a in lst:
        if isinstance(a, dict) and a.get('id'):
            uniq[a['id']] = a
    return list(uniq.values())

@bot.command(name="lookup")
async def lookup_cmd(ctx, *args):
    # optional premium gate
    if ctx.author.id not in authorized_users:
        await ctx.send("⚠️ Premium command. Use `!authorize [password]` first.")
        try:
            await ctx.message.delete()
        except Exception:
            pass
        return

    if not args:
        await ctx.send("Usage:\n`!lookup <name_or_id>`\n`!lookup xbl <gamertag>`\n`!lookup psn <username>`")
        return

    plat = None
    if args[0].lower() in ("xbl", "xbox", "x"):
        plat = "xbl"; value = " ".join(args[1:]); mode = "name"
    elif args[0].lower() in ("psn", "playstation", "ps4", "ps5", "ps"):
        plat = "psn"; value = " ".join(args[1:]); mode = "name"
    else:
        value = " ".join(args); mode = ("id" if _HEX32.match(value) else "name")

    msg = await ctx.send(f"🔍 Looking up by {'ID' if mode=='id' else 'name'}{(' on '+plat.upper()) if plat else ''}…")
    res = await asyncio.get_event_loop().run_in_executor(None, lambda: epic_lookup(value, mode, plat))

    if isinstance(res, dict) and res.get("status") in {"ERROR","INACTIVE","FORBIDDEN","INVALID"}:
        await msg.edit(content=f"❌ {res.get('message','Lookup failed')}")
        return

    try:
        if mode == "name" and isinstance(res, list):
            res = deduplicate_accounts(res)
            if not res:
                await msg.edit(content="❌ No results.")
                return
            await msg.delete()
            for acc in res[:5]:
                embed = discord.Embed(title=f"Epic Account: {acc.get('displayName','Unknown')}",
                                      color=discord.Color.green())
                embed.add_field(name="Account ID", value=acc.get("id","Unknown"), inline=False)
                external = acc.get("externalAuths") or {}
                if external:
                    lines = []
                    for p,d in external.items():
                        if isinstance(d, dict):
                            lines.append(f"{p}: {d.get('externalDisplayName','N/A')}")
                    if lines:
                        embed.add_field(name="Linked Accounts", value="\n".join(lines), inline=False)
                await ctx.send(embed=embed)
            return
        else:
            # single object
            if isinstance(res, list) and res:
                res = res[0]
            await msg.delete()
            embed = discord.Embed(title=f"Epic Account: {res.get('displayName','Unknown')}",
                                  color=discord.Color.green())
            embed.add_field(name="Account ID", value=res.get("id","Unknown"), inline=False)
            external = res.get("externalAuths") or {}
            if external:
                lines = []
                for p,d in external.items():
                    if isinstance(d, dict):
                        lines.append(f"{p}: {d.get('externalDisplayName','N/A')}")
                if lines:
                    embed.add_field(name="Linked Accounts", value="\n".join(lines), inline=False)
            await ctx.send(embed=embed)
    except Exception as e:
        await msg.edit(content=f"❌ Error formatting response: {e}")

@bot.command(name="testproxies")
async def testproxies_cmd(ctx):
    if ctx.author.id not in authorized_users:
        await ctx.send("⚠️ Premium command. Use `!authorize [password]` first.")
        return
    await ctx.send("Testing proxies…")
    ok = []
    for p in PROXIES:
        if test_proxy(p):
            ok.append(p)
    await ctx.send(f"✅ {len(ok)} working / {len(PROXIES)} total")
    if ok:
        await ctx.send("```\n" + "\n".join(ok) + "\n```")

@bot.command(name="proxyinfo")
async def proxyinfo_cmd(ctx):
    p = current_proxy or "None"
    await ctx.send(f"Proxy: `{p}` (last checked {int(time.time()-proxy_last_checked)}s ago)")

# ------------------------------------------------------
#        Channel setup (restored) + leaderboard setup
# ------------------------------------------------------
def get_channels(guild_id: int):
    cfg = server_configs.get(guild_id, {})
    return (cfg.get("names_channel", 0), cfg.get("pre_search_channel", 0), cfg.get("post_search_channel", 0))

@bot.command(name='setup')
@commands.has_permissions(administrator=True)
async def setup_channels(ctx,
                         names_channel: discord.TextChannel = None,
                         pre_search_channel: discord.TextChannel = None,
                         post_search_channel: discord.TextChannel = None):
    """Set up channels for names / pre-search / post-search (restored)."""
    if ctx.author.id not in authorized_users:
        await ctx.send("⚠️ Premium command. Use `!authorize [password]` first.")
        return
    if not names_channel:
        await ctx.send("Usage: `!setup #names #pre-search #post-search` (you can repeat #names for all)")
        return
    if not pre_search_channel:
        pre_search_channel = names_channel
    if not post_search_channel:
        post_search_channel = pre_search_channel
    server_configs.setdefault(ctx.guild.id, {})
    server_configs[ctx.guild.id].update({
        "names_channel": names_channel.id,
        "pre_search_channel": pre_search_channel.id,
        "post_search_channel": post_search_channel.id,
    })
    await ctx.send(
        f"✅ Channels set!\n"
        f"• Names: {names_channel.mention}\n"
        f"• Pre-search: {pre_search_channel.mention}\n"
        f"• Post-search: {post_search_channel.mention}"
    )

@bot.command(name="lbsetup")
@commands.has_permissions(administrator=True)
async def lbsetup_cmd(ctx, channel: discord.TextChannel = None):
    """Choose the channel that will receive leaderboard usernames."""
    if not channel:
        await ctx.send("Usage: `!lbsetup #channel`")
        return
    server_configs.setdefault(ctx.guild.id, {})
    server_configs[ctx.guild.id]["lb_channel_id"] = channel.id
    await ctx.send(f"✅ Leaderboard output channel set to {channel.mention}. Use `!scrapelb <url> [start_page]` to begin.")

# ------------------------------------------------------
#         Leaderboard scraping (tracker.gg)
# ------------------------------------------------------
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import undetected_chromedriver as uc

HEADLESS = True

def create_driver(headless=True, profile_dir=None):
    opts = uc.ChromeOptions()
    if profile_dir:
        opts.add_argument(f"--user-data-dir={profile_dir}")
    opts.add_argument("--disable-blink-features=AutomationControlled")
    opts.add_argument("--disable-gpu")
    opts.add_argument("--no-sandbox")
    opts.add_argument("--disable-dev-shm-usage")
    opts.add_argument("--window-size=1280,900")
    opts.add_argument("--lang=en-US")
    opts.add_argument("--user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
    if headless:
        opts.add_argument("--headless=new")
    driver = uc.Chrome(options=opts, headless=headless)
    driver.set_page_load_timeout(30)
    return driver

def build_url(parsed, qs, page):
    params = {k: v for k, v in qs.items()}
    params["page"] = [str(page)]
    query = urlencode({k: v if isinstance(v, list) else [v] for k, v in params.items()}, doseq=True)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", query, ""))

async def scrape_one_page(ctx, driver, out_channel: discord.TextChannel, leaderboard_url: str, page_num: int, seen: set):
    parsed = urlparse(leaderboard_url)
    qs = parse_qs(parsed.query)
    page_url = build_url(parsed, qs, page_num)

    try:
        driver.get(page_url)
        WebDriverWait(driver, 25).until(EC.presence_of_all_elements_located((By.CSS_SELECTOR, "a[href*='/valorant/profile/']")))
        anchors = driver.find_elements(By.CSS_SELECTOR, "a[href*='/valorant/profile/']")

        links = []
        seen_local = set()
        for a in anchors:
            href = a.get_attribute("href") or ""
            label = (a.text or "").strip()
            if "/valorant/profile/" in href and href not in seen_local and label:
                seen_local.add(href)
                links.append((label, href))

        if not links:
            await out_channel.send(f"🛑 Page {page_num}: no players found.")
            return False

        found = 0
        for label, href in links:
            key = f"{label}|{href}".lower()
            if key in seen:
                continue
            driver.get(href)
            await asyncio.sleep(1.0)
            social_as = driver.find_elements(By.CSS_SELECTOR, "a[href]")
            twitter, twitch = "", ""
            for a in social_as:
                h = a.get_attribute("href") or ""
                if "twitter.com/" in h and not twitter:
                    twitter = h
                if "twitch.tv/" in h and not twitch:
                    twitch = h
            if twitter:
                line = f"{label} | {twitter} | {twitch}".rstrip(" |")
                await out_channel.send(line)
                seen.add(key)
                found += 1
            await asyncio.sleep(0.5)

        await out_channel.send(f"✅ Page {page_num} done — {found} with socials.")
        return True
    except Exception as e:
        await out_channel.send(f"❌ Page {page_num} error: {e}")
        return False

@bot.command(name="scrapelb")
async def scrapelb_cmd(ctx, url: str, start_page: int = 1):
    cfg = server_configs.get(ctx.guild.id, {})
    lb_id = cfg.get("lb_channel_id")
    if not lb_id:
        await ctx.send("⚠️ Set a target channel first: `!lbsetup #channel`")
        return
    out_channel = ctx.guild.get_channel(lb_id) or ctx.channel
    await ctx.send(f"🕓 Starting scrape from page {start_page} → posting to {out_channel.mention}")

    seen = set()
    driver = None
    try:
        driver = create_driver(headless=HEADLESS)
    except Exception as e:
        await ctx.send(f"❌ Could not start browser: {e}")
        return

    page = start_page
    try:
        while True:
            ok = await scrape_one_page(ctx, driver, out_channel, url, page, seen)
            if not ok:
                break
            page += 1
            # safety: stop after 100 pages
            if page - start_page > 100:
                await out_channel.send("⛔ Safety stop after 100 pages.")
                break
    finally:
        if driver:
            driver.quit()

# ------------------------------------------------------
#                    Misc commands
# ------------------------------------------------------
@bot.command(name="authorize")
async def authorize_cmd(ctx, password: Optional[str] = None):
    if not password:
        await ctx.send("Usage: `!authorize [password]`")
        return
    if password == PREMIUM_PASSWORD:
        authorized_users.add(ctx.author.id)
        await ctx.send("✅ Authorized.")
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

@bot.command(name="version")
async def version_cmd(ctx):
    embed = discord.Embed(title="Bot Version", color=0x00ff00)
    embed.add_field(name="Last Updated", value=LAST_UPDATED, inline=False)
    embed.add_field(name="Python", value=f"{sys.version.split()[0]}", inline=True)
    try:
        import selenium, undetected_chromedriver as uc  # noqa
        embed.add_field(name="Selenium", value=selenium.__version__, inline=True)
        embed.add_field(name="UC", value="OK", inline=True)
    except Exception:
        embed.add_field(name="Selenium/UC", value="missing?", inline=True)
    embed.set_footer(text=f"DATA_DIR: {DATA_DIR}")
    await ctx.send(embed=embed)

@bot.command(name="diag")
async def diag_cmd(ctx):
    import shutil
    chrome_bin = os.getenv("CHROME_BIN", "/usr/bin/google-chrome")
    try:
        import undetected_chromedriver as uc  # noqa
        uc_ok = "OK"
    except Exception as e:
        uc_ok = f"FAILED: {e!r}"
    await ctx.send(
        "```\n"
        f"UC import: {uc_ok}\n"
        f"Chrome bin: {chrome_bin} (exists={os.path.exists(chrome_bin)})\n"
        f"which google-chrome: {shutil.which('google-chrome')}\n"
        f"DATA_DIR: {DATA_DIR}\n"
        "```"
    )

# ------------------------------------------------------
#                    Bot lifecycle
# ------------------------------------------------------
@bot.event
async def on_ready():
    log.info(f"Bot logged in as {bot.user} | Updated: {LAST_UPDATED}")
    print(f"Bot is ready! Logged in as {bot.user}")
    print(f"Last updated: {LAST_UPDATED}")

# ------------------------------------------------------
#                        RUN
# ------------------------------------------------------
if __name__ == "__main__":
    print("Starting bot…")
    print(f"DATA_DIR: {DATA_DIR}")
    bot.run(BOT_TOKEN)
