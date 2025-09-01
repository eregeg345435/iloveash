#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Discord Bot with PDF Processing
- Extracts information from and unlocks PDF files
- Checks Epic Games account status via API
Last updated: 2025-09-01 11:03:20
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
from typing import List, Dict, Tuple, Union, Optional
from collections import defaultdict
import requests
import discord
from discord.ext import commands
import datetime
import PyPDF2
import traceback

# Silence PyNaCl warning if not installed
try:
    import nacl
except ImportError:
    logging.warning("PyNaCl is not installed, voice will NOT be supported")

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("discord_bot.log")
    ]
)
logger = logging.getLogger("discord_bot")

# --- USER CONFIG (ALL IN ONE FILE) ---
# Put your bot token here or in environment variable (recommended)
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "")  # Empty default, must be set in environment variables

# Premium command password
PREMIUM_PASSWORD = "ZavsMasterKey2025"

# Bot version info
LAST_UPDATED = "2025-09-01 11:03:20"
BOT_USER = "eregeg345435"

# Epic API base URL
API_BASE = "https://api.proswapper.xyz/external"
_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")

# Simple headers to avoid detection
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
}

# List of proxies to use for API lookups
PROXIES = [
    "51.159.5.19:13128",
    "14.225.3.194:3128",
    "103.172.196.221:8080",
    "186.215.87.194:30010",
    "45.167.126.168:999",
    "66.36.234.130:1339",
    "152.53.194.55:24657",
    "42.96.16.176:1312",
    "38.127.172.60:24171",
    "38.191.214.4:999",
    "103.144.90.75:8082",
    "39.110.235.25:13128",
    "49.229.100.235:8080",
    "222.59.173.105:45108",
    "190.52.99.220:999",
    "185.4.29.243:7887",
    "186.96.70.57:999",
    "103.41.250.97:8080",
    "152.53.194.55:14691",
    "152.53.194.55:58872",
    "5.252.74.3:30001",
    "27.147.129.26:5050",
    "45.22.209.157:8888",
    "38.194.246.34:999",
    "116.102.106.101:10007",
    "36.136.27.2:4999",
    "41.223.119.156:3128",
    "102.23.245.112:8080",
    "171.239.232.119:10002",
    "219.93.111.125:9412",
    "190.93.102.136:999",
    "102.213.248.38:8080",
    "103.161.69.233:2698",
    "152.53.194.46:8065",
    "91.84.99.28:80",
    "116.100.250.40:10028",
    "116.100.250.40:10005",
    "187.111.144.102:8080",
    "213.221.43.246:8088",
    "5.252.74.5:30003",
    "40.71.46.210:8214",
    "157.180.121.252:16621",
    "222.59.173.105:45085",
    "72.10.160.170:3949",
    "181.78.197.235:999",
    "13.211.233.22:36619",
    "103.177.235.207:83",
    "116.98.40.45:1452",
    "45.167.126.170:999",
    "119.148.35.38:4840",
    "117.161.170.163:9348",
    "222.59.173.105:45104",
    "152.53.194.55:59837",
    "222.59.173.105:45219",
    "202.162.195.54:8080",
    "222.59.173.105:45148",
    "191.97.14.189:999",
    "38.127.172.50:24171",
    "38.127.172.79:24171",
    "157.20.236.8:3128",
    "103.156.16.45:8080",
    "152.53.194.55:25320",
    "115.178.49.47:8080",
    "176.126.103.194:44214",
    "23.237.210.82:80",
    "38.127.172.106:24171",
    "47.247.141.78:8080",
    "38.127.172.252:24171",
    "154.0.14.116:3128",
    "77.110.114.116:8081",
    "116.100.250.40:10012",
    "85.133.240.75:8080",
    "27.124.81.146:8080",
    "186.96.50.113:999",
    "38.52.155.166:999",
    "171.228.184.67:5107",
    "115.72.39.21:8080",
    "51.159.159.73:80",
    "41.33.142.182:8081",
    "167.99.172.98:8118",
    "103.158.252.196:8090",
    "38.191.209.130:999",
    "103.161.69.252:2698",
    "157.180.121.252:35993",
    "38.172.128.104:999",
    "201.62.125.142:8080",
    "46.16.229.254:8079",
    "175.118.246.102:3128",
    "200.215.248.112:999",
    "123.200.31.210:100",
    "61.144.152.124:9000",
    "103.137.91.250:8080",
    "171.228.187.56:5107",
    "157.10.97.229:8080",
    "209.14.98.5:8080",
    "157.180.121.252:35519",
    "40.172.232.213:13279",
    "195.133.220.46:1971",
    "115.72.42.175:10002",
    "200.205.60.2:8080",
    "222.127.227.102:8082",
    "116.97.3.251:1002",
    "38.180.2.107:3128",
    "222.74.73.202:42055",
    "179.96.28.58:80",
    "201.182.242.211:999",
    "154.62.226.126:8888",
    "185.191.236.162:3128",
    "171.228.185.99:5102",
    "38.127.172.239:24171",
    "154.236.177.105:1976",
    "103.230.81.121:8080",
    "77.238.103.98:8080",
    "186.96.111.214:999",
    "132.145.75.68:5457",
    "188.132.221.189:8080",
    "94.156.152.115:3128",
    "41.33.203.238:1981",
    "181.196.207.114:999",
    "45.174.95.142:999",
    "157.180.121.252:53919",
    "1.0.170.50:8080",
    "157.180.121.252:55503",
    "5.252.74.6:30004",
    "171.228.128.206:5102",
    "64.92.82.61:8081",
    "45.71.15.2:8080",
    "38.172.131.64:999",
    "171.228.187.56:5104",
    "178.252.171.230:8080",
    "183.88.220.245:8080",
    "36.147.78.166:80",
    "38.127.172.127:24171",
    "171.227.178.16:1008",
    "190.242.157.215:8080",
    "45.89.53.245:3128",
    "38.188.178.1:999",
    "113.116.180.180:9000",
    "171.228.191.8:5107",
    "46.19.68.45:4555",
    "116.100.250.40:10006",
    "120.50.11.225:8080",
    "27.76.166.182:10003",
    "45.167.126.1:8080",
    "188.132.221.8:8080",
    "216.195.100.57:3129",
    "103.163.24.48:10002",
    "115.77.160.145:10001",
    "45.123.142.146:8181"
]

# Default to 0 - will be set by the user with the setup command
NAMES_CHANNEL_ID = 0  # Channel for user submissions
PRE_SEARCH_CHANNEL_ID = 0  # Channel for progress updates
POST_SEARCH_CHANNEL_ID = 0  # Channel for final results

# Server-specific channel configurations
server_configs = {}

# Store user IDs who have been authorized for premium commands
authorized_users = set()

# Set to track already processed account IDs to prevent duplicates
processed_account_ids = set()

# Try to load processed account IDs from file
try:
    if os.path.exists("processed_accounts.json"):
        with open("processed_accounts.json", "r") as f:
            processed_account_ids = set(json.load(f))
except Exception as e:
    logger.error(f"Error loading processed accounts: {e}")

# Delete messages after processing
DELETE_MESSAGES = True

# Delay before message deletion (in seconds)
MESSAGE_DELETE_DELAY = 2
# -------------------

# Set up Discord bot with intents
intents = discord.Intents.default()
intents.message_content = True  # Enable message content intent
bot = commands.Bot(command_prefix='!', intents=intents)

# Processing lock to prevent multiple concurrent processes
processing_lock = asyncio.Lock()


def find_working_proxy():
    """Test proxies and find a working one"""
    # Shuffle the proxy list to try different ones first
    test_proxies = PROXIES.copy()
    random.shuffle(test_proxies)
    
    # Test URL - using a known endpoint that should return quickly
    test_url = "https://api.proswapper.xyz/external/name/test"
    
    for proxy in test_proxies:
        proxy_dict = {
            'http': f'http://{proxy}',
            'https': f'http://{proxy}'
        }
        
        try:
            # Set a short timeout to quickly skip non-working proxies
            response = requests.get(test_url, proxies=proxy_dict, timeout=3, headers=HEADERS)
            
            # If we get any response (even an error), the proxy is working
            if response.status_code:
                logger.info(f"Found working proxy: {proxy}")
                return proxy
        except:
            # If connection fails, try the next proxy
            continue
    
    # If no proxy works, return None
    logger.warning("No working proxy found")
    return None


def epic_lookup_with_proxy(value, mode=None, timeout=12.0):
    """
    Look up Epic account info using proxies to avoid IP blocking.
    First tries to find a working proxy, then falls back to direct connection if needed.
    """
    value = (value or "").strip()
    if not value:
        return {"status": "ERROR", "message": "Please provide a display name or account ID"}

    if mode is None:
        mode = "id" if _HEX32.match(value) else "name"
    elif mode not in {"name", "id"}:
        return {"status": "ERROR", "message": "mode must be 'name', 'id', or None"}

    url = f"{API_BASE}/{mode}/{value}"
    
    # Try with proxy first
    working_proxy = find_working_proxy()
    if working_proxy:
        proxy_dict = {
            'http': f'http://{working_proxy}',
            'https': f'http://{working_proxy}'
        }
        
        try:
            resp = requests.get(url, headers=HEADERS, proxies=proxy_dict, timeout=timeout)
            if resp.status_code == 404:
                return {"status": "INACTIVE", "message": "Account not found or inactive"}
            if resp.status_code == 403:
                logger.info("403 error with proxy, will try another approach")
                # Don't return here, fall through to no-proxy attempt
            else:
                resp.raise_for_status()
                return resp.json()
        except requests.exceptions.RequestException:
            # If proxy fails, we'll try without proxy
            logger.info(f"Proxy {working_proxy} failed, trying without proxy")
        except Exception as e:
            logger.error(f"Error with proxy request: {e}")
            # Continue to try without proxy
    
    # Try without proxy as fallback
    try:
        resp = requests.get(url, headers=HEADERS, timeout=timeout)
        if resp.status_code == 404:
            return {"status": "INACTIVE", "message": "Account not found or inactive"}
        if resp.status_code == 403:
            return {"status": "FORBIDDEN", "message": "403 Forbidden — host/IP or headers blocked by API"}
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        logger.error(f"HTTP error in epic_lookup: {e}")
        return {"status": "ERROR", "message": f"HTTP error: {e}"}
    except Exception as e:
        logger.error(f"Error in epic_lookup: {e}")
        return {"status": "ERROR", "message": f"Error: {e}"}


def epic_lookup_direct(value, mode="name"):
    """
    Most direct API lookup, tries with and without proxies
    """
    if not value:
        return {"error": "No lookup value provided"}
    
    # Use absolutely minimal request to avoid detection
    url = f"https://api.proswapper.xyz/external/{mode}/{value}"
    headers = {"User-Agent": "Mozilla/5.0"}
    
    # First try with a working proxy
    working_proxy = find_working_proxy()
    if working_proxy:
        proxy_dict = {
            'http': f'http://{working_proxy}',
            'https': f'http://{working_proxy}'
        }
        
        try:
            resp = requests.get(url, headers=headers, proxies=proxy_dict, timeout=5)
            if resp.status_code == 200:
                return resp.json()
            # If proxy fails with non-200, we'll try without proxy
        except:
            # If proxy connection fails, we'll try without proxy
            pass
    
    # Try without proxy as fallback
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code != 200:
            return {"error": f"API returned status code {resp.status_code}"}
            
        try:
            return resp.json()
        except:
            return {"error": "Could not parse API response as JSON"}
    except Exception as e:
        return {"error": f"Request failed: {str(e)}"}


async def check_account_status(account_id):
    """Asynchronous wrapper for Epic account lookup"""
    if not account_id:
        return None
        
    # Clean up the account ID (remove any non-alphanumeric characters)
    account_id = re.sub(r'[^a-zA-Z0-9]', '', account_id)
    
    # Validate account ID format (usually 32 characters for Epic)
    if len(account_id) != 32:
        return {"status": "INVALID", "message": f"Invalid account ID format: {account_id}"}
        
    # Run the API call in a thread pool to avoid blocking
    loop = asyncio.get_event_loop()
    try:
        result = await loop.run_in_executor(
            None, 
            lambda: epic_lookup_with_proxy(account_id, mode="id")
        )
        
        # If the account is active and result is a dict (not an error response), add status
        if result and isinstance(result, dict) and "status" not in result:
            result["status"] = "ACTIVE"
            
        return result
    except Exception as e:
        logger.error(f"Error checking account status: {e}")
        return {"status": "ERROR", "message": f"Error checking account status: {e}"}


def get_channels(guild_id):
    """Get the configured channels for a guild"""
    if guild_id in server_configs:
        config = server_configs[guild_id]
        names_channel_id = config["names_channel"]
        pre_search_channel_id = config["pre_search_channel"]
        post_search_channel_id = config["post_search_channel"]
    else:
        # Fall back to global config
        names_channel_id = NAMES_CHANNEL_ID
        pre_search_channel_id = PRE_SEARCH_CHANNEL_ID
        post_search_channel_id = POST_SEARCH_CHANNEL_ID

    return names_channel_id, pre_search_channel_id, post_search_channel_id


def save_processed_account_ids():
    """Save the processed account IDs to a JSON file"""
    try:
        with open("processed_accounts.json", "w") as f:
            json.dump(list(processed_account_ids), f)
    except Exception as e:
        logger.error(f"Error saving processed accounts: {e}")


def extract_user_info_from_text(text):
    """Extract user information from PDF text"""
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
        'source_file': None,  # To store the source file name
        'is_encrypted': False,  # To track if the PDF was encrypted
        'account_status': None  # To store the account status from the API
    }

    # Look for file name in the text
    filename_match = re.search(r'(?:information extracted from|file|data source)[:\s]+([^\n]+\.(?:pdf|txt|json))', 
                               text, re.IGNORECASE)
    if filename_match:
        info['source_file'] = filename_match.group(1).strip()

    # Look for Display Name, externalAuthDisplayName and similar patterns
    display_name_patterns = [
        r'(?:Display\s*Name|externalAuthDisplayName|displayName|username)[s\:]*[:\s="]+([^\r\n,;"\'][\S][^\r\n,;"\']+)',
        r'displayName\s*:?\s*["\'"]([^"\'"\n]+)["\'"]\s*[,;]?',
        r'name\s*:?\s*["\'"]([^"\'"\n]+)["\'"]\s*[,;]?',
        r'gamertag\s*:?\s*["\'"]([^"\'"\n]+)["\'"]\s*[,;]?'
    ]
    
    for pattern in display_name_patterns:
        display_name_matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in display_name_matches:
            display_name = match.group(1).strip()
            # Remove quotes if present
            if display_name.startswith('"') and display_name.endswith('"'):
                display_name = display_name[1:-1]
            if display_name and display_name not in info['display_names']:
                info['display_names'].append(display_name)

    # Look for email addresses
    email_patterns = [
        r'(?:Current\s*Email|Original\s*Email|email)[:\s="]+\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})',
        r'[\w\.-]+@[\w\.-]+\.\w+',  # Standard email pattern
        r'email\s*[=:]\s*"([^"]+@[^"]+\.\w+)"',  # email = "user@example.com"
        r'email\s*[=:]\s*([^\s;,]+@[^\s;,]+\.\w+)'  # email = user@example.com
    ]

    for pattern in email_patterns:
        email_matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in email_matches:
            email = match.group(1) if len(match.groups()) > 0 else match.group(0)
            email = email.strip('"\'')  # Remove any quotes
            if '@' in email and email not in info['all_emails']:
                info['all_emails'].append(email)

                # Check if this is specifically marked as current email
                current_context = text[max(0, match.start() - 20):match.start()]
                if 'current' in current_context.lower():
                    info['email'] = email

    # Use the first email as the email if not set
    if info['all_emails'] and not info['email']:
        info['email'] = info['all_emails'][0]

    # Look for account ID (various formats)
    account_id_patterns = [
        r'(?:Account\s*ID|account|user|id)[\s_-]*(?:id|number|#)[\s:_-]+([^\s\n,]+)',
        r'Account\s*ID:?\s*([a-f0-9]+)'  # Format from image 7
    ]
    
    for pattern in account_id_patterns:
        account_id_match = re.search(pattern, text, re.IGNORECASE)
        if account_id_match:
            info['account_id'] = account_id_match.group(1).strip()
            break

    # Look for creation/registration date
    date_patterns = [
        r'Creation\s*Date:?\s*(\d{1,2}[\/\.-]\d{1,2}[\/\.-]\d{2,4})',  # Format from image 7
        r'(?:created|registered|joined|creation|registration|date)[\s:_-]+(\d{1,2}[\/\.-]\d{1,2}[\/\.-]\d{2,4}|\d{4}[\/\.-]\d{1,2}[\/\.-]\d{1,2})'
    ]
    
    for pattern in date_patterns:
        date_match = re.search(pattern, text, re.IGNORECASE)
        if date_match:
            info['creation_date'] = date_match.group(1)
            break

    # Look for platform info (format from image 7)
    platform_match = re.search(r'Platform:?\s*([^\n]+)', text, re.IGNORECASE)
    if platform_match:
        platform_text = platform_match.group(1).strip().lower()
        # First check for exact matches to ensure platform is detected correctly
        if platform_text == "playstation (psn)" or platform_text == "playstation" or platform_text == "psn" or platform_text == "playstation network":
            info['platform'] = 'PlayStation (PSN)'
        elif platform_text == "xbox (xbl)" or platform_text == "xbox" or platform_text == "xbl" or platform_text == "xbox live":
            info['platform'] = 'Xbox (XBL)'
        elif platform_text == "pc/epic games" or platform_text == "pc" or platform_text == "epic games" or platform_text == "epic":
            info['platform'] = 'PC/Epic Games'
        elif platform_text == "nintendo switch" or platform_text == "switch" or platform_text == "nintendo":
            info['platform'] = 'Nintendo Switch'
        elif platform_text == "mobile (ios/android)" or platform_text == "mobile" or platform_text == "ios" or platform_text == "android":
            info['platform'] = 'Mobile (iOS/Android)'
        elif platform_text == "1":  # Special case from Image 8
            info['platform'] = 'PlayStation (PSN)'
        else:
            # Fallback to checking for partial matches
            if any(term in platform_text for term in ["playstation", "psn", "ps4", "ps5"]):
                info['platform'] = 'PlayStation (PSN)'
            elif any(term in platform_text for term in ["xbox", "xbl", "xb1", "xsx"]):
                info['platform'] = 'Xbox (XBL)'
            elif any(term in platform_text for term in ["pc", "epic", "computer", "windows"]):
                info['platform'] = 'PC/Epic Games'
            elif any(term in platform_text for term in ["nintendo", "switch"]):
                info['platform'] = 'Nintendo Switch'
            elif any(term in platform_text for term in ["mobile", "ios", "android", "phone"]):
                info['platform'] = 'Mobile (iOS/Android)'
            else:
                # If no platform was detected, just store the original text
                info['platform'] = platform_match.group(1).strip()

    # Look for IP addresses with dates
    ip_patterns = [
        r'Oldest\s*IP:?\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',  # Format from image 7
        r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:[\s:_-]+(\d{1,2}/\d{1,2}/\d{2,4}))?'
    ]
    
    for pattern in ip_patterns:
        ip_match = re.search(pattern, text, re.IGNORECASE)
        if ip_match:
            info['oldest_ip'] = ip_match.group(1)
            if len(ip_match.groups()) > 1 and ip_match.group(2):
                info['oldest_ip_date'] = ip_match.group(2)
            break

    # Look for account status
    status_match = re.search(r'Account\s*Status:?\s*([^\n]+)', text, re.IGNORECASE)
    if status_match:
        status_text = status_match.group(1).lower().strip()
        if 'disabled' in status_text or 'disable' in status_text:
            info['account_disabled'] = True
            # Try to extract disable count if available
            count_match = re.search(r'disabled\s+(\d+)\s+time', status_text, re.IGNORECASE)
            if count_match:
                info['disable_count'] = int(count_match.group(1))
            else:
                info['disable_count'] = 1
                
            # Check for other status indicators
            if 'compromised' in status_text:
                info['compromised_account'] = True
            if 'deactivated' in status_text:
                info['deactivated'] = True
            if 'reactivated' in status_text:
                info['reactivated'] = True
        elif 'no disable' in status_text or 'no history' in status_text:
            info['account_disabled'] = False

    # Look for transactions (HISTORY_ACCOUNT entries) to determine if account was disabled/compromised
    transaction_matches = re.finditer(r'HISTORY_ACCOUNT_([A-Z_]+)\s+(\d{1,2}/\d{1,2}/\d{2,4})\s+(.+?)(?=\n|$)', text)
    for match in transaction_matches:
        transaction_type = match.group(1)
        date = match.group(2)
        details = match.group(3).strip()

        # Track account disable/reactivate events
        if 'DISABLE' in transaction_type:
            info['account_disabled'] = True
            info['disable_count'] += 1
            info['disable_dates'].append(date)
            if 'meta data' in details.lower():
                info['deactivated'] = True

        if 'REACTIVE' in transaction_type or 'REENABLE' in transaction_type or 'ENABLED' in transaction_type:
            info['reactivated'] = True
            info['reactivate_dates'].append(date)

        # Check for compromised account pattern
        if 'METADATA_ADD' in transaction_type and 'DISABLED_REASON' in details and 'Compromised' in details:
            info['compromised_account'] = True

        info['transactions'].append({
            'type': transaction_type,
            'date': date,
            'details': details
        })

    return info


async def process_pdf(ctx, attachment, password=None, delete_message=True):
    """Process a PDF file to extract user information and unlock if needed"""
    message_to_delete = None
    if hasattr(ctx, 'message'):
        message_to_delete = ctx.message

    try:
        # Download the PDF file first, before deleting the message
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
        
        # Create a response message with file info
        initial_msg = await ctx.send(f"Processing PDF: `{attachment.filename}` ({attachment.size / 1024:.1f} KB)")
        
        # Now that we've downloaded the file and sent the initial message, we can delete the original message
        if delete_message and message_to_delete:
            try:
                await message_to_delete.delete()
            except Exception as e:
                logger.error(f"Error deleting message: {str(e)}")

        # Create a file-like object from the bytes
        pdf_file = io.BytesIO(file_bytes)

        try:
            # Open the PDF with PyPDF2
            pdf_reader = PyPDF2.PdfReader(pdf_file)
            is_encrypted = pdf_reader.is_encrypted

            # Check if the PDF is encrypted
            if is_encrypted:
                if not password:
                    await ctx.send("This PDF is password protected. Please provide a password with `!pdf [password]`")
                    return

                # Try to decrypt with the provided password
                try:
                    pdf_reader.decrypt(password)
                    # Send the success message here
                    decryption_msg = await ctx.send("✅ PDF successfully decrypted!")
                except Exception as e:
                    await ctx.send("❌ Failed to decrypt PDF. The password may be incorrect.")
                    return

            # Extract text from all pages
            all_text = ""
            try:
                for page in pdf_reader.pages:
                    try:
                        page_text = page.extract_text()
                        if page_text:
                            all_text += page_text + "\n\n"
                    except:
                        continue
            except Exception as e:
                logger.error(f"Error extracting all pages: {str(e)}")

            # If we couldn't extract from all pages, try just the first page
            if not all_text:
                try:
                    first_page = pdf_reader.pages[0]
                    all_text = first_page.extract_text()
                except Exception as e:
                    await ctx.send(f"Error extracting text from PDF: {str(e)}")
                    return

            # Look for user information in the text
            info = extract_user_info_from_text(all_text)
            # Store the filename and encryption status
            info['source_file'] = attachment.filename
            info['is_encrypted'] = is_encrypted

            # Check if this account ID has already been processed
            if info['account_id'] and info['account_id'] in processed_account_ids:
                await ctx.send(f"⚠️ This PDF has already been searched (Account ID: {info['account_id']})")
                return
                
            # Check current account status using the API with proxy
            if info['account_id']:
                status_message = await ctx.send(f"🔍 Checking current account status for ID: `{info['account_id']}` (using proxy if available)...")
                account_status = await check_account_status(info['account_id'])
                info['account_status'] = account_status
                await status_message.edit(content=f"✅ Account status check complete.")

            # Format and send the results in a clean profile format
            await send_pdf_analysis(ctx, info)

            # If account ID exists, add it to the processed list and save
            if info['account_id']:
                processed_account_ids.add(info['account_id'])
                save_processed_account_ids()

            # Save the unlocked PDF if it was originally encrypted
            if is_encrypted and password:
                # Create a new PDF writer
                pdf_writer = PyPDF2.PdfWriter()

                # Add all pages to the writer
                for page in pdf_reader.pages:
                    pdf_writer.add_page(page)

                try:
                    # Create a temporary file for the unlocked PDF
                    with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as temp_file:
                        # Write the unlocked PDF to the temporary file
                        pdf_writer.write(temp_file)

                    # Send the unlocked PDF as a Discord attachment
                    await ctx.send("Here is the unlocked PDF:",
                                   file=discord.File(temp_file.name, f"unlocked_{attachment.filename}"))

                    # Delete the temporary file
                    os.unlink(temp_file.name)
                except Exception as e:
                    logger.error(f"Error saving unlocked PDF: {str(e)}")
                    await ctx.send("Error saving the unlocked PDF.")

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


async def send_pdf_analysis(ctx, info):
    """Send a clean PDF analysis format, similar to Image 7"""
    # Get the source filename
    source_file = info.get('source_file', 'Unknown')

    # Start with the header
    output = "**📧 EMAIL CHANGE ANALYSIS**\n\n"
    
    # Information Source
    if source_file:
        output += f"**Information extracted from:** {source_file}\n\n"
    
    # Current Account Status from API
    if info.get('account_status'):
        status_data = info['account_status']
        
        if isinstance(status_data, dict) and status_data.get('status') == 'ACTIVE':
            output += "**🟢 ACCOUNT CURRENTLY ACTIVE**\n"
            
            # Include current display name if available
            if 'displayName' in status_data:
                output += f"**Current Display Name:** {status_data['displayName']}\n"
            elif 'display_name' in status_data:
                output += f"**Current Display Name:** {status_data['display_name']}\n"
                
            # Include links if available
            if 'links' in status_data and status_data['links']:
                output += "**Current Linked Accounts:**\n"
                for platform, link_data in status_data['links'].items():
                    if isinstance(link_data, dict) and 'value' in link_data:
                        output += f"- {platform}: {link_data['value']}\n"
                    elif isinstance(link_data, str):
                        output += f"- {platform}: {link_data}\n"
                output += "\n"
            
            # Include externalAuths if available
            elif 'externalAuths' in status_data and status_data['externalAuths']:
                output += "**Current Linked Accounts:**\n"
                for platform, link_data in status_data['externalAuths'].items():
                    if isinstance(link_data, dict) and 'externalDisplayName' in link_data:
                        output += f"- {platform}: {link_data['externalDisplayName']}\n"
                    elif isinstance(link_data, str):
                        output += f"- {platform}: {link_data}\n"
                output += "\n"
                
        elif isinstance(status_data, dict) and status_data.get('status') == 'INACTIVE':
            output += "**🔴 ACCOUNT CURRENTLY INACTIVE**\n"
            if 'message' in status_data:
                output += f"{status_data['message']}\n"
            output += "The account may have been banned, deleted, or changed username.\n\n"
            
        elif isinstance(status_data, dict) and status_data.get('status') in ['ERROR', 'FORBIDDEN']:
            output += "**⚠️ ERROR CHECKING ACCOUNT STATUS**\n"
            if 'message' in status_data:
                output += f"{status_data['message']}\n\n"
        
        elif isinstance(status_data, dict) and status_data.get('status') == 'INVALID':
            output += "**⚠️ INVALID ACCOUNT ID FORMAT**\n"
            if 'message' in status_data:
                output += f"{status_data['message']}\n\n"
            
    # Display Names with count if multiple
    if info['display_names']:
        display_names_text = ", ".join(info['display_names'])
        output += f"**Display Names:** {display_names_text}\n"
        if len(info['display_names']) > 1:
            output += f"Changed: {len(info['display_names']) - 1}\n"
    
    # Current Email
    if info['email']:
        output += f"**Current Email:** {info['email']}\n"
    
    # Account ID
    if info['account_id']:
        output += f"**Account ID:** {info['account_id']}\n"
    
    # Creation Date
    if info['creation_date']:
        output += f"**Creation Date:** {info['creation_date']}\n"
    
    # Platform - using exact format from Image 8
    if info['platform']:
        output += f"**Platform:** {info['platform']}\n"
    
    # Oldest IP
    if info['oldest_ip']:
        output += f"**Oldest IP:** {info['oldest_ip']}\n"
    
    # Account Status
    output += "\n**Account Status:** "
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
    
    # Send the primary information
    await ctx.send(output)
    
    # If it was originally an encrypted PDF, mention that
    if info.get('is_encrypted', False):
        await ctx.send("Here is the unlocked PDF.")


async def check_premium_access(ctx):
    """Check if the user has premium access and prompt if not"""
    if ctx.author.id not in authorized_users:
        await ctx.send("⚠️ This is a premium command. Please use `!authorize [password]` to access premium features.")
        # Try to delete the message
        try:
            await ctx.message.delete()
        except Exception as e:
            pass
        return False
    return True


@bot.event
async def on_ready():
    """Called when the bot is ready"""
    logger.info(f"Bot logged in as {bot.user.name} ({bot.user.id})")
    logger.info(f"Current Date: {LAST_UPDATED}")
    logger.info(f"User: {BOT_USER}")
    print(f"Bot is ready! Logged in as {bot.user.name}")
    print(f"Last updated: {LAST_UPDATED}")
    print(f"User: {BOT_USER}")
    print(f"Current Time (UTC): {LAST_UPDATED}")
    
    # Test if any proxies work
    working_proxy = find_working_proxy()
    if working_proxy:
        print(f"Found a working proxy: {working_proxy}")
    else:
        print("No working proxies found. Will use direct connections.")
    
    # Automatically authorize the first person who uses the bot
    global authorized_users
    if not authorized_users:
        print("No authorized users yet. The first user to interact will be automatically authorized.")


@bot.event
async def on_message(message):
    """Called when a message is sent to a channel the bot can see"""
    # Ignore messages from the bot
    if message.author == bot.user:
        return

    # Automatically authorize the first user who interacts with the bot
    if not authorized_users and not message.author.bot:
        authorized_users.add(message.author.id)
        try:
            await message.author.send("✅ You've been automatically authorized for premium commands as the first user.")
        except:
            # Can't DM them, send in channel instead
            await message.channel.send(f"✅ {message.author.mention}, you've been automatically authorized for premium commands as the first user.")

    # Process commands first
    await bot.process_commands(message)

    # Process PDF attachments in the designated channel
    if message.guild and message.channel.id:
        names_channel_id, _, _ = get_channels(message.guild.id)
        if names_channel_id and message.channel.id == names_channel_id:
            # If there's a PDF attachment, process it automatically
            for attachment in message.attachments:
                if attachment.filename.lower().endswith('.pdf'):
                    await process_pdf(message.channel, attachment, delete_message=False)
                    return  # Return to prevent deleting the message here

            # For non-PDF messages, delete after a delay
            try:
                await asyncio.sleep(MESSAGE_DELETE_DELAY)  # Wait a moment
                await message.delete()
            except Exception as e:
                logger.error(f"Error deleting message: {str(e)}")


@bot.command(name='setup')
@commands.has_permissions(administrator=True)
async def setup_channels(ctx, names_channel: discord.TextChannel = None, pre_search_channel: discord.TextChannel = None,
                         post_search_channel: discord.TextChannel = None):
    """Set up channels for the bot"""
    # Check premium access
    if not await check_premium_access(ctx):
        return
    
    if not names_channel:
        await ctx.send("Please specify channels: `!setup #names-channel #pre-search-channel #post-search-channel`")
        return

    if not pre_search_channel:
        pre_search_channel = names_channel

    if not post_search_channel:
        post_search_channel = pre_search_channel

    # Store the channel IDs for this guild
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
    """Authorize a user for premium commands"""
    if not password:
        await ctx.send("Please provide a password: `!authorize [password]`")
        return

    if password == PREMIUM_PASSWORD:
        authorized_users.add(ctx.author.id)
        await ctx.send("✅ You are now authorized for premium commands!")
        # Delete the command message to hide the password
        try:
            await ctx.message.delete()
        except:
            pass
    else:
        await ctx.send("❌ Invalid password.")
        # Delete the command message to hide the password attempt
        try:
            await ctx.message.delete()
        except:
            pass


@bot.command(name='pdf')
async def process_pdf_command(ctx, password=None):
    """Process a PDF file attached to the message"""
    if not ctx.message.attachments:
        await ctx.send("Please attach a PDF file to process.")
        return

    attachment = ctx.message.attachments[0]
    if not attachment.filename.lower().endswith('.pdf'):
        await ctx.send("Please attach a PDF file.")
        return

    await process_pdf(ctx, attachment, password, delete_message=True)


@bot.command(name='lookup')
async def lookup_command(ctx, value, mode=None):
    """Look up an Epic account by display name or account ID"""
    # Check premium access
    if not await check_premium_access(ctx):
        return

    if not value:
        await ctx.send("Please provide a display name or account ID to look up.")
        return

    # Auto-detect mode if not provided
    if mode is None:
        mode = "id" if _HEX32.match(value) else "name"
    elif mode not in ["name", "id"]:
        await ctx.send("Mode must be 'name' or 'id'. Using auto-detect instead.")
        mode = "id" if _HEX32.match(value) else "name"

    # Find a working proxy first
    working_proxy = find_working_proxy()
    proxy_status = f"using proxy {working_proxy}" if working_proxy else "using direct connection (no working proxy found)"
    await ctx.send(f"🔍 Looking up Epic account by {mode}: `{value}`... ({proxy_status})")
    
    # Try the proxy-enabled lookup method
    result = await asyncio.get_event_loop().run_in_executor(
        None, lambda: epic_lookup_with_proxy(value, mode)
    )
    
    # Handle explicit error dicts
    if isinstance(result, dict) and result.get("status") in {"ERROR", "INACTIVE", "FORBIDDEN", "INVALID"}:
        await ctx.send(f"❌ {result.get('message', 'Lookup failed')}")
        await ctx.send("Trying direct API URL as fallback...")
        
        # Try direct lookup as fallback
        direct_result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: epic_lookup_direct(value, mode)
        )
        
        if direct_result and not direct_result.get("error"):
            await ctx.send("✅ Direct API lookup successful!")
            result = direct_result
        else:
            await ctx.send(f"❌ Direct API lookup also failed: {direct_result.get('error', 'Unknown error')}")
            await ctx.send("You can try the API URL directly in your browser:\n" +
                         f"`https://api.proswapper.xyz/external/{mode}/{value}`")
            return

    try:
        # NAME LOOKUP -> list of accounts
        if mode == "name" and isinstance(result, list):
            if not result:
                await ctx.send("❌ No results found.")
                return

            # Show up to 5 matches to avoid spam
            for acc in result[:5]:
                display_name = acc.get("displayName", "Unknown")
                epic_id = acc.get("id", "Unknown")

                embed = discord.Embed(
                    title=f"Epic Account (name match): {display_name}",
                    color=discord.Color.green()
                )
                embed.add_field(name="Account ID", value=epic_id, inline=False)

                # externalAuths may be empty {}
                external = acc.get("externalAuths") or {}
                if external:
                    linked_lines = []
                    for platform, data in external.items():
                        if isinstance(data, dict):
                            linked_lines.append(f"{platform}: {data.get('externalDisplayName', 'N/A')}")
                        else:
                            linked_lines.append(f"{platform}: {str(data)}")
                    if linked_lines:
                        embed.add_field(name="Linked Accounts", value="\n".join(linked_lines), inline=False)

                await ctx.send(embed=embed)

            # If there are more than 5, hint that more exist
            if len(result) > 5:
                await ctx.send(f"ℹ️ More results exist ({len(result)-5} more). Refine your name for fewer matches.")
            return

        # ID LOOKUP -> single account object
        elif mode == "id" and isinstance(result, dict):
            display_name = result.get("displayName", "Unknown")
            epic_id = result.get("id", value)  # fall back to input

            embed = discord.Embed(
                title=f"Epic Account (by ID): {display_name}",
                color=discord.Color.green()
            )
            embed.add_field(name="Account ID", value=epic_id, inline=False)

            external = result.get("externalAuths") or {}
            if external:
                linked_lines = []
                for platform, data in external.items():
                    if isinstance(data, dict):
                        linked_lines.append(f"{platform}: {data.get('externalDisplayName', 'N/A')}")
                    else:
                        linked_lines.append(f"{platform}: {str(data)}")
                if linked_lines:
                    embed.add_field(name="Linked Accounts", value="\n".join(linked_lines), inline=False)

            await ctx.send(embed=embed)
            return
            
        # NAME LOOKUP but got a single object (happens sometimes)
        elif mode == "name" and isinstance(result, dict):
            display_name = result.get("displayName", "Unknown")
            epic_id = result.get("id", "Unknown")

            embed = discord.Embed(
                title=f"Epic Account (exact name match): {display_name}",
                color=discord.Color.green()
            )
            embed.add_field(name="Account ID", value=epic_id, inline=False)

            external = result.get("externalAuths") or {}
            if external:
                linked_lines = []
                for platform, data in external.items():
                    if isinstance(data, dict):
                        linked_lines.append(f"{platform}: {data.get('externalDisplayName', 'N/A')}")
                    else:
                        linked_lines.append(f"{platform}: {str(data)}")
                if linked_lines:
                    embed.add_field(name="Linked Accounts", value="\n".join(linked_lines), inline=False)

            await ctx.send(embed=embed)
            return

        # Fallback for unexpected response format
        await ctx.send(f"❌ Unexpected response format: {type(result).__name__}")
        await ctx.send(f"```\n{str(result)[:1000]}\n```")

    except Exception as e:
        logger.error(f"Error in lookup command: {e}")
        await ctx.send(f"❌ Error processing API response: {str(e)}")


@bot.command(name='testproxies')
async def test_proxies_command(ctx):
    """Test all proxies and show which ones work"""
    # Check premium access
    if not await check_premium_access(ctx):
        return
    
    await ctx.send("Testing proxies... this may take a moment.")
    
    # Test each proxy
    working_proxies = []
    test_url = "https://api.proswapper.xyz/external/name/test"
    
    for i, proxy in enumerate(PROXIES):
        if i % 20 == 0 and i > 0:
            await ctx.send(f"Testing proxy {i}/{len(PROXIES)}...")
            
        proxy_dict = {
            'http': f'http://{proxy}',
            'https': f'http://{proxy}'
        }
        
        try:
            # Set a short timeout to quickly skip non-working proxies
            response = requests.get(test_url, proxies=proxy_dict, timeout=2, headers=HEADERS)
            
            # If we get any response (even an error), the proxy is working
            if response.status_code:
                working_proxies.append(proxy)
        except:
            # If connection fails, skip this proxy
            continue
    
    # Report results
    if working_proxies:
        await ctx.send(f"✅ Found {len(working_proxies)} working proxies out of {len(PROXIES)}:")
        
        # Send proxies in batches to avoid message limit
        batch_size = 20
        for i in range(0, len(working_proxies), batch_size):
            batch = working_proxies[i:i+batch_size]
            await ctx.send("```\n" + "\n".join(batch) + "\n```")
    else:
        await ctx.send("❌ No working proxies found.")


@bot.command(name='reset')
@commands.has_permissions(administrator=True)
async def reset_processed_accounts(ctx):
    """Reset the processed accounts list (admin only)"""
    # Check premium access
    if not await check_premium_access(ctx):
        return
    
    global processed_account_ids
    processed_account_ids = set()
    save_processed_account_ids()
    await ctx.send("✅ Processed accounts list has been reset.")


@bot.command(name='version')
async def version_info(ctx):
    """Show version information about the bot"""
    # Check premium access
    if not await check_premium_access(ctx):
        return
    
    embed = discord.Embed(title="Bot Version Information", color=0x00ff00)
    embed.add_field(name="Last Updated", value=LAST_UPDATED, inline=False)
    embed.add_field(name="User", value=BOT_USER, inline=False)
    embed.add_field(name="Discord.py Version", value=discord.__version__, inline=True)
    embed.add_field(name="Python Version",
                    value=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                    inline=True)
    
    # Test if any proxies work
    working_proxy = find_working_proxy()
    if working_proxy:
        embed.add_field(name="Proxy Status", value=f"Working proxy available: {working_proxy}", inline=False)
    else:
        embed.add_field(name="Proxy Status", value="No working proxies found, using direct connections", inline=False)
        
    embed.set_footer(text=f"Bot is running on {os.name.upper()} platform")
    await ctx.send(embed=embed)


# Rename from 'help' to 'commands' to avoid conflict with built-in help
@bot.command(name='commands')
async def custom_commands_help(ctx):
    """Show help information about the bot commands"""
    # Check premium access
    if not await check_premium_access(ctx):
        return
    
    embed = discord.Embed(title="Bot Commands", color=0x00ff00)
    embed.set_footer(text=f"Bot Last Updated: {LAST_UPDATED}")

    embed.add_field(name="!pdf [password]",
                    value="Process an attached PDF file to extract user information\n"
                          "(Optional password if the PDF is encrypted)",
                    inline=False)
                    
    if ctx.author.id in authorized_users:
        embed.add_field(name="!lookup [value] [mode]",
                        value="Look up an Epic Games account by name or ID\n"
                              "mode can be 'name' or 'id' (default: auto-detect)\n"
                              "Uses proxies to avoid 403 errors",
                        inline=False)
        
        embed.add_field(name="!testproxies",
                        value="Test all proxies to see which ones are working",
                        inline=False)
                    
        embed.add_field(name="!setup #channel1 #channel2 #channel3",
                        value="Set up channels for the bot (admin only)\n"
                            "#channel1 = Names Channel\n"
                            "#channel2 = Pre-search Channel\n"
                            "#channel3 = Post-search Channel",
                        inline=False)
                    
        embed.add_field(name="!reset",
                        value="Reset the processed accounts list (admin only)",
                        inline=False)

        embed.add_field(name="!version",
                        value="Show version information for the bot",
                        inline=False)

        embed.add_field(name="!commands",
                        value="Show this help message",
                        inline=False)

    embed.add_field(name="!authorize [password]",
                    value="Authorize yourself for premium commands",
                    inline=False)

    await ctx.send(embed=embed)


if __name__ == "__main__":
    # Check if the bot token is set
    if not BOT_TOKEN:
        print("ERROR: No bot token provided. Please set the DISCORD_BOT_TOKEN environment variable.")
        sys.exit(1)
        
    print("Starting bot...")
    print(f"Last updated: {LAST_UPDATED}")
    print(f"User: {BOT_USER}")
    print("Current Time (UTC): 2025-09-01 11:03:20")
    print("Use Ctrl+C to stop")
    print(f"Using {len(PROXIES)} proxies for API lookups")
    
    try:
        bot.run(BOT_TOKEN)
    except discord.errors.LoginFailure:
        print("ERROR: Invalid bot token. Please check your DISCORD_BOT_TOKEN environment variable.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to start the bot: {e}")
        sys.exit(1)
