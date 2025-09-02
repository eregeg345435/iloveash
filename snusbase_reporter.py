#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Discord Bot with PDF Processing
- Extracts information from and unlocks PDF files
- Checks Epic Games account status via API
Last updated: 2025-09-02 05:47:18
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
LAST_UPDATED = "2025-09-02 05:47:18"
BOT_USER = "eregeg345435"

# Epic API base URL
API_BASE = "https://api.proswapper.xyz/external"
_HEX32 = re.compile(r"^[0-9a-fA-F]{32}$")

# Simple headers to avoid detection
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0 Safari/537.36"
    ),
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

# List of proxies to use for API lookups (using only specified proxies)
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

# Currently active proxy for API requests
current_proxy = None
proxy_last_checked = 0
proxy_check_interval = 60  # Check proxy every 60 seconds
proxy_lock = threading.Lock()

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
MESSAGE_DELETE_DELAY = 1  # Reduced to 1 second for faster response

# Track messages sent to avoid duplication
message_cache = set()

# -------------------

# Set up Discord bot with intents
intents = discord.Intents.default()
intents.message_content = True  # Enable message content intent
bot = commands.Bot(command_prefix='!', intents=intents)

# Processing lock to prevent multiple concurrent processes
processing_lock = asyncio.Lock()


def test_proxy(proxy, timeout=3):
    """Test if a proxy works with the API"""
    proxy_dict = {
        'http': f'http://{proxy}',
        'https': f'http://{proxy}'
    }
    
    try:
        response = requests.get("https://api.proswapper.xyz/external/name/test", 
                               proxies=proxy_dict, timeout=timeout, headers=HEADERS)
        return response.status_code == 200
    except:
        return False


def find_working_proxy(force_check=False):
    """
    Find a working proxy from the list. If a working proxy is already found and hasn't expired,
    return that one. Otherwise, test all proxies to find a new one.
    
    Returns the proxy string if found, None otherwise.
    """
    global current_proxy, proxy_last_checked
    
    with proxy_lock:
        current_time = time.time()
        
        # If we already have a working proxy and it hasn't expired, use it
        if not force_check and current_proxy and (current_time - proxy_last_checked) < proxy_check_interval:
            return current_proxy
        
        # Test the current proxy first if we have one
        if current_proxy:
            if test_proxy(current_proxy):
                logger.info(f"Current proxy still working: {current_proxy}")
                proxy_last_checked = current_time
                return current_proxy
            else:
                logger.info(f"Current proxy no longer working: {current_proxy}")
        
        # Try each proxy in random order
        shuffled_proxies = PROXIES.copy()
        random.shuffle(shuffled_proxies)
        
        for proxy in shuffled_proxies:
            if test_proxy(proxy):
                logger.info(f"Found working proxy: {proxy}")
                current_proxy = proxy
                proxy_last_checked = current_time
                return proxy
        
        # If no proxy works, reset current proxy and return None
        logger.warning("No working proxy found")
        current_proxy = None
        return None


def get_api_response(url, timeout=8.0):
    """
    Make an API request using the current proxy or try to find a working proxy.
    Returns the API response or an error dict.
    """
    global current_proxy
    
    # Make sure we have a working proxy
    if not current_proxy:
        current_proxy = find_working_proxy()
    
    if current_proxy:
        # Try with current proxy
        proxy_dict = {
            'http': f'http://{current_proxy}',
            'https': f'http://{current_proxy}'
        }
        
        try:
            resp = requests.get(url, headers=HEADERS, proxies=proxy_dict, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 404:
                return {"status": "INACTIVE", "message": "Account not found or inactive"}
            elif resp.status_code == 403:
                # Proxy might be getting blocked, try to find a new one
                threading.Thread(target=lambda: find_working_proxy(force_check=True)).start()
        except:
            # If proxy fails, try to find a new one
            threading.Thread(target=lambda: find_working_proxy(force_check=True)).start()
    
    # Try all other proxies
    for proxy in PROXIES:
        if proxy == current_proxy:
            continue
            
        proxy_dict = {
            'http': f'http://{proxy}',
            'https': f'http://{proxy}'
        }
        
        try:
            resp = requests.get(url, headers=HEADERS, proxies=proxy_dict, timeout=timeout)
            if resp.status_code == 200:
                # Found a working proxy, update global
                current_proxy = proxy
                proxy_last_checked = time.time()
                return resp.json()
            elif resp.status_code == 404:
                return {"status": "INACTIVE", "message": "Account not found or inactive"}
        except:
            continue
    
    # If all proxies fail, try direct connection as last resort
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


def epic_lookup(value, mode=None, platform=None):
    """
    Look up Epic account info by display name or account ID.
    Uses a working proxy if available.
    
    Parameters:
    - value: The display name or account ID to look up
    - mode: 'name', 'id', or None (auto-detect)
    - platform: Optional platform filter ('xbl', 'psn', etc.)
    """
    if not value or value.strip() == "":
        return {"status": "ERROR", "message": "Please provide a display name or account ID"}
    
    # Strip whitespace
    value = value.strip()

    # Auto-detect mode if not provided
    if mode is None:
        mode = "id" if _HEX32.match(value) else "name"
    elif mode not in {"name", "id"}:
        return {"status": "ERROR", "message": "mode must be 'name', 'id', or None"}

    # Construct API URL
    url = f"{API_BASE}/{mode}/{value}"
    
    # Make the API request
    response = get_api_response(url)
    
    # If we got a platform filter and the response is a list, filter it
    if platform and isinstance(response, list):
        filtered_results = []
        for account in response:
            if 'externalAuths' in account:
                # Check if the account has the requested platform
                if platform.lower() in account['externalAuths']:
                    filtered_results.append(account)
        
        # Return filtered results if we found any, otherwise return the original response
        if filtered_results:
            return filtered_results
    
    return response


def detect_platform_from_transactions(text):
    """
    Detect platform (XBL, PSN, PC) from transaction data or text
    Returns platform code and display name.
    """
    # Priority check for specific platform tokens
    if 'xbl_xtoken' in text.lower():
        return 'Xbox (XBL)', 'xbl_xtoken'
    elif 'psn_xtoken' in text.lower():
        return 'PlayStation (PSN)', 'psn_xtoken'
    elif 'nintendo' in text.lower():
        return 'Nintendo Switch', 'nintendo'
    
    # Secondary checks for platform names
    if any(term in text.lower() for term in ["xbox", "xbl", "xb1", "xsx"]):
        return 'Xbox (XBL)', 'xbl_xtoken'
    elif any(term in text.lower() for term in ["playstation", "psn", "ps4", "ps5"]):
        return 'PlayStation (PSN)', 'psn_xtoken'
    elif any(term in text.lower() for term in ["pc", "epic", "computer", "windows"]):
        return 'PC/Epic Games', 'epic'
    elif any(term in text.lower() for term in ["nintendo", "switch"]):
        return 'Nintendo Switch', 'nintendo'
    elif any(term in text.lower() for term in ["mobile", "ios", "android", "phone"]):
        return 'Mobile (iOS/Android)', 'mobile'
    
    # Default to unknown if no specific platform found
    return 'Unknown', ''


def deduplicate_accounts(accounts_list):
    """
    Remove duplicate accounts from a list of account objects.
    Duplicates are identified by having the same account ID.
    """
    if not isinstance(accounts_list, list):
        return accounts_list
        
    # Use a dictionary to track unique accounts by ID
    unique_accounts = {}
    
    for account in accounts_list:
        # Skip if not a dict or missing ID
        if not isinstance(account, dict):
            continue
            
        # Use ID as unique identifier
        account_id = account.get('id')
        if account_id:
            unique_accounts[account_id] = account
    
    # Return the list of unique accounts
    return list(unique_accounts.values())


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
            lambda: epic_lookup(account_id, mode="id")
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

    # Look for external auth tokens and platform info
    auth_patterns = [
        r'addedExternalAuth[:\s]+([^\s\n]+)',  # addedExternalAuth: xbl_xtoken
        r'externalAuth[:\s]+([^\s\n]+)',       # externalAuth: psn_xtoken
        r'platform[:\s]+([^\n]+)',             # Platform: PlayStation (PSN)
        r'\b(psn_xtoken|xbl_xtoken|epic)\b'    # Direct token mentions
    ]
    
    # First, collect all possible platform mentions in the text
    platform_mentions = []
    for pattern in auth_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            token = match.group(1).strip().lower()
            platform_mentions.append(token)
    
    # Determine the platform from collected mentions
    if any('xbl_xtoken' in mention for mention in platform_mentions):
        info['platform'] = 'Xbox (XBL)'
        info['platform_token'] = 'xbl_xtoken'
    elif any('psn_xtoken' in mention for mention in platform_mentions):
        info['platform'] = 'PlayStation (PSN)'
        info['platform_token'] = 'psn_xtoken'
    elif any('nintendo' in mention for mention in platform_mentions):
        info['platform'] = 'Nintendo Switch'
        info['platform_token'] = 'nintendo'
    elif any('epic' in mention or 'pc' in mention for mention in platform_mentions):
        info['platform'] = 'PC/Epic Games'
        info['platform_token'] = 'epic'
    else:
        # Fallback to platform field detection if no tokens found
        platform_match = re.search(r'Platform:?\s*([^\n]+)', text, re.IGNORECASE)
        if platform_match:
            platform_text = platform_match.group(1).strip().lower()
            platform, token = detect_platform_from_transactions(platform_text)
            info['platform'] = platform
            info['platform_token'] = token

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
    transaction_patterns = [
        # Standard format with HISTORY_ACCOUNT_ prefix
        r'HISTORY_ACCOUNT_([A-Z_]+)\s+(\d{1,2}/\d{1,2}/\d{2,4})\s+(.+?)(?=\n|$)',
        
        # Looking specifically for addedExternalAuth entries (like in image 4)
        r'(\d{1,2}/\d{1,2}/\d{4})\s+(addedExternalAuth)\s*:\s*([^\n]+)',
        
        # Any date followed by action that might be relevant
        r'(\d{1,2}/\d{1,2}/\d{2,4})\s+([^\s:]+)(?:\s*:\s*|\s+)([^\n]+)'
    ]
    
    for pattern in transaction_patterns:
        matches = re.finditer(pattern, text, re.IGNORECASE)
        for match in matches:
            # Handle different formats
            if len(match.groups()) == 3:
                if match.group(1).lower() in ['addedexternalauth']:
                    # Format: date action details
                    transaction_type = match.group(1).upper()
                    date = match.group(2)
                    details = match.group(3).strip()
                else:
                    # Format: HISTORY_ACCOUNT_TYPE date details
                    transaction_type = match.group(1)
                    date = match.group(2)
                    details = match.group(3).strip()
            else:
                # Fallback format
                transaction_type = match.group(2).upper()
                date = match.group(1)
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
                
            # Check for platform tokens - highest priority
            if ('addedexternalauth' in transaction_type.lower() or 
                'externalauth' in transaction_type.lower()):
                if 'xbl_xtoken' in details.lower():
                    info['platform'] = 'Xbox (XBL)'
                    info['platform_token'] = 'xbl_xtoken'
                elif 'psn_xtoken' in details.lower():
                    info['platform'] = 'PlayStation (PSN)'
                    info['platform_token'] = 'psn_xtoken'
                elif 'nintendo' in details.lower():
                    info['platform'] = 'Nintendo Switch'
                    info['platform_token'] = 'nintendo'
                elif any(t in details.lower() for t in ['pc', 'epic']):
                    info['platform'] = 'PC/Epic Games'
                    info['platform_token'] = 'epic'

            info['transactions'].append({
                'type': transaction_type,
                'date': date,
                'details': details
            })

    # If we still don't have a platform, use the full text as a fallback
    if not info['platform'] or info['platform'] == 'Unknown':
        platform, token = detect_platform_from_transactions(text)
        if platform != 'Unknown':  # Only update if we found something
            info['platform'] = platform
            info['platform_token'] = token

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
                
            # Check current account status using the API
            if info['account_id']:
                status_message = await ctx.send(f"🔍 Checking current account status for ID: `{info['account_id']}`...")
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
    """
    Send a clean PDF analysis format with account status information.
    """
    # Get the source filename
    source_file = info.get('source_file', 'Unknown')

    # Start with the header and account status (MOVED TO THE TOP)
    output = "**📊 ACCOUNT ANALYSIS**\n\n"
    
    # FIRST check current account status and include it at the TOP of the message
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
            if 'externalAuths' in status_data and status_data['externalAuths']:
                output += "**Current Linked Accounts:**\n"
                for platform, data in status_data['externalAuths'].items():
                    if isinstance(data, dict):
                        output += f"- {platform}: {data.get('externalDisplayName', 'N/A')}\n"
                    else:
                        output += f"- {platform}: {str(data)}\n"
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
    else:
        # Make sure we always show status even if API check failed
        output += "**⚠️ ACCOUNT STATUS UNKNOWN**\n"
        output += "Could not check current account status.\n\n"
    
    # THEN show information extracted from the PDF
    output += f"**Information extracted from:** {source_file}\n\n"
    
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
    
    # Platform - now includes platform token if available
    if info['platform']:
        if info['platform_token']:
            output += f"**Platform:** {info['platform']} [{info['platform_token']}]\n"
        else:
            output += f"**Platform:** {info['platform']}\n"
    
    # Oldest IP
    if info['oldest_ip']:
        output += f"**Oldest IP:** {info['oldest_ip']}\n"
    
    # Account Status History
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
    
    # Send the complete information in one message
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


# Background task to periodically check for working proxies
async def proxy_maintenance_task():
    """Background task to periodically check proxies"""
    await bot.wait_until_ready()
    while not bot.is_closed():
        # Ensure we always have a working proxy ready
        find_working_proxy()
        
        # Wait for a while before checking again (don't hit the API too much)
        await asyncio.sleep(60)  # Check every minute


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
    
    # Start proxy maintenance task
    bot.loop.create_task(proxy_maintenance_task())
    
    # Find a working proxy immediately so it's ready for the first command
    working_proxy = find_working_proxy()
    if working_proxy:
        print(f"✓ Successfully connected to proxy server")
        print(f"API connection ready")
    else:
        print("✗ Could not establish proxy connection")
        print("Using direct connection mode")
    
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

    # Delete user lookup commands quickly (special handling)
    if message.content.startswith('!lookup '):
        # Try to delete message right away
        try:
            await message.delete()
        except:
            pass

    # Process commands
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
async def lookup_command(ctx, *args):
    """
    Look up an Epic account by display name, account ID, or platform
    Usage: 
    - !lookup <name/id>            - Look up by name or ID
    - !lookup xbl <gamertag>       - Look up Xbox gamertag
    - !lookup psn <username>       - Look up PlayStation username
    - !lookup switch <username>    - Look up Nintendo Switch username
    """
    # Check premium access
    if not await check_premium_access(ctx):
        return

    # If no arguments are provided, show usage information
    if not args:
        await ctx.send("⚠️ Please provide a display name or account ID to look up.\n"
                     "Usage:\n"
                     "- `!lookup <name/id>` - Look up by name or ID\n"
                     "- `!lookup xbl <gamertag>` - Look up Xbox gamertag\n"
                     "- `!lookup psn <username>` - Look up PlayStation username\n"
                     "- `!lookup switch <username>` - Look up Nintendo Switch username")
        return

    # Handle platform-specific lookups
    platform = None
    if args[0].lower() in ['xbl', 'xbox', 'x']:
        # Xbox Live lookup
        if len(args) < 2:
            await ctx.send("⚠️ Please provide an Xbox gamertag to look up.\nExample: `!lookup xbl Ninja`")
            return
        platform = 'xbl'
        value = ' '.join(args[1:])  # Allow spaces in gamertag
        mode = 'name'
    elif args[0].lower() in ['psn', 'playstation', 'ps', 'ps4', 'ps5']:
        # PlayStation Network lookup
        if len(args) < 2:
            await ctx.send("⚠️ Please provide a PlayStation username to look up.\nExample: `!lookup psn Ninja`")
            return
        platform = 'psn'
        value = ' '.join(args[1:])  # Allow spaces in username
        mode = 'name'
    elif args[0].lower() in ['switch', 'nintendo', 'ns']:
        # Nintendo Switch lookup
        if len(args) < 2:
            await ctx.send("⚠️ Please provide a Nintendo Switch username to look up.\nExample: `!lookup switch Ninja`")
            return
        platform = 'nintendo'
        value = ' '.join(args[1:])  # Allow spaces in username
        mode = 'name'
    else:
        # Standard lookup (auto-detect mode)
        value = ' '.join(args)  # Allow spaces in username/ID
        mode = "id" if _HEX32.match(value) else "name"

    # Show what we're looking up
    lookup_type = "account ID" if mode == "id" else "display name" 
    platform_msg = f" on {platform.upper()}" if platform else ""
    
    # Quick status message
    lookup_msg = await ctx.send(f"🔍 Looking up Epic account by {lookup_type}{platform_msg}: `{value}`...")
    
    # Make the API request
    result = await asyncio.get_event_loop().run_in_executor(
        None, lambda: epic_lookup(value, mode, platform)
    )

    # Handle errors
    if isinstance(result, dict) and result.get("status") in {"ERROR", "INACTIVE", "FORBIDDEN", "INVALID"}:
        await lookup_msg.edit(content=f"❌ {result.get('message', 'Lookup failed')}")
        return

    try:
        # NAME LOOKUP -> list of accounts
        if mode == "name" and isinstance(result, list):
            # Remove the lookup message since we'll send embeds
            await lookup_msg.delete()
            
            # Deduplicate the results to avoid showing the same account multiple times
            unique_results = deduplicate_accounts(result)
            
            if not unique_results:
                await ctx.send(f"❌ No results found for `{value}`{platform_msg}.")
                return

            # Show up to 5 matches to avoid spam
            for acc in unique_results[:5]:
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
            if len(unique_results) > 5:
                await ctx.send(f"ℹ️ More results exist ({len(unique_results)-5} more). Refine your search for fewer matches.")
            return

        # ID LOOKUP -> single account object
        elif mode == "id" and isinstance(result, dict):
            # Remove the lookup message since we'll send an embed
            await lookup_msg.delete()
            
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
            # Remove the lookup message since we'll send an embed
            await lookup_msg.delete()
            
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

        # Fallback for unexpected response format (edit the lookup message)
        await lookup_msg.edit(content=f"❌ No results found for `{value}`{platform_msg}.")

    except Exception as e:
        logger.error(f"Error in lookup command: {e}")
        await lookup_msg.edit(content=f"❌ Error processing API response: {str(e)}")


@bot.command(name='testproxies')
async def test_proxies_command(ctx):
    """Test all proxies and show which ones work"""
    # Check premium access
    if not await check_premium_access(ctx):
        return
    
    await ctx.send("Testing proxies... this may take a moment.")
    
    # Use a shorter timeout for this test to be faster
    working_count = 0
    total_proxies = len(PROXIES)
    
    # Progress updates - using a single message
    progress_msg = await ctx.send(f"Progress: 0/{total_proxies} tested")
    working_list = []
    
    # Remember the content we've already sent to avoid duplication
    processed_counts = set()
    
    for i, proxy in enumerate(PROXIES):
        progress = i + 1
        status = f"Progress: {progress}/{total_proxies} tested"
        
        # Only update at specific points to avoid rate limits
        if progress % 5 == 0 or progress == total_proxies:
            if test_proxy(proxy):
                working_count += 1
                working_list.append(proxy)
                
            # Only update if we haven't sent this exact progress before
            update_text = f"Progress: {progress}/{total_proxies} tested, {working_count} working"
            if update_text not in processed_counts:
                processed_counts.add(update_text)
                await progress_msg.edit(content=update_text)
        else:
            # Test without updating message
            if test_proxy(proxy):
                working_count += 1
                working_list.append(proxy)
    
    # Send final results
    await ctx.send(f"✅ Found {working_count} working proxies out of {total_proxies}")
    
    # Send working proxies in batches to avoid message limit
    if working_list:
        batch_size = 20
        for i in range(0, len(working_list), batch_size):
            batch = working_list[i:i+batch_size]
            await ctx.send("```\n" + "\n".join(batch) + "\n```")


@bot.command(name='proxyinfo')
async def proxy_info_command(ctx):
    """Show proxy connection status"""
    # Check premium access
    if not await check_premium_access(ctx):
        return
    
    if current_proxy:
        # Test if the current proxy is still working
        if test_proxy(current_proxy):
            status = "✅ Connected"
        else:
            status = "❌ Not working (will find new proxy)"
            # Trigger a proxy check in the background
            threading.Thread(target=lambda: find_working_proxy(force_check=True)).start()
            
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
        # No proxy is active, try to find one now
        working_proxy = find_working_proxy()
        if working_proxy:
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
    
    # Show API connection status
    if current_proxy:
        embed.add_field(name="API Connection", value="Active (using proxy)", inline=False)
    else:
        embed.add_field(name="API Connection", value="Direct connection", inline=False)
        
    embed.set_footer(text=f"Bot is running on {os.name.upper()} platform")
    
    await ctx.send(embed=embed)


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
        embed.add_field(name="!lookup [value]",
                        value="Look up an Epic Games account by name or ID\n"
                              "Examples:\n"
                              "- `!lookup Ninja` - Look up by name\n"
                              "- `!lookup 1234567890abcdef1234567890abcdef` - Look up by ID\n"
                              "- `!lookup xbl NinjaXbox` - Look up Xbox gamertag\n"
                              "- `!lookup psn NinjaPS5` - Look up PlayStation username",
                        inline=False)
        
        embed.add_field(name="!testproxies",
                        value="Test all proxies to see which ones are working",
                        inline=False)
                        
        embed.add_field(name="!proxyinfo",
                        value="Check the current API connection status",
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
    print(f"Current Time (UTC): 2025-09-02 05:54:19")
    print("Use Ctrl+C to stop")
    
    # Find a working proxy before starting the bot
    print("Testing API connection...")
    working_proxy = find_working_proxy()
    if working_proxy:
        print(f"✅ API connection ready (proxy mode)")
    else:
        print("⚠️ No working proxy found, will use direct connections")
    
    try:
        bot.run(BOT_TOKEN)
    except discord.errors.LoginFailure:
        print("ERROR: Invalid bot token. Please check your DISCORD_BOT_TOKEN environment variable.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to start the bot: {e}")
        sys.exit(1)
