#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Discord Bot with PDF Processing
- Extracts information from and unlocks PDF files
- Checks Epic Games account status via API
Last updated: 2025-09-01 08:23:12
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
BOT_TOKEN = os.getenv("DISCORD_BOT_TOKEN", "MTQxMTYwNzA3MTA1MjI3MTY2Ng.abcdef.ghijklmnopqrstuvwxyz1234567890AB")  # Empty default, must be set in environment variables

# Premium command password
PREMIUM_PASSWORD = "ZavsMasterKey2025"

# Bot version info
LAST_UPDATED = "2025-09-01 08:23:12"
BOT_USER = "eregeg345435"

# Epic API base URL
API_BASE = "https://api.proswapper.xyz/external"

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


def epic_lookup(value, mode="name"):
    """
    Look up Epic account info by display name or account ID.

    mode: "name" or "id"
    value: the display name (string) or the 32-char account ID
    """
    if mode not in {"name", "id"}:
        raise ValueError("mode must be 'name' or 'id'")
    url = f"{API_BASE}/{mode}/{value}"
    try:
        resp = requests.get(url, timeout=12)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            # Account not found - it's inactive
            return {"status": "INACTIVE", "message": "Account not found or inactive"}
        logger.error(f"HTTP error in epic_lookup: {e}")
        return {"status": "ERROR", "message": f"HTTP error: {e}"}
    except Exception as e:
        logger.error(f"Error in epic_lookup: {e}")
        return {"status": "ERROR", "message": f"Error: {e}"}


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
        
        # If the account is active, add status information
        if result and "status" not in result:
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
        
        if status_data.get('status') == 'ACTIVE':
            output += "**🟢 ACCOUNT CURRENTLY ACTIVE**\n"
            
            # Include current display name if available
            if 'displayName' in status_data:
                output += f"**Current Display Name:** {status_data['displayName']}\n"
                
            # Include links if available
            if 'links' in status_data and status_data['links']:
                output += "**Current Linked Accounts:**\n"
                for platform, link_data in status_data['links'].items():
                    if isinstance(link_data, dict) and 'value' in link_data:
                        output += f"- {platform}: {link_data['value']}\n"
                    elif isinstance(link_data, str):
                        output += f"- {platform}: {link_data}\n"
                output += "\n"
                
        elif status_data.get('status') == 'INACTIVE':
            output += "**🔴 ACCOUNT CURRENTLY INACTIVE**\n"
            if 'message' in status_data:
                output += f"{status_data['message']}\n"
            output += "The account may have been banned, deleted, or changed username.\n\n"
            
        elif status_data.get('status') == 'ERROR':
            output += "**⚠️ ERROR CHECKING ACCOUNT STATUS**\n"
            if 'message' in status_data:
                output += f"{status_data['message']}\n\n"
        
        elif status_data.get('status') == 'INVALID':
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
async def lookup_command(ctx, value, mode="name"):
    """Look up an Epic account by display name or account ID"""
    # Check premium access
    if not await check_premium_access(ctx):
        return
    
    if not value:
        await ctx.send("Please provide a display name or account ID to look up.")
        return
        
    if mode not in ["name", "id"]:
        mode = "name"
    
    await ctx.send(f"🔍 Looking up Epic account by {mode}: `{value}`...")
    
    try:
        result = await asyncio.get_event_loop().run_in_executor(
            None, lambda: epic_lookup(value, mode)
        )
        
        if result:
            if 'status' in result and result['status'] in ['ERROR', 'INACTIVE', 'INVALID']:
                await ctx.send(f"❌ {result.get('message', 'Unknown error')}")
                return
                
            # Format the account info
            embed = discord.Embed(
                title=f"Epic Account: {result.get('displayName', 'Unknown')}",
                color=discord.Color.green()
            )
            
            embed.add_field(name="Account ID", value=result.get('accountId', 'Unknown'), inline=False)
            
            if 'externalAuths' in result and result['externalAuths']:
                linked = []
                for platform, data in result['externalAuths'].items():
                    if isinstance(data, dict) and 'externalDisplayName' in data:
                        linked.append(f"{platform}: {data['externalDisplayName']}")
                    elif isinstance(data, str):
                        linked.append(f"{platform}: {data}")
                        
                if linked:
                    embed.add_field(name="Linked Accounts", value="\n".join(linked), inline=False)
            
            await ctx.send(embed=embed)
        else:
            await ctx.send("❌ No results found.")
    except Exception as e:
        logger.error(f"Error in lookup command: {e}")
        await ctx.send(f"❌ Error looking up account: {str(e)}")


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
                              "mode can be 'name' or 'id' (default: name)",
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


@bot.event
async def on_message(message):
    """Called when a message is sent to a channel the bot can see"""
    # Ignore messages from the bot
    if message.author == bot.user:
        return

    # Process commands first
    await bot.process_commands(message)

    # If the channel is not the designated names channel, return
    if message.guild and message.channel.id:
        names_channel_id, _, _ = get_channels(message.guild.id)
        if names_channel_id and message.channel.id == names_channel_id:
            # If there's a PDF attachment, process it automatically
            for attachment in message.attachments:
                if attachment.filename.lower().endswith('.pdf'):
                    await process_pdf(message.channel, attachment, delete_message=False)
                    # Don't delete the message immediately, wait until the file is processed
                    # The message will be deleted by the process_pdf function
                    return  # Return to prevent deleting the message here

            # For non-PDF messages, delete after a delay
            try:
                await asyncio.sleep(MESSAGE_DELETE_DELAY)  # Wait a moment
                await message.delete()
            except Exception as e:
                logger.error(f"Error deleting message: {str(e)}")


if __name__ == "__main__":
    # Check if the bot token is set
    if not BOT_TOKEN:
        print("ERROR: No bot token provided. Please set the DISCORD_BOT_TOKEN environment variable.")
        sys.exit(1)
        
    print("Starting bot...")
    print(f"Last updated: {LAST_UPDATED}")
    print(f"User: {BOT_USER}")
    print("Current Time (UTC): 2025-09-01 08:23:12")
    print("Use Ctrl+C to stop")
    
    try:
        bot.run(BOT_TOKEN)
    except discord.errors.LoginFailure:
        print("ERROR: Invalid bot token. Please check your DISCORD_BOT_TOKEN environment variable.")
        sys.exit(1)
    except Exception as e:
        print(f"ERROR: Failed to start the bot: {e}")
        sys.exit(1)
