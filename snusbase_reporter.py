#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Discord + Snusbase Reporter
- Standard mode: Processes users from twitter_users.txt file
- Discord input mode: Monitors a Discord webhook for uploaded text files with usernames
- Progress/results messages: DISCORD_WEBHOOK (auto-deleted, no sensitive details)
- Final output: FINISH_WEBHOOK (kept, formatted as code block)
"""

import os
import json
import time
import logging
import threading
import re
from typing import List, Dict, Tuple, Union, Optional
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from io import StringIO
import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("snusbase_report.log")
    ]
)
logger = logging.getLogger("snusbase_reporter")

# --- USER CONFIG ---
# Original webhooks
DISCORD_WEBHOOK = "https://discord.com/api/webhooks/1411256887797878884/q1CzdbfYW17Dr06zFg8w2JmqlzGtdtWlanYBlb1wmJvKfptX-puB_3jS8AwolSAHzT6K"
FINISH_WEBHOOK = "https://discord.com/api/webhooks/1411254674908250203/kaQyNHbMsXnxMwT_QT0FL78qHPLsxdqwCkhStsJ77GlMT4fqGkovWovxFBZLVs9-ecfX"

# New input webhook to monitor for file uploads
INPUT_WEBHOOK = "https://discord.com/api/webhooks/1411603435190751312/a3WMELh4M8sB1kdU-jIzwZ6KRkTjGHp42_SCqW67zBw_05XgAHqkpFOv4OEtJozvJ_49"

SNUSBASE_API_KEY = "sb3afud8h893krzzy8ec9r6s5m7u7n"
API_URL = "https://api.snusbase.com/data/search"
IP_WHOIS_URL = "https://api.snusbase.com/tools/ip-whois"
BREACH_FILTER = "TWITTER_COM"
CONCURRENCY = 8
RATE_LIMIT_DELAY = 0.12
INPUT_FILE = "twitter_users.txt"
CHECK_INTERVAL = 60  # How often to check Discord for new files (seconds)
# -------------------

# Global tracking of processed Discord messages to avoid duplicates
processed_message_ids = set()
_send_lock = threading.Lock()

def _http_post_json(url: str, payload: dict, timeout: int = 30):
    """Send a POST request with JSON payload"""
    body = json.dumps(payload).encode("utf-8")
    r = requests.post(url, headers={"Content-Type": "application/json"}, data=body, timeout=timeout)
    try: 
        data = r.json()
    except Exception: 
        data = r.text
    return r.status_code, data

def _http_get_json(url: str, params: dict = None, timeout: int = 30):
    """Send a GET request and return JSON response"""
    r = requests.get(url, params=params, timeout=timeout)
    try: 
        data = r.json()
    except Exception: 
        data = r.text
    return r.status_code, data

def _chunk(text: str, limit=2000) -> List[str]:
    """Split text into chunks respecting Discord's message size limit"""
    if not text: 
        return []
    out = []
    while text:
        if len(text) <= limit: 
            out.append(text)
            break
        cut = text.rfind("\n", 0, limit)
        if cut == -1 or cut < limit//3: 
            out.append(text[:limit])
            text = text[limit:]
        else: 
            out.append(text[:cut])
            text = text[cut+1:]
    return out

def send_discord_message(
    webhook_url: str, 
    content: str = None, *, 
    username: str = None, 
    avatar_url: str = None, 
    embeds: list = None,
    retries: int = 3, 
    return_id: bool = False,
):
    """Send a message to a Discord webhook"""
    if not webhook_url or (not content and not embeds): 
        return None
    url = webhook_url.rstrip("/") + "?wait=true"
    msg_ids = []
    
    def post(payload: dict):
        nonlocal retries
        while True:
            with _send_lock:
                status, data = _http_post_json(url, payload)
            if status in (200, 204): 
                return data if isinstance(data, dict) else {}
            if status == 429:
                try: 
                    retry_after = float(getattr(data, "get", lambda *_: 1.0)("retry_after", 1.0))
                except Exception: 
                    retry_after = 1.0
                time.sleep(max(0.05, retry_after))
                continue
            if status >= 500 and retries > 0:
                retries -= 1
                time.sleep(0.3)
                continue
            logger.error(f"Discord webhook error {status}: {data}")
            return {}
    
    if content:
        for part in _chunk(content, 2000):
            payload = {"content": part}
            if username: 
                payload["username"] = username
            if avatar_url: 
                payload["avatar_url"] = avatar_url
            if embeds: 
                payload["embeds"] = embeds
            resp = post(payload)
            embeds = None
            if RATE_LIMIT_DELAY: 
                time.sleep(RATE_LIMIT_DELAY)
            if return_id and resp and 'id' in resp: 
                msg_ids.append(resp['id'])
    else:
        payload = {}
        if username: 
            payload["username"] = username
        if avatar_url: 
            payload["avatar_url"] = avatar_url
        if embeds: 
            payload["embeds"] = embeds
        resp = post(payload)
        if return_id and resp and 'id' in resp: 
            msg_ids.append(resp['id'])
    
    if return_id: 
        return msg_ids if len(msg_ids) > 1 else (msg_ids[0] if msg_ids else None)
    return None

def delete_discord_message(webhook_url: str, message_id: str):
    """Delete a Discord message by ID"""
    url = f"{webhook_url.rstrip('/')}/messages/{message_id}"
    with _send_lock:
        try:
            resp = requests.delete(url, timeout=7)
            return resp.status_code in (204, 200)
        except Exception:
            return False

def delete_many_messages(webhook_url: str, message_ids: List[str]):
    """Delete multiple Discord messages"""
    with ThreadPoolExecutor(max_workers=12) as ex:
        list(ex.map(lambda mid: delete_discord_message(webhook_url, mid), message_ids))

def extract_handle(link: str, domain: str) -> str:
    """Extract a handle from a social media link"""
    try:
        handle = link.split(f"{domain}/")[-1]
        handle = handle.split('?')[0].split('#')[0].rstrip('/').strip()
        return handle
    except Exception: 
        return ""

def load_users_from_file(filename="twitter_users.txt") -> List[Dict[str, str]]:
    """Load user data from a file"""
    users = []
    try:
        with open(filename, "r", encoding="utf-8") as f:
            for line in f:
                if not line.strip(): 
                    continue
                parts = [x.strip() for x in line.strip().split("|")]
                if len(parts) >= 2:
                    username_tag = parts[0]
                    twitter_link = parts[1]
                    twitch_link = parts[2] if len(parts) > 2 else ""
                    
                    if "#" in username_tag:
                        username, discriminator = username_tag.split("#", 1)
                    else: 
                        username, discriminator = username_tag, ""
                        
                    users.append({
                        "username": username, 
                        "discriminator": discriminator,
                        "twitter_link": twitter_link, 
                        "twitch_link": twitch_link
                    })
    except FileNotFoundError: 
        logger.warning(f"Could not find {filename}.")
    return users

def load_users_from_text(text: str) -> List[Dict[str, str]]:
    """Parse user data from text content"""
    users = []
    for line in text.splitlines():
        if not line.strip(): 
            continue
        parts = [x.strip() for x in line.strip().split("|")]
        if len(parts) >= 2:
            username_tag = parts[0]
            twitter_link = parts[1]
            twitch_link = parts[2] if len(parts) > 2 else ""
            
            if "#" in username_tag:
                username, discriminator = username_tag.split("#", 1)
            else: 
                username, discriminator = username_tag, ""
                
            users.append({
                "username": username, 
                "discriminator": discriminator,
                "twitter_link": twitter_link, 
                "twitch_link": twitch_link
            })
    return users

def query_snusbase_api(term, search_type, max_retries=4, backoff_factor=1.5):
    """Query the Snusbase API"""
    headers = {"Auth": SNUSBASE_API_KEY, "Content-Type": "application/json"}
    data = {"terms": [term], "types": [search_type]}
    attempt = 0
    
    while attempt < max_retries:
        try:
            resp = requests.post(API_URL, headers=headers, json=data, timeout=15)
            logger.debug(f"Snusbase API [{search_type}] {term} status={resp.status_code}")
            
            if resp.status_code == 401:
                logger.error("ERROR: Snusbase API key unauthorized!")
                break
                
            resp.raise_for_status()
            resp_json = resp.json()
            
            all_results = []
            for db, entries in resp_json.get("results", {}).items():
                for entry in entries:
                    entry["breach"] = db
                    all_results.append(entry)
            return all_results
            
        except requests.exceptions.HTTPError as e:
            if resp.status_code == 503:
                wait_time = backoff_factor ** attempt
                time.sleep(wait_time)
                attempt += 1
                continue
            logger.error(f"HTTP error for {search_type} {term}: {e}")
            break
            
        except Exception as e:
            logger.error(f"API error for {search_type} {term}: {e}")
            break
            
    return []

def lookup_ip_location(ip_list):
    """Look up location information for IP addresses"""
    if not ip_list: 
        return None
    headers = {"Auth": SNUSBASE_API_KEY, "Content-Type": "application/json"}
    data = {"terms": ip_list}
    
    try:
        resp = requests.post(IP_WHOIS_URL, headers=headers, json=data, timeout=15)
        logger.debug("IP WHOIS status %s", resp.status_code)
        resp.raise_for_status()
        
        results = resp.json().get("results", {})
        locations = []
        
        for ip, info in results.items():
            city = info.get("city", "")
            region = info.get("regionName", "")
            country = info.get("country", "")
            
            if city or region or country:
                loc = ", ".join(filter(None, [city, region, country]))
                locations.append(loc)
                
        if not locations: 
            return None
        return max(set(locations), key=locations.count)
        
    except Exception as e:
        logger.error(f"IP WHOIS lookup error: {e}")
        return None

class ProgressReporter:
    """Reports progress to Discord"""
    
    def __init__(self, webhook: str, finish_webhook: str, phase_name: str, total: int, username: str, summary_to_finish=True):
        self.webhook = webhook
        self.finish_webhook = finish_webhook or webhook
        self.phase_name = phase_name
        self.total = total
        self.username = username
        self.summary_to_finish = summary_to_finish
        self.start_ts = time.time()
        self.count_ok = 0
        self.count_skip = 0
        self.count_nores = 0
        self._msg_ids = []
        
        msg_id = send_discord_message(
            self.webhook,
            f"**Starting {self.phase_name}** — 0/{self.total}",
            username=self.username,
            return_id=True
        )
        if msg_id: 
            self._msg_ids.append(msg_id)

    def step(self, index1: int, label: str):
        """Report progress on a single step"""
        msg_id = send_discord_message(
            self.webhook,
            f"Going through **{index1}/{self.total}**: `{label}`",
            username=self.username,
            return_id=True
        )
        if msg_id: 
            self._msg_ids.append(msg_id)
        logger.info(f"PROGRESS: {self.phase_name} {index1}/{self.total} {label}")

    def item_result(self, label: str, data: Union[str, dict, list]):
        """Report result for a single item"""
        # Only display non-sensitive status for first pass usernames
        if isinstance(data, dict) and ("emails_collected" in data or "twitter_handle" in data):
            status = data.get("status", "").upper()
            text = f"Status: {status}"
            if status == "OK":
                text += " (emails found)"
            elif status == "NO_RESULTS":
                text += " (no results)"
            elif status == "SKIP":
                text += " (skipped)"
            elif status == "ERROR":
                text += f" (error: {data.get('error', '')})"
        elif isinstance(data, (dict, list)):
            text = "```json\n" + json.dumps(data, ensure_ascii=False, indent=2) + "\n```"
            status = data.get("status", "").upper() if isinstance(data, dict) else ""
        else:
            text = str(data)
            status = ""
            
        if "SKIP" in status: 
            self.count_skip += 1
        elif "NO" in status and "RESULT" in status: 
            self.count_nores += 1
        else: 
            self.count_ok += 1
            
        msg_id = send_discord_message(
            self.webhook,
            f"**Result for** `{label}`:\n{text}",
            username=self.username,
            return_id=True
        )
        if msg_id: 
            self._msg_ids.append(msg_id)
        logger.info(f"RESULT: {label} -> {status}")

    def finish(self):
        """Finish reporting and clean up messages"""
        elapsed = time.time() - self.start_ts
        summary = (
            f"✅ **Finished {self.phase_name}** in {elapsed:.1f}s\n"
            f"- Total: **{self.total}**\n"
            f"- OK: **{self.count_ok}** | Skipped: **{self.count_skip}** | No Results: **{self.count_nores}**"
        )
        if self.summary_to_finish:
            send_discord_message(self.finish_webhook, summary, username=self.username)
        else:
            send_discord_message(self.webhook, summary, username=self.username)
        logger.info(f"Deleting {len(self._msg_ids)} messages from {self.webhook}...")
        delete_many_messages(self.webhook, self._msg_ids)

def _first_pass_one(user: Dict[str, str]) -> Tuple[str, Dict[str, str], List[str]]:
    """Process a single user in the first pass"""
    ident = f"{user['username']}#{user['discriminator']}"
    handle = extract_handle(user.get("twitter_link", ""), "twitter.com")
    
    if not handle:
        return ident, {"status": "SKIP", "reason": "no twitter handle", "twitter_link": user.get("twitter_link", "")}, []
        
    start_time = time.time()
    results = query_snusbase_api(handle, "username")
    elapsed = time.time() - start_time
    logger.debug(f"Lookup for {handle} took {elapsed:.2f} seconds")
    
    emails = []
    for entry in results:
        breach_name = entry.get("breach", "")
        email_val = entry.get("email", "")
        logger.debug(f"Entry: {entry}")
        logger.debug(f"Breach: {breach_name}, Email: {email_val}")
        
        if BREACH_FILTER and BREACH_FILTER.lower() not in breach_name.lower():
            continue
        if not email_val: 
            continue
        emails.append(email_val)
        
    if not emails:
        return ident, {"status": "NO_RESULTS", "twitter_handle": handle}, []
        
    # Only return summary, not emails for progress reporting
    return ident, {"status": "OK", "twitter_handle": handle, "emails_collected": "[hidden]"}, emails

def first_pass(users: List[Dict[str, str]], webhook: str, finish_webhook: str) -> Dict[str, List[Dict[str, str]]]:
    """First pass: search for emails based on Twitter handles"""
    email_user_map: Dict[str, List[Dict[str, str]]] = defaultdict(list)
    rep = ProgressReporter(webhook, finish_webhook, "username scan", len(users), username="Usernames", summary_to_finish=True)
    results_by_idx = {}
    users_with_idx = list(enumerate(users, 1))
    
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        future_to_idx = {ex.submit(_first_pass_one, user): idx for idx, user in users_with_idx}
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            user = users[idx-1]
            try: 
                ident, result, emails = future.result()
            except Exception as e:
                ident = f"{user['username']}#{user['discriminator']}"
                result = {"status": "ERROR", "error": str(e)}
                emails = []
            results_by_idx[idx] = (user, ident, result, emails)
            
    for idx in range(1, len(users)+1):
        user, ident, result, emails = results_by_idx[idx]
        rep.step(idx, f"{user['username']}#{user['discriminator']}")
        rep.item_result(ident, result)
        
        for e in emails:
            email_user_map[e].append({
                "username": user['username'],
                "discriminator": user['discriminator'],
                "twitter_link": user['twitter_link'],
                "twitch_link": user['twitch_link'],
            })
            
        if RATE_LIMIT_DELAY: 
            time.sleep(RATE_LIMIT_DELAY)
            
    rep.finish()
    return email_user_map

def _second_pass_one(email: str, attached_users: List[Dict[str, str]]) -> List[Tuple[str, dict]]:
    """Process a single email in the second pass"""
    results = query_snusbase_api(email, "email")
    logger.debug(f"RAW API RESPONSE FOR {email}: {results}")
    
    ip_candidates, usernames, birthdates = [], [], []
    for res in results:
        lastip = res.get("lastip", "")
        regip = res.get("regip", "")
        
        if lastip: 
            ip_candidates.append(lastip)
        if regip: 
            ip_candidates.append(regip)
            
        uname = res.get("username", "")
        if uname: 
            usernames.append(uname)
            
        bdate = res.get("birthdate", "") or res.get("birthday", "")
        if bdate: 
            birthdates.append(bdate)
            
    ip_candidates = list(set(ip_candidates))
    location = lookup_ip_location(ip_candidates)
    
    most_common_username = max(set(usernames), key=usernames.count) if usernames else "NA"
    birthdate_out = birthdates[0] if birthdates else "NA"
    ips_out = ", ".join(sorted(ip_candidates)) if ip_candidates else "NA"
    location_out = location if location else "NA"
    
    outs = []
    for info in attached_users:
        twitter_handle = extract_handle(info.get("twitter_link", ""), "twitter.com") or "NA"
        out = {
            "status": "OK",
            "user": f"{info['username']}#{info['discriminator']}",
            "twitter": info["twitter_link"],
            "twitch": info["twitch_link"],
            "email": email,
            "ips_found": ips_out,
            "most_common_ip_location": location_out,
            "most_common_username": most_common_username,
            "twitter_username": twitter_handle,
            "birthdate": birthdate_out,
        }
        outs.append((email, out))
    return outs

def format_final_output(all_results: List[dict]) -> str:
    """Format all results into a final output string"""
    lines = []
    lines.append("Snusbase Email Search Results\n====================================\n")
    for res in all_results:
        lines.append(json.dumps(res, ensure_ascii=False, indent=2))
        lines.append("------------------------------------")
    lines.append("====================================")
    return "```json\n" + "\n".join(lines) + "\n```"

def second_pass(email_user_map: Dict[str, List[Dict[str, str]]], webhook: str, finish_webhook: str):
    """Second pass: search for additional data based on found emails"""
    all_emails = list(email_user_map.keys())
    rep = ProgressReporter(webhook, finish_webhook, "email search", len(all_emails), username="Emails", summary_to_finish=True)
    results_by_idx = {}
    emails_with_idx = list(enumerate(all_emails, 1))
    all_results = []
    
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as ex:
        future_to_idx = {ex.submit(_second_pass_one, email, email_user_map[email]): idx for idx, email in emails_with_idx}
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            email = all_emails[idx-1]
            try: 
                outs = future.result()
            except Exception as e: 
                outs = [(email, {"status": "ERROR", "error": str(e)})]
            results_by_idx[idx] = (email, outs)
            
    for idx in range(1, len(all_emails)+1):
        email, outs = results_by_idx[idx]
        rep.step(idx, email)
        for _, data in outs:
            rep.item_result(email, data)
            all_results.append(data)
        if RATE_LIMIT_DELAY: 
            time.sleep(RATE_LIMIT_DELAY)
            
    rep.finish()
    
    # Send one big output to FINISH_WEBHOOK (never deleted), formatted in code block
    final_info = format_final_output(all_results)
    logger.info("Sending final email search output to FINISH_WEBHOOK")
    send_discord_message(finish_webhook, final_info, username="Emails · Output")
    return all_results

def extract_webhook_id_token(webhook_url):
    """Extract webhook ID and token from URL"""
    match = re.search(r'webhooks/(\d+)/([^/]+)', webhook_url)
    if match:
        return match.group(1), match.group(2)
    return None, None

def get_webhook_messages(webhook_id, webhook_token, limit=25):
    """Get recent messages from a webhook"""
    url = f"https://discord.com/api/webhooks/{webhook_id}/{webhook_token}/messages"
    try:
        status, data = _http_get_json(url, params={"limit": limit})
        if status == 200 and isinstance(data, list):
            return data
    except Exception as e:
        logger.error(f"Error fetching webhook messages: {e}")
    return []

def download_attachment(url):
    """Download an attachment from Discord"""
    try:
        response = requests.get(url, timeout=30)
        if response.status_code == 200:
            return response.text
        logger.error(f"Failed to download attachment: HTTP {response.status_code}")
    except Exception as e:
        logger.error(f"Error downloading attachment: {e}")
    return None

def process_webhook_messages():
    """Check for new files in the input webhook and process them"""
    webhook_id, webhook_token = extract_webhook_id_token(INPUT_WEBHOOK)
    if not webhook_id or not webhook_token:
        logger.error(f"Could not extract ID and token from INPUT_WEBHOOK URL")
        return
        
    messages = get_webhook_messages(webhook_id, webhook_token)
    
    for message in messages:
        message_id = message.get("id")
        
        # Skip if we've already processed this message
        if message_id in processed_message_ids:
            continue
            
        # Look for attachments
        attachments = message.get("attachments", [])
        for attachment in attachments:
            filename = attachment.get("filename", "")
            content_type = attachment.get("content_type", "")
            
            # Only process text files
            if not (filename.endswith(".txt") or content_type == "text/plain"):
                continue
                
            logger.info(f"Processing file attachment: {filename}")
            
            # Download the file content
            file_content = download_attachment(attachment.get("url"))
            if not file_content:
                continue
                
            # Parse users from the file content
            users = load_users_from_text(file_content)
            if not users:
                logger.warning(f"No valid users found in file: {filename}")
                send_discord_message(
                    INPUT_WEBHOOK,
                    f"No valid users found in file: `{filename}`\nFormat should be: `Username#Tag | https://twitter.com/handle | https://twitch.tv/handle`",
                    username="Snusbase Reporter"
                )
                continue
                
            # Acknowledge receipt
            send_discord_message(
                INPUT_WEBHOOK,
                f"Processing {len(users)} users from file: `{filename}`",
                username="Snusbase Reporter"
            )
            
            # Run the processing
            try:
                email_user_map = first_pass(users, DISCORD_WEBHOOK, FINISH_WEBHOOK)
                if not email_user_map:
                    send_discord_message(
                        INPUT_WEBHOOK,
                        f"No emails collected for users in file: `{filename}`",
                        username="Snusbase Reporter"
                    )
                    continue
                    
                results = second_pass(email_user_map, DISCORD_WEBHOOK, FINISH_WEBHOOK)
                
                # Send a completion message to the input webhook
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
                send_discord_message(
                    INPUT_WEBHOOK,
                    f"Completed processing `{filename}` at {timestamp}\n"
                    f"- Found data for {len(results)} entries\n"
                    f"- Results sent to output webhook",
                    username="Snusbase Reporter"
                )
                
            except Exception as e:
                logger.error(f"Error processing file {filename}: {e}")
                send_discord_message(
                    INPUT_WEBHOOK,
                    f"Error processing file `{filename}`: {str(e)}",
                    username="Snusbase Reporter"
                )
                
        # Mark this message as processed
        processed_message_ids.add(message_id)
        
        # Limit the size of the processed messages set
        if len(processed_message_ids) > 1000:
            # Keep only the most recent 500 message IDs
            processed_message_ids.clear()
            processed_message_ids.update(msg.get("id") for msg in messages[:500])

def run_discord_monitor():
    """Run the Discord webhook monitor as a background thread"""
    while True:
        try:
            process_webhook_messages()
        except Exception as e:
            logger.error(f"Error in Discord monitor: {e}")
        
        time.sleep(CHECK_INTERVAL)

def process_file(filename=INPUT_FILE):
    """Process users from a file (original functionality)"""
    users = load_users_from_file(filename)
    if not users:
        logger.error("No users loaded. Ensure the input file exists and has the correct format:")
        logger.error("  Username#Tag | https://twitter.com/handle | https://twitch.tv/handle (optional)")
        return False
        
    logger.info(f"Loaded {len(users)} users from {filename}")
    
    email_user_map = first_pass(users, DISCORD_WEBHOOK, FINISH_WEBHOOK)
    if not email_user_map:
        send_discord_message(
            FINISH_WEBHOOK or DISCORD_WEBHOOK, 
            "**No emails collected in first pass.**", 
            username="Emails"
        )
        return False
        
    second_pass(email_user_map, DISCORD_WEBHOOK, FINISH_WEBHOOK)
    return True

def main():
    """Main entry point"""
    if not DISCORD_WEBHOOK.startswith("https://"):
        logger.error("Please set a valid DISCORD_WEBHOOK.")
        return 1
        
    if FINISH_WEBHOOK and not FINISH_WEBHOOK.startswith("https://"):
        logger.error("FINISH_WEBHOOK looks invalid.")
        return 1
        
    if INPUT_WEBHOOK and not INPUT_WEBHOOK.startswith("https://"):
        logger.error("INPUT_WEBHOOK looks invalid.")
        return 1
        
    # Start the Discord monitor thread if we have an input webhook
    if INPUT_WEBHOOK:
        logger.info(f"Starting Discord monitor for webhook: {INPUT_WEBHOOK}")
        monitor_thread = threading.Thread(target=run_discord_monitor, daemon=True)
        monitor_thread.start()
        
    # Process the input file (original functionality)
    process_file(INPUT_FILE)
    
    # If we started a Discord monitor, keep the main thread alive
    if INPUT_WEBHOOK:
        try:
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received, shutting down...")
            return 0
    
    return 0

if __name__ == "__main__":
    exit_code = main()
    exit(exit_code)
