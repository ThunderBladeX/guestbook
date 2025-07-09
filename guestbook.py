from flask import Flask, request, jsonify, render_template, Response, send_file
from flask_cors import CORS
import requests
import json
import os
import logging
from datetime import datetime
import re
import uuid
import hashlib
import bleach
from markdown_it import MarkdownIt
import io
import csv
import ipinfo
import requests_cache
from user_agents import parse
import ipaddress
import tempfile
import gzip
import sqlite3
from contextlib import contextmanager
import threading
from typing import Optional, List, Dict, Any
import pathlib

# Configure logging to reduce noise in production
logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.WARNING)

md = MarkdownIt()

IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN')
ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN) if IPINFO_TOKEN else None

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

CORS(
    app,
    origins=["https://alatheary0p.neocities.org", "https://ry0p.lovestoblog.com"],
    methods=["GET", "POST", "DELETE", "OPTIONS", "PUT"],  # Explicitly allow necessary methods
    allow_headers=["Content-Type", "X-Admin-Key", "X-Deletion-Token"] # Explicitly allow custom header
)

# Vercel KV HTTP REST API setup
KV_REST_API_URL = os.environ.get('KV_REST_API_URL')
KV_REST_API_TOKEN = os.environ.get('KV_REST_API_TOKEN')
kv_available = bool(KV_REST_API_URL and KV_REST_API_TOKEN)

if kv_available:
    app.logger.info("Vercel KV REST API credentials found and configured")
else:
    app.logger.warning("Vercel KV REST API credentials not found")

GUESTBOOK_KV_KEY = 'guestbook_entries_v2' # Key to store entries in KV
DELETED_GUESTBOOK_KV_KEY = 'guestbook_deleted_entries_v2'
LOCAL_GUESTBOOK_FILE = os.path.join(os.path.dirname(__file__), 'guestbook_local.json')
LOCAL_DELETED_FILE = os.path.join(os.path.dirname(__file__), 'guestbook_deleted_local.json')
ALLOWED_EMOJIS = ["👍", "❤️", "😂", "🤔", "😢", "🔥", "🎉", "👏"]

DB_PATH = os.path.join(os.path.dirname(__file__), 'guestbook.db')
CACHE_DB_PATH = os.path.join(os.path.dirname(__file__), 'requests_cache.db')

class DatabaseError(Exception):
    """Custom exception for database errors"""
    pass

@contextmanager
def get_db_connection():
    """Context manager for database connections"""
    conn = None
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        yield conn
    except sqlite3.Error as e:
        raise DatabaseError(f"Database error: {e}")
    finally:
        if conn:
            conn.close()

def init_db():
    """Initialize the SQLite database with required tables"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            
            # Create entries table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY,
                    data JSON NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create deleted_entries table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS deleted_entries (
                    id INTEGER PRIMARY KEY,
                    data JSON NOT NULL,
                    deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
    except Exception as e:
        app.logger.error(f"Failed to initialize database: {e}")
        raise

def kv_get(key):
    if not kv_available: return None
    try:
        response = requests.get(f"{KV_REST_API_URL}/get/{key}", headers={'Authorization': f'Bearer {KV_REST_API_TOKEN}'}, timeout=10)
        if response.status_code == 200: return response.json().get('result')
        return None
    except Exception as e:
        app.logger.error(f"KV GET error: {e}")
        return None

def kv_set(key, value):
    if not kv_available: return False
    try:
        response = requests.post(f"{KV_REST_API_URL}/set/{key}", headers={'Authorization': f'Bearer {KV_REST_API_TOKEN}'}, json=value, timeout=10)
        return response.status_code == 200
    except Exception as e:
        app.logger.error(f"KV SET error: {e}")
        return False

def load_entries() -> List[Dict[str, Any]]:
    """Load entries from SQLite, fallback to KV, then local file"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM entries ORDER BY json_extract(data, '$.timestamp') DESC")
            rows = cursor.fetchall()
            if rows:
                return [json.loads(row['data']) for row in rows]
    except Exception as e:
        app.logger.warning(f"SQLite load failed, falling back to KV: {e}")
    if kv_available:
        try:
            data = kv_get(GUESTBOOK_KV_KEY)
            if data:
                return json.loads(data) if isinstance(data, str) else data
        except Exception as e:
            app.logger.warning(f"KV load failed, falling back to local file: {e}")
    if os.path.exists(LOCAL_GUESTBOOK_FILE):
        with open(LOCAL_GUESTBOOK_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_entries(entries: List[Dict[str, Any]]) -> bool:
    """Save entries to SQLite, then KV if available"""
    success = False
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM entries")
            for entry in entries:
                cursor.execute(
                    "INSERT INTO entries (data) VALUES (?)",
                    (json.dumps(entry),)
                )
            conn.commit()
            success = True
    except Exception as e:
        app.logger.error(f"SQLite save failed: {e}")
        if not kv_available:
            raise
    if kv_available:
        try:
            if kv_set(GUESTBOOK_KV_KEY, entries):
                success = True
        except Exception as e:
            app.logger.error(f"KV save failed: {e}")
            if not success:
                raise
    if not success:
        with open(LOCAL_GUESTBOOK_FILE, 'w', encoding='utf-8') as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)
            success = True
    return success

def load_deleted_entries() -> List[Dict[str, Any]]:
    """Load deleted entries from SQLite, fallback to KV"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT data FROM deleted_entries ORDER BY deleted_at DESC")
            rows = cursor.fetchall()
            if rows:
                return [json.loads(row['data']) for row in rows]
    except Exception as e:
        app.logger.warning(f"SQLite deleted entries load failed, falling back to KV: {e}")
    if kv_available:
        try:
            data = kv_get(DELETED_GUESTBOOK_KV_KEY)
            if data:
                return json.loads(data) if isinstance(data, str) else data
        except Exception as e:
            app.logger.warning(f"KV deleted entries load failed, falling back to local file: {e}")
    if os.path.exists(LOCAL_DELETED_FILE):
        with open(LOCAL_DELETED_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_deleted_entries(entries: List[Dict[str, Any]]) -> bool:
    """Save deleted entries to SQLite, then KV if available"""
    success = False
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM deleted_entries")
            for entry in entries:
                cursor.execute(
                    "INSERT INTO deleted_entries (data) VALUES (?)",
                    (json.dumps(entry),)
                )
            conn.commit()
            success = True
    except Exception as e:
        app.logger.error(f"SQLite deleted entries save failed: {e}")
        if not kv_available:
            raise
    if kv_available:
        try:
            if kv_set(DELETED_GUESTBOOK_KV_KEY, entries):
                success = True
        except Exception as e:
            app.logger.error(f"KV deleted entries save failed: {e}")
            if not success:
                raise
    if not success:
        with open(LOCAL_DELETED_FILE, 'w', encoding='utf-8') as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)
            success = True
    return success

def setup_request_cache():
    """Configure requests-cache with SQLite backend"""
    try:
        requests_cache.install_cache(
            cache_name=CACHE_DB_PATH,
            backend='sqlite',
            expire_after=86400,  # 24 hours
            allowable_methods=('GET', 'POST'),  # Cache both GET and POST requests
        )
        app.logger.info("Requests cache configured with SQLite backend")
    except Exception as e:
        app.logger.warning(f"Failed to setup SQLite requests cache, falling back to memory cache: {e}")
        # Fallback to memory cache
        requests_cache.install_cache(
            cache_name='memory_cache',
            backend='memory',
            expire_after=86400
        )

def sanitize_html(html_content):
    """Sanitizes HTML, allowing only specific tags and attributes."""
    allowed_tags = {'strong', 'b', 'em', 'i', 'a', 'p', 'br'}
    allowed_attrs = {'a': ['href', 'title', 'target']}
    clean_html = bleach.clean(
        html_content,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip=True  # Removes disallowed tags instead of escaping them
    )
    # Ensure links open in a new tab for security
    clean_html = bleach.linkify(clean_html, callbacks=[lambda attrs, new: {**attrs, '_target': 'blank', '_rel': 'noopener noreferrer'}])
    return clean_html

def sanitize_text(text):
    """Basic sanitization for non-Markdown fields like name."""
    if not text: return ""
    return bleach.clean(str(text), tags=[], strip=True).strip()[:100]

def _filter_entry_for_public(entry):
    """Removes sensitive fields from an entry before sending to the client."""
    public_entry = entry.copy()
    sensitive_keys = ['ip_hash', 'deletion_token', 'flagged_by_ips']
    for key in sensitive_keys:
        public_entry.pop(key, None)
    if not public_entry.get('show_country', False):
        public_entry.pop('country', None)
        public_entry.pop('country_name', None)
    return public_entry

def validate_email(email):
    """Basic email validation"""
    if not email:
        return True  # Email is optional
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def _get_user_ip():
    """Get user IP, respecting proxy headers and handling IPv6"""
    headers = [
        'X-Forwarded-For',
        'HTTP_X_REAL_IP',
        'X-Real-IP',
        'X-Cluster-Client-IP',
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED',
    ]
    for header in headers:
        if header in request.headers:
            ip_list = request.headers[header].split(',')
            for ip in ip_list:
                ip = ip.strip()
                try:
                    # Validate the IP address
                    ipaddress.ip_address(ip)
                    # Remove private IPs
                    if not ipaddress.ip_address(ip).is_private:
                        return ip
                except ValueError:
                    # Invalid IP, skip to the next one
                    continue
    # Fallback to proxy IP, better than nothing!
    return request.remote_addr

def _get_user_agent_data(request):
    """Parses and returns user agent information."""
    user_agent_string = request.headers.get('User-Agent')
    if user_agent_string:
        user_agent = parse(user_agent_string)
        return {
            'browser': user_agent.browser.family,
            'browser_version': user_agent.browser.version_string,
            'os': user_agent.os.family,
            'os_version': user_agent.os.version_string,
            'device': user_agent.device.family
        }
    return {}

def validate_entry(entry):
    """Validates a guestbook entry against a schema."""
    required_fields = ['name', 'message', 'timestamp']
    for field in required_fields:
        if field not in entry:
            return False, f"Missing required field: {field}"
    try:
        datetime.fromisoformat(entry['timestamp'])
    except ValueError:
        return False, "Invalid timestamp format"
    return True, None

def initialize_app():
    """Initialize the application"""
    db_dir = os.path.dirname(DB_PATH)
    pathlib.Path(db_dir).mkdir(parents=True, exist_ok=True)
    try:
        init_db()
        app.logger.info("SQLite database initialized successfully")
    except Exception as e:
        app.logger.error(f"Failed to initialize SQLite database: {e}")
    setup_request_cache()

initialize_app()

@app.route('/', methods=['GET'])
def home():
    """Render the home page with API status"""
    # Data to be passed to the template
    kv_status_message = 'Vercel KV REST API configured' if kv_available else 'Vercel KV REST API not configured'
    version_number = '2.0.0-replies'

    # Render the HTML template and pass the variables to it
    return render_template(
        'index.html',
        version=version_number,
        kv_status=kv_status_message
    )

@app.route('/entries', methods=['GET'])
def get_entries():
    try:
        entries = load_entries()
        entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        public_entries = [_filter_entry_for_public(e) for e in entries if not e.get('is_deleted')]
        return jsonify({'success': True, 'entries': public_entries, 'count': len(public_entries)})
    except Exception as e:
        app.logger.error(f"Error retrieving entries: {e}")
        return jsonify({'success': False, 'error': 'Failed to retrieve entries'}), 500

@app.route('/entries', methods=['POST'])
def add_entry():
    """Add a new guestbook entry (heavily updated)."""
    try:
        data = request.get_json()
        if not data: return jsonify({'success': False, 'error': 'No data provided'}), 400

        name = sanitize_text(data.get('name'))
        message_raw = data.get('message', '') # Keep raw Markdown

        if not name or not message_raw: return jsonify({'success': False, 'error': 'Name and message are required'}), 400
        if len(name) < 2 or len(message_raw) < 5: return jsonify({'success': False, 'error': 'Name/message too short'}), 400

        message_html = sanitize_html(md.render(message_raw))
        entries = load_entries()
        next_id = max([e.get('id', 0) for e in entries], default=0) + 1
        user_ip = _get_user_ip()
        ip_hash = hashlib.sha256(user_ip.encode('utf-8')).hexdigest()
        country_code = None
        country_name = "Unknown"
        latitude = None
        longitude = None

        if ipinfo_handler:
            try:
                details = ipinfo_handler.getDetails(user_ip)
                country_code = details.country
                country_name = details.country_name
                latitude = details.latitude
                longitude = details.longitude
            except Exception as e:
                app.logger.warning(f"Could not get geo-info for IP: {e}")

        user_agent_data = _get_user_agent_data(request)

        entry = {
            'id': next_id,
            'name': name,
            'message': message_raw, # Store raw markdown
            'message_html': message_html, # Store sanitized HTML
            'timestamp': datetime.now().isoformat(),
            'date_display': datetime.now().strftime('%B %d, %Y at %I:%M %p'),
            'replies': [],
            'reactions': {},
            'flagged': False,
            'flagged_by_ips': [],
            'ip_hash': ip_hash,
            'country': country_code,
            'country_name': country_name,
            'latitude': latitude,
            'longitude': longitude,
            'show_country': data.get('show_country', False),
            'deletion_token': uuid.uuid4().hex,
            'is_deleted': False
        }
        
        if data.get('website'):
            website = sanitize_text(data.get('website'))
            if website and not website.startswith(('http://', 'https://')):
                website = 'https://' + website
            entry['website'] = website

        entries.append(entry)
        save_entries(entries)
        
        app.logger.info(f"Added new entry (ID: {entry['id']}) from {name} ({country_name})")
        
        # Return the public-safe version of the entry, plus the token for the user
        public_entry = _filter_entry_for_public(entry)
        public_entry['deletion_token'] = entry['deletion_token']

        return jsonify({'success': True, 'message': 'Entry added!', 'entry': public_entry}), 201
        
    except Exception as e:
        app.logger.error(f"Error adding entry: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Server error while adding entry'}), 500

@app.route('/entries/<int:entry_id>/react', methods=['POST'])
def react_to_entry(entry_id):
    data = request.get_json()
    emoji = data.get('emoji')
    if not emoji or emoji not in ALLOWED_EMOJIS:
        return jsonify({'success': False, 'error': 'Invalid emoji'}), 400

    user_ip_hash = hashlib.sha256(_get_user_ip().encode('utf-8')).hexdigest()
    
    entries = load_entries()
    entry = next((e for e in entries if e.get('id') == entry_id), None)
    if not entry:
        return jsonify({'success': False, 'error': 'Entry not found'}), 404

    entry.setdefault('reactions', {})
    reactions = entry['reactions']
    user_reaction = next((emoji_key for emoji_key in reactions if user_ip_hash in reactions[emoji_key].get('ips', [])), None)

    if user_reaction:
        if user_reaction == emoji:
            # Remove reaction
            reactions[emoji]['ips'] = [ip for ip in reactions[emoji]['ips'] if ip != user_ip_hash]
            reactions[emoji]['count'] -= 1
            if reactions[emoji]['count'] == 0:
                del reactions[emoji]  # Remove emoji if no reactions left
            message = 'Reaction removed'
        else:
            if emoji in reactions:
                reactions[emoji]['ips'].append(user_ip_hash)
                reactions[emoji]['count'] += 1
            else:
                reactions[emoji] = {'count': 1, 'ips': [user_ip_hash]}

            reactions[user_reaction]['ips'] = [ip for ip in reactions[user_reaction]['ips'] if ip != user_ip_hash]
            reactions[user_reaction]['count'] -= 1
            if reactions[user_reaction]['count'] == 0:
                del reactions[user_reaction]
            message = 'Reaction changed'
    else:
        # New reaction
        reactions.setdefault(emoji, {'count': 0, 'ips': []})
        reactions[emoji]['ips'].append(user_ip_hash)
        reactions[emoji]['count'] += 1
        message = 'Reaction added!'

    save_entries(entries)
    return jsonify({'success': True, 'message': 'Reaction added!'})

@app.route('/entries/<int:entry_id>/flag', methods=['POST'])
def flag_entry(entry_id):
    user_ip_hash = hashlib.sha256(_get_user_ip().encode('utf-8')).hexdigest()
    
    entries = load_entries()
    entry = next((e for e in entries if e.get('id') == entry_id), None)
    if not entry:
        return jsonify({'success': False, 'error': 'Entry not found'}), 404
        
    entry.setdefault('flagged_by_ips', [])
    if user_ip_hash in entry['flagged_by_ips']:
        return jsonify({'success': False, 'error': 'Already flagged'}), 409

    entry['flagged'] = True
    entry['flagged_by_ips'].append(user_ip_hash)
    
    save_entries(entries)
    app.logger.warning(f"Entry {entry_id} was flagged by user with IP hash ending in ...{user_ip_hash[-6:]}")
    return jsonify({'success': True, 'message': 'Entry has been flagged for review.'})

@app.route('/entries/<int:entry_id>/request-delete', methods=['POST'])
def request_delete_entry(entry_id):
    """Allows a user to delete their own post using a token."""
    data = request.get_json()
    token = data.get('deletion_token')
    if not token:
        return jsonify({'success': False, 'error': 'Deletion token required'}), 400

    entries = load_entries()
    entry_to_delete = next((e for e in entries if e.get('id') == entry_id), None)

    if not entry_to_delete:
        return jsonify({'success': False, 'error': 'Entry not found'}), 404

    if entry_to_delete.get('deletion_token') != token:
        app.logger.warning(f"Failed delete attempt on entry {entry_id} with wrong token.")
        return jsonify({'success': False, 'error': 'Invalid deletion token'}), 403

    # Move entry to deleted list instead of erasing it
    entry_to_delete['is_deleted'] = True
    entry_to_delete['deleted_at'] = datetime.now().isoformat()
    
    deleted_entries = load_deleted_entries()
    deleted_entries.append(entry_to_delete)
    
    # Remove from main list
    active_entries = [e for e in entries if e.get('id') != entry_id]
    
    try:
        save_entries(active_entries)
        save_deleted_entries(deleted_entries)
        app.logger.info(f"User deleted entry {entry_id} and moved to history.")
        return jsonify({'success': True, 'message': 'Entry deleted successfully.'})
    except Exception as e:
        app.logger.error(f"Error during user deletion of entry {entry_id}: {e}")
        return jsonify({'success': False, 'error': 'Server error during deletion'}), 500

def is_admin():
    """Helper to check for admin key."""
    admin_key = request.headers.get('X-Admin-Key')
    expected_key = os.environ.get('ADMIN_KEY')
    return expected_key and admin_key == expected_key

@app.before_request
def check_admin_auth():
    """Protects all /admin/* routes."""
    if request.path.startswith('/admin/') and request.path != '/admin' and not is_admin():
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

@app.route('/admin/all-entries', methods=['GET'])
def get_all_entries_admin():
    entries = load_entries()
    entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    return jsonify({'success': True, 'entries': entries})

@app.route('/admin/deleted-entries', methods=['GET'])
def get_deleted_entries_admin():
    deleted = load_deleted_entries()
    deleted.sort(key=lambda x: x.get('deleted_at', ''), reverse=True)
    return jsonify({'success': True, 'entries': deleted})

# Admin Delete is a hard delete, user delete is a soft delete
@app.route('/entries/<int:entry_id>', methods=['DELETE'])
def admin_delete_entry(entry_id):
    if not is_admin():
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    
    entries = load_entries()
    original_count = len(entries)
    entries = [e for e in entries if e.get('id') != entry_id]
    
    if len(entries) == original_count:
        return jsonify({'success': False, 'error': f'Entry {entry_id} not found'}), 404
        
    save_entries(entries)
    app.logger.info(f"ADMIN deleted entry {entry_id}")
    return jsonify({'success': True, 'message': 'Entry permanently deleted.'})

@app.route('/entries/<int:entry_id>/reply', methods=['POST'])
def add_reply(entry_id):
    if not is_admin(): return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    """Add a reply to a specific guestbook entry"""
    try:
        admin_key = request.headers.get('X-Admin-Key')
        expected_key = os.environ.get('ADMIN_KEY', '')
        
        app.logger.info(f"--- DEBUG: Received Admin Key: '{admin_key}'")
        app.logger.info(f"--- DEBUG: Expected Admin Key from Vercel: '{expected_key}'")
        app.logger.info(f"--- DEBUG: Do they match? {admin_key == expected_key}")
        # Admin key check
        if not expected_key or admin_key != expected_key:
            app.logger.warning(f"Unauthorized reply attempt for entry {entry_id}")
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401

        data = request.get_json()
        reply_message_raw = data.get('message', '')
        if not reply_message_raw: return jsonify({'success': False, 'error': 'Reply cannot be empty'}), 400
        reply_message_html = sanitize_html(md.render(reply_message_raw))

        entries = load_entries()
        # Find the entry to reply to
        target_entry = next((e for e in entries if e.get('id') == entry_id), None)
        if not target_entry:
            return jsonify({'success': False, 'error': f'Entry {entry_id} not found'}), 404
        
        # Ensure the 'replies' key exists (for backward compatibility)
        target_entry.setdefault('replies', [])
        new_reply = {
            'id': max([r.get('id', 0) for r in target_entry['replies']], default=0) + 1,
            'author': 'Admin',
            'message': reply_message_raw,
            'message_html': reply_message_html,
            'timestamp': datetime.now().isoformat(),
            'date_display': datetime.now().strftime('%B %d, %Y at %I:%M %p')
        }
        
        target_entry['replies'].append(new_reply)
        save_entries(entries)
        return jsonify({
            'success': True, 
            'message': 'Reply added successfully',
            'reply': new_reply
        }), 201

    except Exception as e:
        app.logger.error(f"Error adding reply to entry {entry_id}: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to add reply'}), 500

@app.route('/entries/<int:entry_id>/replies/<int:reply_id>', methods=['DELETE'])
def delete_reply(entry_id, reply_id):
    """Delete a specific reply from an entry (admin function)"""
    try:
        # Admin key check
        admin_key = request.headers.get('X-Admin-Key')
        expected_key = os.environ.get('ADMIN_KEY', '')
        if not expected_key or admin_key != expected_key:
            app.logger.warning(f"Unauthorized reply delete attempt for entry {entry_id}, reply {reply_id}")
            return jsonify({'success': False, 'error': 'Unauthorized'}), 401

        entries = load_entries()

        # Find the parent entry
        target_entry = next((e for e in entries if e.get('id') == entry_id), None)
        
        if not target_entry:
            return jsonify({'success': False, 'error': f'Entry {entry_id} not found'}), 404

        # Find the reply and filter it out
        original_reply_count = len(target_entry.get('replies', []))
        # Create a new list of replies excluding the one to be deleted
        target_entry['replies'] = [r for r in target_entry.get('replies', []) if r.get('id') != reply_id]
        
        if len(target_entry['replies']) == original_reply_count:
            return jsonify({'success': False, 'error': f'Reply {reply_id} not found in entry {entry_id}'}), 404
        
        # Save the updated entries list
        save_entries(entries)
        
        app.logger.info(f"Deleted reply {reply_id} from entry {entry_id}")
        return jsonify({
            'success': True, 
            'message': 'Reply deleted successfully'
        })

    except Exception as e:
        app.logger.error(f"Error deleting reply {reply_id} from entry {entry_id}: {str(e)}")
        return jsonify({'success': False, 'error': 'Failed to delete reply'}), 500

@app.route('/entries/<int:entry_id>', methods=['DELETE'])
def delete_entry(entry_id):
    """Delete an entry (admin function)"""
    try:
        # Simple admin key check
        admin_key = request.headers.get('X-Admin-Key')
        expected_key = os.environ.get('ADMIN_KEY', '')
        
        if not expected_key or admin_key != expected_key: # <-- MODIFIED: Check if expected_key is set
            app.logger.warning(f"Unauthorized delete attempt for entry {entry_id}")
            return jsonify({
                'success': False,
                'error': 'Unauthorized - invalid admin key'
            }), 401
        
        entries = load_entries()
        original_count = len(entries)
        entries = [e for e in entries if e.get('id') != entry_id]
        
        if len(entries) == original_count:
            return jsonify({
                'success': False,
                'error': f'Entry {entry_id} not found'
            }), 404
        
        save_entries(entries)
        
        app.logger.info(f"Deleted guestbook entry {entry_id}")
        return jsonify({
            'success': True,
            'message': f'Entry {entry_id} deleted successfully'
        })
        
    except Exception as e:
        app.logger.error(f"Error deleting entry {entry_id}: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to delete entry'
        }), 500

@app.route('/admin', methods=['GET'])
def admin_panel():
    """Serve the custom admin panel"""
    try:
        return app.send_static_file('admin.html')
    except Exception as e:
        return jsonify({
            'error': 'Admin panel not found. Please ensure admin.html is in the static folder.',
            'details': str(e)
        }), 404

@app.route('/admin/export', methods=['GET'])
def export_entries():
    file_format = request.args.get('format', 'json').lower()
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    compress = request.args.get('compress', 'false').lower() == 'true'

    entries = load_entries()

    if start_date and end_date:
        try:
            start = datetime.fromisoformat(start_date)
            end = datetime.fromisoformat(end_date)
            entries = [e for e in entries if start <= datetime.fromisoformat(e['timestamp']) <= end]
        except ValueError:
            return jsonify({'success': False, 'error': 'Invalid date format.  Use YYYY-MM-DD.'}), 400

    if file_format == 'csv':
        output = io.StringIO()
        # Define CSV fields, including new ones
        fieldnames = ['id', 'name', 'message', 'timestamp', 'website', 'country_name', 'ip_hash', 'flagged']
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(entries)
        content = output.getvalue()
        mimetype = "text/csv"
        filename = f"guestbook_export_{datetime.now().strftime('%Y%m%d')}.csv"
    else:
        content = json.dumps(entries, indent=2, ensure_ascii=False)
        mimetype = "application/json"
        filename = f"guestbook_export_{datetime.now().strftime('%Y%m%d')}.json"

    if compress:
        output = io.BytesIO()
        with gzip.GzipFile(fileobj=output, mode='wb') as gz:
            gz.write(content.encode('utf-8'))
        content = output.getvalue()
        mimetype = "application/gzip"
        filename += ".gz"
    
    return Response(
        content,
        mimetype=mimetype,
        headers={"Content-disposition": f"attachment; filename={filename}"}
    )

@app.route('/admin/import', methods=['POST'])
def import_entries():
    if not is_admin():
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401

    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400

    try:
        content = file.read().decode('utf-8')
        new_entries = json.loads(content)
        
        if not isinstance(new_entries, list):
            return jsonify({'success': False, 'error': 'Invalid JSON format: must be a list of objects.'}), 400

        imported_count = 0
        skipped_count = 0
        errors = []
        valid_entries = []

        # Backup existing entries
        existing_entries = load_entries()  # Load existing data
        backup_filename = "guestbook_backup_" + datetime.now().strftime("%Y%m%d_%H%M%S") + ".json"
        with open(backup_filename, 'w', encoding='utf-8') as backup_file:
            json.dump(existing_entries, backup_file, indent=2, ensure_ascii=False)

        for i, entry in enumerate(new_entries):
            is_valid, error_message = validate_entry(entry)
            if not is_valid:
                skipped_count += 1
                errors.append(f"Entry {i + 1}: {error_message}")
                continue

            # Sanitize data
            entry['name'] = sanitize_text(entry['name'])
            entry['message'] = entry.get('message', '')  # Handle missing 'message'
            entry['message_html'] = sanitize_html(md.render(entry['message']))

            valid_entries.append(entry) # Append the validated entry, not the original

            imported_count += 1

        if imported_count > 0:
            save_entries(valid_entries) # Overwrite with validated entries only
            app.logger.info(f"Admin imported {imported_count} entries, skipped {skipped_count} due to errors.")
            result = {'success': True, 'message': f'Successfully imported {imported_count} entries, skipped {skipped_count} entries due to errors.'}
        else:
             result = {'success': False, 'error': f'No entries imported, all entries had errors.'}

        if errors:
            result['errors'] = errors # Add errors to the response

        return jsonify(result)

    except json.JSONDecodeError as e:
        return jsonify({'success': False, 'error': f'Invalid JSON: {e}'}), 400
    except Exception as e:
        app.logger.error(f"Import failed: {e}")
        return jsonify({'success': False, 'error': f'Import failed: {e}'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    entries_count = 0
    storage_status = "KV not configured"
    status = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'storage': {
            'sqlite': 'unavailable',
            'kv': 'not configured',
            'local': 'available'
        }
    }
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM entries")
            entries_count = cursor.fetchone()[0]
            status['storage']['sqlite'] = 'available'
            status['entries_count'] = entries_count
    except Exception as e:
        status['storage']['sqlite'] = f'error: {str(e)}'
        status['status'] = 'degraded'
    if kv_available:
        status['storage']['kv'] = 'available'
        try:
            kv_get('test')
        except Exception as e:
            status['storage']['kv'] = f'error: {str(e)}'
            if status['storage']['sqlite'] != 'available':
                status['status'] = 'unhealthy'
    return jsonify(status)

@app.route('/api/_vercel/speed-insights', methods=['GET'])
def vercel_speed_insights():
    return jsonify({'status': 'ok'}), 200

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    if request.path.startswith('/api/') or request.path.startswith('/entries'):
        return jsonify({
            'success': False,
            'error': 'Endpoint not found'
        }), 404
    return error, 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    app.logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500
