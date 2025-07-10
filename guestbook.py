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
import tempfile
import socket
import struct
import ipaddress
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.WARNING)

# Use a temporary directory for the cache file if possible
try:
    cache_file = os.path.join(tempfile.gettempdir(), 'api_cache')
    # Install a GLOBAL cache for requests. This will be used by the ipinfo library.
    requests_cache.install_cache(cache_file, backend='sqlite', expire_after=86400) # Cache for 1 day
except Exception as e:
    logging.warning(f"Failed to setup requests cache: {e}")

# Create a separate session that BYPASSES the global cache
no_cache_session = requests.Session()

md = MarkdownIt()

IPINFO_TOKEN = os.environ.get('IPINFO_TOKEN')
ipinfo_handler = ipinfo.getHandler(IPINFO_TOKEN) if IPINFO_TOKEN else None

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

CORS(
    app,
    origins=["https://alatheary0p.neocities.org", "https://ry0p.lovestoblog.com"],
    methods=["GET", "POST", "DELETE", "OPTIONS", "PUT"],
    allow_headers=["Content-Type", "X-Admin-Key", "X-Deletion-Token"]
)

# Vercel KV HTTP REST API setup
KV_REST_API_URL = os.environ.get('KV_REST_API_URL')
KV_REST_API_TOKEN = os.environ.get('KV_REST_API_TOKEN')
kv_available = bool(KV_REST_API_URL and KV_REST_API_TOKEN)

if kv_available:
    app.logger.info("Vercel KV REST API credentials found and configured")
else:
    app.logger.warning("Vercel KV REST API credentials not found")

DATA_VERSION = 'v2'
GUESTBOOK_KV_KEY = f'guestbook_entries_{DATA_VERSION}'
DELETED_GUESTBOOK_KV_KEY = f'guestbook_deleted_entries_{DATA_VERSION}'
LOCAL_GUESTBOOK_FILE = os.path.join(os.path.dirname(__file__), 'guestbook_local.json')
LOCAL_DELETED_FILE = os.path.join(os.path.dirname(__file__), 'guestbook_deleted_local.json')

def kv_get(key):
    if not kv_available: return None
    try:
        headers = {
            'Authorization': f'Bearer {KV_REST_API_TOKEN}',
            # These headers tell Vercel's cache and any other proxies to get fresh data
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        }
        # Use the non-cached session for freshness
        response = no_cache_session.get(f"{KV_REST_API_URL}/get/{key}", headers=headers, timeout=10)
        if response.status_code == 200: return response.json().get('result')
        return None
    except Exception as e:
        app.logger.error(f"KV GET error: {e}")
        return None

def kv_set(key, value):
    if not kv_available: return False
    try:
        data_to_set = json.dumps(value, ensure_ascii=False)
        # Use the non-cached session for freshness
        response = no_cache_session.post(f"{KV_REST_API_URL}/set/{key}",
            headers={'Authorization': f'Bearer {KV_REST_API_TOKEN}'},
            data=data_to_set,
            timeout=10
        )
        return response.status_code == 200
    except Exception as e:
        app.logger.error(f"KV SET error: {e}")
        return False

def _load_data_from_source(kv_key, local_file):
    """Generic data loader for KV or local file."""
    data_str = None
    if kv_available:
        data_str = kv_get(kv_key)
    else:
        if os.path.exists(local_file):
            with open(local_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []

    if data_str:
        try:
            return json.loads(data_str) if isinstance(data_str, str) else data_str
        except json.JSONDecodeError:
            return []
    return []

def _save_data_to_source(data, kv_key, local_file):
    """Generic data saver for KV or local file."""
    if kv_available:
        if not kv_set(kv_key, data):
             raise IOError(f"Failed to save data to KV key {kv_key}")
    else:
        # This part will fail on Vercel's read-only filesystem, which is expected.
        with open(local_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

def load_entries():
    return _load_data_from_source(GUESTBOOK_KV_KEY, LOCAL_GUESTBOOK_FILE)

def save_entries(entries):
    _save_data_to_source(entries, GUESTBOOK_KV_KEY, LOCAL_GUESTBOOK_FILE)

def load_deleted_entries():
    return _load_data_from_source(DELETED_GUESTBOOK_KV_KEY, LOCAL_DELETED_FILE)

def save_deleted_entries(entries):
    _save_data_to_source(entries, DELETED_GUESTBOOK_KV_KEY, LOCAL_DELETED_FILE)

def sanitize_html(html_content):
    """Sanitizes HTML, allowing only specific tags and attributes."""
    def set_link_attrs(attrs, new=False):
        attrs[(None, 'target')] = '_blank'
        attrs[(None, 'rel')] = 'noopener noreferrer'
        return attrs

    allowed_tags = {'strong', 'b', 'em', 'i', 'a', 'p', 'br'}
    allowed_attrs = {'a': ['href', 'title', 'target', 'rel']}

    interim_clean = bleach.clean(html_content, tags=allowed_tags, strip=True)
    linked_content = bleach.linkify(interim_clean, callbacks=[set_link_attrs])

    clean_html = bleach.clean(
        linked_content,
        tags=allowed_tags,
        attributes=allowed_attrs,
        strip=True
    )
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

def _get_user_ip():
    """
    Enhanced IP detection with multiple fallback methods
    Uses the confidence-based approach for best results
    """
    result = _get_user_ip_with_confidence()
    return result['ip']

def _is_valid_ip(ip):
    """Validate if a string is a valid IP address (IPv4 or IPv6)"""
    if not ip:
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def _is_private_ip(ip):
    """Check if an IP address is private/local"""
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
    except ValueError:
        return False

def _get_user_ip_comprehensive():
    """
    Comprehensive IP detection with multiple fallback methods
    Returns a dict with the IP and the method used to find it
    """
    # Extended header list with more proxy/CDN headers
    headers_to_check = [
        'CF-Connecting-IP',        # Cloudflare
        'X-Vercel-Forwarded-For',  # Vercel
        'True-Client-IP',          # Akamai, Cloudflare
        'X-Forwarded-For',         # Standard proxy header
        'X-Real-IP',               # Nginx proxy
        'X-Client-IP',             # Apache mod_remoteip
        'X-Cluster-Client-IP',     # Cluster load balancer
        'X-Forwarded',             # RFC 7239
        'Forwarded-For',           # RFC 7239
        'Forwarded',               # RFC 7239
        'Via',                     # HTTP via header
        'X-Originating-IP',        # Microsoft Exchange
        'X-Remote-IP',             # Custom header
        'X-Remote-Addr',           # Custom header
        'X-ProxyUser-Ip',          # Custom header
        'X-Original-IP',           # Custom header
        'X-Azure-ClientIP',        # Azure
        'X-Azure-SocketIP',        # Azure
        'WL-Proxy-Client-IP',      # WebLogic
        'Proxy-Client-IP',         # Apache
        'HTTP_X_FORWARDED_FOR',    # Sometimes appears this way
        'HTTP_CLIENT_IP',          # Sometimes appears this way
    ]

    for header in headers_to_check:
        if header in request.headers:
            header_value = request.headers.get(header)
            # Handle comma-separated IPs (X-Forwarded-For can have multiple IPs)
            if ',' in header_value:
                ips = [ip.strip() for ip in header_value.split(',')]
                # Find the first public IP
                for ip in ips:
                    if _is_valid_ip(ip) and not _is_private_ip(ip):
                        app.logger.info(f"Public IP {ip} found in header {header}")
                        return {'ip': ip, 'method': f'header_{header}', 'all_ips': ips}
                # If no public IP found, use the first valid IP
                for ip in ips:
                    if _is_valid_ip(ip):
                        app.logger.info(f"Private IP {ip} found in header {header}")
                        return {'ip': ip, 'method': f'header_{header}_private', 'all_ips': ips}
            else:
                ip = header_value.strip()
                if _is_valid_ip(ip):
                    method_suffix = '_private' if _is_private_ip(ip) else '_public'
                    app.logger.info(f"IP {ip} found in header {header}")
                    return {'ip': ip, 'method': f'header_{header}{method_suffix}'}

    # Parse Forwarded header (RFC 7239)
    forwarded = request.headers.get('Forwarded', '')
    if forwarded:
        ip = _extract_ip_from_forwarded_header(forwarded)
        if ip:
            method_suffix = '_private' if _is_private_ip(ip) else '_public'
            app.logger.info(f"IP {ip} parsed from Forwarded header")
            return {'ip': ip, 'method': f'forwarded_header{method_suffix}'}

    # Flask's request.remote_addr
    if hasattr(request, 'remote_addr') and request.remote_addr:
        ip = request.remote_addr
        if _is_valid_ip(ip):
            method_suffix = '_private' if _is_private_ip(ip) else '_public'
            app.logger.info(f"IP {ip} from request.remote_addr")
            return {'ip': ip, 'method': f'flask_remote_addr{method_suffix}'}

    # WSGI environ fallback
    environ = getattr(request, 'environ', {})
    wsgi_headers = [
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_REAL_IP',
        'HTTP_CF_CONNECTING_IP',
        'REMOTE_ADDR',
        'HTTP_CLIENT_IP',
        'HTTP_X_CLUSTER_CLIENT_IP'
    ]
    
    for wsgi_header in wsgi_headers:
        if wsgi_header in environ:
            ip = environ[wsgi_header]
            if ',' in ip:
                ip = ip.split(',')[0].strip()
            if _is_valid_ip(ip):
                method_suffix = '_private' if _is_private_ip(ip) else '_public'
                app.logger.info(f"IP {ip} found in WSGI environ {wsgi_header}")
                return {'ip': ip, 'method': f'wsgi_{wsgi_header}{method_suffix}'}

    # Fallback: Return localhost
    app.logger.warning("No valid IP found, falling back to localhost")
    return {'ip': '127.0.0.1', 'method': 'fallback_localhost'}

def _get_user_ip_with_confidence():
    """
    Get user IP with confidence scoring
    Returns the IP with the highest confidence score
    """
    confidence_scores = {
        'CF-Connecting-IP': 95,        # Cloudflare is very reliable
        'X-Vercel-Forwarded-For': 90,  # Vercel is reliable
        'True-Client-IP': 85,          # Akamai/Cloudflare
        'X-Real-IP': 80,               # Nginx proxy
        'X-Forwarded-For': 70,         # Standard but can be spoofed
        'X-Client-IP': 60,             # Less reliable
        'X-Remote-IP': 50,             # Custom header
        'Forwarded': 75,               # RFC standard
        'remote_addr': 40,             # Fallback
        'X-Azure-ClientIP': 85,        # Azure
        'X-Originating-IP': 65,        # Microsoft Exchange
    }
    
    candidates = []
    
    # Check headers with confidence scoring
    for header in confidence_scores:
        if header == 'remote_addr':
            if hasattr(request, 'remote_addr') and request.remote_addr:
                ip = request.remote_addr
                if _is_valid_ip(ip):
                    score = confidence_scores[header]
                    if not _is_private_ip(ip):
                        score += 20  # Bonus for public IP
                    candidates.append({
                        'ip': ip,
                        'score': score,
                        'source': 'flask_remote_addr'
                    })
        else:
            if header in request.headers:
                header_value = request.headers.get(header)
                if ',' in header_value:
                    # For comma-separated IPs, prefer the first public IP
                    ips = [ip.strip() for ip in header_value.split(',')]
                    for idx, ip in enumerate(ips):
                        if _is_valid_ip(ip):
                            score = confidence_scores[header]
                            if not _is_private_ip(ip):
                                score += 20  # Bonus for public IP
                            if idx == 0:
                                score += 10  # Bonus for first IP
                            candidates.append({
                                'ip': ip,
                                'score': score,
                                'source': f'header_{header}',
                                'position': idx
                            })
                else:
                    ip = header_value.strip()
                    if _is_valid_ip(ip):
                        score = confidence_scores[header]
                        if not _is_private_ip(ip):
                            score += 20  # Bonus for public IP
                        candidates.append({
                            'ip': ip,
                            'score': score,
                            'source': f'header_{header}'
                        })
    
    if candidates:
        # Sort by score (highest first)
        candidates.sort(key=lambda x: x['score'], reverse=True)
        best_candidate = candidates[0]
        app.logger.info(f"Selected IP {best_candidate['ip']} with confidence score {best_candidate['score']} from {best_candidate['source']}")
        return best_candidate
    
    # Final fallback
    app.logger.warning("No valid IP candidates found, using localhost")
    return {'ip': '127.0.0.1', 'score': 0, 'source': 'fallback'}

def _extract_ip_from_forwarded_header(forwarded_header):
    """
    Extract IP from RFC 7239 Forwarded header
    Handles formats like: for=192.0.2.60;proto=http;by=203.0.113.43
    """
    if not forwarded_header:
        return None
    
    # Match for= parameter
    for_pattern = r'for=([^;,\s]+)'
    match = re.search(for_pattern, forwarded_header, re.IGNORECASE)
    
    if match:
        ip_part = match.group(1).strip('"')
        
        # Handle IPv6 in brackets: [2001:db8::1]:8080
        if ip_part.startswith('[') and ']:' in ip_part:
            ip = ip_part.split(']:')[0][1:]
        # Handle IPv4 with port: 192.168.1.1:8080
        elif ':' in ip_part and not ip_part.startswith('['):
            ip = ip_part.split(':')[0]
        else:
            ip = ip_part
        
        if _is_valid_ip(ip):
            return ip
    
    return None

def _get_all_possible_ips():
    """
    Get all possible IP addresses from all sources for debugging
    Returns a list of dictionaries with IP and source information
    """
    all_ips = []
    # Check all headers that might contain IP information
    for header_name, header_value in request.headers.items():
        if any(keyword in header_name.lower() for keyword in ['ip', 'forward', 'client', 'real', 'origin']):
            if ',' in header_value:
                ips = [ip.strip() for ip in header_value.split(',')]
                for idx, ip in enumerate(ips):
                    if _is_valid_ip(ip):
                        all_ips.append({
                            'ip': ip,
                            'source': f'header_{header_name}',
                            'position': idx,
                            'is_private': _is_private_ip(ip),
                            'raw_value': header_value
                        })
            else:
                ip = header_value.strip()
                if _is_valid_ip(ip):
                    all_ips.append({
                        'ip': ip,
                        'source': f'header_{header_name}',
                        'position': 0,
                        'is_private': _is_private_ip(ip),
                        'raw_value': header_value
                    })
    # Check WSGI environ
    environ = getattr(request, 'environ', {})
    for key, value in environ.items():
        if any(keyword in key.lower() for keyword in ['ip', 'addr', 'forward', 'client', 'real']):
            if isinstance(value, str) and value:
                ip = value.split(',')[0].strip()
                if _is_valid_ip(ip):
                    all_ips.append({
                        'ip': ip,
                        'source': f'wsgi_{key}',
                        'position': 0,
                        'is_private': _is_private_ip(ip),
                        'raw_value': value
                    })

    if hasattr(request, 'remote_addr') and request.remote_addr:
        ip = request.remote_addr
        if _is_valid_ip(ip):
            all_ips.append({
                'ip': ip,
                'source': 'flask_remote_addr',
                'position': 0,
                'is_private': _is_private_ip(ip),
                'raw_value': ip
            })

    return all_ips

@app.route('/', methods=['GET'])
def home():
    """Render a simple home page for API status"""
    return "<h1>Guestbook API</h1><p>Status: Healthy</p>"

@app.route('/entries', methods=['GET'])
def get_entries():
    try:
        entries = load_entries()
        active_entries = [e for e in entries if not e.get('is_deleted')]
        active_entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        public_entries = [_filter_entry_for_public(e) for e in active_entries]
        return jsonify({'success': True, 'entries': public_entries, 'count': len(public_entries)})
    except Exception as e:
        app.logger.error(f"Error retrieving entries: {e}")
        return jsonify({'success': False, 'error': 'Failed to retrieve entries'}), 500

@app.route('/entries', methods=['POST'])
def add_entry():
    try:
        data = request.get_json()
        if not data: return jsonify({'success': False, 'error': 'No data provided'}), 400

        name = sanitize_text(data.get('name'))
        message_raw = data.get('message', '')

        if not name or not message_raw: return jsonify({'success': False, 'error': 'Name and message are required'}), 400
        if len(name) < 2 or len(message_raw) < 5: return jsonify({'success': False, 'error': 'Name/message too short'}), 400

        message_html = sanitize_html(md.render(message_raw))
        
        entries = load_entries()
        
        entry_id = uuid.uuid4().hex
        user_ip = _get_user_ip()
        ip_hash = hashlib.sha256(user_ip.encode('utf-8')).hexdigest()
        country_code = None
        country_name = "Unknown"
        if ipinfo_handler:
            try:
                details = ipinfo_handler.getDetails(user_ip)
                country_code = details.country
                country_name = details.country_name
            except Exception as e:
                app.logger.warning(f"Could not get geo-info for IP: {e}")

        entry = {
            'id': entry_id, 'name': name, 'message': message_raw,
            'message_html': message_html, 'timestamp': datetime.now().isoformat(),
            'date_display': datetime.now().strftime('%B %d, %Y at %I:%M %p'),
            'replies': [], 'reactions': {}, 'flagged': False,
            'flagged_by_ips': [], 'ip_hash': ip_hash, 'country': country_code,
            'country_name': country_name, 'show_country': data.get('show_country', False),
            'deletion_token': uuid.uuid4().hex, 'is_deleted': False
        }
        
        if data.get('website'):
            website = bleach.clean(data.get('website'), tags=[], strip=True).strip()
            if website and not re.match(r'^[a-zA-Z]+://', website):
                website = 'https://' + website
            entry['website'] = website

        entries.insert(0, entry)
        save_entries(entries)
        
        app.logger.info(f"Added new entry (ID: {entry['id']}) from {name} ({country_name})")
        
        public_entry = _filter_entry_for_public(entry)
        public_entry['deletion_token'] = entry['deletion_token']

        return jsonify({'success': True, 'message': 'Entry added!', 'entry': public_entry}), 201
        
    except Exception as e:
        app.logger.error(f"Error adding entry: {e}", exc_info=True)
        return jsonify({'success': False, 'error': 'Server error while adding entry'}), 500

@app.route('/entries/<string:entry_id>/react', methods=['POST'])
def react_to_entry(entry_id):
    data = request.get_json()
    emoji = data.get('emoji')
    if not emoji or len(emoji) > 2:
        return jsonify({'success': False, 'error': 'Invalid emoji'}), 400

    user_ip_hash = hashlib.sha256(_get_user_ip().encode('utf-8')).hexdigest()
    
    entries = load_entries()
    entry = next((e for e in entries if e.get('id') == entry_id), None)
    if not entry:
        return jsonify({'success': False, 'error': 'Entry not found'}), 404

    entry.setdefault('reactions', {})
    entry['reactions'].setdefault(emoji, {'count': 0, 'ips': []})

    if user_ip_hash in entry['reactions'][emoji]['ips']:
        return jsonify({'success': False, 'error': 'Already reacted'}), 409 # Conflict

    entry['reactions'][emoji]['ips'].append(user_ip_hash)
    entry['reactions'][emoji]['count'] += 1
    
    save_entries(entries)
    return jsonify({'success': True, 'message': 'Reaction added!'})

@app.route('/entries/<string:entry_id>/flag', methods=['POST'])
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

@app.route('/entries/<string:entry_id>/request-delete', methods=['POST'])
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
    updated_active_entries = [e for e in entries if e.get('id') != entry_id]
    deleted_entries = load_deleted_entries()
    deleted_entries.append(entry_to_delete)
    
    try:
        save_entries(updated_active_entries)
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

@app.route('/admin/entries/<string:entry_id>/reply', methods=['POST'])
def add_reply(entry_id):
    """Add a reply to a specific guestbook entry"""
    try:
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

@app.route('/admin/entries/<string:entry_id>/replies/<int:reply_id>', methods=['DELETE'])
def delete_reply(entry_id, reply_id):
    """Delete a specific reply from an entry (admin function)"""
    try:
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

@app.route('/admin/entries/<string:entry_id>', methods=['DELETE'])
def admin_delete_entry(entry_id):
    """
    Admin delete with two stages:
    1. First call: Soft-deletes an active entry (moves to deleted items).
    2. Second call: Hard-deletes a soft-deleted entry (purges it permanently).
    """
    try:
        active_entries = load_entries()
        deleted_entries = load_deleted_entries()

        entry_to_soft_delete = next((e for e in active_entries if e.get('id') == entry_id), None)
        if entry_to_soft_delete:
            updated_active_entries = [e for e in active_entries if e.get('id') != entry_id]
            entry_to_soft_delete['is_deleted'] = True
            entry_to_soft_delete['deleted_at'] = datetime.now().isoformat()
            deleted_entries.append(entry_to_soft_delete)

            save_entries(updated_active_entries)
            save_deleted_entries(deleted_entries)

            app.logger.info(f"ADMIN soft-deleted guestbook entry {entry_id}")
            return jsonify({
                'success': True,
                'message': f'Entry {entry_id} moved to deleted items. To permanently delete, delete it again from the deleted items view.'
            })

        entry_to_hard_delete = next((e for e in deleted_entries if e.get('id') == entry_id), None)
        if entry_to_hard_delete:
            # It's a deleted entry, so we purge it permanently.
            updated_deleted_entries = [e for e in deleted_entries if e.get('id') != entry_id]
            save_deleted_entries(updated_deleted_entries)
            app.logger.info(f"ADMIN permanently deleted entry {entry_id}.")
            return jsonify({
                'success': True,
                'message': f'Entry {entry_id} has been permanently deleted.'
            })
        return jsonify({'success': False, 'error': f'Entry {entry_id} not found in active or deleted items.'}), 404
        
    except Exception as e:
        app.logger.error(f"Error during admin deletion of entry {entry_id}: {str(e)}")
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
    entries = load_entries()
    
    if file_format == 'csv':
        output = io.StringIO()
        # Define CSV fields, including new ones
        fieldnames = ['id', 'name', 'message', 'timestamp', 'website', 'country_name', 'ip_hash', 'flagged']
        writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
        
        writer.writeheader()
        writer.writerows(entries)
        
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename=guestbook_export_{datetime.now().strftime('%Y%m%d')}.csv"}
        )
    
    # Default to JSON
    return Response(
        json.dumps(entries, indent=2),
        mimetype="application/json",
        headers={"Content-disposition": f"attachment; filename=guestbook_export_{datetime.now().strftime('%Y%m%d')}.json"}
    )

@app.route('/admin/import', methods=['POST'])
def import_entries():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400

    try:
        # overwrite existing entries for simplicity.
        # A more complex strategy could merge entries.
        content = file.read().decode('utf-8')
        new_entries = json.loads(content)
        
        # Basic validation
        if not isinstance(new_entries, list):
            return jsonify({'success': False, 'error': 'Invalid JSON format: must be a list of objects.'}), 400
        
        # Re-process messages to ensure they have the correct HTML version
        for entry in new_entries:
            if 'message' in entry:
                entry['message_html'] = sanitize_html(md.render(entry['message']))
            else:
                entry['message_html'] = ''

        save_entries(new_entries)
        app.logger.info(f"Admin imported {len(new_entries)} entries, overwriting previous data.")
        return jsonify({'success': True, 'message': f'Successfully imported {len(new_entries)} entries.'})
    except Exception as e:
        app.logger.error(f"Import failed: {e}")
        return jsonify({'success': False, 'error': f'Import failed: {e}'}), 500

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    entries_count = 0
    storage_status = "KV not configured"
    if kv_available:
        storage_status = "Vercel KV REST API available"
        try:
            entries = load_entries()
            entries_count = len(entries)
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'entries_count': entries_count,
                'storage': storage_status
            })
        except Exception as e:
            return jsonify({
                'status': 'unhealthy',
                'timestamp': datetime.now().isoformat(),
                'error': str(e),
                'storage': storage_status
            }), 500
    else:
        try:
            entries = load_entries()
            entries_count = len(entries)
            storage_status = 'Using local file fallback'
            status = 'degraded' # Degraded because primary storage (KV) is not used
        except Exception as e:
            app.logger.error(f"Health check - error during local file operation: {e}")
            storage_status = f'Local file fallback error: {str(e)}'
            status = 'unhealthy'
        return jsonify({
            'status': status,
            'timestamp': datetime.now().isoformat(),
            'entries_count': entries_count,
            'storage': storage_status
        })

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

@app.route('/debug/ip-info', methods=['GET'])
def debug_ip_info():
    """Debug endpoint to see all IP detection results (admin only)"""
    if not is_admin():
        return jsonify({'error': 'Unauthorized'}), 401
    
    try:
        # Get results from all methods
        comprehensive_result = _get_user_ip_comprehensive()
        all_ips = _get_all_possible_ips()
        confidence_result = _get_user_ip_with_confidence()
        
        return jsonify({
            'current_method': {
                'ip': _get_user_ip(),
                'method': 'enhanced_get_user_ip'
            },
            'comprehensive_method': comprehensive_result,
            'confidence_method': confidence_result,
            'all_detected_ips': all_ips,
            'request_headers': dict(request.headers),
            'wsgi_environ_ip_keys': {
                k: v for k, v in getattr(request, 'environ', {}).items() 
                if any(keyword in k.lower() for keyword in ['ip', 'addr', 'forward', 'client', 'real'])
            }
        })
    except Exception as e:
        app.logger.error(f"Error in IP debug endpoint: {e}")
        return jsonify({'error': str(e)}), 500
