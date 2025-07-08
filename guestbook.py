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

# Configure logging to reduce noise in production
logging.basicConfig(level=logging.INFO)
logging.getLogger("urllib3").setLevel(logging.WARNING)

requests_cache.install_cache('api_cache', expire_after=86400)
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

GUESTBOOK_KV_KEY = 'guestbook_entries' # Key to store entries in KV
DELETED_GUESTBOOK_KV_KEY = 'guestbook_deleted_entries'
LOCAL_GUESTBOOK_FILE = os.path.join(os.path.dirname(__file__), 'guestbook_local.json')
LOCAL_DELETED_FILE = os.path.join(os.path.dirname(__file__), 'guestbook_deleted_local.json')

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
    """Get user IP, respecting Vercel's headers."""
    if 'X-Forwarded-For' in request.headers:
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr

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
        if ipinfo_handler:
            try:
                details = ipinfo_handler.getDetails(user_ip)
                country_code = details.country
                country_name = details.country_name
            except Exception as e:
                app.logger.warning(f"Could not get geo-info for IP: {e}")

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
            if 'message' in entry and 'message_html' not in entry:
                entry['message_html'] = sanitize_html(md.render(entry['message']))

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
