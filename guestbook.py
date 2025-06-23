from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import requests
import json
import os
import logging
from datetime import datetime
import re

# Configure logging to reduce noise in production
logging.getLogger("urllib3").setLevel(logging.WARNING)
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
# Configure logging for better debugging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "dev-secret-key")

CORS(
    app,
    origins=["https://alatheary0p.neocities.org", "https://ry0p.lovestoblog.com"],
    methods=["GET", "POST", "DELETE", "OPTIONS"],  # Explicitly allow necessary methods
    allow_headers=["Content-Type", "X-Admin-Key"] # Explicitly allow custom header
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
LOCAL_GUESTBOOK_FILE = os.path.join(os.path.dirname(__file__), 'guestbook_local.json')

def kv_get(key):
    """Get value from Vercel KV using REST API"""
    if not kv_available:
        return None
    try:
        url = f"{KV_REST_API_URL}/get/{key}"
        headers = {
            'Authorization': f'Bearer {KV_REST_API_TOKEN}'
        }
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get('result')
        elif response.status_code == 404:
            # Key doesn't exist yet
            return None
        else:
            app.logger.error(f"KV GET failed: {response.status_code} - {response.text}")
            return None
    except Exception as e:
        app.logger.error(f"KV GET error: {e}")
        return None

def kv_set(key, value):
    """Set value in Vercel KV using REST API"""
    if not kv_available:
        return False
    try:
        url = f"{KV_REST_API_URL}/set/{key}"
        headers = {
            'Authorization': f'Bearer {KV_REST_API_TOKEN}',
            'Content-Type': 'application/json'
        }
        # Send the value as JSON
        payload = json.dumps(value)
        response = requests.post(url, headers=headers, data=payload, timeout=10)
        if response.status_code == 200:
            app.logger.info(f"Successfully saved to KV key: {key}")
            return True
        else:
            app.logger.error(f"KV SET failed: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        app.logger.error(f"KV SET error: {e}")
        return False

def load_entries():
    """Load guestbook entries from KV or file"""
    if kv_available:
        try:
            data = kv_get(GUESTBOOK_KV_KEY)
            if data:
                # Parse JSON if it's a string
                if isinstance(data, str):
                    entries = json.loads(data)
                else:
                    entries = data
                app.logger.info(f"Loaded {len(entries)} entries from Vercel KV")
                return entries
            else:
                app.logger.info("No entries found in KV, starting with empty list")
                return []
        except Exception as e:
            app.logger.error(f"Failed to load entries from KV: {e}")
            return [] # Or raise an error to be caught by the endpoint
    else:
        app.logger.warning("KV client not available. Using local file ({LOCAL_GUESTBOOK_FILE}) for entries - for local dev only.")
        if os.path.exists(LOCAL_GUESTBOOK_FILE):
            try:
                with open(LOCAL_GUESTBOOK_FILE, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                app.logger.error(f"Error reading local fallback file {LOCAL_GUESTBOOK_FILE}: {e}")
                return []
        else:
            app.logger.info(f"Local fallback file {LOCAL_GUESTBOOK_FILE} not found. Returning empty list.")
        return []

def save_entries(entries):
    """Save guestbook entries to file"""
    if kv_available:
        success = kv_set(GUESTBOOK_KV_KEY, entries)
        if not success:
            app.logger.error("Failed to save entries to KV")
            raise Exception("KV save failed")
        else:
            app.logger.info(f"Successfully saved {len(entries)} entries to KV")
    else:
        app.logger.warning("KV not available, saving to local file")
        try:
            with open(LOCAL_GUESTBOOK_FILE, 'w', encoding='utf-8') as f:
                json.dump(entries, f, indent=2, ensure_ascii=False)
            app.logger.info(f"Saved {len(entries)} entries to local file")
        except Exception as e:
            app.logger.error(f"Failed to save entries locally to {LOCAL_GUESTBOOK_FILE}: {e}")
            raise Exception("Local file save failed")

def sanitize_input(text):
    """Basic input sanitization"""
    if not text:
        return ""
    # Remove HTML tags and limit length
    text = re.sub(r'<[^>]*>', '', str(text))
    return text.strip()[:500]  # Limit to 500 characters

def validate_email(email):
    """Basic email validation"""
    if not email:
        return True  # Email is optional
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

@app.route('/', methods=['GET'])
def home():
    """Render the home page with API status"""
    # Data to be passed to the template
    kv_status_message = 'Vercel KV REST API configured' if kv_available else 'Vercel KV REST API not configured'
    version_number = '1.1.0-replies'

    # Render the HTML template and pass the variables to it
    return render_template(
        'index.html',
        version=version_number,
        kv_status=kv_status_message
    )

@app.route('/entries', methods=['GET'])
def get_entries():
    """Get all guestbook entries"""
    try:
        entries = load_entries()
        # Sort by timestamp, newest first
        entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        app.logger.info(f"Retrieved {len(entries)} guestbook entries")
        return jsonify({
            'success': True,
            'entries': entries,
            'count': len(entries)
        })
    except Exception as e:
        app.logger.error(f"Error retrieving entries: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to retrieve entries'
        }), 500

@app.route('/entries', methods=['POST'])
def add_entry():
    """Add a new guestbook entry"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({
                'success': False,
                'error': 'No data provided'
            }), 400
        
        # Validate required fields
        name = sanitize_input(data.get('name', ''))
        message = sanitize_input(data.get('message', ''))
        
        if not name or not message:
            return jsonify({
                'success': False,
                'error': 'Name and message are required'
            }), 400
        
        if len(name) < 2:
            return jsonify({
                'success': False,
                'error': 'Name must be at least 2 characters long'
            }), 400
            
        if len(message) < 5:
            return jsonify({
                'success': False,
                'error': 'Message must be at least 5 characters long'
            }), 400
        
        # Validate optional email
        email = sanitize_input(data.get('email', ''))
        if email and not validate_email(email):
            return jsonify({
                'success': False,
                'error': 'Invalid email format'
            }), 400
        
        # Load existing entries to get next ID
        existing_entries = load_entries()
        next_id = max([e.get('id', 0) for e in existing_entries], default=0) + 1
        
        # Create new entry
        entry = {
            'id': next_id,
            'name': name,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'date_display': datetime.now().strftime('%B %d, %Y at %I:%M %p'),
            'replies': []  # Initialize with an empty list for replies
        }
        
        # Optional fields
        if email:
            entry['email'] = email
        
        if data.get('website'):
            website = sanitize_input(data.get('website'))
            # Add protocol if missing
            if website and not website.startswith(('http://', 'https://')):
                website = 'https://' + website
            entry['website'] = website
        
        # Add new entry and save
        existing_entries.append(entry)
        save_entries(existing_entries)
        
        app.logger.info(f"Added new guestbook entry from {name}")
        return jsonify({
            'success': True,
            'message': 'Entry added successfully',
            'entry': entry
        }), 201
        
    except Exception as e:
        app.logger.error(f"Error adding entry: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to add entry'
        }), 500

@app.route('/entries/<int:entry_id>/reply', methods=['POST'])
def add_reply(entry_id):
    """Add a reply to a specific guestbook entry (admin function)"""
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
        if not data or 'message' not in data:
            return jsonify({'success': False, 'error': 'Reply message is required'}), 400
        
        reply_message = sanitize_input(data['message'])
        if not reply_message:
            return jsonify({'success': False, 'error': 'Reply message cannot be empty'}), 400

        entries = load_entries()
        
        # Find the entry to reply to
        target_entry = next((e for e in entries if e.get('id') == entry_id), None)
        
        if not target_entry:
            return jsonify({'success': False, 'error': f'Entry {entry_id} not found'}), 404
        
        # Ensure the 'replies' key exists (for backward compatibility)
        target_entry.setdefault('replies', [])
        
        # Create the new reply
        new_reply = {
            'id': max([r.get('id', 0) for r in target_entry['replies']], default=0) + 1,
            'author': 'Admin', # Or make this configurable
            'message': reply_message,
            'timestamp': datetime.now().isoformat(),
            'date_display': datetime.now().strftime('%B %d, %Y at %I:%M %p')
        }
        
        target_entry['replies'].append(new_reply)
        save_entries(entries)
        
        app.logger.info(f"Added reply to entry {entry_id}")
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
