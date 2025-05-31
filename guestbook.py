from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import json
import os
import logging
from datetime import datetime
import re

# Configure logging for better debugging
logging.basicConfig(level=logging.DEBUG)

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
CORS(app)  # Enable CORS for cross-origin requests from Neocities

# File to store guestbook entries
GUESTBOOK_FILE = 'guestbook.json'

def load_entries():
    """Load guestbook entries from file"""
    if os.path.exists(GUESTBOOK_FILE):
        try:
            with open(GUESTBOOK_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError):
            app.logger.warning("Failed to load guestbook entries, returning empty list")
            return []
    return []

def save_entries(entries):
    """Save guestbook entries to file"""
    try:
        with open(GUESTBOOK_FILE, 'w', encoding='utf-8') as f:
            json.dump(entries, f, indent=2, ensure_ascii=False)
        app.logger.info(f"Saved {len(entries)} entries to {GUESTBOOK_FILE}")
    except Exception as e:
        app.logger.error(f"Failed to save entries: {str(e)}")
        raise

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
    """Simple status endpoint"""
    return jsonify({
        'status': 'Guestbook service running',
        'version': '1.0.0',
        'endpoints': {
            'GET /entries': 'Get all entries',
            'POST /entries': 'Add new entry',
            'DELETE /entries/<id>': 'Delete entry (admin)',
            'GET /admin': 'Admin panel',
            'GET /health': 'Health check'
        }
    })

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
            'date_display': datetime.now().strftime('%B %d, %Y at %I:%M %p')
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

@app.route('/entries/<int:entry_id>', methods=['DELETE'])
def delete_entry(entry_id):
    """Delete an entry (admin function)"""
    try:
        # Simple admin key check
        admin_key = request.headers.get('X-Admin-Key')
        expected_key = os.environ.get('ADMIN_KEY')
        
        if admin_key != expected_key:
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
    try:
        # Test that we can read/write to the guestbook file
        entries = load_entries()
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'entries_count': len(entries),
            'storage': 'operational'
        })
    except Exception as e:
        app.logger.error(f"Health check failed: {str(e)}")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'error': 'Storage error'
        }), 500

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({
        'success': False,
        'error': 'Endpoint not found'
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    app.logger.error(f"Internal server error: {str(error)}")
    return jsonify({
        'success': False,
        'error': 'Internal server error'
    }), 500

if __name__ == '__main__':
    # Create guestbook file if it doesn't exist
    if not os.path.exists(GUESTBOOK_FILE):
        save_entries([])
        app.logger.info("Created new guestbook.json file")
    
    # Run the app on port 5000 as per guidelines
    port = int(os.environ.get('PORT', 5000))
    app.logger.info(f"Starting guestbook service on port {port}")
    app.run(host='0.0.0.0', port=port, debug=True)
