from flask import Flask, request, jsonify
from flask_cors import CORS
import json
import os
from datetime import datetime
import re

app = Flask(__name__)
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
            return []
    return []

def save_entries(entries):
    """Save guestbook entries to file"""
    with open(GUESTBOOK_FILE, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)

def sanitize_input(text):
    """Basic input sanitization"""
    if not text:
        return ""
    # Remove HTML tags and limit length
    text = re.sub(r'<[^>]*>', '', str(text))
    return text.strip()[:500]  # Limit to 500 characters

@app.route('/', methods=['GET'])
def home():
    """Simple status endpoint"""
    return jsonify({
        'status': 'Guestbook service running',
        'endpoints': {
            'GET /entries': 'Get all entries',
            'POST /entries': 'Add new entry',
            'DELETE /entries/<id>': 'Delete entry (admin)',
            'GET /admin': 'Admin panel'
        }
    })

@app.route('/entries', methods=['GET'])
def get_entries():
    """Get all guestbook entries"""
    try:
        entries = load_entries()
        # Sort by timestamp, newest first
        entries.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        return jsonify({
            'success': True,
            'entries': entries,
            'count': len(entries)
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
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
        
        # Create new entry
        entry = {
            'id': len(load_entries()) + 1,
            'name': name,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'date_display': datetime.now().strftime('%B %d, %Y at %I:%M %p')
        }
        
        # Optional fields
        if data.get('email'):
            entry['email'] = sanitize_input(data.get('email'))
        if data.get('website'):
            website = sanitize_input(data.get('website'))
            # Add protocol if missing
            if website and not website.startswith(('http://', 'https://')):
                website = 'https://' + website
            entry['website'] = website
        
        # Load existing entries and add new one
        entries = load_entries()
        entries.append(entry)
        save_entries(entries)
        
        return jsonify({
            'success': True,
            'message': 'Entry added successfully',
            'entry': entry
        }), 201
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/entries/<int:entry_id>', methods=['DELETE'])
def delete_entry(entry_id):
    """Delete an entry (admin function)"""
    try:
        # Simple admin key check - you should set this as environment variable
        admin_key = request.headers.get('X-Admin-Key')
        if admin_key != os.environ.get('ADMIN_KEY', 'ThunderBladeX'):
            return jsonify({
                'success': False,
                'error': 'Unauthorized'
            }), 401
        
        entries = load_entries()
        entries = [e for e in entries if e.get('id') != entry_id]
        save_entries(entries)
        
        return jsonify({
            'success': True,
            'message': f'Entry {entry_id} deleted'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/admin', methods=['GET'])
def admin_panel():
    """Simple admin panel"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Guestbook Admin</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
            .entry { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 4px; }
            .entry-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
            .delete-btn { background: #ff4444; color: white; border: none; padding: 5px 10px; border-radius: 3px; cursor: pointer; }
            .delete-btn:hover { background: #cc0000; }
            input[type="text"] { width: 300px; padding: 5px; margin: 10px 0; }
            #admin-key { margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Guestbook Admin Panel</h1>
            <div id="admin-key">
                <label>Admin Key: <input type="password" id="adminKey" placeholder="Enter admin key"></label>
                <button onclick="loadEntries()">Load Entries</button>
            </div>
            <div id="entries"></div>
        </div>
        
        <script>
            async function loadEntries() {
                try {
                    const response = await fetch('/entries');
                    const data = await response.json();
                    
                    if (data.success) {
                        displayEntries(data.entries);
                    } else {
                        alert('Error loading entries: ' + data.error);
                    }
                } catch (error) {
                    alert('Error: ' + error.message);
                }
            }
            
            function displayEntries(entries) {
                const container = document.getElementById('entries');
                container.innerHTML = '<h2>Total Entries: ' + entries.length + '</h2>';
                
                entries.forEach(entry => {
                    const div = document.createElement('div');
                    div.className = 'entry';
                    div.innerHTML = `
                        <div class="entry-header">
                            <strong>${entry.name}</strong>
                            <span>${entry.date_display}</span>
                            <button class="delete-btn" onclick="deleteEntry(${entry.id})">Delete</button>
                        </div>
                        <p>${entry.message}</p>
                        ${entry.website ? '<p><a href="' + entry.website + '" target="_blank">' + entry.website + '</a></p>' : ''}
                    `;
                    container.appendChild(div);
                });
            }
            
            async function deleteEntry(id) {
                const adminKey = document.getElementById('adminKey').value;
                if (!adminKey) {
                    alert('Please enter admin key');
                    return;
                }
                
                if (!confirm('Are you sure you want to delete this entry?')) return;
                
                try {
                    const response = await fetch('/entries/' + id, {
                        method: 'DELETE',
                        headers: {
                            'X-Admin-Key': adminKey
                        }
                    });
                    
                    const data = await response.json();
                    if (data.success) {
                        loadEntries(); // Reload entries
                        alert('Entry deleted successfully');
                    } else {
                        alert('Error: ' + data.error);
                    }
                } catch (error) {
                    alert('Error: ' + error.message);
                }
            }
            
            // Load entries on page load
            loadEntries();
        </script>
    </body>
    </html>
    '''

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'timestamp': datetime.now().isoformat()})

if __name__ == '__main__':
    # Create guestbook file if it doesn't exist
    if not os.path.exists(GUESTBOOK_FILE):
        save_entries([])
    
    # Run the app
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
