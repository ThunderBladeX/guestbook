from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session
from flask_cors import CORS
import json
import os
from datetime import datetime
import hashlib

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'  # Change this!
CORS(app)  # Allow cross-origin requests from your Neocities site

# Simple file-based storage
GUESTBOOK_FILE = 'guestbook.json'
ADMIN_PASSWORD = 'amita0424'  # Change this!

def load_entries():
    """Load guestbook entries from JSON file"""
    if os.path.exists(GUESTBOOK_FILE):
        with open(GUESTBOOK_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    return []

def save_entries(entries):
    """Save guestbook entries to JSON file"""
    with open(GUESTBOOK_FILE, 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=2, ensure_ascii=False)

def sanitize_text(text):
    """Basic text sanitization"""
    if not text:
        return ""
    # Remove potential HTML/script tags
    text = text.replace('<', '&lt;').replace('>', '&gt;')
    return text.strip()[:500]  # Limit length

@app.route('/')
def home():
    """Simple info page"""
    return """
    <h1>Guestbook API</h1>
    <p>Endpoints:</p>
    <ul>
        <li>GET /entries - Get all entries (JSON)</li>
        <li>POST /sign - Add new entry</li>
        <li>GET /admin - Admin panel</li>
    </ul>
    """

@app.route('/entries', methods=['GET'])
def get_entries():
    """Get all guestbook entries as JSON"""
    entries = load_entries()
    # Return entries in reverse chronological order
    return jsonify(sorted(entries, key=lambda x: x['timestamp'], reverse=True))

@app.route('/sign', methods=['POST'])
def sign_guestbook():
    """Add a new guestbook entry"""
    try:
        # Handle both form data and JSON
        if request.is_json:
            data = request.get_json()
        else:
            data = request.form.to_dict()
        
        name = sanitize_text(data.get('name', ''))
        message = sanitize_text(data.get('message', ''))
        website = sanitize_text(data.get('website', ''))
        
        if not name or not message:
            return jsonify({'error': 'Name and message are required'}), 400
        
        # Create new entry
        entry = {
            'id': hashlib.md5(f"{name}{message}{datetime.now()}".encode()).hexdigest()[:8],
            'name': name,
            'message': message,
            'website': website,
            'timestamp': datetime.now().isoformat(),
            'approved': True  # Auto-approve for now, you can change this
        }
        
        # Load existing entries and add new one
        entries = load_entries()
        entries.append(entry)
        save_entries(entries)
        
        return jsonify({'success': True, 'message': 'Entry added successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin')
def admin():
    """Admin panel for managing entries"""
    if not session.get('admin_logged_in'):
        return render_template_string(LOGIN_TEMPLATE)
    
    entries = load_entries()
    return render_template_string(ADMIN_TEMPLATE, entries=entries)

@app.route('/admin/login', methods=['POST'])
def admin_login():
    """Handle admin login"""
    password = request.form.get('password')
    if password == ADMIN_PASSWORD:
        session['admin_logged_in'] = True
        return redirect(url_for('admin'))
    return render_template_string(LOGIN_TEMPLATE, error="Invalid password")

@app.route('/admin/delete/<entry_id>', methods=['POST'])
def delete_entry(entry_id):
    """Delete a guestbook entry"""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin'))
    
    entries = load_entries()
    entries = [e for e in entries if e['id'] != entry_id]
    save_entries(entries)
    
    return redirect(url_for('admin'))

@app.route('/admin/logout')
def admin_logout():
    """Logout admin"""
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin'))

# HTML Templates
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Guestbook Admin</title>
    <style>
        body { font-family: monospace; max-width: 400px; margin: 100px auto; padding: 20px; }
        input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; }
        button { background: #000; color: #fff; padding: 10px 20px; border: none; cursor: pointer; }
        .error { color: red; margin: 10px 0; }
    </style>
</head>
<body>
    <h2>Admin Login</h2>
    {% if error %}
        <div class="error">{{ error }}</div>
    {% endif %}
    <form method="post" action="/admin/login">
        <input type="password" name="password" placeholder="Password" required>
        <button type="submit">Login</button>
    </form>
</body>
</html>
"""

ADMIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Guestbook Admin</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 20px auto; padding: 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; }
        .entry { border: 1px solid #ccc; margin: 10px 0; padding: 15px; }
        .entry-meta { color: #666; font-size: 12px; margin-bottom: 10px; }
        .delete-btn { background: #ff4444; color: white; border: none; padding: 5px 10px; cursor: pointer; }
        .no-entries { text-align: center; color: #666; margin: 50px 0; }
        a { color: #000; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Guestbook Admin</h1>
        <a href="/admin/logout">Logout</a>
    </div>
    
    <p>Total entries: {{ entries|length }}</p>
    
    {% if entries %}
        {% for entry in entries|sort(attribute='timestamp', reverse=true) %}
        <div class="entry">
            <div class="entry-meta">
                {{ entry.timestamp }} | ID: {{ entry.id }}
            </div>
            <strong>{{ entry.name }}</strong>
            {% if entry.website %}
                | <a href="{{ entry.website }}" target="_blank">{{ entry.website }}</a>
            {% endif %}
            <p>{{ entry.message }}</p>
            <form method="post" action="/admin/delete/{{ entry.id }}" style="display: inline;">
                <button type="submit" class="delete-btn" onclick="return confirm('Delete this entry?')">Delete</button>
            </form>
        </div>
        {% endfor %}
    {% else %}
        <div class="no-entries">No entries yet.</div>
    {% endif %}
</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
