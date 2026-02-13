from flask import Flask, render_template, jsonify
import sqlite3
import os

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "guardian_events.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return "<h1>Guardian V2.0 Dashboard</h1><p>Mission Control is Online.</p><a href='/api/events'>View Live Events</a>"

@app.route('/api/events')
def get_events():
    conn = get_db_connection()
    try:
        events = conn.execute('SELECT * FROM events ORDER BY timestamp DESC LIMIT 50').fetchall()
        return jsonify([dict(ix) for ix in events])
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)