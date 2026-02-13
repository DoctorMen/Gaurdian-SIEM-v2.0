import sqlite3
from datetime import datetime
import os

class EventBus:
    def __init__(self):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_dir = os.path.join(base_dir, "database")
        if not os.path.exists(db_dir):
            os.makedirs(db_dir)
        self.db_path = os.path.join(db_dir, "guardian_events.db")
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS events 
                     (id INTEGER PRIMARY KEY, timestamp TEXT, source TEXT, severity TEXT, message TEXT)''')
        conn.close()

    def emit(self, source, severity, message):
        timestamp = datetime.now().isoformat()
        conn = sqlite3.connect(self.db_path)
        conn.execute("INSERT INTO events (timestamp, source, severity, message) VALUES (?, ?, ?, ?)",
                     (timestamp, source, severity, message))
        conn.commit()
        conn.close()
        print(f"[{severity}] {source}: {message}")

if __name__ == "__main__":
    bus = EventBus()
    bus.emit("System", "INFO", "Event Bus Initialized Successfully.")