import sqlite3
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

class Database:
    def __init__(self, db_path='ids_auth.db'):
        self.db_path = db_path
        self.init_db()

    def get_connection(self):
        return sqlite3.connect(self.db_path)

    def init_db(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT,
                    role TEXT DEFAULT 'user',
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    login_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP
                )
            ''')

            # Sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')

            # Login attempts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    ip_address TEXT,
                    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    success BOOLEAN DEFAULT 0
                )
            ''')

            # User activity log
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS user_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    details TEXT,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            ''')

            conn.commit()

    # User management methods
    def create_user(self, username, email, password, full_name=None, role='user'):
        """Create a new user"""
        try:
            password_hash = generate_password_hash(password)
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO users (username, email, password_hash, full_name, role)
                    VALUES (?, ?, ?, ?, ?)
                ''', (username, email, password_hash, full_name, role))
                conn.commit()
                return cursor.lastrowid
        except sqlite3.IntegrityError:
            return None

    def get_user(self, user_id=None, username=None, email=None):
        """Get user by ID, username, or email"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if user_id:
                cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
            elif username:
                cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
            elif email:
                cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            else:
                return None

            row = cursor.fetchone()
            if row:
                return {
                    'id': row[0],
                    'username': row[1],
                    'email': row[2],
                    'password_hash': row[3],
                    'full_name': row[4],
                    'role': row[5],
                    'is_active': row[6],
                    'created_at': row[7],
                    'last_login': row[8],
                    'login_attempts': row[9],
                    'locked_until': row[10]
                }
        return None

    def verify_password(self, username, password):
        """Verify user password"""
        user = self.get_user(username=username)
        if user and user['is_active'] and check_password_hash(user['password_hash'], password):
            return user
        return None

    def update_last_login(self, user_id):
        """Update user's last login time"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
            ''', (user_id,))
            conn.commit()

    def increment_login_attempts(self, username):
        """Increment login attempts for user"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET login_attempts = login_attempts + 1 WHERE username = ?
            ''', (username,))
            conn.commit()

    def reset_login_attempts(self, username):
        """Reset login attempts for user"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET login_attempts = 0, locked_until = NULL WHERE username = ?
            ''', (username,))
            conn.commit()

    def lock_user(self, username, duration_minutes=15):
        """Lock user account for specified duration"""
        lock_until = datetime.now() + timedelta(minutes=duration_minutes)
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET locked_until = ? WHERE username = ?
            ''', (lock_until, username))
            conn.commit()

    def is_user_locked(self, username):
        """Check if user is currently locked"""
        user = self.get_user(username=username)
        if user and user['locked_until']:
            lock_until = datetime.fromisoformat(user['locked_until'])
            if datetime.now() < lock_until:
                return True, lock_until
        return False, None

    # Session management methods
    def create_session(self, user_id, ip_address=None, user_agent=None, expires_in_hours=24):
        """Create a new session"""
        session_id = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=expires_in_hours)

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO sessions (id, user_id, ip_address, user_agent, expires_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (session_id, user_id, ip_address, user_agent, expires_at))
            conn.commit()

        return session_id

    def get_session(self, session_id):
        """Get session by ID"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT s.*, u.username, u.email, u.full_name, u.role
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.id = ? AND s.is_active = 1 AND s.expires_at > CURRENT_TIMESTAMP
            ''', (session_id,))

            row = cursor.fetchone()
            if row:
                return {
                    'session_id': row[0],
                    'user_id': row[1],
                    'ip_address': row[2],
                    'user_agent': row[3],
                    'created_at': row[4],
                    'expires_at': row[5],
                    'is_active': row[6],
                    'username': row[7],
                    'email': row[8],
                    'full_name': row[9],
                    'role': row[10]
                }
        return None

    def invalidate_session(self, session_id):
        """Invalidate a session"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions SET is_active = 0 WHERE id = ?
            ''', (session_id,))
            conn.commit()

    def cleanup_expired_sessions(self):
        """Clean up expired sessions"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE sessions SET is_active = 0 WHERE expires_at < CURRENT_TIMESTAMP
            ''')
            conn.commit()

    # Login attempts logging
    def log_login_attempt(self, username, ip_address, success=False):
        """Log a login attempt"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO login_attempts (username, ip_address, success)
                VALUES (?, ?, ?)
            ''', (username, ip_address, success))
            conn.commit()

    # User activity logging
    def log_user_activity(self, user_id, action, ip_address=None, details=None):
        """Log user activity"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO user_activity (user_id, action, ip_address, details)
                VALUES (?, ?, ?, ?)
            ''', (user_id, action, ip_address, details))
            conn.commit()

    def get_recent_activity(self, user_id=None, limit=50):
        """Get recent user activity"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if user_id:
                cursor.execute('''
                    SELECT ua.*, u.username FROM user_activity ua
                    JOIN users u ON ua.user_id = u.id
                    WHERE ua.user_id = ?
                    ORDER BY ua.timestamp DESC LIMIT ?
                ''', (user_id, limit))
            else:
                cursor.execute('''
                    SELECT ua.*, u.username FROM user_activity ua
                    JOIN users u ON ua.user_id = u.id
                    ORDER BY ua.timestamp DESC LIMIT ?
                ''', (limit,))

            rows = cursor.fetchall()
            return [{
                'id': row[0],
                'user_id': row[1],
                'action': row[2],
                'ip_address': row[3],
                'timestamp': row[4],
                'details': row[5],
                'username': row[6]
            } for row in rows]

    # Statistics methods
    def get_user_stats(self):
        """Get user statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()

            # Total users
            cursor.execute('SELECT COUNT(*) FROM users')
            total_users = cursor.fetchone()[0]

            # Active users (logged in within last 24 hours)
            cursor.execute('''
                SELECT COUNT(DISTINCT user_id) FROM sessions
                WHERE is_active = 1 AND created_at > datetime('now', '-1 day')
            ''')
            active_users = cursor.fetchone()[0]

            # Failed login attempts in last 24 hours
            cursor.execute('''
                SELECT COUNT(*) FROM login_attempts
                WHERE success = 0 AND attempted_at > datetime('now', '-1 day')
            ''')
            failed_attempts = cursor.fetchone()[0]

            return {
                'total_users': total_users,
                'active_users': active_users,
                'failed_login_attempts': failed_attempts
            }

# Global database instance
db = Database()
