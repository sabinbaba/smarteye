from functools import wraps
from flask import request, redirect, url_for, session, flash, g
from database import db
from datetime import datetime, timedelta
import re

class AuthManager:
    def __init__(self, app=None):
        self.app = app
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.app = app

        # Configure session settings
        app.config['SECRET_KEY'] = app.config.get('SECRET_KEY', 'your-secret-key-change-in-production')
        app.config['SESSION_TYPE'] = 'filesystem'
        app.config['SESSION_PERMANENT'] = True
        app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)

        # Register before_request handler
        app.before_request(self._load_current_user)

    def _load_current_user(self):
        """Load current user from session before each request"""
        g.user = None
        if 'session_id' in session:
            session_data = db.get_session(session['session_id'])
            if session_data:
                g.user = session_data
            else:
                # Invalid session, remove it
                session.pop('session_id', None)

    def login_required(self, f):
        """Decorator to require login for routes"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self.is_authenticated():
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function

    def admin_required(self, f):
        """Decorator to require admin role"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not self.is_authenticated():
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            if g.user.get('role') != 'admin':
                flash('Admin access required.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function

    def is_authenticated(self):
        """Check if user is authenticated"""
        return hasattr(g, 'user') and g.user is not None

    def login_user(self, username, password, remember=False):
        """Authenticate and login user"""
        ip_address = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')

        # Check if user is locked
        is_locked, lock_until = db.is_user_locked(username)
        if is_locked:
            remaining_time = lock_until - datetime.now()
            minutes_left = int(remaining_time.total_seconds() / 60)
            db.log_login_attempt(username, ip_address, success=False)
            return False, f"Account locked. Try again in {minutes_left} minutes."

        # Verify password
        user = db.verify_password(username, password)
        if user:
            # Successful login
            db.log_login_attempt(username, ip_address, success=True)
            db.reset_login_attempts(username)
            db.update_last_login(user['id'])

            # Create session
            session_id = db.create_session(
                user['id'],
                ip_address=ip_address,
                user_agent=user_agent,
                expires_in_hours=24 if remember else 8
            )

            # Set session
            session['session_id'] = session_id
            session.permanent = remember

            # Log activity
            db.log_user_activity(user['id'], 'login', ip_address, f"Login from {ip_address}")

            return True, "Login successful."
        else:
            # Failed login
            db.log_login_attempt(username, ip_address, success=False)
            db.increment_login_attempts(username)

            # Check if should lock account
            user_data = db.get_user(username=username)
            if user_data and user_data['login_attempts'] >= 5:
                db.lock_user(username)
                return False, "Too many failed attempts. Account locked for 15 minutes."

            return False, "Invalid username or password."

    def logout_user(self):
        """Logout current user"""
        if self.is_authenticated():
            ip_address = request.remote_addr
            db.log_user_activity(g.user['user_id'], 'logout', ip_address, f"Logout from {ip_address}")
            db.invalidate_session(session.get('session_id'))

        session.pop('session_id', None)
        g.user = None

    def register_user(self, username, email, password, confirm_password, full_name=None):
        """Register a new user"""
        errors = []

        # Validate input
        if not username or len(username) < 3:
            errors.append("Username must be at least 3 characters long.")

        if not email or not self._is_valid_email(email):
            errors.append("Please enter a valid email address.")

        if not password or len(password) < 8:
            errors.append("Password must be at least 8 characters long.")

        if password != confirm_password:
            errors.append("Passwords do not match.")

        if not self._is_strong_password(password):
            errors.append("Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character.")

        if errors:
            return False, errors

        # Check if username or email already exists
        existing_user = db.get_user(username=username)
        if existing_user:
            return False, ["Username already exists."]

        existing_email = db.get_user(email=email)
        if existing_email:
            return False, ["Email address already registered."]

        # Create user
        try:
            user_id = db.create_user(username, email, password, full_name)
            if user_id:
                # Log registration activity
                ip_address = request.remote_addr
                db.log_user_activity(user_id, 'register', ip_address, f"User registered from {ip_address}")
                return True, "Registration successful. Please log in."
            else:
                return False, ["Failed to create user account."]
        except Exception as e:
            return False, [f"Registration failed: {str(e)}"]

    def _is_valid_email(self, email):
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def _is_strong_password(self, password):
        """Check if password meets strength requirements"""
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'[0-9]', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True

    def get_current_user(self):
        """Get current authenticated user"""
        return g.user if self.is_authenticated() else None

    def change_password(self, current_password, new_password, confirm_password):
        """Change user password"""
        if not self.is_authenticated():
            return False, "User not authenticated."

        user = db.get_user(user_id=g.user['user_id'])
        if not user:
            return False, "User not found."

        # Verify current password
        from werkzeug.security import check_password_hash
        if not check_password_hash(user['password_hash'], current_password):
            return False, "Current password is incorrect."

        # Validate new password
        if len(new_password) < 8:
            return False, "New password must be at least 8 characters long."

        if new_password != confirm_password:
            return False, "New passwords do not match."

        if not self._is_strong_password(new_password):
            return False, "New password must contain at least one uppercase letter, one lowercase letter, one number, and one special character."

        # Update password
        from werkzeug.security import generate_password_hash
        new_hash = generate_password_hash(new_password)

        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE users SET password_hash = ? WHERE id = ?
            ''', (new_hash, user['id']))
            conn.commit()

        # Log activity
        ip_address = request.remote_addr
        db.log_user_activity(user['id'], 'password_change', ip_address, "Password changed")

        return True, "Password changed successfully."

# Global auth manager instance
auth = AuthManager()
