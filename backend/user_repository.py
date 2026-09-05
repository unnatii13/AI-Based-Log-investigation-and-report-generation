import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash


DEFAULT_USERS = (
    ("admin1", "admin123", "Administrator"),
    ("manager1", "manager123", "Investigation Manager"),
    ("analyst1", "analyst123", "Analyst"),
)


class UserRepository:
    def __init__(self, db_path):
        self.db_path = Path(db_path)

    def connect(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        return connection

    def initialize(self):
        with self.connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    is_active INTEGER NOT NULL DEFAULT 1,
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    last_login_at TEXT
                )
                """
            )
            self._ensure_column(connection, "users", "locked_until", "TEXT")

    def ensure_default_users(self):
        for username, password, role in DEFAULT_USERS:
            if not self.get_user_by_username(username):
                self.create_user(username, password, role)

    def create_user(self, username, password, role):
        username = username.strip()
        if not username:
            raise ValueError("Username is required")
        if not password:
            raise ValueError("Password is required")
        if not role:
            raise ValueError("Role is required")

        password_hash = generate_password_hash(password)
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO users (username, password_hash, role, is_active, failed_attempts, created_at)
                VALUES (?, ?, ?, 1, 0, ?)
                """,
                (username, password_hash, role, self._now()),
            )
        return self.get_user_by_username(username)

    def get_user_by_username(self, username):
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT id, username, password_hash, role, is_active, failed_attempts, created_at, last_login_at, locked_until
                FROM users
                WHERE username = ?
                """,
                (username,),
            ).fetchone()
        return dict(row) if row else None

    def verify_password(self, user, password):
        return check_password_hash(user["password_hash"], password)

    def update_last_login(self, username):
        with self.connect() as connection:
            connection.execute(
                "UPDATE users SET last_login_at = ? WHERE username = ?",
                (self._now(), username),
            )

    def record_failed_attempt(self, username, max_attempts, locked_until):
        with self.connect() as connection:
            connection.execute(
                "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?",
                (username,),
            )
            attempts = connection.execute(
                "SELECT failed_attempts FROM users WHERE username = ?", (username,)
            ).fetchone()["failed_attempts"]
            if attempts >= max_attempts:
                connection.execute(
                    "UPDATE users SET locked_until = ? WHERE username = ?",
                    (locked_until, username),
                )

    def reset_failed_attempts(self, username):
        with self.connect() as connection:
            connection.execute(
                "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?",
                (username,),
            )

    def _ensure_column(self, connection, table_name, column_name, column_type):
        columns = {row["name"] for row in connection.execute(f"PRAGMA table_info({table_name})")}
        if column_name not in columns:
            connection.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).isoformat()
