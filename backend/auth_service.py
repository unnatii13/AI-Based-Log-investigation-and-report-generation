from flask import session
from datetime import datetime, timedelta, timezone


MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = timedelta(minutes=15)


class AuthService:
    def __init__(self, user_repository):
        self.user_repository = user_repository

    def authenticate(self, username, password):
        username = (username or "").strip()
        password = password or ""
        if not username or not password:
            return None

        user = self.user_repository.get_user_by_username(username)
        if not user:
            return None

        if not user["is_active"]:
            return None

        if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
            locked_until = self._parse_timestamp(user.get("locked_until"))
            if locked_until and locked_until > datetime.now(timezone.utc):
                return None
            # Existing permanently locked accounts and expired temporary locks
            # are restored automatically on the next login attempt.
            self.user_repository.reset_failed_attempts(username)
            user["failed_attempts"] = 0

        if not self.user_repository.verify_password(user, password):
            locked_until = datetime.now(timezone.utc) + LOCKOUT_DURATION
            self.user_repository.record_failed_attempt(
                username,
                MAX_FAILED_ATTEMPTS,
                locked_until.isoformat(),
            )
            return None

        self.user_repository.reset_failed_attempts(username)
        self.user_repository.update_last_login(username)
        user["failed_attempts"] = 0
        return user

    def create_session(self, user):
        session.clear()
        session.permanent = True
        session["username"] = user["username"]
        session["role"] = user["role"]

    def clear_session(self):
        session.clear()

    def get_current_user(self):
        username = session.get("username")
        role = session.get("role")
        if not username or not role:
            return None
        return {"username": username, "role": role}

    @staticmethod
    def _parse_timestamp(value):
        if not value:
            return None
        try:
            parsed = datetime.fromisoformat(value)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
