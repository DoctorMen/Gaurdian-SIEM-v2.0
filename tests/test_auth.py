"""Tests for Authentication module"""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from auth import UserDB


@pytest.fixture
def user_db():
    f = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
    f.close()
    db = UserDB(db_path=f.name)
    yield db
    os.unlink(f.name)


class TestUserDB:
    def test_default_admin_created(self, user_db):
        users = user_db.list_users()
        assert len(users) == 1
        assert users[0]["username"] == "admin"
        assert users[0]["role"] == "admin"

    def test_authenticate_default_admin(self, user_db):
        user = user_db.authenticate("admin", "guardian-admin")
        assert user is not None
        assert user["username"] == "admin"
        assert user["role"] == "admin"

    def test_authenticate_wrong_password(self, user_db):
        user = user_db.authenticate("admin", "wrong-password")
        assert user is None

    def test_authenticate_nonexistent_user(self, user_db):
        user = user_db.authenticate("nobody", "password")
        assert user is None

    def test_create_user(self, user_db):
        result = user_db.create_user("analyst1", "securepass", "analyst")
        assert result is not None
        assert result["username"] == "analyst1"
        assert result["role"] == "analyst"
        assert "api_key" in result

    def test_create_duplicate_user(self, user_db):
        user_db.create_user("testuser", "pass1")
        result = user_db.create_user("testuser", "pass2")
        assert result is None

    def test_authenticate_new_user(self, user_db):
        user_db.create_user("newuser", "mypassword", "viewer")
        user = user_db.authenticate("newuser", "mypassword")
        assert user is not None
        assert user["role"] == "viewer"

    def test_change_password(self, user_db):
        user_db.change_password("admin", "new-admin-pass")
        # Old password should fail
        assert user_db.authenticate("admin", "guardian-admin") is None
        # New password should work
        assert user_db.authenticate("admin", "new-admin-pass") is not None

    def test_api_key_auth(self, user_db):
        result = user_db.create_user("apiuser", "pass", "analyst")
        api_key = result["api_key"]
        user = user_db.authenticate_api_key(api_key)
        assert user is not None
        assert user["username"] == "apiuser"

    def test_invalid_api_key(self, user_db):
        user = user_db.authenticate_api_key("invalid-key-12345")
        assert user is None

    def test_delete_user(self, user_db):
        user_db.create_user("deleteme", "pass")
        user_db.delete_user("deleteme")
        assert user_db.authenticate("deleteme", "pass") is None

    def test_list_users(self, user_db):
        user_db.create_user("user1", "p1", "viewer")
        user_db.create_user("user2", "p2", "analyst")
        users = user_db.list_users()
        assert len(users) == 3  # admin + 2 new
        usernames = {u["username"] for u in users}
        assert "admin" in usernames
        assert "user1" in usernames
        assert "user2" in usernames
