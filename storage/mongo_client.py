"""
MongoDB connection helper.
Provides a singleton-style database handle used by all storage modules.
"""
from pymongo import MongoClient
from config import MONGO_URI, MONGO_DB_NAME

_client = None
_db = None


def get_client() -> MongoClient:
    """Return (and lazily create) the MongoClient singleton."""
    global _client
    if _client is None:
        _client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    return _client


def get_db():
    """Return the application database handle."""
    global _db
    if _db is None:
        _db = get_client()[MONGO_DB_NAME]
    return _db


def is_connected() -> bool:
    """Quick connectivity check (used by the health endpoint)."""
    try:
        get_client().admin.command("ping")
        return True
    except Exception:
        return False
