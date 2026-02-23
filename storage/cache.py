"""
24-hour cache layer backed by MongoDB.
Sits between the ingestion clients and external APIs.
"""
from datetime import datetime, timedelta, timezone
from storage.mongo_client import get_db
from config import COLLECTION_API_CACHE, CACHE_TTL_SECONDS


def _collection():
    return get_db()[COLLECTION_API_CACHE]


def get_cached(indicator: str, source: str) -> dict | None:
    """
    Return the cached result for *indicator* from *source* if it exists
    and is younger than CACHE_TTL_SECONDS.  Otherwise return None.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=CACHE_TTL_SECONDS)
    doc = _collection().find_one(
        {
            "indicator": indicator,
            "source": source,
            "timestamp": {"$gte": cutoff},
        },
        {"_id": 0},
    )
    return doc


def set_cache(indicator: str, source: str, data: dict) -> None:
    """Upsert a cache entry with the current UTC timestamp."""
    _collection().update_one(
        {"indicator": indicator, "source": source},
        {
            "$set": {
                "indicator": indicator,
                "source": source,
                "data": data,
                "timestamp": datetime.now(timezone.utc),
            }
        },
        upsert=True,
    )
