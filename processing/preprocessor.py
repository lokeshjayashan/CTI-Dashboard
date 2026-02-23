"""
Text preprocessing utilities for the CTI pipeline.
Cleans, normalises, and validates user input before AI inference.
"""
import re
import ipaddress
from urllib.parse import urlparse


# ── Text Cleaning ──────────────────────────────────────────────────

def clean_text(text: str) -> str:
    """Lowercase, strip HTML tags, and replace URLs with their domain names."""
    text = text.lower()
    text = re.sub(r"<[^>]+>", " ", text)          # strip HTML

    # Replace full URLs with just their domain name so the classifier
    # gets unique text per URL instead of stripping them entirely.
    def _url_to_domain(m):
        try:
            return urlparse(m.group(0)).netloc or m.group(0)
        except Exception:
            return m.group(0)

    text = re.sub(r"https?://\S+", _url_to_domain, text)
    text = re.sub(r"[^a-z0-9\s.,!?'-]", " ", text) # keep basic punctuation
    text = re.sub(r"\s+", " ", text).strip()        # collapse whitespace
    return text


def tokenize(text: str) -> list:
    """Simple whitespace + punctuation tokenizer."""
    tokens = re.findall(r"\b\w+\b", text.lower())
    return tokens


def prepare_for_model(text: str) -> str:
    """Full preprocessing pipeline — returns a cleaned string ready for BERT."""
    return clean_text(text)


# ── Input Validation ──────────────────────────────────────────────

def validate_ip(ip: str) -> bool:
    """Return True if *ip* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except ValueError:
        return False


def validate_url(url: str) -> bool:
    """Return True if *url* has a valid scheme and network location."""
    try:
        result = urlparse(url.strip())
        return all([result.scheme in ("http", "https"), result.netloc])
    except Exception:
        return False


def detect_input_type(value: str) -> str:
    """
    Auto-detect whether a user input is an IP, a URL, or free text.
    Returns one of: 'ip', 'url', 'text'.
    """
    value = value.strip()
    if validate_ip(value):
        return "ip"
    if validate_url(value):
        return "url"
    return "text"
