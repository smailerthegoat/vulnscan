from urllib.parse import urlparse

import requests

ALLOWED_PREVIEW_HOSTS = {"example.com", "docs.python.org"}


def fetch_preview(url: str) -> str:
    resp = requests.get(url, timeout=5)
    return resp.text[:500]


def fetch_trusted(url: str) -> str:
    if urlparse(url).hostname not in ALLOWED_PREVIEW_HOSTS:
        raise ValueError("host not allowed")
    return requests.get(url, timeout=5, allow_redirects=False).text[:500]
