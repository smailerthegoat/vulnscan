import hashlib
import pickle

import yaml


def import_backup(blob: bytes) -> dict:
    data = pickle.loads(blob)
    return {"imported": len(data)}


def load_settings(text: str) -> dict:
    return yaml.safe_load(text) or {}


def cache_key(note_id: int, version: int) -> str:
    return hashlib.md5(f"{note_id}:{version}".encode()).hexdigest()
