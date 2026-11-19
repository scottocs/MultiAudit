"""Read recorded experiment labels and verify their archived source provenance."""
import hashlib
import json
import zipfile
from functools import lru_cache
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@lru_cache(maxsize=None)
def rename_manifest(root=ROOT):
    path = root / 'experiments/results/paper/source_rename.json'
    return json.loads(path.read_text()) if path.exists() else {}


def canonicalize(value):
    if isinstance(value, str):
        for old, new in rename_manifest().get('replacements', []):
            value = value.replace(old, new)
        return value
    if isinstance(value, list):
        return [canonicalize(item) for item in value]
    if isinstance(value, dict):
        return {canonicalize(key): canonicalize(item) for key, item in value.items()}
    return value


def verify_sources(root, fingerprints):
    manifest = rename_manifest(root)
    archive = root / 'experiments/results/paper' / manifest.get('source_archive', '')
    archived = False
    for name, expected in fingerprints.items():
        current = root / canonicalize(name)
        actual = hashlib.sha256(current.read_bytes()).hexdigest()
        if actual == expected:
            continue
        entry = manifest.get('sources', {}).get(name)
        assert entry and entry['original_sha256'] == expected, name
        assert entry['current_path'] == canonicalize(name), name
        assert entry['current_sha256'] == actual, name
        if not archived:
            assert hashlib.sha256(archive.read_bytes()).hexdigest() == manifest['source_archive_sha256']
            archived = True
        with zipfile.ZipFile(archive) as snapshot:
            assert hashlib.sha256(snapshot.read(name)).hexdigest() == expected, name
