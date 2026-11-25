"""Verify the source snapshot retained with a published measurement."""
import hashlib
import zipfile


def verify_sources(fingerprints, archive, archive_sha256):
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == archive_sha256
    with zipfile.ZipFile(archive) as snapshot:
        for name, expected in fingerprints.items():
            assert hashlib.sha256(snapshot.read(name)).hexdigest() == expected, name
