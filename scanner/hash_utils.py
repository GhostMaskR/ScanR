import hashlib
import re
from pathlib import Path
from typing import BinaryIO

CHUNK_SIZE = 1024 * 1024

SHA256_PATTERN = re.compile(r"^[a-fA-F0-9]{64}$")
SHA1_PATTERN = re.compile(r"^[a-fA-F0-9]{40}$")
MD5_PATTERN = re.compile(r"^[a-fA-F0-9]{32}$")


def validate_hash(value: str) -> tuple[bool, str]:
    if not isinstance(value, str):
        return False, "Hash must be a string."

    value = value.strip()

    if SHA256_PATTERN.fullmatch(value):
        return True, "sha256"

    if SHA1_PATTERN.fullmatch(value):
        return True, "sha1"

    if MD5_PATTERN.fullmatch(value):
        return True, "md5"

    return False, "Unsupported hash format."


def hash_stream(stream: BinaryIO) -> str:
    digest = hashlib.sha256()

    while True:
        chunk = stream.read(CHUNK_SIZE)

        if not chunk:
            break

        digest.update(chunk)

    return digest.hexdigest()


def hash_file(file_path: str | Path) -> str:
    with open(file_path, "rb") as file_handle:
        return hash_stream(file_handle)


def hash_bytes(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()
