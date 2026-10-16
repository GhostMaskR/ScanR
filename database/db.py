import sqlite3
from pathlib import Path
from contextlib import contextmanager

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_PATH = BASE_DIR / "data" / "scanr.db"


@contextmanager
def get_connection():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        str(DATABASE_PATH),
        timeout=10
    )

    connection.row_factory = sqlite3.Row

    try:
        connection.execute("PRAGMA busy_timeout = 10000")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    with get_connection() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                sha256 TEXT,
                status TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                malicious INTEGER,
                suspicious INTEGER,
                harmless INTEGER,
                undetected INTEGER,
                source TEXT NOT NULL DEFAULT 'virustotal',
                message TEXT,
                created_at TEXT NOT NULL DEFAULT
                    (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_created_at
            ON scans(created_at)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_scans_sha256
            ON scans(sha256)
        """)


def save_scan(
    scan_type,
    target,
    status,
    risk_level,
    sha256=None,
    malicious=None,
    suspicious=None,
    harmless=None,
    undetected=None,
    source="virustotal",
    message=None,
):
    with get_connection() as connection:
        cursor = connection.execute("""
            INSERT INTO scans (
                scan_type,
                target,
                sha256,
                status,
                risk_level,
                malicious,
                suspicious,
                harmless,
                undetected,
                source,
                message
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            scan_type,
            target,
            sha256,
            status,
            risk_level,
            malicious,
            suspicious,
            harmless,
            undetected,
            source,
            message,
        ))

        return cursor.lastrowid


def get_history(limit=50, offset=0):
    with get_connection() as connection:
        rows = connection.execute("""
            SELECT *
            FROM scans
            ORDER BY id DESC
            LIMIT ? OFFSET ?
        """, (limit, offset)).fetchall()

        return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    with get_connection() as connection:
        row = connection.execute(
            "SELECT * FROM scans WHERE id = ?",
            (scan_id,)
        ).fetchone()

        return dict(row) if row else None


def count_scans():
    with get_connection() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM scans"
        ).fetchone()

        return row["total"]
