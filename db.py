import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "shield.db")
SCHEMA_PATH = os.path.join(os.path.dirname(__file__), "scheme.sql")


def get_db_connection():
    """Create and return a new SQLite database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # Allows accessing columns by name
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db():
    """Initialize the database tables from scheme.sql if they do not exist."""
    conn = get_db_connection()
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        conn.executescript(f.read())
    conn.commit()
    conn.close()