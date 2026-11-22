from db import get_db_connection


# --- Folder Operations ---

def get_user_folders(user_id):
    """Fetch all folders belonging to the authenticated user."""
    conn = get_db_connection()
    folders = conn.execute(
        "SELECT folder_id, name FROM folders WHERE user_id = ? ORDER BY name ASC",
        (user_id,)
    ).fetchall()
    conn.close()
    return folders


def get_folder_by_id(folder_id):
    """Fetch a single folder by ID to verify ownership on the server."""
    conn = get_db_connection()
    folder = conn.execute(
        "SELECT folder_id, user_id, name FROM folders WHERE folder_id = ?",
        (folder_id,)
    ).fetchone()
    conn.close()
    return folder


def create_folder(user_id, name):
    """Create a new folder for the authenticated user using parameterized queries."""
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO folders (user_id, name) VALUES (?, ?)",
        (user_id, name)
    )
    conn.commit()
    conn.close()


def delete_folder(folder_id, user_id):
    """Delete a folder only if it belongs to the specified user."""
    conn = get_db_connection()
    cursor = conn.execute(
        "DELETE FROM folders WHERE folder_id = ? AND user_id = ?",
        (folder_id, user_id)
    )
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted


# --- Note Operations ---

def get_user_notes(user_id, folder_id=None, search_query=None):
    """
    Fetch notes belonging to the authenticated user.
    Supports optional folder filtering and parameterized keyword search.
    """
    conn = get_db_connection()
    query = """
        SELECT note_id, user_id, folder_id, title, content, created_at
        FROM notes
        WHERE user_id = ?
    """
    params = [user_id]

    if folder_id is not None:
        query += " AND folder_id = ?"
        params.append(folder_id)

    if search_query:
        like_pattern = f"%{search_query}%"
        query += " AND (title LIKE ? OR content LIKE ?)"
        params.extend([like_pattern, like_pattern])

    query += " ORDER BY created_at DESC"
    notes = conn.execute(query, tuple(params)).fetchall()
    conn.close()
    return notes


def get_note_by_id(note_id):
    """Fetch a single note by ID so the server can enforce ownership checks."""
    conn = get_db_connection()
    note = conn.execute(
        "SELECT note_id, user_id, folder_id, title, content, created_at FROM notes WHERE note_id = ?",
        (note_id,)
    ).fetchone()
    conn.close()
    return note


def create_note(user_id, title, content, folder_id=None):
    """Insert a new note for the authenticated user using parameterized queries."""
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO notes (user_id, folder_id, title, content) VALUES (?, ?, ?, ?)",
        (user_id, folder_id, title, content)
    )
    conn.commit()
    conn.close()


def update_note(note_id, user_id, title, content, folder_id=None):
    """Update a note only if the user_id matches the note owner."""
    conn = get_db_connection()
    cursor = conn.execute(
        """
        UPDATE notes
        SET title = ?, content = ?, folder_id = ?
        WHERE note_id = ? AND user_id = ?
        """,
        (title, content, folder_id, note_id, user_id)
    )
    conn.commit()
    updated = cursor.rowcount > 0
    conn.close()
    return updated


def delete_note(note_id, user_id):
    """Delete a note only if the user_id matches the note owner."""
    conn = get_db_connection()
    cursor = conn.execute(
        "DELETE FROM notes WHERE note_id = ? AND user_id = ?",
        (note_id, user_id)
    )
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    return deleted