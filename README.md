# CS471 Computer Security — Secure Notes System with XSS Prevention

**Deadline:** Sunday 29/11/2026 @ 23:59 (late = ZERO)
**Total marks:** 14
**Group size:** max 4 — only the group leader uploads to Blackboard

---

## Goal

Build a web-based notes app with login, where users manage their own notes. Show how Stored XSS works (in a deliberately vulnerable local example), then show your secured app blocks it. Add proper auth, access control, and logging.

---

## Tech stack

- [X] Python Flask

---

## Build checklist

### 1. Database
- [x] `users` table: `user_id`, `username`, `password` (**hashed**)
- [x] `notes` table: `note_id`, `user_id` (owner), `title`, `content`

### 2. Login system
- [x] Register / login / logout working
- [x] Passwords hashed (never stored in plain text)

### 3. Notes features (logged-in users only)
- [x] Add a new note
- [x] View **their own** notes
- [x] Delete **their own** notes

### 4. Stored XSS demo
- [x] Make a separate, deliberately vulnerable **local** version (or explain it conceptually)
- [x] Use a **harmless** payload only, e.g. a JavaScript `alert()`
- [x] Show the same input being stored and executed in the vulnerable version

### 5. Security in the real (secured) app
- [x] Output encoding / template auto-escaping — notes show as plain text, no HTML/JS runs
- [x] Password hashing
- [x] Input validation — required fields + length limits
- [x] Parameterized queries (prepared statements) for **every** DB operation

### 6. Access control
- [x] Only logged-in users can reach any notes page
- [x] Users can only view/delete their own notes
- [x] Ownership checked **on the server** for every view and delete request (not just hidden in the UI)

### 7. Logging
- [x] Log successful logins
- [x] Log failed logins
- [x] Log denied attempts to view/delete another user's note
- [x] Logs must **NOT** contain passwords or note content

---

## Report (3–5 pages, using the course template)

Sections:
- [x] Cover page filled in (names, IDs, CRN)
- [x] Stored XSS explanation
- [x] Security implementation details
- [x] Testing results
- [x] Conclusion

Screenshots to take:
- [x] Successful login
- [x] Successful note creation and display
- [x] XSS firing in the local vulnerable example
- [x] Same input displayed safely in the secured system
- [x] Denied access to another user's note

---

## Submission

- [x] Report as **Word (.docx)** and **PDF** — two separate files, not compressed
- [x] Source code (zipped folder)
- [x] Upload via the Blackboard assignment folder (group leader only)
- [x] Double-check both files uploaded correctly

> ⚠️ The instructions say files "must not be in compressed format," but the deliverables list asks for source code as a zipped folder. Ask the instructor which applies to the code before submitting.

---

## Rules that can give you ZERO

- Late submission
- Not using the provided template
- Emailing instead of Blackboard
- Trying to bypass SafeAssign (misspellings, hidden characters, other languages, etc.)
- Text converted into images (unless a question asks for it)
- Plagiarism — matching an online project, **AI-generated work**, or another student's project

---

## Marking rubric

| Component | Marks |
|---|---|
| Functional login and notes system | 3 |
| Stored XSS demonstration | 3 |
| Secure implementation (output encoding, password hashing, parameterized queries) | 4 |
| Logging and ownership-based access control | 2 |
| Report quality and screenshots | 2 |
| **Total** | **14** |
