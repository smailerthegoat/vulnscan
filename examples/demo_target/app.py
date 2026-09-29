"""Notes service: an intentionally vulnerable demo target for vulnscan. Do not deploy."""
import os
import sqlite3
import subprocess

from flask import Flask, abort, jsonify, redirect, request, send_file

from assistant import summarize_and_act
from auth import current_user, login_required
from config import SECRET_KEY
from fetcher import fetch_preview
from storage import import_backup, load_settings

app = Flask(__name__)
app.secret_key = SECRET_KEY
DB = os.environ.get("NOTES_DB", "notes.db")
UPLOAD_DIR = os.path.abspath("uploads")
SORT_COLUMNS = {"created": "created_at", "title": "title"}


def db():
    return sqlite3.connect(DB)


@app.route("/users/search")
def search_users():
    name = request.args.get("name", "")
    rows = db().execute(f"SELECT id, email FROM users WHERE name = '{name}'").fetchall()
    return jsonify(rows)


@app.route("/notes")
@login_required
def list_notes():
    column = SORT_COLUMNS.get(request.args.get("sort"), "created_at")
    rows = db().execute(f"SELECT id, title FROM notes WHERE owner_id = ? ORDER BY {column}",
                        (current_user()["id"],)).fetchall()
    return jsonify(rows)


@app.route("/notes/<int:note_id>")
@login_required
def get_note(note_id):
    row = db().execute("SELECT id, owner_id, title, body FROM notes WHERE id = ?", (note_id,)).fetchone()
    if row is None:
        abort(404)
    return jsonify(row)


@app.route("/notes/<int:note_id>", methods=["DELETE"])
@login_required
def delete_note(note_id):
    db().execute("DELETE FROM notes WHERE id = ? AND owner_id = ?", (note_id, current_user()["id"]))
    return "", 204


@app.route("/tools/ping")
@login_required
def ping():
    host = request.args.get("host", "127.0.0.1")
    out = subprocess.check_output(f"ping -c 1 {host}", shell=True)
    return out


@app.route("/tools/uptime")
def uptime():
    return subprocess.run(["uptime"], capture_output=True, text=True).stdout


@app.route("/files/<path:name>")
@login_required
def download(name):
    return send_file(os.path.join(UPLOAD_DIR, name))


@app.route("/files/safe/<path:name>")
@login_required
def download_safe(name):
    path = os.path.realpath(os.path.join(UPLOAD_DIR, name))
    if not path.startswith(UPLOAD_DIR + os.sep):
        abort(400)
    return send_file(path)


@app.route("/preview")
@login_required
def preview():
    return fetch_preview(request.args["url"])


@app.route("/login/next")
def after_login():
    return redirect(request.args.get("next", "/"))


@app.route("/admin/import", methods=["POST"])
@login_required
def admin_import():
    return jsonify(import_backup(request.get_data()))


@app.route("/settings", methods=["POST"])
@login_required
def settings():
    return jsonify(load_settings(request.get_data(as_text=True)))


@app.route("/assistant", methods=["POST"])
@login_required
def assistant():
    return jsonify(summarize_and_act(request.json["note"]))


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
