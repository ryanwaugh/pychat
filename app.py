from flask import Flask, render_template, request, redirect, session, jsonify
from flask_socketio import SocketIO, join_room, emit
import sqlite3
import os
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

DB = 'pychat.db'
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
socketio = SocketIO(app)

def init_db():
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS channels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL
        )
    """)
    c.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            channel_id INTEGER,
            user_id INTEGER,
            content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(channel_id) REFERENCES channels(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    """)

    conn.commit()
    conn.close()

init_db()

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        conn = sqlite3.connect(DB)
        c = conn.cursor()
        c.execute("SELECT id, password_hash FROM users WHERE username=?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            session["user_id"] = user[0]
            session["username"] = username
            return redirect("/channels")
        else:
            return render_template("login.html", error="Invalid username or password")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        hash_pw = generate_password_hash(password)

        try:
            conn = sqlite3.connect(DB)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hash_pw))
            conn.commit()
            conn.close()
            return redirect("/")
        except sqlite3.IntegrityError:
            return render_template("register.html", error="Username already exists")

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/channels", methods=["GET", "POST"])
def channels():
    if "user_id" not in session:
        return redirect("/")

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    if request.method == "POST":
        channel_name = request.form["channel"]
        try:
            c.execute("INSERT INTO channels (name) VALUES (?)", (channel_name,))
            conn.commit()
        except sqlite3.IntegrityError:
            pass  # ignore duplicates

    c.execute("SELECT name FROM channels")
    channels = [row[0] for row in c.fetchall()]
    conn.close()

    return render_template("channels.html", username=session["username"], channels=channels)


@app.route("/chat/<channel_name>")
def chat(channel_name):
    if "user_id" not in session:
        return redirect("/")
    return render_template("chat.html", channel_name=channel_name, username=session["username"])


@app.route("/get_messages/<channel_name>")
def get_messages(channel_name):
    conn = sqlite3.connect(DB)
    c = conn.cursor()
    c.execute("""
        SELECT u.username, m.content, m.timestamp
        FROM messages m
        JOIN users u ON m.user_id = u.id
        JOIN channels ch ON m.channel_id = ch.id
        WHERE ch.name = ?
        ORDER BY m.timestamp ASC
    """, (channel_name,))
    messages = [{"username": r[0], "content": r[1], "timestamp": r[2]} for r in c.fetchall()]
    conn.close()
    return jsonify(messages)


@socketio.on("join")
def handle_join(data):
    username = data["username"]
    channel = data["channel"]
    join_room(channel)
    emit("receive_message", {"username": "Server", "message": f"{username} joined {channel}."}, room=channel)


@socketio.on("send_message")
def handle_message(data):
    username = data["username"]
    channel = data["channel"]
    content = data["message"]

    conn = sqlite3.connect(DB)
    c = conn.cursor()

    c.execute("SELECT id FROM users WHERE username=?", (username,))
    user_id = c.fetchone()[0]
    c.execute("SELECT id FROM channels WHERE name=?", (channel,))
    channel_id = c.fetchone()[0]

    c.execute("INSERT INTO messages (channel_id, user_id, content) VALUES (?, ?, ?)",
              (channel_id, user_id, content))
    conn.commit()
    conn.close()

    emit("receive_message", {"username": username, "message": content}, room=channel)


if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5000, debug=True)
