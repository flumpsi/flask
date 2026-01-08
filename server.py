import os
import re
import yaml
from datetime import datetime
from flask import (
    Flask, render_template, send_from_directory, request,
    redirect, url_for, flash, session, abort
)
from functools import wraps
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# ---------- CONFIG ----------
app = Flask(__name__)
app.secret_key = "supersecretkey"

VIDEO_FOLDER = "videos"
USERS_FILE = "users.yml"
ALLOWED_VIDEO = {"mp4"}
ALLOWED_IMAGE = {"png", "jpg", "jpeg"}

# Ensure video folder exists
os.makedirs(VIDEO_FOLDER, exist_ok=True)
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        yaml.safe_dump({"users": {"root": {"password": "toor", "privilege": 3}}}, f)

def load_users():
    with open(USERS_FILE, "r") as f:
        data = yaml.safe_load(f) or {}
    users = data.get("users", {})

    # Migrate plaintext passwords to hashed
    updated = False
    for username, udata in users.items():
        pw = udata.get("password", "")
        # Check if already hashed (starts with 'pbkdf2:sha256')
        if not pw.startswith("pbkdf2:sha256"):
            udata["password"] = generate_password_hash(pw)
            updated = True

    if updated:
        save_users(users)  # overwrite with hashed passwords

    return users

def check_user_password(username, password):
    users = load_users()
    user = users.get(username)
    if user and check_password_hash(user["password"], password):
        return True
    return False

# ---------- HELPERS ----------
def sanitize_filename(s):
    s = s.strip().lower()
    s = re.sub(r'[^a-z0-9_-]+', '_', s)
    return s

def load_users():
    with open(USERS_FILE, "r") as f:
        data = yaml.safe_load(f) or {}
    return data.get("users", {})

def save_users(users):
    with open(USERS_FILE, "w") as f:
        yaml.safe_dump({"users": users}, f)

def get_videos():
    videos = []
    for file in os.listdir(VIDEO_FOLDER):
        if file.endswith(".yml"):
            with open(os.path.join(VIDEO_FOLDER, file)) as f:
                video = yaml.safe_load(f).get("video")
                if video:
                    videos.append(video)
    return videos

def get_video_by_filename(filename):
    yml_file = os.path.splitext(filename)[0] + ".yml"
    path = os.path.join(VIDEO_FOLDER, yml_file)
    if not os.path.exists(path):
        return None
    return yaml.safe_load(open(path)).get("video")

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            flash("Login required")
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper

def privilege_required(min_level):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if "username" not in session:
                flash("Login required")
                return redirect(url_for("login"))
            users = load_users()
            user = users.get(session["username"])
            if not user or int(user.get("privilege", 2)) < min_level:
                flash("Insufficient privileges")
                return redirect(url_for("index"))
            return func(*args, **kwargs)
        return wrapper
    return decorator

def allowed_file(filename, allowed):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed

@app.route("/video/<video_file>/delete_comment/<int:index>", methods=["POST"])
@login_required
def delete_comment(video_file, index):
    video = get_video_by_filename(video_file)
    if not video:
        abort(404)

    # Permission check
    user_priv = int(session.get("privilege", 1))
    if session["username"] != video.get("uploader") and user_priv < 3:
        flash("You do not have permission to delete this comment.")
        return redirect(url_for("video_page", video_file=video_file))

    comment_file = video.get("comments_file")
    if not comment_file:
        flash("No comment file defined")
        return redirect(url_for("video_page", video_file=video_file))

    path = os.path.join(VIDEO_FOLDER, comment_file)
    if not os.path.exists(path):
        flash("Comment file not found")
        return redirect(url_for("video_page", video_file=video_file))

    # Read all comments, remove the one at index
    with open(path, "r") as f:
        comments = f.readlines()
    if index < 0 or index >= len(comments):
        flash("Invalid comment index")
        return redirect(url_for("video_page", video_file=video_file))
    removed = comments.pop(index)
    with open(path, "w") as f:
        f.writelines(comments)

    flash("Comment deleted")
    return redirect(url_for("video_page", video_file=video_file))


# ---------- ROUTES ----------
@app.route("/")
def index():
    return render_template("index.html", videos=get_videos())

@app.route("/video/<video_file>")
def video_page(video_file):
    video = get_video_by_filename(video_file)
    if not video:
        abort(404)

    comments = []
    comment_file = video.get("comments_file")
    if comment_file:
        comment_path = os.path.join(VIDEO_FOLDER, comment_file)
        if os.path.exists(comment_path):
            with open(comment_path) as f:
                comments = [line.strip() for line in f]

    return render_template("video.html", video=video, comments=comments)

@app.route("/video/<video_file>/comment", methods=["POST"])
@login_required
def add_comment(video_file):
    video = get_video_by_filename(video_file)
    if not video:
        abort(404)

    comment_text = request.form.get("comment")
    video_ts = request.form.get("timestamp")  # optional
    if not comment_text:
        flash("Comment cannot be empty")
        return redirect(url_for("video_page", video_file=video_file))

    try:
        video_ts = float(video_ts) if video_ts else 0.0
    except ValueError:
        flash("Invalid timestamp, using 0")
        video_ts = 0.0

    comment_file = video.get("comments_file")
    if not comment_file:
        flash("No comment file defined")
        return redirect(url_for("video_page", video_file=video_file))

    comment_path = os.path.join(VIDEO_FOLDER, comment_file)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    with open(comment_path, "a") as f:
        # store: server_timestamp video_timestamp username: comment
        f.write(f"[{timestamp}] {video_ts} {session['username']}: {comment_text}\n")

    flash("Comment added")
    return redirect(url_for("video_page", video_file=video_file))

@app.route("/user/<username>")
def user_page(username):
    user_videos = [v for v in get_videos() if v.get("uploader") == username]
    return render_template("user.html", videos=user_videos, username=username)

@app.route("/videos/<path:filename>")
def serve_video(filename):
    return send_from_directory(VIDEO_FOLDER, filename)

# ---------- AUTH ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        users = load_users()
        user = users.get(username)
        if check_user_password(username, password):
            session["username"] = username
            session["privilege"] = int(user.get("privilege", 2))
            flash("Logged in successfully")
            return redirect(url_for("index"))
        flash("Invalid username or password")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("privilege", None)
    flash("Logged out")
    return redirect(url_for("index"))

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if not username or not password:
            flash("All fields required")
            return redirect(request.url)
        users = load_users()
        if username in users:
            flash("Username already exists")
            return redirect(request.url)
        users[username] = {"password": generate_password_hash(password), "privilege": 2}  # default privilege
        save_users(users)
        flash("Signup successful! Please login.")
        return redirect(url_for("login"))
    return render_template("signup.html")

# ---------- UPLOAD ----------
@app.route("/upload", methods=["GET", "POST"])
@privilege_required(2)
def upload():
    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        video_file = request.files.get("video")
        thumbnail = request.files.get("thumbnail")
        if not title or not description or not video_file or not thumbnail:
            flash("All fields are required")
            return redirect(request.url)
        if not allowed_file(video_file.filename, ALLOWED_VIDEO):
            flash("Invalid video file")
            return redirect(request.url)
        if not allowed_file(thumbnail.filename, ALLOWED_IMAGE):
            flash("Invalid thumbnail")
            return redirect(request.url)

        base_name = sanitize_filename(title)
        video_name = base_name + ".mp4"
        thumb_name = base_name + os.path.splitext(thumbnail.filename)[1].lower()
        comments_file = base_name + "_comments.txt"

        # Save files
        video_file.save(os.path.join(VIDEO_FOLDER, video_name))
        thumbnail.save(os.path.join(VIDEO_FOLDER, thumb_name))

        # Save YAML
        yaml_name = base_name + ".yml"
        data = {
            "video": {
                "name": title,
                "video_file": video_name,
                "thumbnail": thumb_name,
                "description": description,
                "uploader": session["username"],
                "comments_file": comments_file
            }
        }
        with open(os.path.join(VIDEO_FOLDER, yaml_name), "w") as f:
            yaml.safe_dump(data, f)

        # Create empty comments file
        open(os.path.join(VIDEO_FOLDER, comments_file), "a").close()

        flash("Upload successful")
        return redirect(url_for("index"))

    return render_template("upload.html")

# ---------- RUN SERVER ----------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=43595, debug=True)

