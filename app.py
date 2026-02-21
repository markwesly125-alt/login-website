import os
from flask import Flask, render_template, request, redirect, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from PIL import Image

# -------------------------------------------------
# APP CONFIG
# -------------------------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-fallback-key")

# DATABASE
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL environment variable not set")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# UPLOADS
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
THUMB_FOLDER = os.path.join(UPLOAD_FOLDER, "thumbnails")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(THUMB_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["THUMB_FOLDER"] = THUMB_FOLDER

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "zip"}

db = SQLAlchemy(app)

# -------------------------------------------------
# MODELS
# -------------------------------------------------
class User(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="user")
    approved = db.Column(db.Boolean, default=False)

class Project(db.Model):
    __tablename__ = "projects"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    filename = db.Column(db.String(300), nullable=False)
    thumbnail = db.Column(db.String(300))
    uploaded_by = db.Column(db.String(150), nullable=False)

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def create_thumbnail(image_path, thumb_path):
    img = Image.open(image_path)
    img.thumbnail((400, 300))
    img.save(thumb_path)

# -------------------------------------------------
# ADMIN BOOTSTRAP
# -------------------------------------------------
def create_default_admin():
    admin_password = os.environ.get("ADMIN_PASSWORD")
    if not admin_password:
        raise RuntimeError("ADMIN_PASSWORD environment variable not set")

    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            username="admin",
            password=generate_password_hash(admin_password),
            role="admin",
            approved=True
        )
        db.session.add(admin)
        db.session.commit()

# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if not user or not check_password_hash(user.password, request.form["password"]):
            return "Invalid credentials", 401
        if not user.approved:
            return "Awaiting admin approval", 403

        session["user"] = user.username
        session["role"] = user.role
        return redirect("/projects")

    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if User.query.filter_by(username=request.form["username"]).first():
            return "User exists"

        user = User(
            username=request.form["username"],
            password=generate_password_hash(request.form["password"]),
            approved=False
        )
        db.session.add(user)
        db.session.commit()
        return "Registered. Await admin approval."

    return render_template("register.html")

@app.route("/projects")
def projects():
    if "user" not in session:
        return redirect("/")
    projects = Project.query.all()
    return render_template(
        "projects.html",
        projects=projects,
        is_admin=session.get("role") == "admin"
    )

@app.route("/admin/upload", methods=["GET", "POST"])
def upload_project():
    if session.get("role") != "admin":
        return "Access denied", 403

    if request.method == "POST":
        file = request.files["file"]
        thumb = request.files.get("thumbnail")

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)

        thumb_name = None
        if thumb and thumb.filename:
            thumb_name = secure_filename(thumb.filename)
            thumb_path = os.path.join(app.config["THUMB_FOLDER"], thumb_name)
            thumb.save(thumb_path)
            create_thumbnail(thumb_path, thumb_path)

        project = Project(
            title=request.form["title"],
            description=request.form["description"],
            filename=filename,
            thumbnail=thumb_name,
            uploaded_by=session["user"]
        )
        db.session.add(project)
        db.session.commit()

        return redirect("/projects")

    return render_template("upload.html")

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

@app.route("/uploads/thumbnails/<filename>")
def thumbnail_file(filename):
    return send_from_directory(app.config["THUMB_FOLDER"], filename)

# -------------------------------------------------
# START
# -------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_default_admin()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))