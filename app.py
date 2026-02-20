# =========================
# IMPORTS (ONCE)
# =========================
import os
from flask import (
    Flask, render_template, request,
    redirect, session, send_from_directory
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# =========================
# BASE CONFIG
# =========================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")

ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "zip"}

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# =========================
# APP INIT
# =========================
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.path.join(BASE_DIR, "users.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

# =========================
# MODELS
# =========================
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(50), default="user")

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    filename = db.Column(db.String(300), nullable=False)
    uploaded_by = db.Column(db.String(80), nullable=False)

# =========================
# HELPERS
# =========================
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def create_default_admin():
    admin = User.query.filter_by(username="admin").first()
    if not admin:
        admin = User(
            username="admin",
            password=generate_password_hash("1234"),
            role="admin"
        )
        db.session.add(admin)
        db.session.commit()
        print("✅ Admin created: admin / 1234")

# =========================
# AUTH ROUTES
# =========================
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(username=request.form["username"]).first()
        if not user or not check_password_hash(user.password, request.form["password"]):
            return "Invalid credentials"

        session.clear()
        session["user"] = user.username
        session["role"] = user.role
        return redirect("/dashboard")

    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if User.query.filter_by(username=request.form["username"]).first():
            return "User already exists"

        user = User(
            username=request.form["username"],
            password=generate_password_hash(request.form["password"]),
            role="user"
        )
        db.session.add(user)
        db.session.commit()
        return redirect("/")

    return render_template("register.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# =========================
# DASHBOARD
# =========================
@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    return render_template("dashboard.html")

# =========================
# ADMIN
# =========================
@app.route("/admin/users")
def manage_users():
    if session.get("role") != "admin":
        return "Access denied", 403

    users = User.query.all()
    return render_template("users.html", users=users)

@app.route("/admin/promote/<int:user_id>")
def promote_user(user_id):
    if session.get("role") != "admin":
        return "Access denied", 403

    user = User.query.get(user_id)
    if user:
        user.role = "admin"
        db.session.commit()
    return redirect("/admin/users")

@app.route("/admin/demote/<int:user_id>")
def demote_user(user_id):
    if session.get("role") != "admin":
        return "Access denied", 403

    user = User.query.get(user_id)
    if user and user.username != session.get("user"):
        user.role = "user"
        db.session.commit()
    return redirect("/admin/users")

# =========================
# PROJECT UPLOAD
# =========================
@app.route("/admin/upload", methods=["GET", "POST"])
def upload_project():
    if session.get("role") != "admin":
        return "Access denied", 403

    if request.method == "POST":
        file = request.files.get("file")
        if not file or file.filename == "":
            return "No file selected"

        if not allowed_file(file.filename):
            return "File type not allowed"

        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

        project = Project(
            title=request.form["title"],
            description=request.form["description"],
            filename=filename,
            uploaded_by=session["user"]
        )
        db.session.add(project)
        db.session.commit()

        return redirect("/dashboard")

    return render_template("upload.html")

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# =========================
# START
# =========================
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        create_default_admin()
    app.run(debug=True)