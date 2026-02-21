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

# Fix postgres URL for SQLAlchemy if needed
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# UPLOADS
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
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
    thumbnail = db.Column(db.String(300), nullable=True)
    uploaded_by = db.Column(db.String(150), nullable=False)

# -------------------------------------------------
# HELPERS
# -------------------------------------------------
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def create_thumbnail(input_path, output_path, size=(300, 200)):
    try:
        with Image.open(input_path) as img:
            img.thumbnail(size)
            img.save(output_path)
    except Exception as e:
        print(f"⚠️ Thumbnail creation failed: {e}")

# -------------------------------------------------
# ADMIN CREATION
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
        print("✅ Admin user created securely")
    else:
        print("ℹ️ Admin already exists")

# -------------------------------------------------
# ROUTES
# -------------------------------------------------
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            return "Invalid credentials", 401
        if not user.approved:
            return "Account pending admin approval", 403
        session.clear()
        session["user"] = user.username
        session["role"] = user.role
        return redirect("/dashboard")
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        if User.query.filter_by(username=username).first():
            return "User already exists", 400
        user = User(
            username=username,
            password=generate_password_hash(request.form["password"]),
            role="user",
            approved=False
        )
        db.session.add(user)
        db.session.commit()
        return "Registration successful. Await admin approval."
    return render_template("register.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/")
    projects = Project.query.all()
    is_admin = session.get("role") == "admin"
    return render_template("dashboard.html", projects=projects, is_admin=is_admin)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# ----------------- ADMIN ROUTES -----------------
@app.route("/admin/users")
def manage_users():
    if session.get("role") != "admin":
        return "Access denied", 403
    users = User.query.all()
    return render_template("users.html", users=users)

@app.route("/admin/approve/<int:user_id>")
def approve_user(user_id):
    if session.get("role") != "admin":
        return "Access denied", 403
    user = User.query.get_or_404(user_id)
    user.approved = True
    db.session.commit()
    return redirect("/admin/users")

@app.route("/admin/promote/<int:user_id>")
def promote_user(user_id):
    if session.get("role") != "admin":
        return "Access denied", 403
    user = User.query.get_or_404(user_id)
    user.role = "admin"
    db.session.commit()
    return redirect("/admin/users")

@app.route("/admin/upload", methods=["GET", "POST"])
def upload_project():
    if session.get("role") != "admin":
        return "Access denied", 403
    if request.method == "POST":
        file = request.files.get("file")
        title = request.form["title"]
        description = request.form["description"]
        if not file or file.filename == "":
            return "No file selected", 400
        if not allowed_file(file.filename):
            return "File type not allowed", 400

        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
        file.save(file_path)

        # Create thumbnail if image
        thumbnail_path = None
        thumbnail_name = None
        if filename.rsplit(".", 1)[1].lower() in {"png", "jpg", "jpeg"}:
            thumbnail_name = f"thumb_{filename}"
            thumbnail_path = os.path.join(app.config["UPLOAD_FOLDER"], thumbnail_name)
            create_thumbnail(file_path, thumbnail_path)

        project = Project(
            title=title,
            description=description,
            filename=filename,
            thumbnail=thumbnail_name if thumbnail_path else None,
            uploaded_by=session["user"]
        )
        db.session.add(project)
        db.session.commit()
        return redirect("/dashboard")
    return render_template("upload.html")

@app.route("/uploads/<filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# -------------------------------------------------
# STARTUP
# -------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        # DROP and RECREATE tables to include the new thumbnail column
        db.drop_all()
        db.create_all()
        create_default_admin()
    app.run(debug=True)