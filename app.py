# app.py
from __future__ import annotations

import functools
import os
import time
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import select, func

# --- Optional imports that must exist in your venv ---
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
except Exception as e:  # pragma: no cover
    boto3 = None
    BotoCoreError = ClientError = Exception
    _import_error = e  # used below to give a helpful error

db = SQLAlchemy()

ALLOWED_EXTENSIONS = {"csv", "xlsx", "xls", "txt", "pdf", "png", "jpg", "jpeg"}

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def create_app() -> Flask:
    app = Flask(__name__)

    # SECURITY: set a strong secret via env in production
    app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

    # Limit uploads (match this with your Nginx client_max_body_size)
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH_MB", "200")) * 1024 * 1024

    # --- Database (SQLite by default) ---
    base_dir = os.path.dirname(__file__)
    default_sqlite = f"sqlite:///{os.path.join(base_dir, 'app.db')}?check_same_thread=False"
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", default_sqlite)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    db.init_app(app)

    # --- S3 settings ---
    app.config["UPLOADS_BUCKET"] = os.environ.get("UPLOADS_BUCKET", "kelan-chris-email-pipeline")
    app.config["UPLOADS_PREFIX"] = os.environ.get("UPLOADS_PREFIX", "/raw_data/customers")
    app.config["AWS_REGION"] = os.environ.get("AWS_REGION")

    # Single S3 client. With an EC2 instance role, no keys are needed.
    if boto3 is None:
        raise RuntimeError(
            f"boto3 is required for uploads but is not installed: {_import_error}. "
            "Install it in your venv: pip install boto3"
        )
    s3 = boto3.client("s3", region_name=app.config["AWS_REGION"]) if app.config["AWS_REGION"] else boto3.client("s3")

    # --- Models ---
    class User(db.Model):
        __tablename__ = "user"
        id = db.Column(db.Integer, primary_key=True)
        username = db.Column(db.String(80), unique=True, nullable=False, index=True)
        password_hash = db.Column(db.String(255), nullable=False)

        def set_password(self, password: str) -> None:
            self.password_hash = generate_password_hash(password)

        def check_password(self, password: str) -> bool:
            return check_password_hash(self.password_hash, password)

    class Upload(db.Model):
        __tablename__ = "upload"
        id = db.Column(db.Integer, primary_key=True)
        user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
        original_name = db.Column(db.String(512), nullable=False)
        s3_key = db.Column(db.String(1024), nullable=False, unique=True)
        size_bytes = db.Column(db.Integer, nullable=True)
        content_type = db.Column(db.String(255), nullable=True)
        created_at = db.Column(db.DateTime, server_default=func.now(), nullable=False)

        user = db.relationship("User")

    # Make models reachable from app shell if needed
    app.User = User
    app.Upload = Upload

    with app.app_context():
        db.create_all()

    # --- Auth helper ---
    def login_required(view):
        @functools.wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("uid"):
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapped

    # --- Routes ---

    @app.route("/", methods=["GET"])
    def root():
        return redirect(url_for("upload") if session.get("uid") else url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            confirm = request.form.get("confirm") or ""

            if not username or not password:
                flash("Username and password are required.", "error")
                return redirect(url_for("register"))
            if password != confirm:
                flash("Passwords do not match.", "error")
                return redirect(url_for("register"))
            if db.session.execute(select(User).filter_by(username=username)).scalar_one_or_none():
                flash("Username already taken.", "error")
                return redirect(url_for("register"))

            u = User(username=username)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("login"))

        return render_template("register.html", title="Create Account")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            user = db.session.execute(select(User).filter_by(username=username)).scalar_one_or_none()
            if user and user.check_password(password):
                session["uid"] = user.id
                flash("Logged in!", "success")
                return redirect(request.args.get("next") or url_for("upload"))
            flash("Invalid username or password.", "error")
            return redirect(url_for("login"))

        return render_template("login.html", title="Login")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("Logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/upload", methods=["GET", "POST"])
    @login_required
    def upload():
        if request.method == "POST":
            f = request.files.get("file")
            if not f or f.filename == "":
                flash("Please choose a file.", "error")
                return redirect(url_for("upload"))
            if not allowed_file(f.filename):
                flash("File type not allowed.", "error")
                return redirect(url_for("upload"))

            #safe_name = secure_filename(f.filename)
            #uid = session["uid"]
            #ts = int(time.time())
            #prefix = app.config["UPLOADS_PREFIX"].rstrip("/")
            #s3_key = f"{prefix}/{uid}/{ts}_{safe_name}"
            
            #safe_name = secure_filename(f.filename)
            #uid = session["uid"]
            #prefix = app.config["UPLOADS_PREFIX"].rstrip("/")
            #s3_key = f"{prefix}/{uid}/{safe_name}"
            
            safe_name = secure_filename(f.filename)
            uid = session["uid"]
            # ensure prefix is 'rawData/customers'
            prefix = "/raw_data/customers/"
            s3_key = f"{prefix}/{uid}/{safe_name}"


            extra_args = {
                "Metadata": {"uploaded_by": str(uid), "original_name": safe_name}
            }
            if f.mimetype:
                extra_args["ContentType"] = f.mimetype

            try:
                s3.upload_fileobj(
                    Fileobj=f.stream,
                    Bucket=app.config["UPLOADS_BUCKET"],
                    Key=s3_key,
                    ExtraArgs=extra_args,
                )
            except (BotoCoreError, ClientError) as e:
                app.logger.exception("S3 upload failed")
                flash(f"S3 upload failed: {e}", "error")
                return redirect(url_for("upload"))

            size_bytes = request.content_length
            up = Upload(
                user_id=uid,
                original_name=safe_name,
                s3_key=s3_key,
                size_bytes=size_bytes,
                content_type=f.mimetype,
            )
            db.session.add(up)
            db.session.commit()

            session["last_upload_name"] = safe_name
            session["last_upload_s3key"] = s3_key

            flash(f"Uploaded {safe_name} to S3.", "success")
            return redirect(url_for("dashboard"))

        return render_template("upload.html", title="Upload or Connect")

    @app.route("/connect/klaviyo", methods=["POST"])
    @login_required
    def connect_klaviyo():
        flash("Klaviyo connection coming soon.", "info")
        return redirect(url_for("dashboard"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        uid = session["uid"]
        recent = db.session.execute(
            select(app.Upload).where(app.Upload.user_id == uid).order_by(app.Upload.created_at.desc()).limit(10)
        ).scalars().all()
        return render_template("dashboard.html", title="Dashboard", recent_uploads=recent)

    @app.route("/healthz")
    def healthz():
        return "ok", 200

    return app


# Gunicorn entrypoint
app = create_app()
