import os
import re
import sqlite3
import uuid
from pathlib import Path
from functools import wraps
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, abort, send_from_directory
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
# =====================================================
# 1. CẤU HÌNH
# =====================================================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", str(BASE_DIR)))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE = DATA_DIR / "database.db"
UPLOAD_DIR = DATA_DIR / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
app = Flask(__name__)
# Set FLASK_SECRET_KEY in hosting; this fallback is only for local development.
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or "local-development-only-change-before-deploy"
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
app.config["UPLOAD_FOLDER"] = str(UPLOAD_DIR)
ALLOWED_EXTENSIONS = {"pdf", "docx"}
ROLE_NAMES = {
    "student": "Sinh viên",
    "lecturer": "Giảng viên",
    "admin": "Quản trị viên"
}
# =====================================================
# 2. DATABASE
# =====================================================
def get_db():
    conn = sqlite3.connect(str(DATABASE))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL DEFAULT '',
            email TEXT NOT NULL UNIQUE,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'student',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            is_locked INTEGER NOT NULL DEFAULT 0
        )
    """)
    user_columns = {
        row["name"]
        for row in conn.execute("PRAGMA table_info(users)").fetchall()
    }
    if "full_name" not in user_columns:
        conn.execute(
            "ALTER TABLE users ADD COLUMN full_name TEXT NOT NULL DEFAULT ''"
        )
    if "role" not in user_columns:
        conn.execute(
            "ALTER TABLE users ADD COLUMN role TEXT NOT NULL DEFAULT 'student'"
        )
    if "created_at" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN created_at TEXT")
    if "is_locked" not in user_columns:
        conn.execute(
            "ALTER TABLE users ADD COLUMN is_locked INTEGER NOT NULL DEFAULT 0"
        )
    conn.execute("""
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT DEFAULT '',
            faculty TEXT DEFAULT '',
            major TEXT DEFAULT '',
            cohort TEXT DEFAULT '',
            class_name TEXT DEFAULT '',
            category TEXT DEFAULT '',
            original_filename TEXT NOT NULL,
            stored_filename TEXT NOT NULL UNIQUE,
            file_format TEXT NOT NULL,
            uploaded_by INTEGER NOT NULL,
            downloads INTEGER NOT NULL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users(id)
                ON DELETE RESTRICT
        )
    """)
    conn.commit()
    conn.close()
# =====================================================
# 3. TIỆN ÍCH
# =====================================================
def valid_email(email):
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email or ""))
def valid_username(username):
    return bool(re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username or ""))
def allowed_file(filename):
    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )
def save_uploaded_file(file):
    if not file or not file.filename:
        raise ValueError("Vui lòng chọn tài liệu.")
    original = secure_filename(file.filename)
    if not original or not allowed_file(original):
        raise ValueError("Chỉ chấp nhận PDF hoặc DOCX.")
    extension = original.rsplit(".", 1)[1].lower()
    stored = f"{uuid.uuid4().hex}.{extension}"
    path = UPLOAD_DIR / stored
    file.save(str(path))
    try:
        with open(path, "rb") as f:
            header = f.read(8)
        if extension == "pdf" and not header.startswith(b"%PDF-"):
            raise ValueError("Nội dung tệp không đúng định dạng PDF.")
        if extension == "docx" and not header.startswith(b"PK\x03\x04"):
            raise ValueError("Nội dung tệp không đúng định dạng DOCX.")
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return original, stored, extension.upper()
def get_current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    conn.close()
    if user is None or user["is_locked"]:
        session.clear()
        return None
    # Trả về một bản dict thống nhất cho các template.
    user_data = dict(user)
    full_name = (user_data.get("full_name") or "").strip()
    username = (user_data.get("username") or "").strip()
    # Nếu họ tên bị trống, dùng tên đăng nhập làm phương án dự phòng.
    user_data["display_name"] = full_name or username or "Người dùng"
    return user_data
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if get_current_user() is None:
            flash("Vui lòng đăng nhập để tiếp tục.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped
def role_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = get_current_user()
            if user is None:
                flash("Vui lòng đăng nhập.", "warning")
                return redirect(url_for("login"))
            if user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator
def get_document(document_id):
    conn = get_db()
    document = conn.execute("""
        SELECT d.*, u.full_name AS uploader_name
        FROM documents d
        JOIN users u ON u.id = d.uploaded_by
        WHERE d.id = ?
    """, (document_id,)).fetchone()
    conn.close()
    return document
def can_manage_document(document, user):
    return (
        user["role"] == "admin"
        or (
            user["role"] == "lecturer"
            and document["uploaded_by"] == user["id"]
        )
    )
# =====================================================
# 4. TRANG CHỦ
# =====================================================
@app.route("/")
def home():
    current_user = get_current_user()
    keyword = request.args.get("keyword", "").strip()
    category = request.args.get("category", "").strip()
    faculty = request.args.get("faculty", "").strip()
    major = request.args.get("major", "").strip()
    cohort = request.args.get("cohort", "").strip()
    class_name = request.args.get("class_name", "").strip()
    file_format = request.args.get("format", "").strip().upper()
    sql = """
        SELECT d.*, u.full_name AS uploader_name
        FROM documents d
        JOIN users u ON u.id = d.uploaded_by
        WHERE 1 = 1
    """
    params = []
    if keyword:
        sql += """
            AND (
                d.title LIKE ? OR d.description LIKE ?
                OR d.faculty LIKE ? OR d.major LIKE ?
                OR d.category LIKE ? OR d.cohort LIKE ?
                OR d.class_name LIKE ?
            )
        """
        params.extend([f"%{keyword}%"] * 7)
    for column, value in [
        ("category", category),
        ("faculty", faculty),
        ("major", major),
        ("cohort", cohort),
        ("class_name", class_name)
    ]:
        if value:
            sql += f" AND d.{column} = ?"
            params.append(value)
    if file_format in ("PDF", "DOCX"):
        sql += " AND d.file_format = ?"
        params.append(file_format)
    sql += " ORDER BY d.created_at DESC"
    conn = get_db()
    documents = conn.execute(sql, params).fetchall()
    categories = [
        row["category"] for row in conn.execute("""
            SELECT DISTINCT category FROM documents
            WHERE category <> '' ORDER BY category
        """).fetchall()
    ]
    faculties = [
        row["faculty"] for row in conn.execute("""
            SELECT DISTINCT faculty FROM documents
            WHERE faculty <> '' ORDER BY faculty
        """).fetchall()
    ]
    conn.close()
    return render_template(
        "index.html",
        documents=documents,
        categories=categories,
        faculties=faculties,
        keyword=keyword,
        selected_category=category,
        selected_faculty=faculty,
        selected_major=major,
        selected_cohort=cohort,
        selected_class_name=class_name,
        selected_format=file_format,
        total_documents=len(documents),
        current_user=current_user
    )
# =====================================================
# 5. ĐĂNG KÝ
# =====================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm = request.form.get(
            "confirm_password",
            request.form.get("password_confirm", "")
        )
        if not all([full_name, email, username, password]):
            flash("Vui lòng nhập đầy đủ thông tin.", "danger")
            return render_template("register.html")
        if not valid_email(email):
            flash("Email không hợp lệ.", "danger")
            return render_template("register.html")
        if not valid_username(username):
            flash("Tên đăng nhập phải có 3–30 ký tự hợp lệ.", "danger")
            return render_template("register.html")
        if len(password) < 8:
            flash("Mật khẩu phải có ít nhất 8 ký tự.", "danger")
            return render_template("register.html")
        if password != confirm:
            flash("Hai mật khẩu không khớp.", "danger")
            return render_template("register.html")
        conn = get_db()
        try:
            conn.execute("""
                INSERT INTO users (
                    full_name, email, username, password_hash, role
                )
                VALUES (?, ?, ?, ?, 'student')
            """, (
                full_name,
                email,
                username,
                generate_password_hash(password)
            ))
            conn.commit()
            flash("Đăng ký thành công. Hãy đăng nhập.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email hoặc tên đăng nhập đã tồn tại.", "danger")
        finally:
            conn.close()
    return render_template("register.html")
# =====================================================
# 6. ĐĂNG NHẬP / ĐĂNG XUẤT
# =====================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        identifier = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("""
            SELECT * FROM users
            WHERE username = ? OR email = ?
        """, (identifier, identifier.lower())).fetchone()
        conn.close()
        if user is None or not check_password_hash(
            user["password_hash"], password
        ):
            flash("Tên đăng nhập hoặc mật khẩu không đúng.", "danger")
            return render_template("login.html")
        if user["is_locked"]:
            flash("Tài khoản đã bị khóa.", "danger")
            return render_template("login.html")
        session.clear()
        session["user_id"] = user["id"]
        flash("Đăng nhập thành công.", "success")
        if user["role"] == "admin":
            return redirect(url_for("admin_page"))
        return redirect(url_for("home"))
    return render_template("login.html")
@app.route("/logout", methods=["GET", "POST"])
@login_required
def logout():
    session.clear()
    flash("Bạn đã đăng xuất.", "success")
    return redirect(url_for("login"))
# =====================================================
# 7. TÀI KHOẢN
# =====================================================
@app.route("/account")
@login_required
def account():
    current_user = get_current_user()
    if current_user is None:
        return redirect(url_for("login"))
    return render_template(
        "account.html",
        current_user=current_user
    )
# =====================================================
# 8. QUẢN TRỊ TÀI KHOẢN
# =====================================================
@app.route("/admin")
@role_required("admin")
def admin_page():
    keyword = request.args.get("keyword", "").strip()
    role = request.args.get("role", "").strip()
    status = request.args.get("status", "").strip()
    sql = "SELECT * FROM users WHERE 1=1"
    params = []
    if keyword:
        sql += " AND (full_name LIKE ? OR email LIKE ? OR username LIKE ?)"
        term = f"%{keyword}%"
        params.extend([term, term, term])
    if role in ROLE_NAMES:
        sql += " AND role = ?"
        params.append(role)
    if status == "locked":
        sql += " AND is_locked = 1"
    elif status == "active":
        sql += " AND is_locked = 0"
    sql += " ORDER BY id DESC"
    conn = get_db()
    users = conn.execute(sql, params).fetchall()
    stats = {
        "total_users": conn.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0],
        "students": conn.execute(
            "SELECT COUNT(*) FROM users WHERE role='student'"
        ).fetchone()[0],
        "lecturers": conn.execute(
            "SELECT COUNT(*) FROM users WHERE role='lecturer'"
        ).fetchone()[0],
        "admins": conn.execute(
            "SELECT COUNT(*) FROM users WHERE role='admin'"
        ).fetchone()[0],
        "locked_users": conn.execute(
            "SELECT COUNT(*) FROM users WHERE is_locked=1"
        ).fetchone()[0]
    }
    conn.close()
    return render_template(
        "admin.html",
        users=users,
        stats=stats,
        keyword=keyword,
        selected_role=role,
        selected_status=status,
        current_user=get_current_user()
    )
@app.route("/admin/users/add", methods=["POST"])
@role_required("admin")
def admin_add_user():
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "student").strip()
    if not all([full_name, email, username, password]):
        flash("Vui lòng nhập đầy đủ thông tin.", "danger")
        return redirect(url_for("admin_page"))
    if not valid_email(email) or not valid_username(username):
        flash("Email hoặc tên đăng nhập không hợp lệ.", "danger")
        return redirect(url_for("admin_page"))
    if len(password) < 8 or role not in ROLE_NAMES:
        flash("Mật khẩu hoặc vai trò không hợp lệ.", "danger")
        return redirect(url_for("admin_page"))
    conn = get_db()
    try:
        conn.execute("""
            INSERT INTO users (
                full_name, email, username, password_hash, role
            ) VALUES (?, ?, ?, ?, ?)
        """, (
            full_name, email, username,
            generate_password_hash(password), role
        ))
        conn.commit()
        flash("Đã thêm tài khoản.", "success")
    except sqlite3.IntegrityError:
        flash("Email hoặc tên đăng nhập đã tồn tại.", "danger")
    finally:
        conn.close()
    return redirect(url_for("admin_page"))
@app.route("/admin/users/<int:user_id>/edit", methods=["POST"])
@role_required("admin")
def admin_edit_user(user_id):
    admin = get_current_user()
    full_name = request.form.get("full_name", "").strip()
    email = request.form.get("email", "").strip().lower()
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "").strip()
    password = request.form.get("password", "")
    if not all([full_name, email, username]):
        flash("Vui lòng nhập đầy đủ thông tin.", "danger")
        return redirect(url_for("admin_page"))
    if not valid_email(email) or not valid_username(username):
        flash("Email hoặc tên đăng nhập không hợp lệ.", "danger")
        return redirect(url_for("admin_page"))
    if role not in ROLE_NAMES or (password and len(password) < 8):
        flash("Vai trò hoặc mật khẩu không hợp lệ.", "danger")
        return redirect(url_for("admin_page"))
    conn = get_db()
    target = conn.execute(
        "SELECT * FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if target is None:
        conn.close()
        abort(404)
    if target["id"] == admin["id"] and role != "admin":
        conn.close()
        flash("Không thể tự hạ quyền quản trị viên.", "danger")
        return redirect(url_for("admin_page"))
    if target["role"] == "admin" and role != "admin":
        count = conn.execute("""
            SELECT COUNT(*) FROM users
            WHERE role='admin' AND is_locked=0
        """).fetchone()[0]
        if count <= 1:
            conn.close()
            flash("Không thể hạ quyền quản trị viên cuối cùng.", "danger")
            return redirect(url_for("admin_page"))
    try:
        if password:
            conn.execute("""
                UPDATE users
                SET full_name=?, email=?, username=?, role=?, password_hash=?
                WHERE id=?
            """, (
                full_name, email, username, role,
                generate_password_hash(password), user_id
            ))
        else:
            conn.execute("""
                UPDATE users
                SET full_name=?, email=?, username=?, role=?
                WHERE id=?
            """, (full_name, email, username, role, user_id))
        conn.commit()
        flash("Đã cập nhật tài khoản.", "success")
    except sqlite3.IntegrityError:
        flash("Email hoặc tên đăng nhập đã tồn tại.", "danger")
    finally:
        conn.close()
    return redirect(url_for("admin_page"))
@app.route("/admin/users/<int:user_id>/toggle-lock", methods=["POST"])
@role_required("admin")
def admin_toggle_lock(user_id):
    admin = get_current_user()
    conn = get_db()
    target = conn.execute(
        "SELECT * FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if target is None:
        conn.close()
        abort(404)
    if target["id"] == admin["id"]:
        conn.close()
        flash("Không thể khóa tài khoản đang đăng nhập.", "danger")
        return redirect(url_for("admin_page"))
    if target["role"] == "admin" and not target["is_locked"]:
        count = conn.execute("""
            SELECT COUNT(*) FROM users
            WHERE role='admin' AND is_locked=0
        """).fetchone()[0]
        if count <= 1:
            conn.close()
            flash("Không thể khóa quản trị viên cuối cùng.", "danger")
            return redirect(url_for("admin_page"))
    new_status = 0 if target["is_locked"] else 1
    conn.execute(
        "UPDATE users SET is_locked=? WHERE id=?",
        (new_status, user_id)
    )
    conn.commit()
    conn.close()
    flash("Đã cập nhật trạng thái tài khoản.", "success")
    return redirect(url_for("admin_page"))
@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@role_required("admin")
def admin_delete_user(user_id):
    admin = get_current_user()
    conn = get_db()
    target = conn.execute(
        "SELECT * FROM users WHERE id=?", (user_id,)
    ).fetchone()
    if target is None:
        conn.close()
        abort(404)
    if target["id"] == admin["id"]:
        conn.close()
        flash("Không thể xóa tài khoản đang đăng nhập.", "danger")
        return redirect(url_for("admin_page"))
    if target["role"] == "admin":
        count = conn.execute(
            "SELECT COUNT(*) FROM users WHERE role='admin'"
        ).fetchone()[0]
        if count <= 1:
            conn.close()
            flash("Không thể xóa quản trị viên cuối cùng.", "danger")
            return redirect(url_for("admin_page"))
    count_docs = conn.execute(
        "SELECT COUNT(*) FROM documents WHERE uploaded_by=?",
        (user_id,)
    ).fetchone()[0]
    if count_docs:
        conn.close()
        flash("Tài khoản có tài liệu đã tải lên, chưa thể xóa.", "danger")
        return redirect(url_for("admin_page"))
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    flash("Đã xóa tài khoản.", "success")
    return redirect(url_for("admin_page"))
# =====================================================
# 9. QUẢN LÝ TÀI LIỆU
# =====================================================
@app.route("/documents/manage")
@role_required("admin", "lecturer")
def manage_documents():
    user = get_current_user()
    keyword = request.args.get("keyword", "").strip()
    sql = """
        SELECT d.*, u.full_name AS uploader_name
        FROM documents d
        JOIN users u ON u.id=d.uploaded_by
        WHERE 1=1
    """
    params = []
    if user["role"] == "lecturer":
        sql += " AND d.uploaded_by=?"
        params.append(user["id"])
    if keyword:
        sql += " AND (d.title LIKE ? OR d.description LIKE ?)"
        params.extend([f"%{keyword}%", f"%{keyword}%"])
    sql += " ORDER BY d.created_at DESC"
    conn = get_db()
    documents = conn.execute(sql, params).fetchall()
    conn.close()
    return render_template(
        "documents_manage.html",
        documents=documents,
        current_user=user,
        keyword=keyword
    )
@app.route("/documents/upload", methods=["POST"])
@role_required("admin", "lecturer")
def upload_document():
    user = get_current_user()
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    faculty = request.form.get("faculty", "").strip()
    major = request.form.get("major", "").strip()
    cohort = request.form.get("cohort", "").strip()
    class_name = request.form.get("class_name", "").strip()
    category = request.form.get("category", "").strip()
    if not title or len(title) > 200:
        flash("Tên tài liệu không hợp lệ.", "danger")
        return redirect(url_for("manage_documents"))
    saved_path = None
    conn = None
    try:
        original, stored, extension = save_uploaded_file(
            request.files.get("file")
        )
        saved_path = UPLOAD_DIR / stored
        conn = get_db()
        conn.execute("""
            INSERT INTO documents (
                title, description, faculty, major, cohort,
                class_name, category, original_filename,
                stored_filename, file_format, uploaded_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            title, description, faculty, major, cohort,
            class_name, category, original, stored,
            extension, user["id"]
        ))
        conn.commit()
        flash("Đã tải tài liệu lên.", "success")
    except (ValueError, OSError, sqlite3.Error) as error:
        if saved_path:
            saved_path.unlink(missing_ok=True)
        flash(f"Không thể tải tài liệu: {error}", "danger")
    finally:
        if conn:
            conn.close()
    return redirect(url_for("manage_documents"))
@app.route("/documents/<int:document_id>/edit", methods=["POST"])
@role_required("admin", "lecturer")
def edit_document(document_id):
    user = get_current_user()
    document = get_document(document_id)
    if document is None:
        abort(404)
    if not can_manage_document(document, user):
        abort(403)
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    faculty = request.form.get("faculty", "").strip()
    major = request.form.get("major", "").strip()
    cohort = request.form.get("cohort", "").strip()
    class_name = request.form.get("class_name", "").strip()
    category = request.form.get("category", "").strip()
    file = request.files.get("file")
    if not title or len(title) > 200:
        flash("Tên tài liệu không hợp lệ.", "danger")
        return redirect(url_for("manage_documents"))
    new_path = None
    conn = None
    try:
        if file and file.filename:
            original, stored, extension = save_uploaded_file(file)
            new_path = UPLOAD_DIR / stored
        else:
            original = document["original_filename"]
            stored = document["stored_filename"]
            extension = document["file_format"]
        conn = get_db()
        conn.execute("""
            UPDATE documents
            SET title=?, description=?, faculty=?, major=?,
                cohort=?, class_name=?, category=?,
                original_filename=?, stored_filename=?, file_format=?,
                updated_at=CURRENT_TIMESTAMP
            WHERE id=?
        """, (
            title, description, faculty, major, cohort,
            class_name, category, original, stored,
            extension, document_id
        ))
        conn.commit()
        if new_path:
            (UPLOAD_DIR / document["stored_filename"]).unlink(missing_ok=True)
        flash("Đã cập nhật tài liệu.", "success")
    except (ValueError, OSError, sqlite3.Error) as error:
        if new_path:
            new_path.unlink(missing_ok=True)
        flash(f"Không thể cập nhật tài liệu: {error}", "danger")
    finally:
        if conn:
            conn.close()
    return redirect(url_for("manage_documents"))
@app.route("/documents/<int:document_id>/delete", methods=["POST"])
@role_required("admin", "lecturer")
def delete_document(document_id):
    user = get_current_user()
    document = get_document(document_id)
    if document is None:
        abort(404)
    if not can_manage_document(document, user):
        abort(403)
    conn = get_db()
    conn.execute("DELETE FROM documents WHERE id=?", (document_id,))
    conn.commit()
    conn.close()
    (UPLOAD_DIR / document["stored_filename"]).unlink(missing_ok=True)
    flash("Đã xóa tài liệu.", "success")
    return redirect(url_for("manage_documents"))
@app.route("/documents/<int:document_id>/download")
@login_required
def download_document(document_id):
    document = get_document(document_id)
    if document is None:
        abort(404)
    path = UPLOAD_DIR / document["stored_filename"]
    if not path.is_file():
        flash("Tệp không còn tồn tại.", "danger")
        return redirect(url_for("home"))
    conn = get_db()
    conn.execute(
        "UPDATE documents SET downloads=downloads+1 WHERE id=?",
        (document_id,)
    )
    conn.commit()
    conn.close()
    return send_from_directory(
        str(UPLOAD_DIR),
        document["stored_filename"],
        as_attachment=True,
        download_name=document["original_filename"]
    )
# =====================================================
# 10. XỬ LÝ LỖI
# =====================================================
@app.errorhandler(403)
def forbidden(error):
    return render_template(
        "error.html",
        code=403,
        message="Bạn không có quyền truy cập chức năng này."
    ), 403
@app.errorhandler(404)
def not_found(error):
    return render_template(
        "error.html",
        code=404,
        message="Không tìm thấy trang hoặc tài liệu."
    ), 404
@app.errorhandler(413)
def file_too_large(error):
    flash("Tệp vượt quá giới hạn 16 MB.", "danger")
    return redirect(request.referrer or url_for("home"))
# =====================================================
# 11. KHỞI CHẠY
# =====================================================
if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=True)
