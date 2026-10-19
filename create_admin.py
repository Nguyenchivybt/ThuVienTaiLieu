
import sqlite3
from pathlib import Path
from getpass import getpass

from werkzeug.security import generate_password_hash

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "database.db"


def create_admin():
    if not DATABASE.exists():
        print("Chua co database.db. Hay chay init_db.py truoc.")
        return

    full_name = input("Ho va ten quan tri vien: ").strip()
    email = input("Email: ").strip().lower()
    username = input("Ten dang nhap: ").strip()
    password = getpass("Mat khau: ")
    confirm = getpass("Nhap lai mat khau: ")

    if not all([full_name, email, username, password, confirm]):
        print("Loi: Khong duoc de trong thong tin.")
        return

    if len(full_name) > 100:
        print("Loi: Ho ten qua dai.")
        return

    if len(email) > 254 or "@" not in email:
        print("Loi: Email khong hop le.")
        return

    if not username.isascii() or not __import__("re").fullmatch(
        r"[A-Za-z0-9_]{4,30}", username
    ):
        print("Loi: Ten dang nhap phai co 4-30 ky tu.")
        return

    if len(password) < 12:
        print("Loi: Mat khau admin phai co it nhat 12 ky tu.")
        return

    if password != confirm:
        print("Loi: Mat khau nhap lai khong khop.")
        return

    try:
        with sqlite3.connect(DATABASE) as conn:
            existing_admin = conn.execute(
                "SELECT 1 FROM users WHERE role = 'admin' LIMIT 1"
            ).fetchone()

            if existing_admin:
                print("Da co tai khoan admin. Khong tao them.")
                return

            conn.execute(
                """
                INSERT INTO users
                    (full_name, email, username, password_hash, role)
                VALUES (?, ?, ?, ?, 'admin')
                """,
                (
                    full_name,
                    email,
                    username,
                    generate_password_hash(password),
                ),
            )

        print("Tao tai khoan quan tri vien thanh cong!")

    except sqlite3.IntegrityError:
        print("Email hoac ten dang nhap da ton tai.")
    except sqlite3.Error as error:
        print(f"Loi SQLite: {error}")


if __name__ == "__main__":
    create_admin()
