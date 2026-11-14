import os
import sqlite3
import secrets
import hashlib
import hmac
import uuid
from functools import wraps
from pathlib import Path

from flask import Flask, request, jsonify, session, render_template, g
from werkzeug.utils import secure_filename

app = Flask(__name__)

app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
    MAX_CONTENT_LENGTH=8 * 1024 * 1024
)

DB = os.environ.get("DATABASE_PATH", "swall.sqlite3")

UPLOAD_DIR = Path(app.root_path) / "static" / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

OWNER_LOGIN = os.environ.get("OWNER_LOGIN", "SantasWall2006")
OWNER_PASSWORD = os.environ.get("OWNER_PASSWORD", "Slojenikina2006")

READER_LOGIN = os.environ.get("READER_LOGIN", "SantasWall2011")
READER_PASSWORD = os.environ.get("READER_PASSWORD", "Slojenikina2011")

ALLOWED = {"png", "jpg", "jpeg", "webp", "gif"}


# =========================
# ПАРОЛИ
# =========================

def pw_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)

    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        310000
    ).hex()

    return salt + "$" + digest


def verify(password, stored):
    try:
        salt, expected = stored.split("$", 1)

        actual = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            310000
        ).hex()

        return hmac.compare_digest(actual, expected)

    except (ValueError, AttributeError, TypeError):
        return False


# =========================
# БАЗА ДАННЫХ
# =========================

def conn():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")

    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)

    if db is not None:
        db.close()


def add_missing_columns(db, table, columns):
    existing = {
        row["name"]
        for row in db.execute(f"PRAGMA table_info({table})")
    }

    for name, sql_type in columns.items():
        if name not in existing:
            db.execute(
                f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"
            )


def init():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")

    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY,
        login TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'reader',
        bio TEXT DEFAULT '',
        avatar TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS works(
        id INTEGER PRIMARY KEY,
        title TEXT NOT NULL,
        kind TEXT DEFAULT 'Новелла',
        genre TEXT DEFAULT '',
        description TEXT DEFAULT '',
        author TEXT DEFAULT ''
    );

    CREATE TABLE IF NOT EXISTS chapters(
        id INTEGER PRIMARY KEY,
        work_id INTEGER NOT NULL,
        title TEXT DEFAULT '',
        body TEXT DEFAULT '',
        FOREIGN KEY(work_id)
        REFERENCES works(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS comments(
        id INTEGER PRIMARY KEY,
        work_id INTEGER NOT NULL,
        author TEXT DEFAULT '',
        body TEXT DEFAULT '',
        FOREIGN KEY(work_id)
        REFERENCES works(id) ON DELETE CASCADE
    );
    """)

    add_missing_columns(db, "users", {
        "role": "TEXT NOT NULL DEFAULT 'reader'",
        "bio": "TEXT DEFAULT ''",
        "avatar": "TEXT DEFAULT ''"
    })

    add_missing_columns(db, "works", {
        "kind": "TEXT DEFAULT 'Новелла'",
        "genre": "TEXT DEFAULT ''",
        "description": "TEXT DEFAULT ''",
        "author": "TEXT DEFAULT ''",
        "cover": "TEXT DEFAULT ''",
        "views": "INTEGER DEFAULT 0",
        "created_at": "TEXT DEFAULT ''"
    })

    add_missing_columns(db, "chapters", {
        "title": "TEXT DEFAULT ''",
        "body": "TEXT DEFAULT ''"
    })

    add_missing_columns(db, "comments", {
        "author": "TEXT DEFAULT ''",
        "body": "TEXT DEFAULT ''"
    })

    db.execute("""
        UPDATE works
        SET created_at=CURRENT_TIMESTAMP
        WHERE created_at IS NULL OR created_at=''
    """)

    db.executescript("""
    CREATE TABLE IF NOT EXISTS follows(
        follower_id INTEGER NOT NULL,
        followed_id INTEGER NOT NULL,
        UNIQUE(follower_id, followed_id),
        FOREIGN KEY(follower_id)
        REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(followed_id)
        REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS favorites(
        user_id INTEGER NOT NULL,
        work_id INTEGER NOT NULL,
        UNIQUE(user_id, work_id),
        FOREIGN KEY(user_id)
        REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY(work_id)
        REFERENCES works(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS reading_views(
        id INTEGER PRIMARY KEY,
        work_id INTEGER NOT NULL,
        visitor TEXT NOT NULL,
        UNIQUE(work_id, visitor),
        FOREIGN KEY(work_id)
        REFERENCES works(id) ON DELETE CASCADE
    );
    """)

    # Создание аккаунта владельца
    owner = db.execute(
        "SELECT id FROM users WHERE login=? COLLATE NOCASE",
        (OWNER_LOGIN,)
    ).fetchone()

    if owner:
        db.execute(
            "UPDATE users SET role='owner', password_hash=? WHERE id=?",
            (pw_hash(OWNER_PASSWORD), owner["id"])
        )
    else:
        db.execute(
            """
            INSERT INTO users(login,password_hash,role)
            VALUES(?,?,?)
            """,
            (OWNER_LOGIN, pw_hash(OWNER_PASSWORD), "owner")
        )

    # Создание аккаунта читателя
    reader = db.execute(
        "SELECT id FROM users WHERE login=? COLLATE NOCASE",
        (READER_LOGIN,)
    ).fetchone()

    if reader:
        db.execute(
            "UPDATE users SET role='reader', password_hash=? WHERE id=?",
            (pw_hash(READER_PASSWORD), reader["id"])
        )
    else:
        db.execute(
            """
            INSERT INTO users(login,password_hash,role)
            VALUES(?,?,?)
            """,
            (READER_LOGIN, pw_hash(READER_PASSWORD), "reader")
        )

    # Стартовые произведения
    if db.execute("SELECT COUNT(*) FROM works").fetchone()[0] == 0:

        db.executemany(
            """
            INSERT INTO works(title,kind,genre,description,author)
            VALUES(?,?,?,?,?)
            """,
            [
                (
                    "Тень в моём сердце",
                    "Новелла",
                    "Романтика · Драма",
                    "Она была светом в его тьме. История о любви, которая родилась между болью и надеждой.",
                    "S. 壁"
                ),
                (
                    "Ледяная клятва",
                    "Манхва",
                    "Фэнтези · Приключения",
                    "Клятва, данная среди вечных снегов. Древняя магия пробуждается вместе с наследником забытого престола.",
                    "S. 壁"
                ),
                (
                    "Белый лотос",
                    "Новелла",
                    "Фэнтези · Романтика",
                    "Легенда о цветке, который расцветает лишь однажды за тысячу лет.",
                    "S. 壁"
                ),
                (
                    "Пепел и звёзды",
                    "Манхва",
                    "Мистика · Драма",
                    "В городе, где звёзды больше не отражаются в воде, кто-то помнит настоящее небо.",
                    "S. 壁"
                )
            ]
        )

    db.commit()
    db.close()


# =========================
# ПОЛЬЗОВАТЕЛИ
# =========================

def current_user():
    uid = session.get("uid")

    if not uid:
        return None

    return conn().execute(
        """
        SELECT id,login,role,bio,avatar
        FROM users
        WHERE id=?
        """,
        (uid,)
    ).fetchone()


def require(role=None):

    def deco(fn):

        @wraps(fn)
        def wrapped(*args, **kwargs):

            user = current_user()

            if not user:
                return jsonify(
                    error="Сначала войдите в аккаунт."
                ), 401

            if role == "owner" and user["role"] != "owner":
                return jsonify(
                    error="Доступ только владельцу."
                ), 403

            return fn(*args, **kwargs)

        return wrapped

    return deco


def json_data():
    data = request.get_json(silent=True)

    return data if isinstance(data, dict) else {}


# =========================
# ГЛАВНАЯ
# =========================

@app.get("/")
def index():
    return render_template("index.html")


@app.get("/health")
def health():
    return jsonify(ok=True)


# =========================
# АВТОРИЗАЦИЯ
# =========================

@app.get("/api/me")
def api_me():

    user = current_user()

    return jsonify(
        user=dict(user) if user else None
    )


@app.post("/api/register")
def register():

    data = json_data()

    login_name = str(data.get("login", "")).strip()
    password = str(data.get("password", ""))

    if len(login_name) < 3 or len(login_name) > 40:
        return jsonify(
            error="Логин должен содержать от 3 до 40 символов."
        ), 400

    if len(password) < 8:
        return jsonify(
            error="Пароль должен содержать минимум 8 символов."
        ), 400

    if login_name.casefold() in {
        OWNER_LOGIN.casefold(),
        READER_LOGIN.casefold()
    }:
        return jsonify(
            error="Этот логин зарезервирован."
        ), 400

    try:

        cur = conn().execute(
            """
            INSERT INTO users(login,password_hash,role)
            VALUES(?,?,?)
            """,
            (login_name, pw_hash(password), "reader")
        )

        conn().commit()

        session.clear()
        session["uid"] = cur.lastrowid

        return jsonify(
            ok=True,
            user={
                "login": login_name,
                "role": "reader"
            }
        )

    except sqlite3.IntegrityError:

        return jsonify(
            error="Такой логин уже занят."
        ), 409


@app.post("/api/login")
def login():

    data = json_data()

    login_name = str(data.get("login", "")).strip()
    password = str(data.get("password", ""))

    if not login_name or not password:
        return jsonify(
            error="Введите логин и пароль."
        ), 400

    user = conn().execute(
        """
        SELECT *
        FROM users
        WHERE login=? COLLATE NOCASE
        """,
        (login_name,)
    ).fetchone()

    if not user or not verify(password, user["password_hash"]):

        return jsonify(
            error="Неверный логин или пароль."
        ), 401

    session.clear()
    session["uid"] = user["id"]

    return jsonify(
        ok=True,
        user={
            "login": user["login"],
            "role": user["role"]
        }
    )


@app.post("/api/logout")
def logout():

    session.clear()

    return jsonify(ok=True)


# =========================
# ПРОИЗВЕДЕНИЯ
# =========================

@app.get("/api/works")
def works():

    rows = conn().execute("""
        SELECT w.*,
        (
            SELECT COUNT(*)
            FROM chapters c
            WHERE c.work_id=w.id
        ) AS chapter_count
        FROM works w
        ORDER BY w.id DESC
    """).fetchall()

    return jsonify(
        works=[dict(row) for row in rows]
    )


@app.get("/api/works/<int:work_id>")
def work_detail(work_id):

    db = conn()

    work = db.execute(
        "SELECT * FROM works WHERE id=?",
        (work_id,)
    ).fetchone()

    if not work:
        return jsonify(
            error="Произведение не найдено."
        ), 404

    visitor = str(
        session.get("uid")
        or session.get("visitor_id")
        or ""
    )

    if not visitor:
        visitor = secrets.token_urlsafe(18)
        session["visitor_id"] = visitor

    db.execute(
        """
        INSERT OR IGNORE INTO reading_views(work_id,visitor)
        VALUES(?,?)
        """,
        (work_id, visitor)
    )

    db.execute(
        """
        UPDATE works
        SET views=(
            SELECT COUNT(*)
            FROM reading_views
            WHERE work_id=?
        )
        WHERE id=?
        """,
        (work_id, work_id)
    )

    db.commit()

    chapters = db.execute(
        "SELECT * FROM chapters WHERE work_id=? ORDER BY id",
        (work_id,)
    ).fetchall()

    comments = db.execute(
        "SELECT * FROM comments WHERE work_id=? ORDER BY id DESC",
        (work_id,)
    ).fetchall()

    updated_work = db.execute(
        "SELECT * FROM works WHERE id=?",
        (work_id,)
    ).fetchone()

    return jsonify(
        work=dict(updated_work),
        chapters=[dict(row) for row in chapters],
        comments=[dict(row) for row in comments]
    )


@app.get("/api/chapters/<int:chapter_id>")
def get_chapter(chapter_id):

    chapter = conn().execute(
        "SELECT * FROM chapters WHERE id=?",
        (chapter_id,)
    ).fetchone()

    if not chapter:
        return jsonify(
            error="Глава не найдена."
        ), 404

    return jsonify(
        chapter=dict(chapter)
    )


@app.post("/api/works")
@require("owner")
def create_work():

    data = json_data()

    title = str(data.get("title", "")).strip()

    if not title:
        return jsonify(
            error="Нужно название."
        ), 400

    cur = conn().execute(
        """
        INSERT INTO works(title,kind,genre,description,author,cover)
        VALUES(?,?,?,?,?,?)
        """,
        (
            title,
            data.get("kind", "Новелла"),
            data.get("genre", ""),
            data.get("description", ""),
            OWNER_LOGIN,
            data.get("cover", "")
        )
    )

    conn().commit()

    return jsonify(
        ok=True,
        id=cur.lastrowid
    )


@app.put("/api/works/<int:work_id>")
@require("owner")
def update_work(work_id):

    data = json_data()

    title = str(data.get("title", "")).strip()

    if not title:
        return jsonify(
            error="Нужно название."
        ), 400

    cur = conn().execute(
        """
        UPDATE works
        SET title=?,kind=?,genre=?,description=?,cover=?
        WHERE id=?
        """,
        (
            title,
            data.get("kind", "Новелла"),
            data.get("genre", ""),
            data.get("description", ""),
            data.get("cover", ""),
            work_id
        )
    )

    conn().commit()

    if not cur.rowcount:
        return jsonify(
            error="Произведение не найдено."
        ), 404

    return jsonify(ok=True)


@app.delete("/api/works/<int:work_id>")
@require("owner")
def delete_work(work_id):

    cur = conn().execute(
        "DELETE FROM works WHERE id=?",
        (work_id,)
    )

    conn().commit()

    if not cur.rowcount:
        return jsonify(
            error="Произведение не найдено."
        ), 404

    return jsonify(ok=True)


# =========================
# ОБЛОЖКИ
# =========================

@app.post("/api/works/<int:work_id>/cover")
@require("owner")
def upload_cover(work_id):

    if not conn().execute(
        "SELECT id FROM works WHERE id=?",
        (work_id,)
    ).fetchone():

        return jsonify(
            error="Произведение не найдено."
        ), 404

    file = request.files.get("cover")

    if not file or not file.filename:
        return jsonify(
            error="Выберите изображение."
        ), 400

    ext = (
        file.filename.rsplit(".", 1)[-1].lower()
        if "." in file.filename
        else ""
    )

    if ext not in ALLOWED:
        return jsonify(
            error="Поддерживаются JPG, PNG, WEBP и GIF."
        ), 400

    filename = secure_filename(
        f"{uuid.uuid4().hex}.{ext}"
    )

    file.save(UPLOAD_DIR / filename)

    url = "/static/uploads/" + filename

    conn().execute(
        "UPDATE works SET cover=? WHERE id=?",
        (url, work_id)
    )

    conn().commit()

    return jsonify(
        ok=True,
        cover=url
    )


# =========================
# ГЛАВЫ
# =========================

@app.post("/api/works/<int:work_id>/chapters")
@require("owner")
def add_chapter(work_id):

    data = json_data()

    if not conn().execute(
        "SELECT id FROM works WHERE id=?",
        (work_id,)
    ).fetchone():

        return jsonify(
            error="Произведение не найдено."
        ), 404

    title = str(data.get("title", "Глава")).strip() or "Глава"
    body = str(data.get("body", ""))

    cur = conn().execute(
        """
        INSERT INTO chapters(work_id,title,body)
        VALUES(?,?,?)
        """,
        (work_id, title, body)
    )

    conn().commit()

    return jsonify(
        ok=True,
        id=cur.lastrowid
    )


@app.delete("/api/chapters/<int:chapter_id>")
@require("owner")
def delete_chapter(chapter_id):

    cur = conn().execute(
        "DELETE FROM chapters WHERE id=?",
        (chapter_id,)
    )

    conn().commit()

    if not cur.rowcount:
        return jsonify(
            error="Глава не найдена."
        ), 404

    return jsonify(ok=True)


# =========================
# КОММЕНТАРИИ
# =========================

@app.post("/api/works/<int:work_id>/comments")
@require()
def add_comment(work_id):

    data = json_data()

    body = str(data.get("body", "")).strip()

    if not body:
        return jsonify(
            error="Пустой комментарий."
        ), 400

    db = conn()

    if not db.execute(
        "SELECT id FROM works WHERE id=?",
        (work_id,)
    ).fetchone():

        return jsonify(
            error="Произведение не найдено."
        ), 404

    user = current_user()

    db.execute(
        """
        INSERT INTO comments(work_id,author,body)
        VALUES(?,?,?)
        """,
        (work_id, user["login"], body)
    )

    db.commit()

    return jsonify(ok=True)


# =========================
# ПРОФИЛИ
# =========================

@app.get("/api/profile/<path:login_name>")
def profile(login_name):

    db = conn()

    user = db.execute(
        """
        SELECT id,login,role,bio,avatar
        FROM users
        WHERE login=? COLLATE NOCASE
        """,
        (login_name,)
    ).fetchone()

    if not user:
        return jsonify(
            error="Профиль не найден."
        ), 404

    follower_count = db.execute(
        "SELECT COUNT(*) FROM follows WHERE followed_id=?",
        (user["id"],)
    ).fetchone()[0]

    following_count = db.execute(
        "SELECT COUNT(*) FROM follows WHERE follower_id=?",
        (user["id"],)
    ).fetchone()[0]

    authored = db.execute(
        """
        SELECT * FROM works
        WHERE author=?
        ORDER BY id DESC
        """,
        (user["login"],)
    ).fetchall()

    total_reads = sum(
        (row["views"] or 0)
        for row in authored
    )

    me = current_user()

    is_following = bool(
        me and db.execute(
            """
            SELECT 1 FROM follows
            WHERE follower_id=? AND followed_id=?
            """,
            (me["id"], user["id"])
        ).fetchone()
    )

    return jsonify(
        profile=dict(user),
        followers=follower_count,
        following=following_count,
        works_count=len(authored),
        reads=total_reads,
        works=[dict(row) for row in authored],
        is_following=is_following
    )


@app.post("/api/follow/<path:login_name>")
@require()
def follow(login_name):

    db = conn()

    target = db.execute(
        "SELECT id FROM users WHERE login=? COLLATE NOCASE",
        (login_name,)
    ).fetchone()

    me = current_user()

    if not target:
        return jsonify(
            error="Пользователь не найден."
        ), 404

    if target["id"] == me["id"]:
        return jsonify(
            error="Нельзя подписаться на себя."
        ), 400

    existing = db.execute(
        """
        SELECT 1 FROM follows
        WHERE follower_id=? AND followed_id=?
        """,
        (me["id"], target["id"])
    ).fetchone()

    if existing:

        db.execute(
            """
            DELETE FROM follows
            WHERE follower_id=? AND followed_id=?
            """,
            (me["id"], target["id"])
        )

        following = False

    else:

        db.execute(
            """
            INSERT OR IGNORE INTO follows(follower_id,followed_id)
            VALUES(?,?)
            """,
            (me["id"], target["id"])
        )

        following = True

    db.commit()

    count = db.execute(
        "SELECT COUNT(*) FROM follows WHERE followed_id=?",
        (target["id"],)
    ).fetchone()[0]

    return jsonify(
        ok=True,
        following=following,
        followers=count
    )


# =========================
# БИБЛИОТЕКА
# =========================

@app.get("/api/library")
@require()
def get_library():

    user = current_user()

    rows = conn().execute(
        """
        SELECT w.*
        FROM favorites f
        JOIN works w ON w.id=f.work_id
        WHERE f.user_id=?
        ORDER BY w.id DESC
        """,
        (user["id"],)
    ).fetchall()

    return jsonify(
        works=[dict(row) for row in rows]
    )


@app.post("/api/favorites/<int:work_id>")
@require()
def toggle_favorite(work_id):

    db = conn()
    user = current_user()

    if not db.execute(
        "SELECT id FROM works WHERE id=?",
        (work_id,)
    ).fetchone():

        return jsonify(
            error="Произведение не найдено."
        ), 404

    found = db.execute(
        """
        SELECT 1 FROM favorites
        WHERE user_id=? AND work_id=?
        """,
        (user["id"], work_id)
    ).fetchone()

    if found:

        db.execute(
            """
            DELETE FROM favorites
            WHERE user_id=? AND work_id=?
            """,
            (user["id"], work_id)
        )

        saved = False

    else:

        db.execute(
            """
            INSERT OR IGNORE INTO favorites(user_id,work_id)
            VALUES(?,?)
            """,
            (user["id"], work_id)
        )

        saved = True

    db.commit()

    return jsonify(
        ok=True,
        saved=saved
    )


# =========================
# РЕДАКТИРОВАНИЕ ПРОФИЛЯ
# =========================

@app.post("/api/profile")
@require()
def update_profile():

    data = json_data()

    bio = str(data.get("bio", ""))[:500]

    conn().execute(
        "UPDATE users SET bio=? WHERE id=?",
        (bio, current_user()["id"])
    )

    conn().commit()

    return jsonify(ok=True)


# =========================
# ОБРАБОТКА ОШИБОК
# =========================

@app.errorhandler(413)
def too_large(error):

    return jsonify(
        error="Файл слишком большой. Максимальный размер — 8 МБ."
    ), 413


@app.errorhandler(500)
def internal_error(error):

    app.logger.exception("Внутренняя ошибка сервера")

    return jsonify(
        error="Внутренняя ошибка сервера."
    ), 500


# =========================
# ЗАПУСК
# =========================

init()

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", "5000"))
        )
