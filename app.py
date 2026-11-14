import os, sqlite3, secrets, hashlib, hmac, uuid
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
ALLOWED = {"ppng, "jpg", "jpeg", "webp", "gif"}

def pw_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000).hex()
    return salt + "$" + digest

def verify(password, stored):
    try:
        salt, expected = stored.split("$", 1)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 310000).hex()
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False

def conn():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db:
        db.close()

def init():
    db = sqlite3.connect(DB)
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY, login TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'reader',
      bio TEXT DEFAULT '', avatar TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS works(
      id INTEGER PRIMARY KEY, title TEXT NOT NULL, kind TEXT, genre TEXT,
      description TEXT, author TEXT
    );
    CREATE TABLE IF NOT EXISTS chapters(
      id INTEGER PRIMARY KEY, work_id INTEGER NOT NULL, title TEXT, body TEXT,
      FOREIGN KEY(work_id) REFERENCES works(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS comments(
      id INTEGER PRIMARY KEY, work_id INTEGER NOT NULL, author TEXT, body TEXT,
      FOREIGN KEY(work_id) REFERENCES works(id) ON DELETE CASCADE
    );
    """)
    # Safe additive migrations: preserve all existing works and chapters.
    cols = {r[1] for r in db.execute("PRAGMA table_info(works)")}
    for name, sql in [
        ("cover", "ALTER TABLE works ADD COLUMN cover TEXT DEFAULT ''"),
        ("views", "ALTER TABLE works ADD COLUMN views INTEGER DEFAULT 0"),
        ("created_at", "ALTER TABLE works ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP")
    ]:
        if name not in cols:
            db.execute(sql)
    ucols = {r[1] for r in db.execute("PRAGMA table_info(users)")}
    for name, sql in [("bio", "ALTER TABLE users ADD COLUMN bio TEXT DEFAULT ''"),
                      ("avatar", "ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ''")]:
        if name not in ucols:
            db.execute(sql)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS follows(
      follower_id INTEGER NOT NULL, followed_id INTEGER NOT NULL,
      UNIQUE(follower_id, followed_id),
      FOREIGN KEY(follower_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(followed_id) REFERENCES users(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS favorites(
      user_id INTEGER NOT NULL, work_id INTEGER NOT NULL,
      UNIQUE(user_id, work_id),
      FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
      FOREIGN KEY(work_id) REFERENCES works(id) ON DELETE CASCADE
    );
    CREATE TABLE IF NOT EXISTS reading_views(
      id INTEGER PRIMARY KEY, work_id INTEGER NOT NULL, visitor TEXT NOT NULL,
      FOREIGN KEY(work_id) REFERENCES works(id) ON DELETE CASCADE,
      UNIQUE(work_id, visitor)
    );
    """)
    # Create accounts only when explicitly configured in Render environment.
    owner_pw = os.environ.get("OWNER_PASSWORD")
    if owner_pw:
        row = db.execute("SELECT id FROM users WHERE login=? COLLATE NOCASE", ("OWNER_LOGIN",)).fetchone()
        if row:
            db.execute("UPDATE users SET role='owner', password_hash=? WHERE id=?",
                       (pw_hash(owner_pw), row[0]))
        else:
            db.execute("INSERT INTO users(login,password_hash,role) VALUES(?,?,?)",
                       (OWNER_LOGIN, pw_hash(owner_pw), "owner"))
    reader_pw = os.environ.get("READER_PASSWORD")
    if reader_pw:
        row = db.execute("SELECT id FROM users WHERE login=? COLLATE NOCASE", (READER_LOGIN,)).fetchone()
        if row:
            db.execute("UPDATE users SET password_hash=? WHERE id=?", (pw_hash(reader_pw), row[0]))
        else:
            db.execute("INSERT INTO users(login,password_hash,role) VALUES(?,?,?)",
                       (READER_LOGIN, pw_hash(reader_pw), "reader"))
    if db.execute("SELECT COUNT(*) FROM works").fetchone()[0] == 0:
        db.executemany("INSERT INTO works(title,kind,genre,description,author) VALUES(?,?,?,?,?)", [
          ("Тень в моём сердце","Новелла","Романтика · Драма","Она была светом в его тьме. История о любви, которая родилась между болью и надеждой.","S. 壁"),
          ("Ледяная клятва","Манхва","Фэнтези · Приключения","Клятва, данная среди вечных снегов. Древняя магия пробуждается вместе с наследником забытого престола.","S. 壁"),
          ("Белый лотос","Новелла","Фэнтези · Романтика","Легенда о цветке, который расцветает лишь однажды за тысячу лет.","S. 壁"),
          ("Пепел и звёзды","Манхва","Мистика · Драма","В городе, где звёзды больше не отражаются в воде, кто-то помнит настоящее небо.","S. 壁")
        ])
    db.commit()
    db.close()

def current_user():
    if not session.get("uid"):
        return None
    return conn().execute("SELECT id,login,role,bio,avatar FROM users WHERE id=?", (session["uid"],)).fetchone()

def require(role=None):
    def deco(fn):
        @wraps(fn)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify(error="Сначала войдите в аккаунт."), 401
            if role == "owner" and user["role"] != "owner":
                return jsonify(error="Доступ только владельцу."), 403
            return fn(*args, **kwargs)
        return wrapped
    return deco

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/api/me")
def api_me():
    u = current_user()
    return jsonify(user=dict(u) if u else None)

@app.post("/api/register")
def register():
    data = request.get_json(force=True)
    login = str(data.get("login", "")).strip()
    password = str(data.get("password", ""))
    if len(login) < 3 or len(login) > 40 or len(password) < 8:
        return jsonify(error="Логин: 3–40 символов, пароль: минимум 8."), 400
    if login.casefold() == OWNER_LOGIN.casefold():
        return jsonify(error="Этот логин зарезервирован."), 400
    try:
        cur = conn().execute("INSERT INTO users(login,password_hash,role) VALUES(?,?,?)",
                             (login, pw_hash(password), "reader"))
        conn().commit()
        session.clear()
        session["uid"] = cur.lastrowid
        return jsonify(ok=True, user={"login": login, "role": "reader"})
    except sqlite3.IntegrityError:
        return jsonify(error="Такой логин уже занят."), 409

@app.post("/api/login")
def login():
    data = request.get_json(force=True)
    login_name = str(data.get("login", "")).strip()
    password = str(data.get("password", ""))
    u = conn().execute("SELECT * FROM users WHERE login=? COLLATE NOCASE", (login_name,)).fetchone()
    if not u or not verify(password, u["password_hash"]):
        return jsonify(error="Неверный логин или пароль."), 401
    session.clear()
    session["uid"] = u["id"]
    return jsonify(ok=True, user={"login": u["login"], "role": u["role"]})

@app.post("/api/logout")
def logout():
    session.clear()
    return jsonify(ok=True)

@app.get("/api/works")
def works():
    rows = conn().execute("""
      SELECT w.*,(SELECT COUNT(*) FROM chapters c WHERE c.work_id=w.id) chapter_count
      FROM works w ORDER BY w.id DESC
    """).fetchall()
    return jsonify(works=[dict(r) for r in rows])

@app.get("/api/works/<int:work_id>")
def work_detail(work_id):
    db = conn()
    w = db.execute("SELECT * FROM works WHERE id=?", (work_id,)).fetchone()
    if not w:
        return jsonify(error="Произведение не найдено."), 404
    visitor = str(session.get("uid") or session.get("visitor_id") or "")
    if not visitor:
        visitor = secrets.token_urlsafe(18)
        session["visitor_id"] = visitor
    db.execute("INSERT OR IGNORE INTO reading_views(work_id,visitor) VALUES(?,?)", (work_id, visitor))
    db.execute("UPDATE works SET views=(SELECT COUNT(*) FROM reading_views WHERE work_id=?) WHERE id=?",
               (work_id, work_id))
    db.commit()
    chapters = db.execute("SELECT * FROM chapters WHERE work_id=? ORDER BY id", (work_id,)).fetchall()
    comments = db.execute("SELECT * FROM comments WHERE work_id=? ORDER BY id DESC", (work_id,)).fetchall()
    return jsonify(work=dict(db.execute("SELECT * FROM works WHERE id=?", (work_id,)).fetchone()),
                   chapters=[dict(x) for x in chapters], comments=[dict(x) for x in comments])

@app.post("/api/works")
@require("owner")
def create_work():
    d = request.get_json(force=True)
    title = str(d.get("title", "")).strip()
    if not title:
        return jsonify(error="Нужно название."), 400
    cur = conn().execute("INSERT INTO works(title,kind,genre,description,author,cover) VALUES(?,?,?,?,?,?)",
                         (title, d.get("kind","Новелла"), d.get("genre",""), d.get("description",""), READER_LOGIN, d.get("cover","")))
    conn().commit()
    return jsonify(ok=True, id=cur.lastrowid)

@app.put("/api/works/<int:work_id>")
@require("owner")
def update_work(work_id):
    d = request.get_json(force=True)
    cur = conn().execute("UPDATE works SET title=?,kind=?,genre=?,description=?,cover=? WHERE id=?",
                         (d.get("title",""), d.get("kind","Новелла"), d.get("genre",""),
                          d.get("description",""), d.get("cover",""), work_id))
    conn().commit()
    return (jsonify(ok=True) if cur.rowcount else (jsonify(error="Не найдено."), 404))

@app.delete("/api/works/<int:work_id>")
@require("owner")
def delete_work(work_id):
    conn().execute("DELETE FROM works WHERE id=?", (work_id,))
    conn().commit()
    return jsonify(ok=True)

@app.post("/api/works/<int:work_id>/cover")
@require("owner")
def upload_cover(work_id):
    if not conn().execute("SELECT id FROM works WHERE id=?", (work_id,)).fetchone():
        return jsonify(error="Произведение не найдено."), 404
    f = request.files.get("cover")
    if not f or not f.filename:
        return jsonify(error="Выберите изображение."), 400
    ext = f.filename.rsplit(".", 1)[-1].lower() if "." in f.filename else ""
    if ext not in ALLOWED:
        return jsonify(error="Поддерживаются JPG, PNG, WEBP и GIF."), 400
    filename = secure_filename(f"{uuid.uuid4().hex}.{ext}")
    f.save(UPLOAD_DIR / filename)
    url = "/static/uploads/" + filename
    conn().execute("UPDATE works SET cover=? WHERE id=?", (url, work_id))
    conn().commit()
    return jsonify(ok=True, cover=url)

@app.post("/api/works/<int:work_id>/chapters")
@require("owner")
def add_chapter(work_id):
    d = request.get_json(force=True)
    if not conn().execute("SELECT id FROM works WHERE id=?", (work_id,)).fetchone():
        return jsonify(error="Не найдено."), 404
    conn().execute("INSERT INTO chapters(work_id,title,body) VALUES(?,?,?)",
                   (work_id, d.get("title","Глава"), d.get("body","")))
    conn().commit()
    return jsonify(ok=True)

@app.delete("/api/chapters/<int:chapter_id>")
@require("owner")
def delete_chapter(chapter_id):
    conn().execute("DELETE FROM chapters WHERE id=?", (chapter_id,))
    conn().commit()
    return jsonify(ok=True)

@app.post("/api/works/<int:work_id>/comments")
@require()
def add_comment(work_id):
    body = str(request.get_json(force=True).get("body","")).strip()
    if not body:
        return jsonify(error="Пустой комментарий."), 400
    u = current_user()
    conn().execute("INSERT INTO comments(work_id,author,body) VALUES(?,?,?)",
                   (work_id, u["login"], body))
    conn().commit()
    return jsonify(ok=True)

@app.get("/api/profile/<path:login_name>")
def profile(login_name):
    db = conn()
    u = db.execute("SELECT id,login,role,bio,avatar FROM users WHERE login=? COLLATE NOCASE", (login_name,)).fetchone()
    if not u:
        return jsonify(error="Профиль не найден."), 404
    follower_count = db.execute("SELECT COUNT(*) FROM follows WHERE followed_id=?", (u["id"],)).fetchone()[0]
    following_count = db.execute("SELECT COUNT(*) FROM follows WHERE follower_id=?", (u["id"],)).fetchone()[0]
    authored = db.execute("SELECT * FROM works WHERE author=? OR (?=? AND author='S. 壁') ORDER BY id DESC", (u["login"], u["login"], READER_LOGIN)).fetchall()
    total_reads = sum((r["views"] or 0) for r in authored)
    me = current_user()
    is_following = bool(me and db.execute("SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?",
                                          (me["id"], u["id"])).fetchone())
    return jsonify(profile=dict(u), followers=follower_count, following=following_count,
                   works_count=len(authored), reads=total_reads, works=[dict(r) for r in authored],
                   is_following=is_following)

@app.post("/api/follow/<path:login_name>")
@require()
def follow(login_name):
    db = conn()
    target = db.execute("SELECT id FROM users WHERE login=? COLLATE NOCASE", (login_name,)).fetchone()
    me = current_user()
    if not target:
        return jsonify(error="Пользователь не найден."), 404
    if target["id"] == me["id"]:
        return jsonify(error="Нельзя подписаться на себя."), 400
    existing = db.execute("SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?",
                          (me["id"], target["id"])).fetchone()
    if existing:
        db.execute("DELETE FROM follows WHERE follower_id=? AND followed_id=?", (me["id"], target["id"]))
        following = False
    else:
        db.execute("INSERT OR IGNORE INTO follows(follower_id,followed_id) VALUES(?,?)",
                   (me["id"], target["id"]))
        following = True
    db.commit()
    count = db.execute("SELECT COUNT(*) FROM follows WHERE followed_id=?", (target["id"],)).fetchone()[0]
    return jsonify(ok=True, following=following, followers=count)

@app.get("/api/library")
@require()
def get_library():
    u = current_user()
    rows = conn().execute("""SELECT w.* FROM favorites f JOIN works w ON w.id=f.work_id
                             WHERE f.user_id=? ORDER BY w.id DESC""", (u["id"],)).fetchall()
    return jsonify(works=[dict(r) for r in rows])

@app.post("/api/favorites/<int:work_id>")
@require()
def toggle_favorite(work_id):
    db = conn()
    u = current_user()
    found = db.execute("SELECT 1 FROM favorites WHERE user_id=? AND work_id=?", (u["id"], work_id)).fetchone()
    if found:
        db.execute("DELETE FROM favorites WHERE user_id=? AND work_id=?", (u["id"], work_id))
        saved = False
    else:
        db.execute("INSERT OR IGNORE INTO favorites(user_id,work_id) VALUES(?,?)", (u["id"], work_id))
        saved = True
    db.commit()
    return jsonify(ok=True, saved=saved)

@app.post("/api/profile")
@require()
def update_profile():
    d = request.get_json(force=True)
    bio = str(d.get("bio",""))[:500]
    conn().execute("UPDATE users SET bio=? WHERE id=?", (bio, current_user()["id"]))
    conn().commit()
    return jsonify(ok=True)

init()
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT","5000")))
