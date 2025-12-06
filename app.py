from flask import Flask, request, render_template, redirect, url_for, flash, session, g, Response, jsonify, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3, os, json, shutil, mimetypes, re, uuid
# put near top of app.py with other imports
import boto3
from botocore.exceptions import ClientError
import math

from datetime import datetime

USE_S3 = True

if USE_S3:
    from s3_utils import upload_to_s3, download_from_s3, get_s3_url

# Configuration
USE_S3 = True   # <--- IMPORTANT

if USE_S3:
    from s3_utils import upload_to_s3, download_from_s3, get_s3_url as generate_s3_url
MAX_STORAGE_BYTES = 32 * 1024**3  # 32 GiB per user
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_ROOT = os.path.join(BASE_DIR, "uploads")
UPLOAD_TMP_ROOT = os.path.join(BASE_DIR, "uploads_tmp")
DOWNLOAD_ROOT = os.path.join(BASE_DIR, "downloads")
DB_PATH = os.path.join(BASE_DIR, "file_app.db")

os.makedirs(UPLOAD_ROOT, exist_ok=True)
os.makedirs(UPLOAD_TMP_ROOT, exist_ok=True)
os.makedirs(DOWNLOAD_ROOT, exist_ok=True)

app = Flask(__name__)
app.secret_key = "change-this-secret-in-production"

# --- Database init ---
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL
    );
    """)
    conn.commit()
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        # create default admin with hashed password
        pw = generate_password_hash("admin123")
        cur.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)", ("admin", pw, "admin", datetime.utcnow().isoformat()))
        conn.commit()
    conn.close()

init_db()

# --- DB helpers ---
def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()

def get_user_by_username(username):
    db = get_db()
    cur = db.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()

def create_user(username, password, role="user"):
    db = get_db()
    pw_hash = generate_password_hash(password)
    db.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)", (username, pw_hash, role, datetime.utcnow().isoformat()))
    db.commit()

def list_all_usernames():
    db = get_db()
    cur = db.execute("SELECT username FROM users ORDER BY username")
    return [r["username"] for r in cur.fetchall()]

# --- Auth helpers ---
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login", next=request.path))
        return f(*args, **kwargs)
    return wrap

def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if session.get("role") != "admin":
            flash("Admin only", "danger")
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrap

# --- Utilities ---
def sanitize_folder(folder):
    if not folder:
        return ""
    parts = [secure_filename(p) for p in folder.split("/") if p and p not in (".", "..")]
    return "/".join([p for p in parts if p])

def user_root(username):
    path = os.path.join(UPLOAD_ROOT, username)
    os.makedirs(path, exist_ok=True)
    return path

def ensure_user_subpath(username, rel_path):
    root = user_root(username)
    rel_path = rel_path or ""
    safe_rel = sanitize_folder(rel_path)
    full = os.path.abspath(os.path.join(root, safe_rel))
    # Ensure the requested path remains under user's root
    if os.path.commonpath([full, root]) != root:
        raise ValueError("Invalid path")
    # If the safe_rel looks like a filename (has an extension) OR the full path already exists as a file,
    # we should create the parent directory, not attempt to create a directory at the file path.
    if safe_rel and (os.path.splitext(safe_rel)[1] or (os.path.exists(full) and os.path.isfile(full))):
        parent = os.path.dirname(full)
        os.makedirs(parent, exist_ok=True)
    else:
        # treat as a folder path — create it
        os.makedirs(full, exist_ok=True)
    return full

def user_tmp_dir(username, upload_id):
    path = os.path.join(UPLOAD_TMP_ROOT, username, upload_id)
    os.makedirs(path, exist_ok=True)
    return path

def user_download_dir(username):
    path = os.path.join(DOWNLOAD_ROOT, username)
    os.makedirs(path, exist_ok=True)
    return path

def get_user_usage(username):
    total = 0
    root = user_root(username)
    for root_dir, _, files in os.walk(root):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root_dir, f))
            except OSError:
                pass
    return total

def human_readable(num_bytes):
    for unit in ['B','KB','MB','GB','TB']:
        if num_bytes < 1024.0 or unit == 'TB':
            if unit == 'B':
                return f"{num_bytes} {unit}"
            return f"{num_bytes/ (1024**(['B','KB','MB','GB','TB'].index(unit))):.2f} {unit}"
        num_bytes /= 1024.0

# --- Routes: auth ---
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        if not username or not password:
            flash("Username and password required", "danger")
            return redirect(url_for("register"))
        if get_user_by_username(username):
            flash("Username already taken", "danger")
            return redirect(url_for("register"))
        create_user(username, password)
        flash("Account created. Please log in.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        user = get_user_by_username(username)
        if user and check_password_hash(user["password_hash"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Logged in successfully", "success")
            next_url = request.args.get("next") or url_for("files_view")
            return redirect(next_url)
        flash("Invalid credentials", "danger")
        return redirect(url_for("login"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out", "info")
    return redirect(url_for("login"))

# --- Main pages ---
@app.route("/", methods=["GET"])
@login_required
def index():
    username = session.get("username")
    usage = get_user_usage(username)
    # list user folders at root
    folders = []
    try:
        folders = [d for d in os.listdir(user_root(username)) if os.path.isdir(os.path.join(user_root(username), d))]
    except:
        folders = []
    users = list_all_usernames() if session.get("role") == "admin" else []
    return render_template("index.html", usage=usage, quota=MAX_STORAGE_BYTES, human_readable=human_readable, username=username, folders=folders, users=users)

@app.route("/files", methods=["GET"])
@login_required
def files_view():
    # build s3 client
    AWS_REGION = os.environ.get("AWS_REGION")
    AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
    S3_BUCKET = os.environ.get("S3_BUCKET")

    s3 = boto3.client(
        "s3",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )

    current_user = session.get("username")
    if session.get("role") == "admin":
        view_user = request.args.get("as_user") or current_user
        if not get_user_by_username(view_user):
            flash("Requested user not found", "danger")
            return redirect(url_for("files_view"))
    else:
        view_user = current_user

    # folder from query, sanitized
    folder = sanitize_folder(request.args.get("folder", "").strip())
    q = request.args.get("q", "").strip().lower()
    ftype = request.args.get("type", "").strip().lower()
    min_size = request.args.get("min_size", "").strip()
    max_size = request.args.get("max_size", "").strip()

    # Build prefix. If folder empty -> prefix = "username/"
    prefix = f"{view_user}/"
    if folder:
        prefix = f"{view_user}/{folder.strip('/')}/"
    # Ensure prefix has no leading slashes
    prefix = prefix.lstrip("/")

    folders = []
    items = []

    # Use Delimiter='/' to receive "folders" (CommonPrefixes)
    try:
        resp = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix, Delimiter="/", MaxKeys=1000)
    except Exception as e:
        app.logger.exception("S3 list failed")
        flash("Failed to list files (S3)", "danger")
        return redirect(url_for("index"))

    # extract folders (common prefixes)
    for cp in resp.get("CommonPrefixes", []):
        p = cp.get("Prefix", "")
        # folder name relative to current folder
        if p.startswith(prefix):
            rel = p[len(prefix):].rstrip("/")
            if rel:
                folders.append({"name": rel, "rel": f"{folder}/{rel}".lstrip("/") if folder else rel})

    # extract objects
    for obj in resp.get("Contents", []):
        key = obj.get("Key")
        # skip "folder placeholder" (object with same key as prefix)
        if key.endswith("/") and key == prefix:
            continue
        # compute name relative to current folder
        name = key[len(prefix):] if key.startswith(prefix) else key
        if not name:
            continue
        if "/" in name:
            # object in a subfolder — skip (we only want objects directly in this folder)
            continue
        size = obj.get("Size", 0)
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        rel_entry = f"{folder}/{name}".lstrip("/") if folder else name
        items.append({"name": name, "rel": rel_entry, "size": size, "ext": ext})

    # Filters (q, type, min/max)
    if q:
        items = [it for it in items if q in it["name"].lower()]
        folders = [fo for fo in folders if q in fo["name"].lower()]
    if ftype:
        if ftype == "image":
            items = [it for it in items if it["ext"] in ["png", "jpg", "jpeg", "gif", "webp"]]
        elif ftype == "video":
            items = [it for it in items if it["ext"] in ["mp4", "webm", "ogg", "mov", "mkv"]]
        elif ftype == "docs":
            items = [it for it in items if it["ext"] in ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt"]]

    try:
        if min_size:
            mn = int(min_size); items = [it for it in items if it["size"] >= mn]
        if max_size:
            mx = int(max_size); items = [it for it in items if it["size"] <= mx]
    except:
        pass

    # usage: sum of sizes of objects under user's prefix (non-recursive quick estimate)
    # for an accurate usage you'd want to iterate across all objects with Prefix=f"{view_user}/"
    usage = 0
    try:
        # list up to 1000 objects; if you expect >1000, implement paginator
        resp_all = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=f"{view_user}/", MaxKeys=1000)
        for o in resp_all.get("Contents", []):
            usage += o.get("Size", 0)
    except Exception:
        usage = 0

    # breadcrumbs & parent
    breadcrumbs = []
    if folder:
        parts = folder.split("/")
        for i in range(len(parts)):
            breadcrumbs.append((parts[i], "/".join(parts[:i+1])))
    parent = "/".join(folder.split("/")[:-1]) if folder and "/" in folder else ""

    # all_folders (root-level folders for user)
    all_folders = []
    try:
        root_resp = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=f"{view_user}/", Delimiter="/", MaxKeys=1000)
        for cp in root_resp.get("CommonPrefixes", []):
            p = cp.get("Prefix", "")
            rel = p[len(f"{view_user}/"):].rstrip("/")
            if rel:
                all_folders.append(rel)
    except Exception:
        all_folders = []

    users = list_all_usernames() if session.get("role") == "admin" else []

    return render_template(
        "files.html",
        username=session.get("username"),
        view_user=view_user,
        users=users,
        folders=folders,
        items=items,
        usage=usage,
        quota=MAX_STORAGE_BYTES,
        human_readable=human_readable,
        current_folder=folder,
        breadcrumbs=breadcrumbs,
        parent=parent,
        all_folders=all_folders
    )
# --- Folder ops ---
@app.route("/create_folder", methods=["POST"])
@login_required
def create_folder():
    as_user = request.form.get("as_user") if session.get("role") == "admin" else None
    target_user = as_user if as_user else session.get("username")
    parent = sanitize_folder(request.form.get("parent","").strip())
    name = secure_filename(request.form.get("name","").strip())
    if not name:
        flash("Folder name required", "danger")
        return redirect(url_for("files_view", as_user=target_user) if session.get("role") == "admin" else url_for("files_view"))
    try:
        parent_abs = ensure_user_subpath(target_user, parent)
        new_path = os.path.join(parent_abs, name)
        if os.path.exists(new_path):
            flash("Folder already exists", "warning")
        else:
            os.makedirs(new_path, exist_ok=True)
            flash("Folder created", "success")
    except ValueError:
        flash("Invalid path", "danger")
    return redirect(url_for("files_view", folder=parent, as_user=target_user) if session.get("role") == "admin" else redirect(url_for("files_view", folder=parent)))

# --- Delete & Rename ---
# Replace your delete_item route with this implementation
@app.route("/delete", methods=["POST"])
@login_required
def delete_item():
    """
    Expects JSON:
    { "path": "<relative path or filename>", "recursive": <bool>, "as_user": "<username?>" }
    Deletes local file/dir and corresponding S3 objects under "<username>/<path>".
    """
    data = request.get_json(force=True)
    path = (data.get("path","") or "").strip()
    recursive = bool(data.get("recursive", False))
    as_user = data.get("as_user") if session.get("role") == "admin" else None
    target_user = as_user if as_user else session.get("username")

    if not path:
        return jsonify({"error":"missing"}), 400

    # Ensure path is safe and within user's root
    try:
        abs_path = ensure_user_subpath(target_user, path)
    except ValueError:
        return jsonify({"error":"invalid_path"}), 400

    # Build S3 prefix - we store objects under "<username>/<path>"
    # If path is a folder, want "<username>/<folder>/" prefix to match objects under it.
    s3_prefix = f"{target_user}/{path}".lstrip("/")
    # normalize: if path looks like a folder (ends with slash) or os.path.isdir locally, ensure trailing slash
    if not s3_prefix.endswith("/") and os.path.isdir(abs_path):
        s3_prefix = s3_prefix.rstrip("/") + "/"

    # If the exact file object exists in S3 use exact key deletion; our delete_from_s3 will delete any matching keys under the prefix.
    print(f"delete_item: user={target_user}, path={path}, abs_path={abs_path}, s3_prefix={s3_prefix}, recursive={recursive}")

    # First try delete from S3 (best-effort)
    deleted_s3 = False
    try:
        deleted_s3 = delete_from_s3(s3_prefix)
    except Exception as e:
        print("delete_item: delete_from_s3 failed:", e)
        deleted_s3 = False

    # Then delete from local filesystem if present
    try:
        if os.path.isdir(abs_path):
            if recursive:
                shutil.rmtree(abs_path, ignore_errors=True)
                local_deleted = True
            else:
                try:
                    os.rmdir(abs_path)
                    local_deleted = True
                except OSError:
                    local_deleted = False
                    # folder not empty
        else:
            # file
            try:
                os.remove(abs_path)
                local_deleted = True
            except OSError:
                local_deleted = False
    except Exception as e:
        print("delete_item: local delete error:", e)
        local_deleted = False

    # Decide response:
    # - If either S3 or local deletion succeeded, return ok.
    # - If neither succeeded, return not_found.
    if deleted_s3 or local_deleted:
        return jsonify({"ok": True})
    else:
        # Could be not found in both locations or permission issues
        return jsonify({"error": "not_found"}), 404

@app.route("/rename", methods=["POST"])
@login_required
def rename_item():
    data = request.get_json(force=True)
    path = data.get("path","").strip()
    new_name = data.get("new_name","").strip()
    as_user = data.get("as_user") if session.get("role") == "admin" else None
    target_user = as_user if as_user else session.get("username")
    if not path or not new_name:
        return jsonify({"error":"missing"}), 400
    try:
        abs_path = ensure_user_subpath(target_user, path)
    except ValueError:
        return jsonify({"error":"invalid_path"}), 400
    parent_dir = os.path.dirname(abs_path)
    safe_new = secure_filename(new_name)
    dest = os.path.join(parent_dir, safe_new)
    if os.path.exists(dest):
        return jsonify({"error":"exists"}), 400
    try:
        os.rename(abs_path, dest)
        return jsonify({"ok": True, "new_name": os.path.basename(dest)})
    except Exception as e:
        return jsonify({"error":"rename_failed", "msg": str(e)}), 500

# --- Upload API: init, upload_chunk, uploaded_chunks, complete_upload, abort ---
@app.route("/init_upload", methods=["POST"])
@login_required
def init_upload():
    data = request.get_json(force=True)
    filename = data.get("filename","").strip()
    total_size = int(data.get("total_size", 0))
    chunk_size = int(data.get("chunk_size", 8*1024*1024))
    folder = sanitize_folder(data.get("folder","").strip())
    overwrite = bool(data.get("overwrite", False))
    as_user = data.get("as_user") if session.get("role") == "admin" else None
    target_user = as_user if as_user else session.get("username")

    if not filename or total_size <= 0:
        return jsonify({"error":"invalid"}), 400

    usage = get_user_usage(target_user)
    if usage + total_size > MAX_STORAGE_BYTES:
        return jsonify({"error":"quota_exceeded", "used": usage, "quota": MAX_STORAGE_BYTES}), 403

    try:
        ensure_user_subpath(target_user, folder)
    except ValueError:
        return jsonify({"error":"invalid_folder"}), 400

    upload_id = datetime.utcnow().strftime("%Y%m%d%H%M%S%f") + "_" + uuid.uuid4().hex[:10]
    tmpdir = user_tmp_dir(target_user, upload_id)
    meta = {"username": target_user, "filename": secure_filename(filename), "total_size": total_size, "chunk_size": chunk_size, "folder": folder, "overwrite": overwrite, "created_at": datetime.utcnow().isoformat()}
    with open(os.path.join(tmpdir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f)
    return jsonify({"upload_id": upload_id, "chunk_size": chunk_size})
# --- Dev Replica Credits Page ---
@app.route("/dev-replica")
def dev_replica():
    file_path = os.path.join(BASE_DIR, 'static', 'landing_page_6_1760077771.html')
    if os.path.exists(file_path):
        return send_file(file_path)
    else:
        return f"File not found at: {file_path}", 404
@app.route("/upload_chunk", methods=["POST"])
@login_required
def upload_chunk():
    upload_id = request.form.get("upload_id","").strip()
    index = request.form.get("index")
    if not upload_id or index is None:
        return "missing", 400
    try:
        idx = int(index)
    except:
        return "bad index", 400

    # find tmpdir under uploads_tmp/<username>/<upload_id>
    found = None
    for possible_user in os.listdir(UPLOAD_TMP_ROOT):
        candidate = os.path.join(UPLOAD_TMP_ROOT, possible_user, upload_id)
        if os.path.isdir(candidate):
            found = candidate
            break
    if not found:
        return "no such upload", 404

    if "chunk" not in request.files:
        return "no chunk", 400
    chunk = request.files["chunk"]
    chunk_path = os.path.join(found, f"chunk_{idx:08d}")
    try:
        chunk.save(chunk_path)
    except Exception as e:
        return f"save_failed: {e}", 500
    return "ok", 200

@app.route("/uploaded_chunks", methods=["GET"])
@login_required
def uploaded_chunks():
    upload_id = request.args.get("upload_id","").strip()
    if not upload_id:
        return jsonify({"chunks": []})
    for possible_user in os.listdir(UPLOAD_TMP_ROOT):
        tmpdir = os.path.join(UPLOAD_TMP_ROOT, possible_user, upload_id)
        if os.path.isdir(tmpdir):
            files = os.listdir(tmpdir)
            indices = []
            for f in files:
                if f.startswith("chunk_"):
                    try:
                        idx = int(f.split("_",1)[1])
                        indices.append(idx)
                    except:
                        pass
            indices.sort()
            return jsonify({"chunks": indices})
    return jsonify({"chunks": []})

@app.route("/complete_upload", methods=["POST"])
@login_required
def complete_upload():
    data = request.get_json(force=True)
    upload_id = data.get("upload_id", "").strip()
    if not upload_id:
        return jsonify({"error": "missing"}), 400

    found = None
    found_user = None
    for possible_user in os.listdir(UPLOAD_TMP_ROOT):
        tmpdir = os.path.join(UPLOAD_TMP_ROOT, possible_user, upload_id)
        if os.path.isdir(tmpdir):
            found = tmpdir
            found_user = possible_user
            break

    if not found:
        return jsonify({"error": "not_found"}), 404

    meta_path = os.path.join(found, "meta.json")
    if not os.path.isfile(meta_path):
        return jsonify({"error": "meta_missing"}), 404

    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    filename = meta.get("filename")
    total_size = int(meta.get("total_size", 0))
    folder = meta.get("folder", "")
    overwrite = bool(meta.get("overwrite", False))

    try:
        target_folder_abs = ensure_user_subpath(found_user, folder)
    except ValueError:
        return jsonify({"error": "invalid_folder"}), 400

    final_path = os.path.join(target_folder_abs, filename)
    if os.path.exists(final_path):
        if overwrite:
            try:
                os.remove(final_path)
            except:
                pass
        else:
            base, ext = os.path.splitext(filename)
            filename = f"{base}_{int(datetime.utcnow().timestamp())}{ext}"
            final_path = os.path.join(target_folder_abs, filename)

    # gather chunk files
    chunk_files = sorted([f for f in os.listdir(found) if f.startswith("chunk_")])
    if not chunk_files:
        return jsonify({"error": "no_chunks"}), 400

    # assemble file
    with open(final_path + ".part", "wb") as out_f:
        for cf in chunk_files:
            cf_path = os.path.join(found, cf)
            with open(cf_path, "rb") as r:
                shutil.copyfileobj(r, out_f)

    try:
        final_size = os.path.getsize(final_path + ".part")
    except:
        final_size = 0

    if final_size != total_size:
        try:
            os.remove(final_path + ".part")
        except:
            pass
        return jsonify({"error": "size_mismatch", "final_size": final_size, "expected": total_size}), 500

    # move the .part to final path
    os.replace(final_path + ".part", final_path)

    # build s3 object key and upload if enabled
    s3_object_key = None
    if USE_S3:
        folder_clean = folder.strip("/ ")
        if folder_clean:
            s3_object_key = f"{found_user}/{folder_clean}/{filename}"
        else:
            s3_object_key = f"{found_user}/{filename}"
        s3_object_key = s3_object_key.replace("//", "/")

        try:
            ok = upload_to_s3(final_path, s3_object_key)
        except Exception as e:
            app.logger.exception("S3 upload failed")
            # cleanup temp folder (keep local final file so you can inspect)
            try:
                shutil.rmtree(found)
            except:
                pass
            return jsonify({"error": "s3_upload_failed", "msg": str(e)}), 500

        if not ok:
            # upload_to_s3 returns False on failure (non-exception)
            try:
                shutil.rmtree(found)
            except:
                pass
            return jsonify({"error": "s3_upload_failed"}), 500

        # remove local copy after successful upload to save disk
        try:
            os.remove(final_path)
        except:
            pass

    # clean up tmp chunks
    try:
        shutil.rmtree(found)
    except:
        pass

    # respond with s3 info if applicable
    return jsonify({
        "ok": True,
        "filename": filename,
        "folder": folder,
        "username": found_user,
        "s3_key": s3_object_key,
        "s3_url": get_s3_url(s3_object_key) if USE_S3 and s3_object_key else None
    })

@app.route("/preview/<path:filename>")
@login_required
def preview_file(filename):
    as_user = request.args.get("as_user") if session.get("role") == "admin" else None
    target_user = as_user if as_user else session.get("username")

    # sanitize folder/file path
    try:
        ensure_user_subpath(target_user, filename)
    except ValueError:
        return "Invalid path", 400

    object_key = f"{target_user}/{filename}".lstrip("/")

    AWS_REGION = os.environ.get("AWS_REGION")
    AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
    S3_BUCKET = os.environ.get("S3_BUCKET")

    s3 = boto3.client(
        "s3",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )

    try:
        presigned = s3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": S3_BUCKET,
                "Key": object_key,
                "ResponseContentDisposition": "inline"
            },
            ExpiresIn=300,  # 5 minutes preview expiry
        )
        return redirect(presigned)
    except Exception as e:
        app.logger.exception("Preview failed")
        return "Preview failed", 500


@app.route("/abort_upload", methods=["POST"])
@login_required
def abort_upload():
    data = request.get_json(force=True)
    upload_id = data.get("upload_id","").strip()
    if not upload_id:
        return jsonify({"error":"missing"}), 400
    for possible_user in os.listdir(UPLOAD_TMP_ROOT):
        tmpdir = os.path.join(UPLOAD_TMP_ROOT, possible_user, upload_id)
        if os.path.isdir(tmpdir):
            try:
                shutil.rmtree(tmpdir)
                return jsonify({"ok": True})
            except Exception as e:
                return jsonify({"error":"failed", "msg": str(e)}), 500
    return jsonify({"error":"not_found"}), 404

# --- Range-supported preview & downloads ---
def send_file_partial(path, as_attachment=True, download_name=None):
    size = os.path.getsize(path)
    range_header = request.headers.get('Range', None)
    if not range_header:
        def generate():
            with open(path, 'rb') as f:
                while True:
                    chunk = f.read(8 * 1024 * 1024)
                    if not chunk:
                        break
                    yield chunk
        resp = Response(generate(), mimetype=mimetypes.guess_type(path)[0] or 'application/octet-stream')
        if as_attachment:
            disp_name = download_name or os.path.basename(path)
            resp.headers["Content-Disposition"] = f'attachment; filename="{disp_name}"'
        resp.headers["Content-Length"] = str(size)
        resp.headers["Accept-Ranges"] = "bytes"
        return resp
    m = re.search(r'bytes=(\d+)-(\d*)', range_header)
    if not m:
        return Response(status=416)
    start = int(m.group(1))
    end = m.group(2)
    if end:
        end = int(end)
    else:
        end = size - 1
    if start >= size:
        return Response(status=416)
    if end >= size:
        end = size - 1
    length = end - start + 1
    def generate_range():
        with open(path, 'rb') as f:
            f.seek(start)
            remaining = length
            chunk_size = 8 * 1024 * 1024
            while remaining > 0:
                read_size = chunk_size if remaining >= chunk_size else remaining
                data = f.read(read_size)
                if not data:
                    break
                remaining -= len(data)
                yield data
    resp = Response(generate_range(), status=206, mimetype=mimetypes.guess_type(path)[0] or 'application/octet-stream')
    disp_name = download_name or os.path.basename(path)
    resp.headers["Content-Range"] = f"bytes {start}-{end}/{size}"
    resp.headers["Accept-Ranges"] = "bytes"
    resp.headers["Content-Length"] = str(length)
    if as_attachment:
        resp.headers["Content-Disposition"] = f'attachment; filename="{disp_name}"'
    return resp

@app.route("/uploads/<path:filename>")
@login_required
def uploaded_file(filename):
    as_user = request.args.get("as_user") if session.get("role") == "admin" else None
    target_user = as_user if as_user else session.get("username")
    try:
        abs_path = ensure_user_subpath(target_user, filename)
    except ValueError:
        flash("Invalid file path", "danger")
        return redirect(url_for("files_view"))
    if not os.path.isfile(abs_path):
        flash("File not found", "danger")
        return redirect(url_for("files_view"))
    return send_file_partial(abs_path, as_attachment=False, download_name=os.path.basename(abs_path))

@app.route("/download/<path:filename>")
@login_required
def download_file(filename):
    as_user = request.args.get("as_user") if session.get("role") == "admin" else None
    target_user = as_user if as_user else session.get("username")

    # sanitize and ensure path is valid (ensure_user_subpath checks path traversal)
    try:
        # we still call ensure_user_subpath to validate folder paths (it will create folder if missing)
        abs_path = ensure_user_subpath(target_user, filename)
    except ValueError:
        flash("Invalid file path", "danger")
        return redirect(url_for("files_view"))

    # build s3 object key
    object_key = f"{target_user}/{filename}".lstrip("/")

    # create s3 client
    AWS_REGION = os.environ.get("AWS_REGION")
    AWS_ACCESS_KEY_ID = os.environ.get("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")
    S3_BUCKET = os.environ.get("S3_BUCKET")
    s3 = boto3.client(
        "s3",
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )

    # try to generate presigned URL and redirect
    try:
        presigned = s3.generate_presigned_url(
            "get_object",
            Params={"Bucket": S3_BUCKET, "Key": object_key},
            ExpiresIn=3600,
        )
        return redirect(presigned)
    except Exception as e:
        app.logger.exception("Presign/download failed, falling back to local copy if present")
        # Fallback: try local copy (if somehow present)
        if os.path.isfile(abs_path):
            ddir = user_download_dir(target_user)
            dest = os.path.join(ddir, os.path.basename(abs_path))
            try:
                shutil.copy2(abs_path, dest)
                return send_file_partial(dest, as_attachment=True, download_name=os.path.basename(abs_path))
            except Exception:
                pass
        flash("File not available for download", "danger")
        return redirect(url_for("files_view"))

@app.route("/download_all")
@login_required
def download_all():
    folder = sanitize_folder(request.args.get("folder","").strip())
    as_user = request.args.get("as_user") if session.get("role") == "admin" else None
    target_user = as_user if as_user else session.get("username")
    try:
        abs_folder = ensure_user_subpath(target_user, folder)
    except ValueError:
        flash("Invalid folder", "danger")
        return redirect(url_for("files_view"))
    files = [f for f in sorted(os.listdir(abs_folder)) if os.path.isfile(os.path.join(abs_folder, f))]
    if not files:
        flash("No files to download", "warning")
        return redirect(url_for("files_view", folder=folder))
    import io, zipfile
    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for fname in files:
            fullpath = os.path.join(abs_folder, fname)
            zf.write(fullpath, arcname=fname)
    memory_file.seek(0)
    server_zip_path = os.path.join(user_download_dir(target_user), "all_files.zip")
    with open(server_zip_path, "wb") as f:
        f.write(memory_file.getvalue())
    memory_file.seek(0)
    try:
        return send_file(memory_file, download_name="all_files.zip", as_attachment=True)
    except TypeError:
        return send_file(memory_file, attachment_filename="all_files.zip", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
