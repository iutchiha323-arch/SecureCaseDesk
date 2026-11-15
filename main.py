# -*- coding: utf-8 -*-
"""نظام إدارة القضايا والملفات الأمنية - إصدار محلي مشفر.

التشغيل:
  python -m pip install "flet[all]" cryptography python-docx
  python security_cases_enterprise.py

ملاحظات أمنية:
- قاعدة البيانات تحفظ كحزمة SQLite مشفرة بـ Fernet (AES-128-CBC + HMAC-SHA256).
- مفتاح البيانات عشوائي ويُغلّف لكل مستخدم بكلمة مروره عبر PBKDF2-HMAC-SHA256.
- المرفقات تحفظ مشفرة منفردة.
- سجل التدقيق سلسلة HMAC مترابطة لكشف التعديل والحذف وإعادة الترتيب.
- هذا تطبيق محلي أحادي الجهاز؛ لا يوفر إدارة مفاتيح مؤسسية أو تزامناً متعدد الأجهزة.
"""
from __future__ import annotations
import base64, hashlib, hmac, json, os, re, secrets, shutil, sqlite3, tempfile, zipfile
from datetime import datetime, date
from pathlib import Path
from typing import Optional

import flet as ft
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

APP_NAME = "منظومة إدارة القضايا والملفات الأمنية"
OFFICE_NAME = "وزارة الداخلية | إدارة المباحث الجنائية م / حجة"
DEFAULT_MEMO_TYPES = ["مذكرات وكيل نيابة البحث والأمن والسجون", "مذكرات رئيس نيابة استئناف حجة", "مذكرات مدير عام أمن المحافظة", "مذكرات مدير عام المباحث الجنائية", "مذكرات تكاليف", "مذكرات المستشفى الجمهوري", "مذكرات المستشفى السعودي", "مذكرات السجن المركزي", "تقارير الإحصاء", "الأوامر القهرية"]
DEPARTMENTS = ["قسم الاعتداء والقتل", "قسم التحريات", "قسم الآداب", "قسم مكافحة السرقات", "قسم التحقيقات", "قسم الجرائم الإلكترونية"]
DETENTION_CATEGORIES = ["نزلاء لا زالوا رهن جمع الاستدلالات", "نزلاء النيابة الابتدائية", "نزلاء النيابة الجزائية", "نزلاء باسم مدير عام أمن المحافظة", "نزلاء استخبارات الشرطة", "نزلاء منطقة ظهر أبو طير", "نزلاء أمن المديريات", "نزلاء نيابات المديريات"]
ROLES = {"admin": "مدير النظام", "investigator": "محقق", "viewer": "قارئ القضايا", "detention_viewer": "قارئ بيانات الحجز فقط"}
STATUSES = ["جديدة", "قيد المتابعة", "قيد التحقيق", "بانتظار إجراء", "مغلقة", "مؤرشفة"]
CASE_TYPES = ["أمنية", "جنائية", "إدارية", "تقنية", "مالية", "أخرى"]
PBKDF2_ITERATIONS = 600_000


def data_root() -> Path:
    if os.name == "nt":
        root = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        root = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    p = root / "SecureCaseDesk"
    p.mkdir(parents=True, exist_ok=True)
    for name in ("attachments", "reports", "exports", "tmp"):
        (p / name).mkdir(exist_ok=True)
    return p

ROOT = data_root()
CONFIG_PATH = ROOT / "accounts.json"
DB_PATH = ROOT / "vault.db.enc"
ATTACH_DIR = ROOT / "attachments"
REPORT_DIR = ROOT / "reports"
TMP_DIR = ROOT / "tmp"


def now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def atomic_write(path: Path, payload: bytes) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "wb") as f:
        f.write(payload); f.flush(); os.fsync(f.fileno())
    os.replace(tmp, path)


def load_config() -> dict:
    if not CONFIG_PATH.exists(): return {"version": 1, "users": {}}
    try:
        return json.loads(CONFIG_PATH.read_text("utf-8"))
    except Exception as ex:
        raise RuntimeError("ملف الحسابات تالف أو غير قابل للقراءة. لا تحذفه؛ استعد نسخة احتياطية.") from ex


def _config_canonical(cfg: dict) -> bytes:
    body = {k: v for k, v in cfg.items() if k != "config_mac"}
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def save_config(cfg: dict, dek: bytes) -> None:
    cfg["config_mac"] = hmac.new(dek, _config_canonical(cfg), hashlib.sha256).hexdigest()
    atomic_write(CONFIG_PATH, json.dumps(cfg, ensure_ascii=False, indent=2).encode("utf-8"))


def verify_config(cfg: dict, dek: bytes) -> bool:
    supplied = str(cfg.get("config_mac", ""))
    expected = hmac.new(dek, _config_canonical(cfg), hashlib.sha256).hexdigest()
    return bool(supplied) and hmac.compare_digest(supplied, expected)


def create_user_record(username: str, password: str, role: str, dek: bytes) -> dict:
    salt = secrets.token_bytes(16)
    wrapping_key = derive_key(password, salt)
    verifier = hmac.new(wrapping_key, b"SecureCaseDesk password verifier v1", hashlib.sha256).hexdigest()
    wrapped_dek = Fernet(wrapping_key).encrypt(dek).decode("ascii")
    return {"salt": base64.b64encode(salt).decode(), "verifier": verifier,
            "wrapped_dek": wrapped_dek, "role": role, "enabled": True,
            "created_at": now_iso(), "must_change_password": False}


def authenticate(username: str, password: str, cfg: dict) -> tuple[bytes, dict]:
    rec = cfg.get("users", {}).get(username)
    if not rec or not rec.get("enabled", True): raise ValueError("اسم المستخدم أو كلمة المرور غير صحيحة.")
    salt = base64.b64decode(rec["salt"])
    key = derive_key(password, salt)
    check = hmac.new(key, b"SecureCaseDesk password verifier v1", hashlib.sha256).hexdigest()
    if not hmac.compare_digest(check, rec["verifier"]): raise ValueError("اسم المستخدم أو كلمة المرور غير صحيحة.")
    try: dek = Fernet(key).decrypt(rec["wrapped_dek"].encode("ascii"))
    except InvalidToken as ex: raise ValueError("تعذر فتح مفتاح البيانات. تحقق من الحساب أو النسخة الاحتياطية.") from ex
    if not verify_config(cfg, dek): raise ValueError("فشل التحقق من سلامة إعدادات الحسابات؛ قد يكون الملف قد عُدّل.")
    return dek, rec


class Vault:
    """SQLite في الذاكرة فقط؛ لا يُكتب ملف SQLite مكشوف على القرص."""
    def __init__(self, dek: bytes):
        self.dek = dek
        self.fernet = Fernet(dek)
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        if DB_PATH.exists():
            try:
                raw = self.fernet.decrypt(DB_PATH.read_bytes())
                self.conn.deserialize(raw)
            except InvalidToken as ex:
                raise RuntimeError("فشل فك تشفير قاعدة البيانات. كلمة المرور أو ملف البيانات غير صحيح.") from ex
        self.initialize()

    def initialize(self):
        c = self.conn
        c.executescript("""
        PRAGMA foreign_keys=ON;
        CREATE TABLE IF NOT EXISTS cases (
          id INTEGER PRIMARY KEY AUTOINCREMENT, case_number TEXT NOT NULL UNIQUE,
          party_name TEXT NOT NULL, case_type TEXT NOT NULL, case_date TEXT NOT NULL,
          status TEXT NOT NULL, priority TEXT NOT NULL DEFAULT 'متوسطة',
          summary TEXT DEFAULT '', notes TEXT DEFAULT '', created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL, created_by TEXT NOT NULL, updated_by TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS attachments (
          id INTEGER PRIMARY KEY AUTOINCREMENT, case_id INTEGER NOT NULL,
          original_name TEXT NOT NULL, stored_name TEXT NOT NULL UNIQUE,
          mime_type TEXT DEFAULT 'application/octet-stream', size_bytes INTEGER NOT NULL,
          sha256 TEXT NOT NULL, uploaded_at TEXT NOT NULL, uploaded_by TEXT NOT NULL,
          FOREIGN KEY(case_id) REFERENCES cases(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS audit (
          id INTEGER PRIMARY KEY AUTOINCREMENT, event_time TEXT NOT NULL,
          actor TEXT NOT NULL, action TEXT NOT NULL, entity TEXT NOT NULL,
          entity_id TEXT NOT NULL, details TEXT NOT NULL, previous_hash TEXT NOT NULL,
          event_hash TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_case_number ON cases(case_number);
        CREATE INDEX IF NOT EXISTS idx_party_name ON cases(party_name);
        CREATE INDEX IF NOT EXISTS idx_audit_time ON audit(event_time);
        CREATE TABLE IF NOT EXISTS memos (
          id INTEGER PRIMARY KEY AUTOINCREMENT, memo_type TEXT NOT NULL, memo_number TEXT DEFAULT '',
          memo_date TEXT NOT NULL, recipient TEXT DEFAULT '', subject TEXT NOT NULL,
          body TEXT DEFAULT '', created_at TEXT NOT NULL, created_by TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS memo_types (name TEXT PRIMARY KEY, is_custom INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS departments (
          id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL UNIQUE,
          description TEXT DEFAULT '', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS detainees (
          id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL, detainee_category TEXT NOT NULL,
          entry_date TEXT NOT NULL, release_date TEXT DEFAULT '', charge TEXT NOT NULL,
          detaining_authority TEXT NOT NULL, case_officer TEXT NOT NULL,
          status TEXT NOT NULL DEFAULT 'محتجز', notes TEXT DEFAULT '', created_at TEXT NOT NULL,
          created_by TEXT NOT NULL, archived_at TEXT DEFAULT '', archived_by TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS detainee_movements (
          id INTEGER PRIMARY KEY AUTOINCREMENT, detainee_id INTEGER NOT NULL, movement_type TEXT NOT NULL,
          movement_date TEXT NOT NULL, actor TEXT NOT NULL, reason TEXT NOT NULL DEFAULT '',
          before_json TEXT NOT NULL DEFAULT '{}', after_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS detainee_corrections (
          id INTEGER PRIMARY KEY AUTOINCREMENT, detainee_id INTEGER NOT NULL, corrected_field TEXT NOT NULL,
          old_value TEXT NOT NULL, new_value TEXT NOT NULL, reason TEXT NOT NULL,
          actor TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_detainee_entry ON detainees(entry_date);
        CREATE INDEX IF NOT EXISTS idx_detainee_status ON detainees(status);
        CREATE INDEX IF NOT EXISTS idx_detainee_movement_date ON detainee_movements(movement_date);
        """)
        # ترحيل آمن لقاعدة البيانات الحالية دون حذف أي بيانات
        cols = {r[1] for r in c.execute("PRAGMA table_info(cases)").fetchall()}
        if "department" not in cols:
            c.execute("ALTER TABLE cases ADD COLUMN department TEXT NOT NULL DEFAULT 'قسم التحقيقات'")
        case_cols = {r[1] for r in c.execute("PRAGMA table_info(cases)").fetchall()}
        if "archived_at" not in case_cols: c.execute("ALTER TABLE cases ADD COLUMN archived_at TEXT DEFAULT ''")
        if "archived_by" not in case_cols: c.execute("ALTER TABLE cases ADD COLUMN archived_by TEXT DEFAULT ''")
        detainee_cols = {r[1] for r in c.execute("PRAGMA table_info(detainees)").fetchall()}
        if "archived_at" not in detainee_cols: c.execute("ALTER TABLE detainees ADD COLUMN archived_at TEXT DEFAULT ''")
        if "archived_by" not in detainee_cols: c.execute("ALTER TABLE detainees ADD COLUMN archived_by TEXT DEFAULT ''")
        # سجلات الحركات والتصحيحات وسجل التدقيق append-only: يمنع التعديل والحذف داخل SQLite.
        c.executescript("""
        CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'سجل التدقيق غير قابل للتعديل'); END;
        CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'سجل التدقيق غير قابل للحذف'); END;
        CREATE TRIGGER IF NOT EXISTS movements_no_update BEFORE UPDATE ON detainee_movements BEGIN SELECT RAISE(ABORT,'سجل الحركات غير قابل للتعديل'); END;
        CREATE TRIGGER IF NOT EXISTS movements_no_delete BEFORE DELETE ON detainee_movements BEGIN SELECT RAISE(ABORT,'سجل الحركات غير قابل للحذف'); END;
        CREATE TRIGGER IF NOT EXISTS corrections_no_update BEFORE UPDATE ON detainee_corrections BEGIN SELECT RAISE(ABORT,'سجل التصحيحات غير قابل للتعديل'); END;
        CREATE TRIGGER IF NOT EXISTS corrections_no_delete BEFORE DELETE ON detainee_corrections BEGIN SELECT RAISE(ABORT,'سجل التصحيحات غير قابل للحذف'); END;
        """)
        # ترحيل النزلاء السابقين إلى سجل الحركات مرة واحدة.
        for old in c.execute("SELECT * FROM detainees").fetchall():
            exists = c.execute("SELECT 1 FROM detainee_movements WHERE detainee_id=? LIMIT 1", (old['id'],)).fetchone()
            if not exists:
                c.execute("INSERT INTO detainee_movements(detainee_id,movement_type,movement_date,actor,reason,before_json,after_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                    (old['id'],'ENTRY',old['entry_date'],old['created_by'],'ترحيل سجل دخول سابق إلى دفتر الحركات','{}',json.dumps(dict(old),ensure_ascii=False),now_iso()))
                if old['release_date']:
                    c.execute("INSERT INTO detainee_movements(detainee_id,movement_type,movement_date,actor,reason,before_json,after_json,created_at) VALUES(?,?,?,?,?,?,?,?)",
                        (old['id'],'RELEASE',old['release_date'],old['created_by'],'ترحيل تاريخ إفراج سابق إلى دفتر الحركات','{}',json.dumps({'release_date':old['release_date'],'status':'مفرج عنه'},ensure_ascii=False),now_iso()))
        for name in DEFAULT_MEMO_TYPES:
            c.execute("INSERT OR IGNORE INTO memo_types(name,is_custom) VALUES(?,0)", (name,))
        for name in DEPARTMENTS:
            c.execute("INSERT OR IGNORE INTO departments(name,description,created_at) VALUES(?,?,?)", (name,"قسم إداري",now_iso()))
        self.persist()

    def persist(self):
        raw = self.conn.serialize()
        token = self.fernet.encrypt(raw)
        atomic_write(DB_PATH, token)

    def audit(self, actor: str, action: str, entity: str, entity_id: str, details: str):
        last = self.conn.execute("SELECT event_hash FROM audit ORDER BY id DESC LIMIT 1").fetchone()
        prev = last[0] if last else "0" * 64
        body = {"event_time": now_iso(), "actor": actor, "action": action,
                "entity": entity, "entity_id": str(entity_id), "details": details,
                "previous_hash": prev}
        canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        digest = hmac.new(self.dek, canonical, hashlib.sha256).hexdigest()
        self.conn.execute("INSERT INTO audit(event_time,actor,action,entity,entity_id,details,previous_hash,event_hash) VALUES(?,?,?,?,?,?,?,?)",
            (body["event_time"], actor, action, entity, str(entity_id), details, prev, digest))

    def verify_audit(self) -> tuple[bool, int]:
        prev = "0" * 64
        rows = self.conn.execute("SELECT * FROM audit ORDER BY id").fetchall()
        for r in rows:
            body = {"event_time": r["event_time"], "actor": r["actor"], "action": r["action"],
                    "entity": r["entity"], "entity_id": r["entity_id"], "details": r["details"],
                    "previous_hash": r["previous_hash"]}
            canonical = json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
            expected = hmac.new(self.dek, canonical, hashlib.sha256).hexdigest()
            if r["previous_hash"] != prev or not hmac.compare_digest(expected, r["event_hash"]): return False, len(rows)
            prev = r["event_hash"]
        return True, len(rows)

    def cases(self, query=""):
        q = (query or "").strip()
        if not q: return self.conn.execute("SELECT * FROM cases WHERE COALESCE(archived_at,'')='' ORDER BY id DESC").fetchall()
        like = f"%{q}%"
        return self.conn.execute("SELECT * FROM cases WHERE COALESCE(archived_at,'')='' AND (case_number LIKE ? OR party_name LIKE ? OR case_type LIKE ? OR case_date LIKE ? OR status LIKE ? OR summary LIKE ? OR notes LIKE ?) ORDER BY id DESC", (like,)*7).fetchall()

    def case(self, case_id: int): return self.conn.execute("SELECT * FROM cases WHERE id=?", (case_id,)).fetchone()

    def save_case(self, data: dict, case_id: Optional[int], actor: str):
        stamp = now_iso()
        if case_id is None:
            cur = self.conn.execute("INSERT INTO cases(case_number,party_name,case_type,case_date,status,priority,summary,notes,created_at,updated_at,created_by,updated_by,department) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (data["case_number"],data["party_name"],data["case_type"],data["case_date"],data["status"],data["priority"],data["summary"],data["notes"],stamp,stamp,actor,actor,data.get("department",DEPARTMENTS[4])))
            cid = cur.lastrowid; action = "CREATE"
        else:
            self.conn.execute("UPDATE cases SET case_number=?,party_name=?,case_type=?,case_date=?,status=?,priority=?,summary=?,notes=?,updated_at=?,updated_by=?,department=? WHERE id=?",
                (data["case_number"],data["party_name"],data["case_type"],data["case_date"],data["status"],data["priority"],data["summary"],data["notes"],stamp,actor,data.get("department",DEPARTMENTS[4]),case_id))
            cid = case_id; action = "UPDATE"
        self.audit(actor, action, "case", cid, f"رقم القضية: {data['case_number']}")
        self.persist(); return cid

    def delete_case(self, case_id: int, actor: str):
        row = self.case(case_id)
        if not row: raise ValueError("القضية غير موجودة أو مؤرشفة بالفعل.")
        stamp = now_iso()
        self.conn.execute("UPDATE cases SET archived_at=?, archived_by=?, status='مؤرشفة', updated_at=?, updated_by=? WHERE id=?", (stamp,actor,stamp,actor,case_id))
        self.audit(actor, "CASE_ARCHIVE", "case", case_id, f"أرشفة القضية بدلاً من حذفها: {row['case_number']}")
        self.persist()

    def attachments(self, case_id: int):
        return self.conn.execute("SELECT * FROM attachments WHERE case_id=? ORDER BY id DESC", (case_id,)).fetchall()

    def close(self): self.conn.close()


def build_memo_docx(row, actor: str) -> Path:
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Pt
    doc=Document(); sec=doc.sections[0]; sec.top_margin=Pt(48); sec.bottom_margin=Pt(48)
    h=doc.add_heading(row["memo_type"],0); h.alignment=WD_ALIGN_PARAGRAPH.CENTER
    p=doc.add_paragraph(OFFICE_NAME); p.alignment=WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph(f"رقم المذكرة: {row['memo_number'] or '—'}")
    doc.add_paragraph(f"التاريخ: {row['memo_date']}")
    doc.add_paragraph(f"الجهة المرسل إليها: {row['recipient'] or '—'}")
    doc.add_heading(row["subject"],level=1); doc.add_paragraph(row["body"] or "")
    doc.add_paragraph(f"أُعدت بواسطة: {actor} | {now_iso()}")
    doc.add_paragraph("التوقيع: ____________________       الختم / الاعتماد: ____________________")
    safe=re.sub(r"[^\w-]+","_",row["subject"],flags=re.UNICODE)[:50] or "memo"
    out=REPORT_DIR/f"Memo_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"; doc.save(out); return out


def role_can_write(role: str) -> bool: return role in ("admin", "investigator")
def role_is_admin(role: str) -> bool: return role == "admin"
def role_can_view_detention(role: str) -> bool: return role in ("admin", "investigator", "detention_viewer")
def role_is_detention_only(role: str) -> bool: return role == "detention_viewer"


def build_docx(row, report_type: str, actor: str) -> Path:
    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Pt
    doc = Document()
    section = doc.sections[0]
    section.top_margin = Pt(55); section.bottom_margin = Pt(55)
    title = doc.add_heading("محضر قضية" if report_type == "محضر" else "تقرير رسمي بشأن قضية", 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    doc.add_paragraph("وثيقة داخلية - تخضع لضوابط السرية المعتمدة لدى الجهة")
    table = doc.add_table(rows=0, cols=2); table.style = "Table Grid"
    fields = [("رقم القضية",row["case_number"]),("اسم الطرف",row["party_name"]),("التصنيف",row["case_type"]),
              ("تاريخ التسجيل",row["case_date"]),("الحالة",row["status"]),("الأولوية",row["priority"]),
              ("المسؤول عن آخر تعديل",row["updated_by"]),("آخر تحديث",row["updated_at"])]
    for a,b in fields:
        cells = table.add_row().cells; cells[0].text = a; cells[1].text = str(b)
    doc.add_heading("ملخص القضية", level=2); doc.add_paragraph(row["summary"] or "لا يوجد ملخص مسجل.")
    doc.add_heading("التفاصيل والملاحظات", level=2); doc.add_paragraph(row["notes"] or "لا توجد ملاحظات.")
    doc.add_paragraph(f"أُنشئ المستند بواسطة: {actor} | {now_iso()}")
    doc.add_paragraph("التوقيع: ____________________       الاعتماد: ____________________")
    safe = re.sub(r"[^\w-]+", "_", row["case_number"], flags=re.UNICODE)
    out = REPORT_DIR / f"{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
    doc.save(out); return out


def main(page: ft.Page):
    page.title = APP_NAME; page.theme_mode = ft.ThemeMode.DARK; page.bgcolor = "#08111F"
    page.rtl = True; page.padding = 18; page.window.width = 1420; page.window.height = 900
    page.theme = ft.Theme(color_scheme=ft.ColorScheme(primary="#38BDF8", surface="#111D30"))
    state = {"vault": None, "dek": None, "username": None, "role": None, "selected": None}

    def notify(msg, error=False):
        page.snack_bar = ft.SnackBar(ft.Text(msg), bgcolor="#7F1D1D" if error else "#14532D")
        page.snack_bar.open = True; page.update()

    def text_field(label, **kw):
        return ft.TextField(label=label, border_radius=10, **kw)

    def header(subtitle="إدارة محلية مشفرة للقضايا والمرفقات"):
        return ft.Container(ft.Row([
            ft.Column([ft.Text(OFFICE_NAME, size=16, weight=ft.FontWeight.BOLD, color="#7DD3FC"), ft.Text(APP_NAME, size=23, weight=ft.FontWeight.BOLD, color="#F8FAFC"), ft.Text(subtitle, color="#94A3B8", size=12)], spacing=3, expand=True),
            ft.Icon(ft.Icons.SHIELD_LOCK, size=38, color="#38BDF8")]), padding=ft.padding.only(bottom=12))

    def show_setup():
        page.controls.clear()
        u = text_field("اسم المدير", prefix_icon=ft.Icons.PERSON, autofocus=True)
        p1 = text_field("كلمة مرور قوية (12 حرفاً على الأقل)", password=True, can_reveal_password=True, prefix_icon=ft.Icons.LOCK)
        p2 = text_field("تأكيد كلمة المرور", password=True, can_reveal_password=True)
        hint = ft.Text("سيُنشأ حساب مدير أولي. احفظ كلمة المرور؛ لا توجد آلية لاستعادتها إذا فُقدت.", color="#FBBF24", size=12)
        def create(_):
            username = (u.value or "").strip()
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username): notify("اسم المستخدم: 3-32 حرفاً إنجليزياً أو رقماً أو . _ -", True); return
            if len(p1.value or "") < 12: notify("كلمة المرور يجب ألا تقل عن 12 حرفاً.", True); return
            if p1.value != p2.value: notify("كلمتا المرور غير متطابقتين.", True); return
            dek = Fernet.generate_key(); cfg = {"version":1,"users":{username:create_user_record(username,p1.value,"admin",dek)}}
            save_config(cfg, dek); state["dek"] = dek; state["username"] = username; state["role"] = "admin"
            state["vault"] = Vault(dek); state["vault"].audit(username,"INITIALIZE","system","1","إنشاء مخزن البيانات والحساب الإداري الأول")
            state["vault"].persist(); show_app()
        card = ft.Container(ft.Column([ft.Text("تهيئة آمنة لأول استخدام", size=21, weight=ft.FontWeight.BOLD), ft.Text("إنشاء المدير ومفتاح التشفير المحلي", color="#94A3B8"), u,p1,p2,hint,ft.FilledButton("إنشاء المخزن الآمن", icon=ft.Icons.SECURITY, on_click=create, width=240)], spacing=15), width=520, padding=28, bgcolor="#111D30", border=ft.border.all(1,"#26364D"), border_radius=18)
        page.add(header(), ft.Row([card], alignment=ft.MainAxisAlignment.CENTER, vertical_alignment=ft.CrossAxisAlignment.CENTER, expand=True)); page.update()

    def show_login():
        page.controls.clear(); u = text_field("اسم المستخدم", prefix_icon=ft.Icons.PERSON, autofocus=True)
        pw = text_field("كلمة المرور", password=True, can_reveal_password=True, prefix_icon=ft.Icons.LOCK)
        def login(_):
            try:
                cfg = load_config(); dek, rec = authenticate((u.value or "").strip(), pw.value or "", cfg)
                state.update({"dek":dek,"username":(u.value or "").strip(),"role":rec["role"],"vault":Vault(dek),"selected":None})
                state["vault"].audit(state["username"],"LOGIN","session","local","تسجيل دخول ناجح"); state["vault"].persist(); show_app()
            except Exception as ex: notify(str(ex), True)
        card = ft.Container(ft.Column([ft.Text("تسجيل الدخول", size=22, weight=ft.FontWeight.BOLD),u,pw,ft.FilledButton("دخول آمن", icon=ft.Icons.LOGIN, on_click=login, width=220),ft.Text("البيانات مشفرة على هذا الجهاز ولا تُرسل إلى أي خادم.", color="#94A3B8", size=11)], spacing=15), width=470, padding=28, bgcolor="#111D30", border=ft.border.all(1,"#26364D"), border_radius=18)
        page.add(header(), ft.Row([card], alignment=ft.MainAxisAlignment.CENTER, vertical_alignment=ft.CrossAxisAlignment.CENTER, expand=True)); page.update()

    def show_app():
        page.controls.clear(); vault: Vault = state["vault"]; username=state["username"]; role=state["role"]
        selected = {"id": state.get("selected")}
        search = text_field("بحث فوري: رقم القضية، الطرف، النوع، الحالة...", prefix_icon=ft.Icons.SEARCH, expand=True)
        table_area = ft.Column(expand=True, scroll=ft.ScrollMode.AUTO, spacing=4)
        form_number = text_field("رقم القضية *", expand=True)
        form_party = text_field("اسم الطرف *", expand=True)
        form_type = ft.Dropdown(label="التصنيف", value=CASE_TYPES[0], options=[ft.DropdownOption(key=x, text=x) for x in CASE_TYPES], expand=True)
        form_date = text_field("التاريخ YYYY-MM-DD", value=date.today().isoformat(), expand=True)
        form_status = ft.Dropdown(label="الحالة", value=STATUSES[0], options=[ft.DropdownOption(key=x, text=x) for x in STATUSES], expand=True)
        form_priority = ft.Dropdown(label="الأولوية", value="متوسطة", options=[ft.DropdownOption(key=x, text=x) for x in ["منخفضة","متوسطة","عالية","حرجة"]], expand=True)
        form_department = ft.Dropdown(label="القسم المختص", value=DEPARTMENTS[4], options=[ft.DropdownOption(key=x,text=x) for x in DEPARTMENTS], expand=True)
        form_summary = text_field("ملخص القضية", multiline=True, min_lines=2, max_lines=3)
        form_notes = text_field("التفاصيل والملاحظات", multiline=True, min_lines=3, max_lines=6)
        attach_area = ft.Column(spacing=4)
        count_label = ft.Text("0 قضية", color="#94A3B8", size=12)
        audit_area = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, spacing=5)
        users_area = ft.Column(spacing=8)
        can_write = role_can_write(role); admin = role_is_admin(role)
        for control in [form_number,form_party,form_type,form_date,form_status,form_priority,form_department,form_summary,form_notes]: control.disabled = not can_write

        def refresh_attachments():
            attach_area.controls.clear()
            if not selected["id"]: attach_area.controls.append(ft.Text("احفظ القضية أولاً لإضافة مرفقات.", color="#94A3B8", size=11)); return
            files = vault.attachments(selected["id"])
            if not files: attach_area.controls.append(ft.Text("لا توجد مرفقات لهذه القضية.", color="#94A3B8", size=11))
            for f in files:
                attach_area.controls.append(ft.Row([ft.Icon(ft.Icons.PICTURE_AS_PDF if f["mime_type"]=="application/pdf" else ft.Icons.ATTACH_FILE, color="#7DD3FC"),ft.Text(f["original_name"], expand=True, size=12),ft.Text(f"{f['size_bytes']/1024:.1f} KB", color="#94A3B8", size=10),ft.TextButton("تصدير", on_click=lambda e, aid=f["id"]: export_attachment(aid)),ft.Text("سجل محفوظ",size=10,color="#94A3B8")], spacing=4))

        def clear_form():
            selected["id"] = None; state["selected"] = None
            for c in (form_number,form_party,form_summary,form_notes): c.value=""
            form_type.value=CASE_TYPES[0]; form_date.value=date.today().isoformat(); form_status.value=STATUSES[0]; form_priority.value="متوسطة"; form_department.value=DEPARTMENTS[4]
            refresh_attachments(); page.update()

        def fill(row):
            selected["id"] = row["id"]; state["selected"] = row["id"]
            form_number.value=row["case_number"]; form_party.value=row["party_name"]; form_type.value=row["case_type"]
            form_date.value=row["case_date"]; form_status.value=row["status"]; form_priority.value=row["priority"]; form_department.value=row["department"] if "department" in row.keys() else DEPARTMENTS[4]
            form_summary.value=row["summary"] or ""; form_notes.value=row["notes"] or ""
            refresh_attachments(); page.update()

        def refresh_table():
            rows=vault.cases(search.value or ""); count_label.value=f"{len(rows)} قضية"; table_area.controls.clear()
            if not rows: table_area.controls.append(ft.Container(ft.Text("لا توجد قضايا مطابقة.", color="#94A3B8"), padding=20))
            else:
                table_area.controls.append(ft.DataTable(columns=[ft.DataColumn(ft.Text(x)) for x in ["رقم القضية","الطرف","التصنيف","القسم","التاريخ","الحالة","الأولوية"]], rows=[
                    ft.DataRow(selected=(r["id"]==selected["id"]), on_select_changed=lambda e, rr=r: fill(rr), cells=[ft.DataCell(ft.Text(str(r[k]))) for k in ["case_number","party_name","case_type","department","case_date","status","priority"]]) for r in rows], column_spacing=18, heading_row_height=44, data_row_min_height=45))
            page.update()

        def save_case(_=None):
            if not can_write: notify("صلاحيتك للقراءة فقط.",True); return
            number=(form_number.value or "").strip(); party=(form_party.value or "").strip(); dt=(form_date.value or "").strip()
            if not number or not party: notify("رقم القضية واسم الطرف إلزاميان.",True); return
            try: datetime.strptime(dt,"%Y-%m-%d")
            except ValueError: notify("صيغة التاريخ يجب أن تكون YYYY-MM-DD.",True); return
            data={"case_number":number,"party_name":party,"case_type":form_type.value or CASE_TYPES[0],"case_date":dt,"status":form_status.value or STATUSES[0],"priority":form_priority.value or "متوسطة","department":form_department.value or DEPARTMENTS[4],"summary":form_summary.value or "","notes":form_notes.value or ""}
            try:
                selected["id"]=vault.save_case(data,selected["id"],username); state["selected"]=selected["id"]; refresh_table(); refresh_attachments(); notify("حُفظت القضية وسُجلت العملية في سجل التدقيق.")
            except sqlite3.IntegrityError: notify("رقم القضية مستخدم بالفعل.",True)
            except Exception as ex: notify(f"تعذر الحفظ: {ex}",True)

        def delete_case(_=None):
            if not can_write or not selected["id"]: notify("حدد قضية ولتكن لديك صلاحية التعديل.",True); return
            def yes(_):
                try:
                    vault.delete_case(selected["id"],username); vault.persist(); dlg.open=False; clear_form(); refresh_table(); notify("أُرشفت القضية وحُفظت مرفقاتها وسجلها التاريخي دون حذف نهائي.")
                except Exception as ex: notify(str(ex),True)
            def no(_): dlg.open=False; page.update()
            dlg=ft.AlertDialog(modal=True,title=ft.Text("تأكيد حذف القضية"),content=ft.Text("سيتم إخفاء القضية من السجل النشط مع الاحتفاظ بها ومرفقاتها وتاريخها لأغراض المراجعة. هل تريد الأرشفة؟"),actions=[ft.TextButton("إلغاء",on_click=no),ft.TextButton("أرشفة القضية",on_click=yes)]); page.show_dialog(dlg)

        def process_picked_files(files):
            if not files or not selected["id"]: return
            try:
                for picked in files:
                    name = picked.name
                    suffix = Path(name).suffix.lower()
                    if suffix not in (".pdf", ".png", ".jpg", ".jpeg"):
                        raise ValueError("يسمح فقط بملفات PDF وPNG وJPG.")
                    raw = picked.bytes if getattr(picked, "bytes", None) is not None else (Path(picked.path).read_bytes() if picked.path else None)
                    if raw is None: raise ValueError("تعذر قراءة الملف من مدير الملفات على هذا الجهاز.")
                    size=len(raw)
                    if size > 30*1024*1024: raise ValueError("الحد الأقصى للمرفق الواحد 30 ميغابايت.")
                    digest=hashlib.sha256(raw).hexdigest(); stored=secrets.token_hex(20)+".bin"
                    token=vault.fernet.encrypt(raw); atomic_write(ATTACH_DIR/stored,token)
                    mime="application/pdf" if suffix==".pdf" else ("image/jpeg" if suffix in (".jpg",".jpeg") else "image/png")
                    vault.conn.execute("INSERT INTO attachments(case_id,original_name,stored_name,mime_type,size_bytes,sha256,uploaded_at,uploaded_by) VALUES(?,?,?,?,?,?,?,?)",(selected["id"],name,stored,mime,size,digest,now_iso(),username))
                    vault.audit(username,"ATTACH","attachment",stored,f"إرفاق {name} بالقضية {selected['id']}")
                vault.persist(); refresh_attachments(); notify("تم تشفير المرفق وحفظه.")
            except Exception as ex: notify(f"فشل إرفاق الملف: {ex}",True)

        def export_attachment(aid):
            row=vault.conn.execute("SELECT * FROM attachments WHERE id=?",(aid,)).fetchone()
            if not row: return
            try:
                raw=vault.fernet.decrypt((ATTACH_DIR/row["stored_name"]).read_bytes())
                if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), row["sha256"]):
                    raise ValueError("فشل التحقق من بصمة المرفق؛ لا تصدّر الملف.")
                safe=re.sub(r"[^\w. -]+","_",row["original_name"],flags=re.UNICODE)
                out=ROOT/"exports"/safe; atomic_write(out,raw)
                vault.audit(username,"EXPORT","attachment",aid,f"تصدير المرفق {row['original_name']}"); vault.persist()
                notify(f"تم فك تشفير نسخة التصدير داخل مجلد exports: {safe}")
            except Exception as ex: notify(f"تعذر تصدير المرفق: {ex}",True)

        def delete_attachment(aid):
            row=vault.conn.execute("SELECT * FROM attachments WHERE id=?",(aid,)).fetchone()
            if not row: return
            vault.conn.execute("DELETE FROM attachments WHERE id=?",(aid,)); vault.audit(username,"DELETE","attachment",aid,f"حذف المرفق {row['original_name']}")
            try: (ATTACH_DIR/row["stored_name"]).unlink(missing_ok=True)
            except Exception: pass
            vault.persist(); refresh_attachments(); notify("حُذف المرفق.")

        picker=ft.FilePicker()
        async def pick_files(_):
            if not selected["id"]: notify("احفظ القضية أولاً.",True); return
            files = await picker.pick_files(allow_multiple=True, with_data=True, file_type=ft.FilePickerFileType.CUSTOM, allowed_extensions=["pdf","png","jpg","jpeg"])
            process_picked_files(files)

        def make_report(kind):
            if not selected["id"]: notify("حدد قضية أولاً.",True); return
            try:
                row=vault.case(selected["id"]); path=build_docx(row,kind,username)
                vault.audit(username,"REPORT","case",selected["id"],f"إنشاء {kind}: {path.name}"); vault.persist()
                notify(f"تم إنشاء مستند Word: {path.name}")
            except Exception as ex: notify(f"تعذر إنشاء التقرير: {ex}",True)

        def create_backup(_=None):
            if not admin: notify("هذه العملية للمدير فقط.", True); return
            try:
                vault.audit(username,"BACKUP","system","local","إنشاء نسخة احتياطية مشفرة")
                vault.persist()
                target = ROOT / "exports" / f"SecureCaseDesk_Backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.zip"
                with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as archive:
                    archive.write(CONFIG_PATH, "accounts.json")
                    if DB_PATH.exists(): archive.write(DB_PATH, "vault.db.enc")
                    for item in ATTACH_DIR.glob("*.bin"): archive.write(item, f"attachments/{item.name}")
                notify(f"تم إنشاء نسخة احتياطية؛ جميع محتويات القضايا والمرفقات مشفرة: {target.name}")
            except Exception as ex: notify(f"فشل إنشاء النسخة الاحتياطية: {ex}", True)

        def refresh_audit():
            audit_area.controls.clear(); ok,total=vault.verify_audit()
            audit_area.controls.append(ft.Row([ft.Icon(ft.Icons.VERIFIED_USER if ok else ft.Icons.WARNING,color="#22C55E" if ok else "#EF4444"),ft.Text(f"{'سلسلة التدقيق سليمة' if ok else 'تحذير: فشل التحقق من سلامة السجل'} · {total} حدثاً",color="#86EFAC" if ok else "#FCA5A5",weight=ft.FontWeight.BOLD)]))
            rows=vault.conn.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 250").fetchall()
            for r in rows: audit_area.controls.append(ft.Container(ft.Row([ft.Text(r["event_time"],width=180,size=10,color="#94A3B8"),ft.Text(r["actor"],width=100,size=11),ft.Text(r["action"],width=90,size=11,color="#7DD3FC"),ft.Text(f"{r['entity']} #{r['entity_id']} — {r['details']}",expand=True,size=11)],spacing=8),padding=8,border=ft.border.only(bottom=ft.BorderSide(1,"#26364D"))))

        def refresh_users():
            users_area.controls.clear(); cfg=load_config()
            for uname,rec in cfg["users"].items():
                users_area.controls.append(ft.Row([ft.Icon(ft.Icons.PERSON),ft.Text(uname,expand=True),ft.Text(ROLES.get(rec["role"],rec["role"]),color="#7DD3FC"),ft.Text("نشط" if rec.get("enabled",True) else "معطل",color="#86EFAC" if rec.get("enabled",True) else "#FCA5A5"),ft.TextButton("تفعيل/تعطيل",on_click=lambda e,n=uname:toggle_user(n),disabled=(n==username if False else False))],spacing=8))

        def toggle_user(uname):
            if uname==username: notify("لا يمكنك تعطيل حسابك الحالي.",True); return
            cfg=load_config(); cfg["users"][uname]["enabled"]=not cfg["users"][uname].get("enabled",True); save_config(cfg,state["dek"])
            vault.audit(username,"USER_STATUS","user",uname,"تغيير حالة الحساب"); vault.persist(); refresh_users(); notify("تم تحديث حالة الحساب.")

        def add_user(_):
            nu=(new_user.value or "").strip(); np=new_pass.value or ""; nr=new_role.value or "viewer"
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}",nu): notify("اسم المستخدم غير صالح.",True); return
            if len(np)<12: notify("كلمة المرور يجب ألا تقل عن 12 حرفاً.",True); return
            cfg=load_config()
            if nu in cfg["users"]: notify("اسم المستخدم موجود.",True); return
            cfg["users"][nu]=create_user_record(nu,np,nr,state["dek"]); save_config(cfg,state["dek"])
            vault.audit(username,"USER_CREATE","user",nu,f"إنشاء حساب بدور {ROLES[nr]}"); vault.persist(); new_user.value=""; new_pass.value=""; refresh_users(); notify("تم إنشاء الحساب.")

        new_user=text_field("اسم المستخدم الجديد",expand=True); new_pass=text_field("كلمة مرور أولية قوية",password=True,can_reveal_password=True,expand=True)
        new_role=ft.Dropdown(label="الدور",value="viewer",options=[ft.DropdownOption(key=k,text=v) for k,v in ROLES.items()],expand=True)
        users_tab=ft.Column([ft.Text("إدارة الحسابات والصلاحيات",size=18,weight=ft.FontWeight.BOLD),ft.Text("كلمات المرور لا تُخزن كنص صريح. أوقف الحسابات بدلاً من حذف أثرها.",color="#94A3B8",size=11),ft.Row([new_user,new_pass,new_role],wrap=True),ft.FilledButton("إنشاء مستخدم",icon=ft.Icons.PERSON_ADD,on_click=add_user),users_area],scroll=ft.ScrollMode.AUTO,expand=True)

        form_card=ft.Container(ft.Column([ft.Text("بيانات القضية",size=18,weight=ft.FontWeight.BOLD),ft.Row([form_number,form_party]),ft.Row([form_type,form_date]),ft.Row([form_status,form_priority]),form_department,form_summary,form_notes,ft.Row([ft.FilledButton("حفظ",icon=ft.Icons.SAVE,on_click=save_case,disabled=not can_write),ft.OutlinedButton("جديد",icon=ft.Icons.ADD,on_click=lambda e:clear_form(),disabled=not can_write),ft.OutlinedButton("أرشفة",icon=ft.Icons.ARCHIVE,on_click=delete_case,disabled=not can_write)],wrap=True),ft.Divider(color="#26364D"),ft.Row([ft.Text("المرفقات المشفرة",weight=ft.FontWeight.BOLD),ft.IconButton(ft.Icons.ADD,on_click=pick_files,tooltip="إرفاق PDF أو صورة",disabled=not can_write)],alignment=ft.MainAxisAlignment.SPACE_BETWEEN),attach_area],spacing=11),padding=16,bgcolor="#111D30",border=ft.border.all(1,"#26364D"),border_radius=16)
        cases_tab=ft.Column([ft.Row([ft.Text("سجل القضايا",size=18,weight=ft.FontWeight.BOLD),ft.Container(expand=True),count_label]),search,ft.Text("اختر صفاً لعرض التفاصيل وتعديلها.",size=11,color="#94A3B8"),table_area,ft.Divider(color="#26364D"),ft.Row([ft.OutlinedButton("تقرير رسمي Word",icon=ft.Icons.DESCRIPTION,on_click=lambda e:make_report("تقرير رسمي")),ft.OutlinedButton("محضر Word",icon=ft.Icons.ARTICLE,on_click=lambda e:make_report("محضر"))],wrap=True)],expand=True,spacing=10)
        search.on_change=lambda e:refresh_table()
        dashboard=ft.ResponsiveRow([ft.Container(content=form_card,col={"sm":12,"md":5,"lg":4}),ft.Container(content=cases_tab,col={"sm":12,"md":7,"lg":8})],spacing=14,run_spacing=14)
        audit_tab=ft.Column([ft.Text("سجل التدقيق",size=18,weight=ft.FontWeight.BOLD),ft.Text("سجل محلي مترابط بـ HMAC؛ يعرض آخر 250 حدثاً ويتحقق من سلامة السلسلة.",size=11,color="#94A3B8"),ft.OutlinedButton("إعادة فحص سلامة السجل",icon=ft.Icons.VERIFIED_USER,on_click=lambda e:refresh_audit()),audit_area],expand=True)
        # مكتب مدير المباحث الجنائية: مذكرات قابلة للتوسعة
        memo_type = ft.Dropdown(label="نوع المذكرة", options=[], expand=True)
        memo_number = text_field("رقم المذكرة", expand=True)
        memo_date = text_field("التاريخ YYYY-MM-DD", value=date.today().isoformat(), expand=True)
        memo_to = text_field("الجهة / المرسل إليه", expand=True)
        memo_subject = text_field("الموضوع *", expand=True)
        memo_body = text_field("نص المذكرة / التقرير", multiline=True, min_lines=4, max_lines=9)
        new_memo_type = text_field("إضافة نوع مذكرة جديد...", expand=True)
        memo_rows = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, spacing=4)
        def export_memo(mid):
            row=vault.conn.execute("SELECT * FROM memos WHERE id=?",(mid,)).fetchone()
            if not row: return
            try:
                path=build_memo_docx(row,username); vault.audit(username,"MEMO_EXPORT","memo",mid,f"إنشاء ملف Word: {path.name}"); vault.persist()
                notify(f"تم إنشاء ملف Word للمذكرة: {path.name}")
            except Exception as ex: notify(f"تعذر إنشاء ملف Word: {ex}",True)
        def refresh_memo_types():
            names=[r[0] for r in vault.conn.execute("SELECT name FROM memo_types ORDER BY is_custom,name").fetchall()]
            memo_type.options=[ft.DropdownOption(key=n,text=n) for n in names]
            if names and not memo_type.value: memo_type.value=names[0]
        def add_memo_type(_):
            name=(new_memo_type.value or "").strip()
            if not name: return
            vault.conn.execute("INSERT OR IGNORE INTO memo_types(name,is_custom) VALUES(?,1)",(name,))
            vault.audit(username,"MEMO_TYPE_ADD","memo_type",name,"إضافة نوع مذكرة مخصص"); vault.persist()
            new_memo_type.value=""; refresh_memo_types(); page.update(); notify("تمت إضافة نوع المذكرة.")
        def save_memo(_):
            if not can_write: notify("صلاحيتك للقراءة فقط.",True); return
            subject=(memo_subject.value or "").strip(); d=(memo_date.value or "").strip()
            if not subject: notify("اكتب موضوع المذكرة.",True); return
            try: datetime.strptime(d,"%Y-%m-%d")
            except ValueError: notify("صيغة التاريخ YYYY-MM-DD.",True); return
            cur=vault.conn.execute("INSERT INTO memos(memo_type,memo_number,memo_date,recipient,subject,body,created_at,created_by) VALUES(?,?,?,?,?,?,?,?)",(memo_type.value or "مذكرة",memo_number.value or "",d,memo_to.value or "",subject,memo_body.value or "",now_iso(),username))
            vault.audit(username,"MEMO_CREATE","memo",cur.lastrowid,f"إنشاء {memo_type.value}: {subject}"); vault.persist(); refresh_memos(); notify("تم حفظ المذكرة وتسجيل العملية.")
        def refresh_memos():
            memo_rows.controls.clear()
            rows=vault.conn.execute("SELECT * FROM memos ORDER BY id DESC LIMIT 300").fetchall()
            for r in rows:
                memo_rows.controls.append(ft.Container(ft.Column([ft.Row([ft.Text(r["memo_type"],weight=ft.FontWeight.BOLD,color="#7DD3FC",expand=True),ft.Text(r["memo_date"],size=11,color="#94A3B8")]),ft.Text(f"{r['memo_number']} | {r['subject']}",weight=ft.FontWeight.BOLD),ft.Text(f"إلى: {r['recipient']} | أنشأها: {r['created_by']}",size=11,color="#94A3B8"),ft.Text(r["body"] or "",size=12),ft.Row([ft.OutlinedButton("إنشاء Word",icon=ft.Icons.DESCRIPTION,on_click=lambda e,i=r["id"]:export_memo(i))])],spacing=4),padding=10,border=ft.border.only(bottom=ft.BorderSide(1,"#26364D"))))
        memo_tab=ft.Column([ft.Text("مكتب مدير المباحث الجنائية",size=20,weight=ft.FontWeight.BOLD,color="#7DD3FC"),ft.Text(OFFICE_NAME,color="#94A3B8"),ft.Row([memo_type,memo_number,memo_date],wrap=True),ft.Row([memo_to,memo_subject],wrap=True),memo_body,ft.Row([ft.FilledButton("حفظ المذكرة",icon=ft.Icons.SAVE,on_click=save_memo,disabled=not can_write),new_memo_type,ft.OutlinedButton("إضافة نوع",icon=ft.Icons.ADD,on_click=add_memo_type,disabled=not can_write)],wrap=True),ft.Divider(),ft.Text("سجل المذكرات والتقارير",weight=ft.FontWeight.BOLD),memo_rows],expand=True,scroll=ft.ScrollMode.AUTO,spacing=9)
        refresh_memo_types(); refresh_memos()

        # إدارة الأقسام
        dept_name=text_field("اسم القسم الجديد",expand=True); dept_desc=text_field("الوصف / الاختصاص",expand=True); dept_rows=ft.Column(spacing=5)
        def refresh_departments():
            dept_rows.controls.clear()
            for d in vault.conn.execute("SELECT * FROM departments ORDER BY name").fetchall():
                dept_rows.controls.append(ft.ListTile(title=ft.Text(d["name"]),subtitle=ft.Text(d["description"] or ""),leading=ft.Icon(ft.Icons.ACCOUNT_TREE,color="#7DD3FC")))
        def add_department(_):
            name=(dept_name.value or "").strip()
            if not name: notify("اكتب اسم القسم.",True); return
            try:
                vault.conn.execute("INSERT INTO departments(name,description,created_at) VALUES(?,?,?)",(name,dept_desc.value or "",now_iso()))
                vault.audit(username,"DEPARTMENT_CREATE","department",name,"إضافة قسم"); vault.persist()
                form_department.options=[ft.DropdownOption(key=r[0],text=r[0]) for r in vault.conn.execute("SELECT name FROM departments ORDER BY name").fetchall()]
                dept_name.value=""; dept_desc.value=""; refresh_departments(); notify("تمت إضافة القسم.")
            except sqlite3.IntegrityError: notify("القسم موجود بالفعل.",True)
        departments_tab=ft.Column([ft.Text("الأقسام",size=20,weight=ft.FontWeight.BOLD),ft.Text("توزيع القضايا حسب القسم المختص.",color="#94A3B8"),ft.Row([dept_name,dept_desc,ft.FilledButton("إضافة قسم",on_click=add_department,disabled=not can_write)],wrap=True),ft.Text("الأقسام المعتمدة",weight=ft.FontWeight.BOLD),dept_rows],expand=True,scroll=ft.ScrollMode.AUTO)
        refresh_departments()

        # كشف النزلاء والحجز الاحتياطي
        dn=text_field("اسم النزيل *",expand=True); dc=ft.Dropdown(label="جهة / فئة الإيداع",value=DETENTION_CATEGORIES[0],options=[ft.DropdownOption(key=x,text=x) for x in DETENTION_CATEGORIES],expand=True)
        de=text_field("تاريخ الدخول YYYY-MM-DD",value=date.today().isoformat(),expand=True); dr=text_field("تاريخ الإفراج YYYY-MM-DD (اختياري)",expand=True)
        dcharge=text_field("نوع التهمة *",expand=True); dauthority=text_field("الجهة الحابسة *",expand=True); dofficer=text_field("القضية لدى الضابط *",expand=True)
        dnotes=text_field("ملاحظات",multiline=True,min_lines=2,max_lines=3); detainee_rows=ft.Column(scroll=ft.ScrollMode.AUTO,expand=True,spacing=3)
        movement_rows=ft.Column(spacing=3)
        dfilter=ft.Dropdown(label="تصفية حسب الفئة",options=[ft.DropdownOption(key="الكل",text="الكل")]+[ft.DropdownOption(key=x,text=x) for x in DETENTION_CATEGORIES],value="الكل",expand=True)
        def save_detainee(_):
            if not can_write: notify("صلاحيتك للقراءة فقط.",True); return
            name=(dn.value or "").strip(); charge=(dcharge.value or "").strip(); auth=(dauthority.value or "").strip(); officer=(dofficer.value or "").strip(); ent=(de.value or "").strip(); rel=(dr.value or "").strip()
            if not all([name,charge,auth,officer]): notify("الاسم والتهمة والجهة الحابسة والضابط حقول إلزامية.",True); return
            try:
                datetime.strptime(ent,"%Y-%m-%d")
                if rel: datetime.strptime(rel,"%Y-%m-%d")
                if rel and rel<ent: raise ValueError()
            except ValueError: notify("تحقق من التاريخ؛ يجب أن يكون YYYY-MM-DD وتاريخ الإفراج بعد الدخول.",True); return
            status="مفرج عنه" if rel else "محتجز"
            cur=vault.conn.execute("INSERT INTO detainees(full_name,detainee_category,entry_date,release_date,charge,detaining_authority,case_officer,status,notes,created_at,created_by) VALUES(?,?,?,?,?,?,?,?,?,?,?)",(name,dc.value,ent,rel,charge,auth,officer,status,dnotes.value or "",now_iso(),username))
            did=cur.lastrowid
            vault.conn.execute("INSERT INTO detainee_movements(detainee_id,movement_type,movement_date,actor,reason,before_json,after_json,created_at) VALUES(?,?,?,?,?,?,?,?)",(did,"ENTRY",ent,username,"تسجيل دخول أولي", "{}",json.dumps({"full_name":name,"entry_date":ent,"category":dc.value},ensure_ascii=False),now_iso()))
            if rel:
                vault.conn.execute("INSERT INTO detainee_movements(detainee_id,movement_type,movement_date,actor,reason,before_json,after_json,created_at) VALUES(?,?,?,?,?,?,?,?)",(did,"RELEASE",rel,username,"إفراج مسجل عند القيد الأولي","{}",json.dumps({"release_date":rel,"status":status},ensure_ascii=False),now_iso()))
            vault.audit(username,"DETAINEE_REGISTER","detainee",did,f"تسجيل {name}؛ {status}"); vault.persist(); refresh_detainees(); notify("تم تسجيل النزيل وحفظ حركة الدخول في السجل التاريخي.")
        def refresh_detainees():
            detainee_rows.controls.clear()
            q="SELECT * FROM detainees"; args=[]
            if dfilter.value and dfilter.value!="الكل": q+=" WHERE detainee_category=?"; args.append(dfilter.value)
            q+=" ORDER BY entry_date DESC,id DESC"; rows=vault.conn.execute(q,args).fetchall()
            today=date.today().isoformat()
            total=vault.conn.execute("SELECT COUNT(*) FROM detainees").fetchone()[0]
            detained=vault.conn.execute("SELECT COUNT(*) FROM detainees WHERE status='محتجز'").fetchone()[0]
            released=vault.conn.execute("SELECT COUNT(*) FROM detainees WHERE status='مفرج عنه'").fetchone()[0]
            entered=vault.conn.execute("SELECT COUNT(*) FROM detainees WHERE entry_date=?",(today,)).fetchone()[0]
            exited=vault.conn.execute("SELECT COUNT(*) FROM detainees WHERE release_date=?",(today,)).fetchone()[0]
            stats.value=f"الإجمالي المسجل: {total}   |   المحتجزون حالياً: {detained}   |   المفرج عنهم: {released}   |   دخول اليوم: {entered}   |   خروج اليوم: {exited}"
            movement_rows.controls.clear()
            movement_rows.controls.append(ft.Text("الحركة اليومية — عدد الدخول والخروج لكل يوم",weight=ft.FontWeight.BOLD,color="#7DD3FC"))
            daily=vault.conn.execute("SELECT day, SUM(in_count) AS entries, SUM(out_count) AS exits FROM (SELECT entry_date AS day, COUNT(*) AS in_count, 0 AS out_count FROM detainees GROUP BY entry_date UNION ALL SELECT release_date AS day, 0 AS in_count, COUNT(*) AS out_count FROM detainees WHERE release_date<>'' GROUP BY release_date) GROUP BY day ORDER BY day DESC LIMIT 90").fetchall()
            for m in daily:
                movement_rows.controls.append(ft.Row([ft.Text(m["day"],width=130),ft.Text(f"دخول: {m['entries']}",color="#86EFAC"),ft.Text(f"خروج: {m['exits']}",color="#FBBF24")],spacing=20))
            for r in rows:
                try: days=(date.fromisoformat(r["release_date"] or today)-date.fromisoformat(r["entry_date"])).days
                except Exception: days=0
                hist=vault.conn.execute("SELECT movement_type,movement_date,actor,reason FROM detainee_movements WHERE detainee_id=? ORDER BY id DESC LIMIT 8",(r["id"],)).fetchall()
                history_text=" | ".join([f"{x['movement_date']} · {x['movement_type']} · {x['actor']} · {x['reason']}" for x in hist]) or "لا توجد حركات مسجلة"
                detainee_rows.controls.append(ft.Container(ft.Column([ft.Row([ft.Text(r["full_name"],weight=ft.FontWeight.BOLD,expand=True),ft.Text(r["status"],color="#86EFAC" if r["status"]=="مفرج عنه" else "#FBBF24")]),ft.Text(f"{r['detainee_category']} | دخول: {r['entry_date']} | مدة الحبس: {days} يوم",size=11),ft.Text(f"التهمة: {r['charge']} | الجهة الحابسة: {r['detaining_authority']}",size=11),ft.Text(f"القضية لدى الضابط: {r['case_officer']}",size=11,color="#7DD3FC"),ft.Text(f"الإفراج: {r['release_date'] or 'لم يفرج عنه'}",size=11,color="#94A3B8"),ft.Text("سجل الحركات: "+history_text,size=10,color="#A5B4FC"),ft.Row([ft.OutlinedButton("تسجيل الإفراج اليوم",on_click=lambda e,i=r['id']:release_detainee(i),disabled=(not can_write or r["status"]=="مفرج عنه")),ft.OutlinedButton("تصحيح الحركة",on_click=lambda e,i=r['id']:correct_detainee(i),disabled=not admin)])],spacing=3),padding=10,border=ft.border.only(bottom=ft.BorderSide(1,"#26364D"))))
        def correct_detainee(did):
            if not admin:
                notify("تصحيح بيانات وحركات النزلاء متاح لمدير النظام فقط.",True); return
            row=vault.conn.execute("SELECT * FROM detainees WHERE id=?",(did,)).fetchone()
            if not row: return
            new_release=text_field("تاريخ الإفراج الصحيح YYYY-MM-DD (اتركه فارغاً إذا لم يتم الإفراج)",value=row["release_date"] or "")
            reason=text_field("سبب التصحيح الإلزامي",multiline=True,min_lines=2,max_lines=3)
            def cancel(_): dlg.open=False; page.update()
            def save(_):
                nr=(new_release.value or "").strip(); why=(reason.value or "").strip()
                if not why: notify("يجب كتابة سبب التصحيح.",True); return
                try:
                    if nr:
                        datetime.strptime(nr,"%Y-%m-%d")
                        if nr < row["entry_date"]: raise ValueError()
                except ValueError:
                    notify("تاريخ الإفراج غير صحيح أو يسبق تاريخ الدخول.",True); return
                old=row["release_date"] or ""; new_status="مفرج عنه" if nr else "محتجز"
                if old==nr: notify("لا يوجد تغيير لتسجيله.",True); return
                stamp=now_iso()
                vault.conn.execute("INSERT INTO detainee_corrections(detainee_id,corrected_field,old_value,new_value,reason,actor,created_at) VALUES(?,?,?,?,?,?,?)",(did,"release_date/status",old,nr+" | "+new_status,why,username,stamp))
                before={"release_date":old,"status":row["status"]}; after={"release_date":nr,"status":new_status}
                vault.conn.execute("UPDATE detainees SET release_date=?,status=? WHERE id=?",(nr,new_status,did))
                vault.conn.execute("INSERT INTO detainee_movements(detainee_id,movement_type,movement_date,actor,reason,before_json,after_json,created_at) VALUES(?,?,?,?,?,?,?,?)",(did,"CORRECTION",date.today().isoformat(),username,why,json.dumps(before,ensure_ascii=False),json.dumps(after,ensure_ascii=False),stamp))
                vault.audit(username,"DETAINEE_CORRECTION","detainee",did,f"تصحيح تاريخ/حالة الإفراج من [{old}] إلى [{nr}]؛ السبب: {why}")
                vault.persist(); dlg.open=False; refresh_detainees(); notify("سُجل التصحيح كحدث جديد مع الاحتفاظ بالقيم السابقة.")
            dlg=ft.AlertDialog(modal=True,title=ft.Text("تصحيح حركة الإفراج — سجل غير قابل للمحو"),content=ft.Column([ft.Text(f"النزيل: {row['full_name']}"),new_release,reason],tight=True),actions=[ft.TextButton("إلغاء",on_click=cancel),ft.FilledButton("حفظ التصحيح",on_click=save)])
            page.show_dialog(dlg)

        def release_detainee(did):
            if not can_write: return
            row=vault.conn.execute("SELECT * FROM detainees WHERE id=?",(did,)).fetchone()
            if not row or row["status"]=="مفرج عنه": return
            today=date.today().isoformat()
            before={"release_date":row["release_date"],"status":row["status"]}; after={"release_date":today,"status":"مفرج عنه"}
            vault.conn.execute("UPDATE detainees SET release_date=?,status='مفرج عنه' WHERE id=?",(today,did))
            vault.conn.execute("INSERT INTO detainee_movements(detainee_id,movement_type,movement_date,actor,reason,before_json,after_json,created_at) VALUES(?,?,?,?,?,?,?,?)",(did,"RELEASE",today,username,"تسجيل الإفراج",json.dumps(before,ensure_ascii=False),json.dumps(after,ensure_ascii=False),now_iso()))
            vault.audit(username,"DETAINEE_RELEASE","detainee",did,f"إفراج عن {row['full_name']} بتاريخ {today}"); vault.persist(); refresh_detainees(); notify("تم تسجيل الإفراج وحفظ الحركة السابقة دون محوها.")
        stats=ft.Text("",color="#7DD3FC",weight=ft.FontWeight.BOLD,size=12)
        dfilter.on_change=lambda e:refresh_detainees()
        detention_tab=ft.Column([ft.Text("كشف النزلاء في الحجز الاحتياطي",size=20,weight=ft.FontWeight.BOLD),ft.Text("سجل إداري للحركة: تاريخ الدخول، مدة الحبس، جهة الإيداع، التهمة، الضابط، والإفراج.",color="#94A3B8",size=11),ft.Row([dn,dc],wrap=True),ft.Row([de,dr],wrap=True),ft.Row([dcharge,dauthority,dofficer],wrap=True),dnotes,ft.FilledButton("تسجيل نزيل / حركة دخول",icon=ft.Icons.PERSON_ADD,on_click=save_detainee,disabled=not can_write),ft.Divider(),stats,movement_rows,ft.Divider(),dfilter,detainee_rows],expand=True,scroll=ft.ScrollMode.AUTO,spacing=8)
        if role_can_view_detention(role):
            refresh_detainees()

        if role_is_detention_only(role):
            tab_defs=[ft.Tab(label="الحجز الاحتياطي — عرض فقط",icon=ft.Icons.GROUPS)]
            tab_views=[ft.Column([ft.Text("صلاحية عرض بيانات الحجز فقط",color="#FBBF24",weight=ft.FontWeight.BOLD),detention_tab],expand=True)]
        else:
            tab_defs=[ft.Tab(label="القضايا",icon=ft.Icons.FOLDER_OPEN),ft.Tab(label="مكتب مدير المباحث",icon=ft.Icons.DESCRIPTION),ft.Tab(label="الأقسام",icon=ft.Icons.ACCOUNT_TREE)]
            tab_views=[dashboard,memo_tab,departments_tab]
            if role_can_view_detention(role):
                tab_defs.append(ft.Tab(label="الحجز الاحتياطي",icon=ft.Icons.GROUPS)); tab_views.append(detention_tab)
            tab_defs.append(ft.Tab(label="التدقيق",icon=ft.Icons.HISTORY)); tab_views.append(audit_tab)
        if admin:
            tab_defs.append(ft.Tab(label="المستخدمون",icon=ft.Icons.GROUP)); tab_views.append(users_tab)
        def logout(_):
            try: vault.audit(username,"LOGOUT","session","local","تسجيل خروج"); vault.persist(); vault.close()
            except Exception: pass
            state.update({"vault":None,"dek":None,"username":None,"role":None,"selected":None}); show_login()
        top_controls=[ft.Column([ft.Text(f"مرحباً، {username}",weight=ft.FontWeight.BOLD),ft.Text(ROLES.get(role,role),size=11,color="#94A3B8")],spacing=2,expand=True),ft.Container(content=ft.Text("مشفّر محلياً",color="#86EFAC",size=11),bgcolor="#12352D",padding=10,border_radius=9)]
        if admin: top_controls.append(ft.OutlinedButton("نسخة احتياطية مشفرة",icon=ft.Icons.BACKUP,on_click=create_backup))
        top_controls.append(ft.IconButton(ft.Icons.LOGOUT,on_click=logout,tooltip="تسجيل الخروج"))
        top=ft.Row(top_controls)
        page.add(header(),top,ft.Tabs(length=len(tab_defs),expand=True,content=ft.Column(expand=True,controls=[ft.TabBar(tabs=tab_defs),ft.TabBarView(expand=True,controls=tab_views)]))); refresh_table(); refresh_attachments(); refresh_audit();
        if admin: refresh_users()
        page.update()

    try:
        if not CONFIG_PATH.exists(): show_setup()
        else: show_login()
    except Exception as ex:
        page.add(header(),ft.Text(f"تعذر بدء التطبيق: {ex}",color="#FCA5A5")); page.update()

if __name__ == "__main__":
    ft.run(main)
