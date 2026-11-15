
# -*- coding: utf-8 -*-
"""SecureCaseDesk - Android APK Edition."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import zipfile

from datetime import datetime, date
from pathlib import Path
from typing import Optional

import flet as ft

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


APP_NAME = "منظومة إدارة القضايا والملفات الأمنية"
OFFICE_NAME = "وزارة الداخلية | إدارة المباحث الجنائية م / حجة"

DEFAULT_MEMO_TYPES = [
    "مذكرات وكيل نيابة البحث والأمن والسجون",
    "مذكرات رئيس نيابة استئناف حجة",
    "مذكرات مدير عام أمن المحافظة",
    "مذكرات مدير عام المباحث الجنائية",
    "مذكرات تكاليف",
    "مذكرات المستشفى الجمهوري",
    "مذكرات المستشفى السعودي",
    "مذكرات السجن المركزي",
    "تقارير الإحصاء",
    "الأوامر القهرية",
]

DEPARTMENTS = [
    "قسم الاعتداء والقتل",
    "قسم التحريات",
    "قسم الآداب",
    "قسم مكافحة السرقات",
    "قسم التحقيقات",
    "قسم الجرائم الإلكترونية",
]

DETENTION_CATEGORIES = [
    "نزلاء لا زالوا رهن جمع الاستدلالات",
    "نزلاء النيابة الابتدائية",
    "نزلاء النيابة الجزائية",
    "نزلاء باسم مدير عام أمن المحافظة",
    "نزلاء استخبارات الشرطة",
    "نزلاء منطقة ظهر أبو طير",
    "نزلاء أمن المديريات",
    "نزلاء نيابات المديريات",
]

ROLES = {
    "admin": "مدير النظام",
    "investigator": "محقق",
    "viewer": "قارئ القضايا",
    "detention_viewer": "قارئ بيانات الحجز فقط",
}

STATUSES = [
    "جديدة",
    "قيد المتابعة",
    "قيد التحقيق",
    "بانتظار إجراء",
    "مغلقة",
    "مؤرشفة",
]

CASE_TYPES = ["أمنية", "جنائية", "إدارية", "تقنية", "مالية", "أخرى"]

PBKDF2_ITERATIONS = 600_000


def data_root() -> Path:
    root = Path(
        os.environ.get(
            "XDG_DATA_HOME",
            str(Path.home() / ".local" / "share")
        )
    )

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


def now_iso():
    return datetime.now().astimezone().isoformat(timespec="seconds")


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )

    return base64.urlsafe_b64encode(
        kdf.derive(password.encode("utf-8"))
    )


def atomic_write(path: Path, payload: bytes):
    tmp = path.with_suffix(path.suffix + ".tmp")

    with open(tmp, "wb") as f:
        f.write(payload)
        f.flush()
        os.fsync(f.fileno())

    os.replace(tmp, path)


def load_config():
    if not CONFIG_PATH.exists():
        return {"version": 1, "users": {}}

    try:
        return json.loads(CONFIG_PATH.read_text("utf-8"))
    except Exception as ex:
        raise RuntimeError(
            "ملف الحسابات تالف. لا تحذفه؛ استعد نسخة احتياطية."
        ) from ex


def config_canonical(cfg):
    body = {k: v for k, v in cfg.items() if k != "config_mac"}

    return json.dumps(
        body,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def save_config(cfg, dek):
    cfg["config_mac"] = hmac.new(
        dek,
        config_canonical(cfg),
        hashlib.sha256,
    ).hexdigest()

    atomic_write(
        CONFIG_PATH,
        json.dumps(
            cfg,
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8"),
    )


def verify_config(cfg, dek):
    supplied = str(cfg.get("config_mac", ""))

    expected = hmac.new(
        dek,
        config_canonical(cfg),
        hashlib.sha256,
    ).hexdigest()

    return bool(supplied) and hmac.compare_digest(
        supplied,
        expected,
    )


def create_user_record(username, password, role, dek):
    salt = secrets.token_bytes(16)
    wrapping_key = derive_key(password, salt)

    verifier = hmac.new(
        wrapping_key,
        b"SecureCaseDesk password verifier v1",
        hashlib.sha256,
    ).hexdigest()

    wrapped_dek = Fernet(wrapping_key).encrypt(dek).decode("ascii")

    return {
        "salt": base64.b64encode(salt).decode(),
        "verifier": verifier,
        "wrapped_dek": wrapped_dek,
        "role": role,
        "enabled": True,
        "created_at": now_iso(),
        "must_change_password": False,
    }


def authenticate(username, password, cfg):
    rec = cfg.get("users", {}).get(username)

    if not rec or not rec.get("enabled", True):
        raise ValueError("اسم المستخدم أو كلمة المرور غير صحيحة.")

    salt = base64.b64decode(rec["salt"])
    key = derive_key(password, salt)

    check = hmac.new(
        key,
        b"SecureCaseDesk password verifier v1",
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(check, rec["verifier"]):
        raise ValueError("اسم المستخدم أو كلمة المرور غير صحيحة.")

    try:
        dek = Fernet(key).decrypt(
            rec["wrapped_dek"].encode("ascii")
        )
    except InvalidToken as ex:
        raise ValueError("تعذر فتح مفتاح البيانات.") from ex

    if not verify_config(cfg, dek):
        raise ValueError("فشل التحقق من سلامة إعدادات الحسابات.")

    return dek, rec


class Vault:

    def __init__(self, dek):
        self.dek = dek
        self.fernet = Fernet(dek)

        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row

        if DB_PATH.exists():
            try:
                raw = self.fernet.decrypt(DB_PATH.read_bytes())
                self.conn.deserialize(raw)
            except InvalidToken as ex:
                raise RuntimeError(
                    "فشل فك تشفير قاعدة البيانات."
                ) from ex

        self.initialize()

    def initialize(self):

        c = self.conn

        c.executescript("""
        PRAGMA foreign_keys=ON;

        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_number TEXT NOT NULL UNIQUE,
            party_name TEXT NOT NULL,
            case_type TEXT NOT NULL,
            case_date TEXT NOT NULL,
            status TEXT NOT NULL,
            priority TEXT DEFAULT 'متوسطة',
            summary TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            updated_by TEXT NOT NULL,
            department TEXT DEFAULT 'قسم التحقيقات',
            archived_at TEXT DEFAULT '',
            archived_by TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS attachments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER NOT NULL,
            original_name TEXT NOT NULL,
            stored_name TEXT UNIQUE NOT NULL,
            mime_type TEXT,
            size_bytes INTEGER NOT NULL,
            sha256 TEXT NOT NULL,
            uploaded_at TEXT NOT NULL,
            uploaded_by TEXT NOT NULL,
            FOREIGN KEY(case_id) REFERENCES cases(id)
        );

        CREATE TABLE IF NOT EXISTS audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_time TEXT NOT NULL,
            actor TEXT NOT NULL,
            action TEXT NOT NULL,
            entity TEXT NOT NULL,
            entity_id TEXT NOT NULL,
            details TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS memos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            memo_type TEXT NOT NULL,
            memo_number TEXT DEFAULT '',
            memo_date TEXT NOT NULL,
            recipient TEXT DEFAULT '',
            subject TEXT NOT NULL,
            body TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS memo_types (
            name TEXT PRIMARY KEY,
            is_custom INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT DEFAULT '',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS detainees (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            full_name TEXT NOT NULL,
            detainee_category TEXT NOT NULL,
            entry_date TEXT NOT NULL,
            release_date TEXT DEFAULT '',
            charge TEXT NOT NULL,
            detaining_authority TEXT NOT NULL,
            case_officer TEXT NOT NULL,
            status TEXT DEFAULT 'محتجز',
            notes TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            created_by TEXT NOT NULL,
            archived_at TEXT DEFAULT '',
            archived_by TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS detainee_movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detainee_id INTEGER NOT NULL,
            movement_type TEXT NOT NULL,
            movement_date TEXT NOT NULL,
            actor TEXT NOT NULL,
            reason TEXT DEFAULT '',
            before_json TEXT DEFAULT '{}',
            after_json TEXT DEFAULT '{}',
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS detainee_corrections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detainee_id INTEGER NOT NULL,
            corrected_field TEXT NOT NULL,
            old_value TEXT NOT NULL,
            new_value TEXT NOT NULL,
            reason TEXT NOT NULL,
            actor TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_case_number
        ON cases(case_number);

        CREATE INDEX IF NOT EXISTS idx_party_name
        ON cases(party_name);

        CREATE INDEX IF NOT EXISTS idx_detainee_entry
        ON detainees(entry_date);

        CREATE INDEX IF NOT EXISTS idx_detainee_status
        ON detainees(status);
        """)

        c.executescript("""
        CREATE TRIGGER IF NOT EXISTS audit_no_update
        BEFORE UPDATE ON audit
        BEGIN
            SELECT RAISE(ABORT,'سجل التدقيق غير قابل للتعديل');
        END;

        CREATE TRIGGER IF NOT EXISTS audit_no_delete
        BEFORE DELETE ON audit
        BEGIN
            SELECT RAISE(ABORT,'سجل التدقيق غير قابل للحذف');
        END;

        CREATE TRIGGER IF NOT EXISTS movements_no_update
        BEFORE UPDATE ON detainee_movements
        BEGIN
            SELECT RAISE(ABORT,'سجل الحركات غير قابل للتعديل');
        END;

        CREATE TRIGGER IF NOT EXISTS movements_no_delete
        BEFORE DELETE ON detainee_movements
        BEGIN
            SELECT RAISE(ABORT,'سجل الحركات غير قابل للحذف');
        END;

        CREATE TRIGGER IF NOT EXISTS corrections_no_update
        BEFORE UPDATE ON detainee_corrections
        BEGIN
            SELECT RAISE(ABORT,'سجل التصحيحات غير قابل للتعديل');
        END;

        CREATE TRIGGER IF NOT EXISTS corrections_no_delete
        BEFORE DELETE ON detainee_corrections
        BEGIN
            SELECT RAISE(ABORT,'سجل التصحيحات غير قابل للحذف');
        END;
        """)

        for name in DEFAULT_MEMO_TYPES:
            c.execute(
                "INSERT OR IGNORE INTO memo_types(name,is_custom) VALUES(?,0)",
                (name,),
            )

        for name in DEPARTMENTS:
            c.execute(
                "INSERT OR IGNORE INTO departments(name,description,created_at) VALUES(?,?,?)",
                (name, "قسم إداري", now_iso()),
            )

        self.persist()

    def persist(self):
        raw = self.conn.serialize()
        token = self.fernet.encrypt(raw)
        atomic_write(DB_PATH, token)

    def audit(self, actor, action, entity, entity_id, details):

        last = self.conn.execute(
            "SELECT event_hash FROM audit ORDER BY id DESC LIMIT 1"
        ).fetchone()

        prev = last[0] if last else "0" * 64

        body = {
            "event_time": now_iso(),
            "actor": actor,
            "action": action,
            "entity": entity,
            "entity_id": str(entity_id),
            "details": details,
            "previous_hash": prev,
        }

        canonical = json.dumps(
            body,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

        digest = hmac.new(
            self.dek,
            canonical,
            hashlib.sha256,
        ).hexdigest()

        self.conn.execute(
            """
            INSERT INTO audit(
                event_time,actor,action,entity,entity_id,
                details,previous_hash,event_hash
            ) VALUES(?,?,?,?,?,?,?,?)
            """,
            (
                body["event_time"],
                actor,
                action,
                entity,
                str(entity_id),
                details,
                prev,
                digest,
            ),
        )

    def verify_audit(self):

        prev = "0" * 64
        rows = self.conn.execute(
            "SELECT * FROM audit ORDER BY id"
        ).fetchall()

        for r in rows:

            body = {
                "event_time": r["event_time"],
                "actor": r["actor"],
                "action": r["action"],
                "entity": r["entity"],
                "entity_id": r["entity_id"],
                "details": r["details"],
                "previous_hash": r["previous_hash"],
            }

            canonical = json.dumps(
                body,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()

            expected = hmac.new(
                self.dek,
                canonical,
                hashlib.sha256,
            ).hexdigest()

            if (
                r["previous_hash"] != prev
                or not hmac.compare_digest(expected, r["event_hash"])
            ):
                return False, len(rows)

            prev = r["event_hash"]

        return True, len(rows)

    def cases(self, query=""):

        q = (query or "").strip()

        if not q:
            return self.conn.execute(
                """
                SELECT * FROM cases
                WHERE COALESCE(archived_at,'')=''
                ORDER BY id DESC
                """
            ).fetchall()

        like = f"%{q}%"

        return self.conn.execute(
            """
            SELECT * FROM cases
            WHERE COALESCE(archived_at,'')=''
            AND (
                case_number LIKE ?
                OR party_name LIKE ?
                OR case_type LIKE ?
                OR case_date LIKE ?
                OR status LIKE ?
                OR summary LIKE ?
                OR notes LIKE ?
            )
            ORDER BY id DESC
            """,
            (like,) * 7,
        ).fetchall()

    def case(self, case_id):
        return self.conn.execute(
            "SELECT * FROM cases WHERE id=?",
            (case_id,),
        ).fetchone()

    def save_case(self, data, case_id, actor):

        stamp = now_iso()

        if case_id is None:

            cur = self.conn.execute(
                """
                INSERT INTO cases(
                    case_number,party_name,case_type,case_date,
                    status,priority,summary,notes,created_at,
                    updated_at,created_by,updated_by,department
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    data["case_number"],
                    data["party_name"],
                    data["case_type"],
                    data["case_date"],
                    data["status"],
                    data["priority"],
                    data["summary"],
                    data["notes"],
                    stamp,
                    stamp,
                    actor,
                    actor,
                    data["department"],
                ),
            )

            cid = cur.lastrowid
            action = "CREATE"

        else:

            self.conn.execute(
                """
                UPDATE cases SET
                case_number=?,party_name=?,case_type=?,case_date=?,
                status=?,priority=?,summary=?,notes=?,
                updated_at=?,updated_by=?,department=?
                WHERE id=?
                """,
                (
                    data["case_number"],
                    data["party_name"],
                    data["case_type"],
                    data["case_date"],
                    data["status"],
                    data["priority"],
                    data["summary"],
                    data["notes"],
                    stamp,
                    actor,
                    data["department"],
                    case_id,
                ),
            )

            cid = case_id
            action = "UPDATE"

        self.audit(
            actor,
            action,
            "case",
            cid,
            f"رقم القضية: {data['case_number']}",
        )

        self.persist()
        return cid

    def delete_case(self, case_id, actor):

        row = self.case(case_id)

        if not row:
            raise ValueError("القضية غير موجودة.")

        stamp = now_iso()

        self.conn.execute(
            """
            UPDATE cases SET
            archived_at=?,archived_by=?,status='مؤرشفة',
            updated_at=?,updated_by=?
            WHERE id=?
            """,
            (stamp, actor, stamp, actor, case_id),
        )

        self.audit(
            actor,
            "CASE_ARCHIVE",
            "case",
            case_id,
            f"أرشفة القضية: {row['case_number']}",
        )

        self.persist()

    def attachments(self, case_id):
        return self.conn.execute(
            "SELECT * FROM attachments WHERE case_id=? ORDER BY id DESC",
            (case_id,),
        ).fetchall()

    def close(self):
        self.conn.close()


def role_can_write(role):
    return role in ("admin", "investigator")


def role_is_admin(role):
    return role == "admin"


def role_can_view_detention(role):
    return role in ("admin", "investigator", "detention_viewer")


def build_docx(row, report_type, actor):

    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Pt

    doc = Document()

    section = doc.sections[0]
    section.top_margin = Pt(55)
    section.bottom_margin = Pt(55)

    title = doc.add_heading(
        "محضر قضية" if report_type == "محضر" else "تقرير رسمي بشأن قضية",
        0,
    )

    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_paragraph(
        "وثيقة داخلية - تخضع لضوابط السرية المعتمدة لدى الجهة"
    )

    table = doc.add_table(rows=0, cols=2)
    table.style = "Table Grid"

    fields = [
        ("رقم القضية", row["case_number"]),
        ("اسم الطرف", row["party_name"]),
        ("التصنيف", row["case_type"]),
        ("تاريخ التسجيل", row["case_date"]),
        ("الحالة", row["status"]),
        ("الأولوية", row["priority"]),
        ("القسم", row["department"]),
        ("المسؤول عن آخر تعديل", row["updated_by"]),
        ("آخر تحديث", row["updated_at"]),
    ]

    for a, b in fields:
        cells = table.add_row().cells
        cells[0].text = a
        cells[1].text = str(b)

    doc.add_heading("ملخص القضية", level=2)
    doc.add_paragraph(row["summary"] or "لا يوجد ملخص.")

    doc.add_heading("التفاصيل والملاحظات", level=2)
    doc.add_paragraph(row["notes"] or "لا توجد ملاحظات.")

    doc.add_paragraph(
        f"أُنشئ المستند بواسطة: {actor} | {now_iso()}"
    )

    doc.add_paragraph(
        "التوقيع: ____________________       الاعتماد: ____________________"
    )

    safe = re.sub(
        r"[^\w-]+",
        "_",
        row["case_number"],
        flags=re.UNICODE,
    )

    out = REPORT_DIR / (
        f"{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
    )

    doc.save(out)
    return out


def build_memo_docx(row, actor):

    from docx import Document
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.shared import Pt

    doc = Document()

    sec = doc.sections[0]
    sec.top_margin = Pt(48)
    sec.bottom_margin = Pt(48)

    h = doc.add_heading(row["memo_type"], 0)
    h.alignment = WD_ALIGN_PARAGRAPH.CENTER

    p = doc.add_paragraph(OFFICE_NAME)
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_paragraph(
        f"رقم المذكرة: {row['memo_number'] or '—'}"
    )

    doc.add_paragraph(f"التاريخ: {row['memo_date']}")

    doc.add_paragraph(
        f"الجهة المرسل إليها: {row['recipient'] or '—'}"
    )

    doc.add_heading(row["subject"], level=1)
    doc.add_paragraph(row["body"] or "")

    doc.add_paragraph(
        f"أُعدت بواسطة: {actor} | {now_iso()}"
    )

    doc.add_paragraph(
        "التوقيع: ____________________       الختم: ____________________"
    )

    safe = re.sub(
        r"[^\w-]+",
        "_",
        row["subject"],
        flags=re.UNICODE,
    )[:50] or "memo"

    out = REPORT_DIR / (
        f"Memo_{safe}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.docx"
    )

    doc.save(out)
    return out


def main(page: ft.Page):

    page.title = APP_NAME
    page.theme_mode = ft.ThemeMode.DARK
    page.bgcolor = "#08111F"
    page.rtl = True
    page.padding = 12

    page.theme = ft.Theme(
        color_scheme=ft.ColorScheme(
            primary="#38BDF8",
            surface="#111D30",
        )
    )

    state = {
        "vault": None,
        "dek": None,
        "username": None,
        "role": None,
        "selected": None,
    }

    def notify(msg, error=False):

        page.snack_bar = ft.SnackBar(
            ft.Text(msg),
            bgcolor="#7F1D1D" if error else "#14532D",
        )

        page.snack_bar.open = True
        page.update()

    def text_field(label, **kw):
        return ft.TextField(
            label=label,
            border_radius=10,
            **kw,
        )

    def header(subtitle="إدارة محلية مشفرة للقضايا والمرفقات"):

        return ft.Container(
            ft.Row(
                [
                    ft.Column(
                        [
                            ft.Text(
                                OFFICE_NAME,
                                size=13,
                                weight=ft.FontWeight.BOLD,
                                color="#7DD3FC",
                            ),
                            ft.Text(
                                APP_NAME,
                                size=19,
                                weight=ft.FontWeight.BOLD,
                                color="#F8FAFC",
                            ),
                            ft.Text(
                                subtitle,
                                color="#94A3B8",
                                size=11,
                            ),
                        ],
                        spacing=3,
                        expand=True,
                    ),
                    ft.Icon(
                        ft.Icons.SHIELD_LOCK,
                        size=32,
                        color="#38BDF8",
                    ),
                ]
            ),
            padding=ft.padding.only(bottom=12),
        )

    def show_setup():

        page.controls.clear()

        u = text_field(
            "اسم المدير",
            prefix_icon=ft.Icons.PERSON,
            autofocus=True,
        )

        p1 = text_field(
            "كلمة مرور قوية (12 حرفاً على الأقل)",
            password=True,
            can_reveal_password=True,
        )

        p2 = text_field(
            "تأكيد كلمة المرور",
            password=True,
            can_reveal_password=True,
        )

        def create(_):

            username = (u.value or "").strip()

            if not re.fullmatch(
                r"[A-Za-z0-9_.-]{3,32}",
                username,
            ):
                notify("اسم المستخدم غير صالح.", True)
                return

            if len(p1.value or "") < 12:
                notify("كلمة المرور يجب ألا تقل عن 12 حرفاً.", True)
                return

            if p1.value != p2.value:
                notify("كلمتا المرور غير متطابقتين.", True)
                return

            dek = Fernet.generate_key()

            cfg = {
                "version": 1,
                "users": {
                    username: create_user_record(
                        username,
                        p1.value,
                        "admin",
                        dek,
                    )
                },
            }

            save_config(cfg, dek)

            state["dek"] = dek
            state["username"] = username
            state["role"] = "admin"

            state["vault"] = Vault(dek)

            state["vault"].audit(
                username,
                "INITIALIZE",
                "system",
                "1",
                "إنشاء المخزن الآمن",
            )

            state["vault"].persist()

            show_app()

        card = ft.Container(
            ft.Column(
                [
                    ft.Text(
                        "تهيئة آمنة لأول استخدام",
                        size=21,
                        weight=ft.FontWeight.BOLD,
                    ),
                    u,
                    p1,
                    p2,
                    ft.Text(
                        "احفظ كلمة المرور؛ لا توجد آلية لاستعادتها.",
                        color="#FBBF24",
                        size=12,
                    ),
                    ft.FilledButton(
                        "إنشاء المخزن الآمن",
                        icon=ft.Icons.SECURITY,
                        on_click=create,
                    ),
                ],
                spacing=15,
            ),
            width=520,
            padding=25,
            bgcolor="#111D30",
            border_radius=18,
        )

        page.add(
            header(),
            ft.Row(
                [card],
                alignment=ft.MainAxisAlignment.CENTER,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                expand=True,
            ),
        )

        page.update()

    def show_login():

        page.controls.clear()

        u = text_field("اسم المستخدم")
        pw = text_field(
            "كلمة المرور",
            password=True,
            can_reveal_password=True,
        )

        def login(_):

            try:

                cfg = load_config()

                dek, rec = authenticate(
                    (u.value or "").strip(),
                    pw.value or "",
                    cfg,
                )

                state.update(
                    {
                        "dek": dek,
                        "username": (u.value or "").strip(),
                        "role": rec["role"],
                        "vault": Vault(dek),
                        "selected": None,
                    }
                )

                state["vault"].audit(
                    state["username"],
                    "LOGIN",
                    "session",
                    "local",
                    "تسجيل دخول ناجح",
                )

                state["vault"].persist()

                show_app()

            except Exception as ex:
                notify(str(ex), True)

        card = ft.Container(
            ft.Column(
                [
                    ft.Text(
                        "تسجيل الدخول",
                        size=22,
                        weight=ft.FontWeight.BOLD,
                    ),
                    u,
                    pw,
                    ft.FilledButton(
                        "دخول آمن",
                        icon=ft.Icons.LOGIN,
                        on_click=login,
                    ),
                    ft.Text(
                        "البيانات تحفظ محلياً على الجهاز.",
                        color="#94A3B8",
                        size=11,
                    ),
                ],
                spacing=15,
            ),
            width=470,
            padding=25,
            bgcolor="#111D30",
            border_radius=18,
        )

        page.add(
            header(),
            ft.Row(
                [card],
                alignment=ft.MainAxisAlignment.CENTER,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
                expand=True,
            ),
        )

        page.update()

    def show_app():

        page.controls.clear()

        vault = state["vault"]
        username = state["username"]
        role = state["role"]

        selected = {"id": state.get("selected")}

        can_write = role_can_write(role)
        admin = role_is_admin(role)

        picker = ft.FilePicker()
        page.overlay.append(picker)

        search = text_field(
            "بحث برقم القضية أو اسم الطرف أو الحالة",
        )

        table_area = ft.Column(
            expand=True,
            scroll=ft.ScrollMode.AUTO,
        )

        form_number = text_field("رقم القضية *")
        form_party = text_field("اسم الطرف *")

        form_type = ft.Dropdown(
            label="التصنيف",
            value=CASE_TYPES[0],
            options=[
                ft.DropdownOption(key=x, text=x)
                for x in CASE_TYPES
            ],
        )

        form_date = text_field(
            "التاريخ YYYY-MM-DD",
            value=date.today().isoformat(),
        )

        form_status = ft.Dropdown(
            label="الحالة",
            value=STATUSES[0],
            options=[
                ft.DropdownOption(key=x, text=x)
                for x in STATUSES
            ],
        )

        form_priority = ft.Dropdown(
            label="الأولوية",
            value="متوسطة",
            options=[
                ft.DropdownOption(key=x, text=x)
                for x in ["منخفضة", "متوسطة", "عالية", "حرجة"]
            ],
        )

        form_department = ft.Dropdown(
            label="القسم المختص",
            value=DEPARTMENTS[4],
            options=[
                ft.DropdownOption(key=x, text=x)
                for x in DEPARTMENTS
            ],
        )

        form_summary = text_field(
            "ملخص القضية",
            multiline=True,
            min_lines=2,
        )

        form_notes = text_field(
            "التفاصيل والملاحظات",
            multiline=True,
            min_lines=3,
        )

        attach_area = ft.Column()
        audit_area = ft.Column(
            expand=True,
            scroll=ft.ScrollMode.AUTO,
        )

        count_label = ft.Text("0 قضية")

        for control in [
            form_number,
            form_party,
            form_type,
            form_date,
            form_status,
            form_priority,
            form_department,
            form_summary,
            form_notes,
        ]:
            control.disabled = not can_write

        def refresh_attachments():

            attach_area.controls.clear()

            if not selected["id"]:
                attach_area.controls.append(
                    ft.Text("احفظ القضية أولاً لإضافة مرفقات.")
                )
                return

            files = vault.attachments(selected["id"])

            if not files:
                attach_area.controls.append(
                    ft.Text("لا توجد مرفقات.")
                )

            for f in files:

                attach_area.controls.append(
                    ft.Row(
                        [
                            ft.Text(
                                f["original_name"],
                                expand=True,
                            ),
                            ft.Text(
                                f"{f['size_bytes'] / 1024:.1f} KB"
                            ),
                            ft.TextButton(
                                "تصدير",
                                on_click=lambda e, aid=f["id"]: export_attachment(aid),
                            ),
                        ]
                    )
                )

        def clear_form():

            selected["id"] = None
            state["selected"] = None

            form_number.value = ""
            form_party.value = ""
            form_summary.value = ""
            form_notes.value = ""

            form_type.value = CASE_TYPES[0]
            form_date.value = date.today().isoformat()
            form_status.value = STATUSES[0]
            form_priority.value = "متوسطة"
            form_department.value = DEPARTMENTS[4]

            refresh_attachments()
            page.update()

        def fill(row):

            selected["id"] = row["id"]
            state["selected"] = row["id"]

            form_number.value = row["case_number"]
            form_party.value = row["party_name"]
            form_type.value = row["case_type"]
            form_date.value = row["case_date"]
            form_status.value = row["status"]
            form_priority.value = row["priority"]
            form_department.value = row["department"]

            form_summary.value = row["summary"] or ""
            form_notes.value = row["notes"] or ""

            refresh_attachments()
            page.update()

        def refresh_table():

            rows = vault.cases(search.value or "")

            count_label.value = f"{len(rows)} قضية"
            table_area.controls.clear()

            if not rows:
                table_area.controls.append(
                    ft.Text("لا توجد قضايا مطابقة.")
                )

            else:

                table_area.controls.append(
                    ft.DataTable(
                        columns=[
                            ft.DataColumn(ft.Text("رقم القضية")),
                            ft.DataColumn(ft.Text("الطرف")),
                            ft.DataColumn(ft.Text("التصنيف")),
                            ft.DataColumn(ft.Text("القسم")),
                            ft.DataColumn(ft.Text("التاريخ")),
                            ft.DataColumn(ft.Text("الحالة")),
                        ],
                        rows=[
                            ft.DataRow(
                                on_select_changed=lambda e, rr=r: fill(rr),
                                cells=[
                                    ft.DataCell(ft.Text(str(r[k])))
                                    for k in [
                                        "case_number",
                                        "party_name",
                                        "case_type",
                                        "department",
                                        "case_date",
                                        "status",
                                    ]
                                ],
                            )
                            for r in rows
                        ],
                    )
                )

            page.update()

        def save_case(_=None):

            if not can_write:
                notify("صلاحيتك للقراءة فقط.", True)
                return

            number = (form_number.value or "").strip()
            party = (form_party.value or "").strip()
            dt = (form_date.value or "").strip()

            if not number or not party:
                notify("رقم القضية واسم الطرف إلزاميان.", True)
                return

            try:
                datetime.strptime(dt, "%Y-%m-%d")
            except ValueError:
                notify("صيغة التاريخ يجب أن تكون YYYY-MM-DD.", True)
                return

            data = {
                "case_number": number,
                "party_name": party,
                "case_type": form_type.value or CASE_TYPES[0],
                "case_date": dt,
                "status": form_status.value or STATUSES[0],
                "priority": form_priority.value or "متوسطة",
                "department": form_department.value or DEPARTMENTS[4],
                "summary": form_summary.value or "",
                "notes": form_notes.value or "",
            }

            try:

                selected["id"] = vault.save_case(
                    data,
                    selected["id"],
                    username,
                )

                state["selected"] = selected["id"]

                refresh_table()
                refresh_attachments()

                notify("تم حفظ القضية.")

            except sqlite3.IntegrityError:
                notify("رقم القضية مستخدم بالفعل.", True)

            except Exception as ex:
                notify(str(ex), True)

        def archive_case(_=None):

            if not can_write or not selected["id"]:
                notify("حدد قضية أولاً.", True)
                return

            def confirm(_):

                try:
                    vault.delete_case(selected["id"], username)
                    clear_form()
                    refresh_table()
                    dlg.open = False
                    page.update()
                    notify("تمت أرشفة القضية.")

                except Exception as ex:
                    notify(str(ex), True)

            def cancel(_):
                dlg.open = False
                page.update()

            dlg = ft.AlertDialog(
                modal=True,
                title=ft.Text("أرشفة القضية"),
                content=ft.Text(
                    "سيتم إخفاء القضية من السجل النشط مع الاحتفاظ ببياناتها."
                ),
                actions=[
                    ft.TextButton("إلغاء", on_click=cancel),
                    ft.FilledButton("تأكيد الأرشفة", on_click=confirm),
                ],
            )

            page.show_dialog(dlg)

        def process_picked_files(files):

            if not files or not selected["id"]:
                return

            try:

                for picked in files:

                    name = picked.name
                    suffix = Path(name).suffix.lower()

                    if suffix not in (".pdf", ".png", ".jpg", ".jpeg"):
                        raise ValueError("نوع الملف غير مسموح.")

                    raw = picked.bytes

                    if raw is None:
                        raise ValueError("تعذر قراءة الملف.")

                    if len(raw) > 30 * 1024 * 1024:
                        raise ValueError("الحد الأقصى 30 ميغابايت.")

                    digest = hashlib.sha256(raw).hexdigest()

                    stored = secrets.token_hex(20) + ".bin"

                    token = vault.fernet.encrypt(raw)

                    atomic_write(
                        ATTACH_DIR / stored,
                        token,
                    )

                    mime = (
                        "application/pdf"
                        if suffix == ".pdf"
                        else "image/jpeg"
                        if suffix in (".jpg", ".jpeg")
                        else "image/png"
                    )

                    vault.conn.execute(
                        """
                        INSERT INTO attachments(
                            case_id,original_name,stored_name,
                            mime_type,size_bytes,sha256,
                            uploaded_at,uploaded_by
                        )
                        VALUES(?,?,?,?,?,?,?,?)
                        """,
                        (
                            selected["id"],
                            name,
                            stored,
                            mime,
                            len(raw),
                            digest,
                            now_iso(),
                            username,
                        ),
                    )

                    vault.audit(
                        username,
                        "ATTACH",
                        "attachment",
                        stored,
                        f"إرفاق {name}",
                    )

                vault.persist()
                refresh_attachments()
                notify("تم تشفير المرفقات.")

            except Exception as ex:
                notify(str(ex), True)

        async def pick_files(_):

            if not selected["id"]:
                notify("احفظ القضية أولاً.", True)
                return

            files = await picker.pick_files(
                allow_multiple=True,
                with_data=True,
                file_type=ft.FilePickerFileType.CUSTOM,
                allowed_extensions=["pdf", "png", "jpg", "jpeg"],
            )

            process_picked_files(files)

        def export_attachment(aid):

            row = vault.conn.execute(
                "SELECT * FROM attachments WHERE id=?",
                (aid,),
            ).fetchone()

            if not row:
                return

            try:

                raw = vault.fernet.decrypt(
                    (ATTACH_DIR / row["stored_name"]).read_bytes()
                )

                digest = hashlib.sha256(raw).hexdigest()

                if not hmac.compare_digest(
                    digest,
                    row["sha256"],
                ):
                    raise ValueError("فشل التحقق من بصمة الملف.")

                safe = re.sub(
                    r"[^\w. -]+",
                    "_",
                    row["original_name"],
                    flags=re.UNICODE,
                )

                out = ROOT / "exports" / safe

                atomic_write(out, raw)

                vault.audit(
                    username,
                    "EXPORT",
                    "attachment",
                    aid,
                    f"تصدير {safe}",
                )

                vault.persist()

                notify(
                    f"تم حفظ نسخة داخل مجلد exports: {safe}"
                )

            except Exception as ex:
                notify(str(ex), True)

        def make_report(kind):

            if not selected["id"]:
                notify("حدد قضية أولاً.", True)
                return

            try:

                row = vault.case(selected["id"])

                path = build_docx(
                    row,
                    kind,
                    username,
                )

                vault.audit(
                    username,
                    "REPORT",
                    "case",
                    selected["id"],
                    path.name,
                )

                vault.persist()

                notify(f"تم إنشاء التقرير: {path.name}")

            except Exception as ex:
                notify(str(ex), True)

        def create_backup(_=None):

            if not admin:
                notify("المدير فقط.", True)
                return

            try:

                vault.audit(
                    username,
                    "BACKUP",
                    "system",
                    "local",
                    "إنشاء نسخة احتياطية",
                )

                vault.persist()

                target = ROOT / "exports" / (
                    "SecureCaseDesk_Backup_"
                    + datetime.now().strftime("%Y%m%d_%H%M%S")
                    + ".zip"
                )

                with zipfile.ZipFile(
                    target,
                    "w",
                    zipfile.ZIP_DEFLATED,
                ) as archive:

                    archive.write(
                        CONFIG_PATH,
                        "accounts.json",
                    )

                    archive.write(
                        DB_PATH,
                        "vault.db.enc",
                    )

                    for item in ATTACH_DIR.glob("*.bin"):
                        archive.write(
                            item,
                            f"attachments/{item.name}",
                        )

                notify(f"تم إنشاء النسخة الاحتياطية: {target.name}")

            except Exception as ex:
                notify(str(ex), True)

        def refresh_audit():

            audit_area.controls.clear()

            ok, total = vault.verify_audit()

            audit_area.controls.append(
                ft.Text(
                    f"{'سلسلة التدقيق سليمة' if ok else 'تحذير: فشل التحقق'} · {total} حدثاً",
                    color="#86EFAC" if ok else "#FCA5A5",
                    weight=ft.FontWeight.BOLD,
                )
            )

            rows = vault.conn.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT 250"
            ).fetchall()

            for r in rows:

                audit_area.controls.append(
                    ft.Container(
                        ft.Column(
                            [
                                ft.Text(
                                    f"{r['event_time']} · {r['actor']} · {r['action']}",
                                    size=11,
                                    color="#7DD3FC",
                                ),
                                ft.Text(
                                    f"{r['entity']} #{r['entity_id']} — {r['details']}",
                                    size=12,
                                ),
                            ]
                        ),
                        padding=8,
                    )
                )

        users_area = ft.Column()

        def refresh_users():

            users_area.controls.clear()

            cfg = load_config()

            for uname, rec in cfg["users"].items():

                users_area.controls.append(
                    ft.Row(
                        [
                            ft.Text(uname, expand=True),
                            ft.Text(ROLES.get(rec["role"], rec["role"])),
                            ft.Text(
                                "نشط" if rec.get("enabled", True) else "معطل"
                            ),
                            ft.TextButton(
                                "تفعيل/تعطيل",
                                on_click=lambda e, n=uname: toggle_user(n),
                            ),
                        ]
                    )
                )

        def toggle_user(uname):

            if uname == username:
                notify("لا يمكنك تعطيل حسابك الحالي.", True)
                return

            cfg = load_config()

            cfg["users"][uname]["enabled"] = not cfg["users"][uname].get(
                "enabled",
                True,
            )

            save_config(cfg, state["dek"])

            vault.audit(
                username,
                "USER_STATUS",
                "user",
                uname,
                "تغيير حالة الحساب",
            )

            vault.persist()
            refresh_users()
            notify("تم تحديث حالة الحساب.")

        new_user = text_field("اسم المستخدم الجديد")
        new_pass = text_field(
            "كلمة مرور أولية",
            password=True,
            can_reveal_password=True,
        )

        new_role = ft.Dropdown(
            label="الدور",
            value="viewer",
            options=[
                ft.DropdownOption(key=k, text=v)
                for k, v in ROLES.items()
            ],
        )

        def add_user(_):

            if not admin:
                notify("هذه العملية للمدير فقط.", True)
                return

            nu = (new_user.value or "").strip()
            np = new_pass.value or ""
            nr = new_role.value or "viewer"

            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", nu):
                notify("اسم المستخدم غير صالح.", True)
                return

            if len(np) < 12:
                notify("كلمة المرور يجب ألا تقل عن 12 حرفاً.", True)
                return

            cfg = load_config()

            if nu in cfg["users"]:
                notify("اسم المستخدم موجود.", True)
                return

            cfg["users"][nu] = create_user_record(
                nu,
                np,
                nr,
                state["dek"],
            )

            save_config(cfg, state["dek"])

            vault.audit(
                username,
                "USER_CREATE",
                "user",
                nu,
                f"إنشاء حساب بدور {ROLES[nr]}",
            )

            vault.persist()

            new_user.value = ""
            new_pass.value = ""

            refresh_users()
            notify("تم إنشاء الحساب.")

        users_tab = ft.Column(
            [
                ft.Text(
                    "إدارة الحسابات والصلاحيات",
                    size=19,
                    weight=ft.FontWeight.BOLD,
                ),
                new_user,
                new_pass,
                new_role,
                ft.FilledButton(
                    "إنشاء مستخدم",
                    on_click=add_user,
                ),
                users_area,
            ],
            scroll=ft.ScrollMode.AUTO,
        )

        form_card = ft.Container(
            ft.Column(
                [
                    ft.Text(
                        "بيانات القضية",
                        size=18,
                        weight=ft.FontWeight.BOLD,
                    ),
                    form_number,
                    form_party,
                    form_type,
                    form_date,
                    form_status,
                    form_priority,
                    form_department,
                    form_summary,
                    form_notes,
                    ft.Row(
                        [
                            ft.FilledButton(
                                "حفظ",
                                icon=ft.Icons.SAVE,
                                on_click=save_case,
                                disabled=not can_write,
                            ),
                            ft.OutlinedButton(
                                "جديد",
                                on_click=lambda e: clear_form(),
                                disabled=not can_write,
                            ),
                            ft.OutlinedButton(
                                "أرشفة",
                                on_click=archive_case,
                                disabled=not can_write,
                            ),
                        ],
                        wrap=True,
                    ),
                    ft.Divider(),
                    ft.Row(
                        [
                            ft.Text("المرفقات المشفرة"),
                            ft.IconButton(
                                ft.Icons.ADD,
                                on_click=pick_files,
                                disabled=not can_write,
                            ),
                        ],
                    ),
                    attach_area,
                ],
                spacing=10,
            ),
            padding=15,
            bgcolor="#111D30",
            border_radius=16,
        )

        cases_tab = ft.Column(
            [
                ft.Text(
                    "سجل القضايا",
                    size=18,
                    weight=ft.FontWeight.BOLD,
                ),
                search,
                count_label,
                table_area,
                ft.Divider(),
                ft.OutlinedButton(
                    "تقرير رسمي Word",
                    on_click=lambda e: make_report("تقرير رسمي"),
                ),
                ft.OutlinedButton(
                    "محضر Word",
                    on_click=lambda e: make_report("محضر"),
                ),
            ],
            expand=True,
            scroll=ft.ScrollMode.AUTO,
        )

        search.on_change = lambda e: refresh_table()

        dashboard = ft.Column(
            [
                form_card,
                ft.Divider(),
                cases_tab,
            ],
            expand=True,
            scroll=ft.ScrollMode.AUTO,
        )

        # المذكرات

        memo_type = ft.Dropdown(
            label="نوع المذكرة",
            options=[],
        )

        memo_number = text_field("رقم المذكرة")
        memo_date = text_field(
            "التاريخ",
            value=date.today().isoformat(),
        )
        memo_to = text_field("الجهة المرسل إليها")
        memo_subject = text_field("الموضوع")
        memo_body = text_field(
            "نص المذكرة",
            multiline=True,
            min_lines=4,
        )

        memo_rows = ft.Column()

        new_memo_type = text_field("نوع مذكرة جديد")

        def refresh_memo_types():

            names = [
                r[0]
                for r in vault.conn.execute(
                    "SELECT name FROM memo_types ORDER BY is_custom,name"
                ).fetchall()
            ]

            memo_type.options = [
                ft.DropdownOption(key=n, text=n)
                for n in names
            ]

            if names and not memo_type.value:
                memo_type.value = names[0]

        def add_memo_type(_):

            if not can_write:
                notify("صلاحية غير كافية.", True)
                return

            name = (new_memo_type.value or "").strip()

            if not name:
                return

            vault.conn.execute(
                "INSERT OR IGNORE INTO memo_types(name,is_custom) VALUES(?,1)",
                (name,),
            )

            vault.audit(
                username,
                "MEMO_TYPE_ADD",
                "memo_type",
                name,
                "إضافة نوع مذكرة",
            )

            vault.persist()
            new_memo_type.value = ""
            refresh_memo_types()
            page.update()

        def save_memo(_):

            if not can_write:
                notify("صلاحية غير كافية.", True)
                return

            subject = (memo_subject.value or "").strip()
            d = (memo_date.value or "").strip()

            if not subject:
                notify("اكتب موضوع المذكرة.", True)
                return

            try:
                datetime.strptime(d, "%Y-%m-%d")
            except ValueError:
                notify("التاريخ غير صحيح.", True)
                return

            cur = vault.conn.execute(
                """
                INSERT INTO memos(
                    memo_type,memo_number,memo_date,recipient,
                    subject,body,created_at,created_by
                )
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    memo_type.value or "مذكرة",
                    memo_number.value or "",
                    d,
                    memo_to.value or "",
                    subject,
                    memo_body.value or "",
                    now_iso(),
                    username,
                ),
            )

            vault.audit(
                username,
                "MEMO_CREATE",
                "memo",
                cur.lastrowid,
                subject,
            )

            vault.persist()
            refresh_memos()
            notify("تم حفظ المذكرة.")

        def export_memo(mid):

            row = vault.conn.execute(
                "SELECT * FROM memos WHERE id=?",
                (mid,),
            ).fetchone()

            if not row:
                return

            try:

                path = build_memo_docx(row, username)

                vault.audit(
                    username,
                    "MEMO_EXPORT",
                    "memo",
                    mid,
                    path.name,
                )

                vault.persist()

                notify(f"تم إنشاء Word: {path.name}")

            except Exception as ex:
                notify(str(ex), True)

        def refresh_memos():

            memo_rows.controls.clear()

            rows = vault.conn.execute(
                "SELECT * FROM memos ORDER BY id DESC LIMIT 300"
            ).fetchall()

            for r in rows:

                memo_rows.controls.append(
                    ft.Container(
                        ft.Column(
                            [
                                ft.Text(
                                    r["memo_type"],
                                    weight=ft.FontWeight.BOLD,
                                    color="#7DD3FC",
                                ),
                                ft.Text(r["subject"]),
                                ft.Text(
                                    f"{r['memo_date']} | {r['recipient']}"
                                ),
                                ft.Text(r["body"] or ""),
                                ft.OutlinedButton(
                                    "إنشاء Word",
                                    on_click=lambda e, i=r["id"]: export_memo(i),
                                ),
                            ]
                        ),
                        padding=10,
                    )
                )

        memo_tab = ft.Column(
            [
                ft.Text(
                    "مكتب مدير المباحث الجنائية",
                    size=20,
                    weight=ft.FontWeight.BOLD,
                ),
                memo_type,
                memo_number,
                memo_date,
                memo_to,
                memo_subject,
                memo_body,
                ft.FilledButton(
                    "حفظ المذكرة",
                    on_click=save_memo,
                    disabled=not can_write,
                ),
                new_memo_type,
                ft.OutlinedButton(
                    "إضافة نوع مذكرة",
                    on_click=add_memo_type,
                    disabled=not can_write,
                ),
                ft.Divider(),
                memo_rows,
            ],
            expand=True,
            scroll=ft.ScrollMode.AUTO,
        )

        refresh_memo_types()
        refresh_memos()

        # الأقسام

        dept_name = text_field("اسم القسم الجديد")
        dept_desc = text_field("الوصف")
        dept_rows = ft.Column()

        def refresh_departments():

            dept_rows.controls.clear()

            for d in vault.conn.execute(
                "SELECT * FROM departments ORDER BY name"
            ).fetchall():

                dept_rows.controls.append(
                    ft.ListTile(
                        title=ft.Text(d["name"]),
                        subtitle=ft.Text(d["description"] or ""),
                    )
                )

        def add_department(_):

            if not can_write:
                notify("صلاحية غير كافية.", True)
                return

            name = (dept_name.value or "").strip()

            if not name:
                return

            try:

                vault.conn.execute(
                    """
                    INSERT INTO departments(name,description,created_at)
                    VALUES(?,?,?)
                    """,
                    (
                        name,
                        dept_desc.value or "",
                        now_iso(),
                    ),
                )

                vault.audit(
                    username,
                    "DEPARTMENT_CREATE",
                    "department",
                    name,
                    "إضافة قسم",
                )

                vault.persist()

                form_department.options = [
                    ft.DropdownOption(key=r[0], text=r[0])
                    for r in vault.conn.execute(
                        "SELECT name FROM departments ORDER BY name"
                    ).fetchall()
                ]

                dept_name.value = ""
                dept_desc.value = ""

                refresh_departments()
                page.update()

            except sqlite3.IntegrityError:
                notify("القسم موجود بالفعل.", True)

        departments_tab = ft.Column(
            [
                ft.Text(
                    "إدارة الأقسام",
                    size=20,
                    weight=ft.FontWeight.BOLD,
                ),
                dept_name,
                dept_desc,
                ft.FilledButton(
                    "إضافة قسم",
                    on_click=add_department,
                    disabled=not can_write,
                ),
                dept_rows,
            ],
            expand=True,
            scroll=ft.ScrollMode.AUTO,
        )

        refresh_departments()

        # المحتجزون

        dn = text_field("اسم النزيل")
        dc = ft.Dropdown(
            label="فئة الإيداع",
            value=DETENTION_CATEGORIES[0],
            options=[
                ft.DropdownOption(key=x, text=x)
                for x in DETENTION_CATEGORIES
            ],
        )

        de = text_field(
            "تاريخ الدخول",
            value=date.today().isoformat(),
        )

        dr = text_field("تاريخ الإفراج (اختياري)")
        dcharge = text_field("نوع التهمة")
        dauthority = text_field("الجهة الحابسة")
        dofficer = text_field("القضية لدى الضابط")
        dnotes = text_field("ملاحظات", multiline=True)

        detainee_rows = ft.Column()
        movement_rows = ft.Column()
        stats = ft.Text()

        dfilter = ft.Dropdown(
            label="تصفية حسب الفئة",
            value="الكل",
            options=[
                ft.DropdownOption(key="الكل", text="الكل")
            ] + [
                ft.DropdownOption(key=x, text=x)
                for x in DETENTION_CATEGORIES
            ],
        )

        def save_detainee(_):

            if not can_write:
                notify("صلاحية غير كافية.", True)
                return

            name = (dn.value or "").strip()
            charge = (dcharge.value or "").strip()
            auth = (dauthority.value or "").strip()
            officer = (dofficer.value or "").strip()
            ent = (de.value or "").strip()
            rel = (dr.value or "").strip()

            if not all([name, charge, auth, officer]):
                notify("أكمل الحقول الإلزامية.", True)
                return

            try:

                datetime.strptime(ent, "%Y-%m-%d")

                if rel:
                    datetime.strptime(rel, "%Y-%m-%d")

                if rel and rel < ent:
                    raise ValueError()

            except ValueError:
                notify("تحقق من التواريخ.", True)
                return

            status = "مفرج عنه" if rel else "محتجز"

            cur = vault.conn.execute(
                """
                INSERT INTO detainees(
                    full_name,detainee_category,entry_date,
                    release_date,charge,detaining_authority,
                    case_officer,status,notes,created_at,created_by
                )
                VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    name,
                    dc.value,
                    ent,
                    rel,
                    charge,
                    auth,
                    officer,
                    status,
                    dnotes.value or "",
                    now_iso(),
                    username,
                ),
            )

            did = cur.lastrowid

            vault.conn.execute(
                """
                INSERT INTO detainee_movements(
                    detainee_id,movement_type,movement_date,
                    actor,reason,before_json,after_json,created_at
                )
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    did,
                    "ENTRY",
                    ent,
                    username,
                    "تسجيل دخول أولي",
                    "{}",
                    json.dumps(
                        {"full_name": name, "entry_date": ent},
                        ensure_ascii=False,
                    ),
                    now_iso(),
                ),
            )

            if rel:

                vault.conn.execute(
                    """
                    INSERT INTO detainee_movements(
                        detainee_id,movement_type,movement_date,
                        actor,reason,before_json,after_json,created_at
                    )
                    VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (
                        did,
                        "RELEASE",
                        rel,
                        username,
                        "إفراج مسجل عند القيد الأولي",
                        "{}",
                        json.dumps(
                            {"release_date": rel, "status": status},
                            ensure_ascii=False,
                        ),
                        now_iso(),
                    ),
                )

            vault.audit(
                username,
                "DETAINEE_REGISTER",
                "detainee",
                did,
                f"تسجيل {name}",
            )

            vault.persist()
            refresh_detainees()
            notify("تم تسجيل النزيل.")

        def release_detainee(did):

            if not can_write:
                return

            row = vault.conn.execute(
                "SELECT * FROM detainees WHERE id=?",
                (did,),
            ).fetchone()

            if not row or row["status"] == "مفرج عنه":
                return

            today = date.today().isoformat()

            before = {
                "release_date": row["release_date"],
                "status": row["status"],
            }

            after = {
                "release_date": today,
                "status": "مفرج عنه",
            }

            vault.conn.execute(
                """
                UPDATE detainees
                SET release_date=?,status='مفرج عنه'
                WHERE id=?
                """,
                (today, did),
            )

            vault.conn.execute(
                """
                INSERT INTO detainee_movements(
                    detainee_id,movement_type,movement_date,
                    actor,reason,before_json,after_json,created_at
                )
                VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    did,
                    "RELEASE",
                    today,
                    username,
                    "تسجيل الإفراج",
                    json.dumps(before, ensure_ascii=False),
                    json.dumps(after, ensure_ascii=False),
                    now_iso(),
                ),
            )

            vault.audit(
                username,
                "DETAINEE_RELEASE",
                "detainee",
                did,
                f"إفراج عن {row['full_name']}",
            )

            vault.persist()
            refresh_detainees()
            notify("تم تسجيل الإفراج.")

        def correct_detainee(did):

            if not admin:
                notify("هذه العملية للمدير فقط.", True)
                return

            row = vault.conn.execute(
                "SELECT * FROM detainees WHERE id=?",
                (did,),
            ).fetchone()

            if not row:
                return

            new_release = text_field(
                "تاريخ الإفراج الصحيح (فارغ إذا لم يتم الإفراج)",
                value=row["release_date"] or "",
            )

            reason = text_field(
                "سبب التصحيح",
                multiline=True,
            )

            def cancel(_):
                dlg.open = False
                page.update()

            def save(_):

                nr = (new_release.value or "").strip()
                why = (reason.value or "").strip()

                if not why:
                    notify("سبب التصحيح إلزامي.", True)
                    return

                try:

                    if nr:
                        datetime.strptime(nr, "%Y-%m-%d")

                        if nr < row["entry_date"]:
                            raise ValueError()

                except ValueError:
                    notify("تاريخ الإفراج غير صحيح.", True)
                    return

                old = row["release_date"] or ""

                if old == nr:
                    notify("لا يوجد تغيير.", True)
                    return

                new_status = "مفرج عنه" if nr else "محتجز"
                stamp = now_iso()

                vault.conn.execute(
                    """
                    INSERT INTO detainee_corrections(
                        detainee_id,corrected_field,old_value,
                        new_value,reason,actor,created_at
                    )
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        did,
                        "release_date/status",
                        old,
                        nr + " | " + new_status,
                        why,
                        username,
                        stamp,
                    ),
                )

                before = {
                    "release_date": old,
                    "status": row["status"],
                }

                after = {
                    "release_date": nr,
                    "status": new_status,
                }

                vault.conn.execute(
                    """
                    UPDATE detainees
                    SET release_date=?,status=?
                    WHERE id=?
                    """,
                    (nr, new_status, did),
                )

                vault.conn.execute(
                    """
                    INSERT INTO detainee_movements(
                        detainee_id,movement_type,movement_date,
                        actor,reason,before_json,after_json,created_at
                    )
                    VALUES(?,?,?,?,?,?,?,?)
                    """,
                    (
                        did,
                        "CORRECTION",
                        date.today().isoformat(),
                        username,
                        why,
                        json.dumps(before, ensure_ascii=False),
                        json.dumps(after, ensure_ascii=False),
                        stamp,
                    ),
                )

                vault.audit(
                    username,
                    "DETAINEE_CORRECTION",
                    "detainee",
                    did,
                    why,
                )

                vault.persist()

                dlg.open = False
                page.update()

                refresh_detainees()
                notify("تم تسجيل التصحيح.")

            dlg = ft.AlertDialog(
                modal=True,
                title=ft.Text("تصحيح حركة الإفراج"),
                content=ft.Column(
                    [new_release, reason],
                    tight=True,
                ),
                actions=[
                    ft.TextButton("إلغاء", on_click=cancel),
                    ft.FilledButton("حفظ التصحيح", on_click=save),
                ],
            )

            page.show_dialog(dlg)

        def refresh_detainees():

            detainee_rows.controls.clear()
            movement_rows.controls.clear()

            query = "SELECT * FROM detainees"
            args = []

            if dfilter.value and dfilter.value != "الكل":
                query += " WHERE detainee_category=?"
                args.append(dfilter.value)

            query += " ORDER BY entry_date DESC,id DESC"

            rows = vault.conn.execute(
                query,
                args,
            ).fetchall()

            today = date.today().isoformat()

            total = vault.conn.execute(
                "SELECT COUNT(*) FROM detainees"
            ).fetchone()[0]

            detained = vault.conn.execute(
                "SELECT COUNT(*) FROM detainees WHERE status='محتجز'"
            ).fetchone()[0]

            released = vault.conn.execute(
                "SELECT COUNT(*) FROM detainees WHERE status='مفرج عنه'"
            ).fetchone()[0]

            entered = vault.conn.execute(
                "SELECT COUNT(*) FROM detainees WHERE entry_date=?",
                (today,),
            ).fetchone()[0]

            exited = vault.conn.execute(
                "SELECT COUNT(*) FROM detainees WHERE release_date=?",
                (today,),
            ).fetchone()[0]

            stats.value = (
                f"الإجمالي: {total} | المحتجزون: {detained} | "
                f"المفرج عنهم: {released} | دخول اليوم: {entered} | "
                f"خروج اليوم: {exited}"
            )

            daily = vault.conn.execute(
                """
                SELECT day,
                SUM(in_count) AS entries,
                SUM(out_count) AS exits
                FROM (
                    SELECT entry_date AS day,
                    COUNT(*) AS in_count,0 AS out_count
                    FROM detainees GROUP BY entry_date

                    UNION ALL

                    SELECT release_date AS day,
                    0 AS in_count,COUNT(*) AS out_count
                    FROM detainees
                    WHERE release_date<>''
                    GROUP BY release_date
                )
                GROUP BY day
                ORDER BY day DESC
                LIMIT 90
                """
            ).fetchall()

            movement_rows.controls.append(
                ft.Text(
                    "الحركة اليومية",
                    weight=ft.FontWeight.BOLD,
                    color="#7DD3FC",
                )
            )

            for m in daily:

                movement_rows.controls.append(
                    ft.Text(
                        f"{m['day']} | دخول: {m['entries']} | خروج: {m['exits']}"
                    )
                )

            for r in rows:

                try:
                    days = (
                        date.fromisoformat(r["release_date"] or today)
                        - date.fromisoformat(r["entry_date"])
                    ).days
                except Exception:
                    days = 0

                history = vault.conn.execute(
                    """
                    SELECT movement_type,movement_date,actor,reason
                    FROM detainee_movements
                    WHERE detainee_id=?
                    ORDER BY id DESC LIMIT 8
                    """,
                    (r["id"],),
                ).fetchall()

                history_text = " | ".join(
                    [
                        f"{x['movement_date']} · {x['movement_type']} · {x['actor']}"
                        for x in history
                    ]
                )

                detainee_rows.controls.append(
                    ft.Container(
                        ft.Column(
                            [
                                ft.Text(
                                    r["full_name"],
                                    weight=ft.FontWeight.BOLD,
                                ),
                                ft.Text(
                                    f"{r['status']} | {r['detainee_category']}"
                                ),
                                ft.Text(
                                    f"دخول: {r['entry_date']} | مدة الحبس: {days} يوم"
                                ),
                                ft.Text(f"التهمة: {r['charge']}"),
                                ft.Text(
                                    f"الجهة الحابسة: {r['detaining_authority']}"
                                ),
                                ft.Text(
                                    f"الضابط: {r['case_officer']}"
                                ),
                                ft.Text(
                                    f"الإفراج: {r['release_date'] or 'لم يفرج عنه'}"
                                ),
                                ft.Text(
                                    "الحركات: " + history_text,
                                    size=10,
                                ),
                                ft.Row(
                                    [
                                        ft.OutlinedButton(
                                            "تسجيل الإفراج",
                                            on_click=lambda e, i=r["id"]: release_detainee(i),
                                            disabled=(
                                                not can_write
                                                or r["status"] == "مفرج عنه"
                                            ),
                                        ),
                                        ft.OutlinedButton(
                                            "تصحيح الحركة",
                                            on_click=lambda e, i=r["id"]: correct_detainee(i),
                                            disabled=not admin,
                                        ),
                                    ],
                                    wrap=True,
                                ),
                            ],
                            spacing=4,
                        ),
                        padding=10,
                        border_radius=8,
                        bgcolor="#111D30",
                    )
                )

        dfilter.on_change = lambda e: refresh_detainees()

        detention_tab = ft.Column(
            [
                ft.Text(
                    "كشف النزلاء في الحجز الاحتياطي",
                    size=20,
                    weight=ft.FontWeight.BOLD,
                ),
                dn,
                dc,
                de,
                dr,
                dcharge,
                dauthority,
                dofficer,
                dnotes,
                ft.FilledButton(
                    "تسجيل نزيل",
                    on_click=save_detainee,
                    disabled=not can_write,
                ),
                ft.Divider(),
                stats,
                movement_rows,
                dfilter,
                detainee_rows,
            ],
            expand=True,
            scroll=ft.ScrollMode.AUTO,
        )

        if role_can_view_detention(role):
            refresh_detainees()

        # التبويبات

        tabs = []

        if role == "detention_viewer":

            tabs = [
                ft.Tab(
                    text="الحجز الاحتياطي",
                    content=detention_tab,
                )
            ]

        else:

            tabs = [
                ft.Tab(
                    text="القضايا",
                    content=dashboard,
                ),
                ft.Tab(
                    text="مكتب مدير المباحث",
                    content=memo_tab,
                ),
                ft.Tab(
                    text="الأقسام",
                    content=departments_tab,
                ),
            ]

            if role_can_view_detention(role):
                tabs.append(
                    ft.Tab(
                        text="الحجز الاحتياطي",
                        content=detention_tab,
                    )
                )

            tabs.append(
                ft.Tab(
                    text="التدقيق",
                    content=audit_area,
                )
            )

            if admin:
                tabs.append(
                    ft.Tab(
                        text="المستخدمون",
                        content=users_tab,
                    )
                )

        def logout(_):

            try:

                vault.audit(
                    username,
                    "LOGOUT",
                    "session",
                    "local",
                    "تسجيل خروج",
                )

                vault.persist()
                vault.close()

            except Exception:
                pass

            state.update(
                {
                    "vault": None,
                    "dek": None,
                    "username": None,
                    "role": None,
                    "selected": None,
                }
            )

            show_login()

        top_controls = [
            ft.Text(
                f"مرحباً، {username}",
                weight=ft.FontWeight.BOLD,
                expand=True,
            )
        ]

        if admin:

            top_controls.append(
                ft.OutlinedButton(
                    "نسخة احتياطية",
                    icon=ft.Icons.BACKUP,
                    on_click=create_backup,
                )
            )

        top_controls.append(
            ft.IconButton(
                ft.Icons.LOGOUT,
                on_click=logout,
            )
        )

        page.add(
            header(),
            ft.Row(
                top_controls,
                wrap=True,
            ),
            ft.Tabs(
                tabs=tabs,
                expand=1,
            ),
        )

        refresh_table()
        refresh_attachments()
        refresh_audit()

        if admin:
            refresh_users()

        page.update()

    try:

        if not CONFIG_PATH.exists():
            show_setup()
        else:
            show_login()

    except Exception as ex:

        page.add(
            header(),
            ft.Text(
                f"تعذر بدء التطبيق: {ex}",
                color="#FCA5A5",
            ),
        )

        page.update()


if __name__ == "__main__":
    ft.run(main)