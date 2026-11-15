
import os
import sqlite3
from pathlib import Path
from contextlib import contextmanager

APP_DIR = Path(
    os.environ.get(
        "SECURECASEDESK_DATA_DIR",
        str(Path.home() / ".securecasedesk")
    )
)

APP_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = APP_DIR / "securecasedesk.db"

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    full_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (
        role IN ('admin', 'investigator', 'viewer',
                 'detention_viewer')
    ),
    department_id INTEGER,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS departments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS case_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    complainant TEXT,
    parties TEXT,
    case_type_id INTEGER,
    department_id INTEGER,
    officer_id INTEGER,
    incident_date TEXT,
    registration_date TEXT NOT NULL,
    incident_location TEXT,
    details TEXT,
    status TEXT NOT NULL DEFAULT 'جديدة',
    notes TEXT,
    is_archived INTEGER NOT NULL DEFAULT 0,
    created_by INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (case_type_id) REFERENCES case_types(id),
    FOREIGN KEY (department_id) REFERENCES departments(id),
    FOREIGN KEY (officer_id) REFERENCES users(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS memo_types (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS memos (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    memo_number TEXT NOT NULL UNIQUE,
    memo_type_id INTEGER NOT NULL,
    memo_date TEXT NOT NULL,
    recipient TEXT,
    subject TEXT NOT NULL,
    body TEXT NOT NULL,
    case_id INTEGER,
    created_by INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_archived INTEGER NOT NULL DEFAULT 0,

    FOREIGN KEY (memo_type_id) REFERENCES memo_types(id),
    FOREIGN KEY (case_id) REFERENCES cases(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS detainee_categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS detainees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reference_number TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    category_id INTEGER,
    entry_date TEXT NOT NULL,
    release_date TEXT,
    accusation_type TEXT,
    accusation_details TEXT,
    holding_authority TEXT,
    officer_id INTEGER,
    status TEXT NOT NULL DEFAULT 'محتجز',
    notes TEXT,
    created_by INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (category_id)
        REFERENCES detainee_categories(id),
    FOREIGN KEY (officer_id) REFERENCES users(id),
    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS detainee_movements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detainee_id INTEGER NOT NULL,
    movement_type TEXT NOT NULL,
    previous_authority TEXT,
    new_authority TEXT,
    movement_date TEXT NOT NULL,
    reason TEXT,
    performed_by INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (detainee_id) REFERENCES detainees(id),
    FOREIGN KEY (performed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS correction_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    detainee_id INTEGER NOT NULL,
    field_name TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    reason TEXT NOT NULL,
    changed_by INTEGER,
    changed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (detainee_id) REFERENCES detainees(id),
    FOREIGN KEY (changed_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS attachments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    entity_type TEXT NOT NULL,
    entity_id INTEGER NOT NULL,
    file_name TEXT NOT NULL,
    file_type TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    file_hash TEXT,
    created_by INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT,
    details TEXT,
    previous_hash TEXT,
    record_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_cases_number
ON cases(case_number);

CREATE INDEX IF NOT EXISTS idx_cases_status
ON cases(status);

CREATE INDEX IF NOT EXISTS idx_cases_department
ON cases(department_id);

CREATE INDEX IF NOT EXISTS idx_cases_officer
ON cases(officer_id);

CREATE INDEX IF NOT EXISTS idx_memos_number
ON memos(memo_number);

CREATE INDEX IF NOT EXISTS idx_detainees_reference
ON detainees(reference_number);

CREATE INDEX IF NOT EXISTS idx_detainees_status
ON detainees(status);

CREATE INDEX IF NOT EXISTS idx_movements_detainee
ON detainee_movements(detainee_id);

CREATE INDEX IF NOT EXISTS idx_audit_created
ON audit_logs(created_at);
"""

DEFAULT_DEPARTMENTS = [
    "قسم الاعتداء والقتل",
    "قسم التحريات",
    "قسم الآداب",
    "قسم مكافحة السرقات",
    "قسم التحقيقات",
    "قسم الجرائم الإلكترونية",
]

DEFAULT_MEMO_TYPES = [
    "مذكرات وكيل نيابة البحث والأمن والسجون",
    "مذكرات رئيس نيابة استئناف حجة",
    "مذكرات مدير عام أمن المحافظة",
    "مذكرات مدير عام المباحث الجنائية",
    "التكاليف",
    "مذكرات المستشفى الجمهوري",
    "مذكرات المستشفى السعودي",
    "مذكرات السجن المركزي",
    "تقارير الإحصاء",
    "الأوامر القهرية",
]

DEFAULT_DETAINEE_CATEGORIES = [
    "رهن جمع الاستدلالات",
    "النيابة الابتدائية",
    "النيابة الجزائية",
    "باسم مدير عام أمن المحافظة",
    "استخبارات الشرطة",
    "منطقة ظهر أبو طير",
    "أمن المديريات",
    "نيابات المديريات",
]


@contextmanager
def get_connection():
    connection = sqlite3.connect(
        str(DB_PATH),
        timeout=30
    )

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 30000")

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database():
    with get_connection() as connection:
        connection.executescript(SCHEMA)

        for name in DEFAULT_DEPARTMENTS:
            connection.execute(
                "INSERT OR IGNORE INTO departments (name) VALUES (?)",
                (name,)
            )

        for name in DEFAULT_MEMO_TYPES:
            connection.execute(
                "INSERT OR IGNORE INTO memo_types (name) VALUES (?)",
                (name,)
            )

        for name in DEFAULT_DETAINEE_CATEGORIES:
            connection.execute(
                """
                INSERT OR IGNORE INTO detainee_categories (name)
                VALUES (?)
                """,
                (name,)
            )

        connection.execute(
            """
            INSERT OR IGNORE INTO case_types (name)
            VALUES (?)
            """,
            ("عام",)
        )

    return True


def fetch_all(query, parameters=()):
    with get_connection() as connection:
        rows = connection.execute(
            query, parameters
        ).fetchall()

        return [dict(row) for row in rows]


def execute_query(query, parameters=()):
    with get_connection() as connection:
        cursor = connection.execute(
            query, parameters
        )

        return cursor.lastrowid


def check_database():
    try:
        with get_connection() as connection:
            connection.execute("SELECT 1")
        return True
    except sqlite3.Error:
        return False


if __name__ == "__main__":
    initialize_database()
    print("SecureCaseDesk database initialized.")
    print(f"Database location: {DB_PATH}")
