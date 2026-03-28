from __future__ import annotations

from typing import Iterable

from .models import Difficulty, TaskSpec, VulnerabilityType


# NOTE: Task ordering is fixed to keep episodes reproducible and deterministic.
TASKS: list[TaskSpec] = [
    TaskSpec(
        task_id="easy_sql_injection_01",
        language="python",
        context="A Flask endpoint builds a SQL query from user input.",
        code=(
            "from flask import request\n"
            "import sqlite3\n"
            "\n"
            "def login():\n"
            "    user = request.args.get('user', '')\n"
            "    conn = sqlite3.connect('app.db')\n"
            "    query = \"SELECT * FROM users WHERE name = '\" + user + \"'\"\n"
            "    return str(conn.execute(query).fetchall())\n"
        ),
        vulnerability_type=VulnerabilityType.SQL_INJECTION,
        vulnerable_line=7,
        expected_fix=(
            "Use a parameterized query, e.g. "
            "conn.execute('SELECT * FROM users WHERE name = ?', (user,))."
        ),
        difficulty=Difficulty.EASY,
    ),
    TaskSpec(
        task_id="easy_hardcoded_secret_01",
        language="python",
        context="A service uses embedded credentials to connect to a backend system.",
        code=(
            "import os\n"
            "\n"
            "DB_HOST = 'db.internal.local'\n"
            "DB_USER = 'admin'\n"
            "DB_PASSWORD = 'P@ssw0rd123!'\n"
            "\n"
            "def build_conn_string() -> str:\n"
            "    return f\"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/maindb\"\n"
        ),
        vulnerability_type=VulnerabilityType.HARDCODED_SECRET,
        vulnerable_line=5,
        expected_fix=(
            "Load secrets from a secure secret store or environment variable, "
            "and never commit credentials in source code."
        ),
        difficulty=Difficulty.EASY,
    ),
    TaskSpec(
        task_id="medium_improper_validation_01",
        language="python",
        context="A file download endpoint receives a user-provided filename.",
        code=(
            "from pathlib import Path\n"
            "\n"
            "BASE_DIR = Path('/srv/reports')\n"
            "\n"
            "def read_report(filename: str) -> str:\n"
            "    target = BASE_DIR / filename\n"
            "    return target.read_text(encoding='utf-8')\n"
        ),
        vulnerability_type=VulnerabilityType.IMPROPER_VALIDATION,
        vulnerable_line=6,
        expected_fix=(
            "Validate and normalize user input; reject traversal sequences and ensure "
            "resolved path stays within BASE_DIR before reading."
        ),
        difficulty=Difficulty.MEDIUM,
    ),
    TaskSpec(
        task_id="medium_weak_hashing_01",
        language="python",
        context="Password storage implementation for a user registration flow.",
        code=(
            "import hashlib\n"
            "\n"
            "def hash_password(password: str) -> str:\n"
            "    return hashlib.md5(password.encode('utf-8')).hexdigest()\n"
            "\n"
            "def store_user(username: str, password: str) -> dict:\n"
            "    return {'username': username, 'password_hash': hash_password(password)}\n"
        ),
        vulnerability_type=VulnerabilityType.WEAK_HASHING,
        vulnerable_line=4,
        expected_fix=(
            "Use a password hashing algorithm like bcrypt/argon2/scrypt with a unique salt "
            "and appropriate work factor."
        ),
        difficulty=Difficulty.MEDIUM,
    ),
    TaskSpec(
        task_id="hard_ssrf_01",
        language="python",
        context=(
            "A backend fetcher accepts a URL and internal token, then forwards requests to "
            "another service."
        ),
        code=(
            "import requests\n"
            "\n"
            "def fetch_remote(url: str, token: str) -> str:\n"
            "    headers = {'Authorization': f'Bearer {token}'}\n"
            "    response = requests.get(url, headers=headers, timeout=3)\n"
            "    return response.text\n"
        ),
        vulnerability_type=VulnerabilityType.SSRF,
        vulnerable_line=5,
        expected_fix=(
            "Restrict outbound destinations via allowlist, block internal/private IP ranges, "
            "and validate URL scheme/host before issuing requests."
        ),
        difficulty=Difficulty.HARD,
    ),
    TaskSpec(
        task_id="hard_insecure_deserialization_01",
        language="python",
        context="A queue worker loads payload data from untrusted sources.",
        code=(
            "import pickle\n"
            "\n"
            "def process_payload(raw: bytes) -> str:\n"
            "    obj = pickle.loads(raw)\n"
            "    return f\"Processed {obj.get('job_id')}\"\n"
        ),
        vulnerability_type=VulnerabilityType.INSECURE_DESERIALIZATION,
        vulnerable_line=4,
        expected_fix=(
            "Do not deserialize untrusted bytes with pickle; use safe formats like JSON with "
            "strict schema validation."
        ),
        difficulty=Difficulty.HARD,
    ),
]


def get_all_tasks() -> list[TaskSpec]:
    """Return a deterministic copy of all task specs."""

    return list(TASKS)


def get_tasks_by_difficulty(difficulty: Difficulty) -> list[TaskSpec]:
    """Return tasks filtered by difficulty while preserving stable order."""

    return [task for task in TASKS if task.difficulty == difficulty]


def iter_task_ids() -> Iterable[str]:
    """Yield task IDs in deterministic order."""

    for task in TASKS:
        yield task.task_id
