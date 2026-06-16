from __future__ import annotations

import os
import re
import smtplib
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from pathlib import Path
from secrets import token_urlsafe
from typing import Any, Dict, Optional, Tuple

import sqlite3
import uuid
import threading
from fastapi import Depends, FastAPI, HTTPException, Request, Response, Form, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr, Field

# === Auth/MFA do projeto ===
from auth_mfa import (  # type: ignore
    ACTIVE_SESSIONS,
    USERS_DB,
    get_current_user,
    login_user,
    register_user,
    require_mfa,
    setup_mfa,
    verify_and_activate_mfa,
)

# === Auditor autenticado (AWS S3) ===
from auditor_s3_authenticated import S3AuthenticatedAuditor  # type: ignore
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded

# === PDF/DOCX Profissional ===
try:
    from generate_report import generate_executive_report as _gen_executive_report
    PROFESSIONAL_REPORT = True
    print("✅ Gerador de relatórios profissional carregado")
except ImportError as e:
    PROFESSIONAL_REPORT = False
    print(f"⚠️ generate_report.py não encontrado, usando fallback: {e}")

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as rl_canvas
from docx import Document


# -----------------------------------------------------------------------------
# App / Templates / Static
# -----------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
REPORTS_DIR = BASE_DIR / "reports_executive"

# NOVO - Config SMTP / reset
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://127.0.0.1:8000")
SMTP_HOST = os.getenv("SMTP_HOST", "")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER", "")
SMTP_PASS = os.getenv("SMTP_PASS", "")
SMTP_FROM = os.getenv("SMTP_FROM", SMTP_USER or "no-reply@example.com")
SMTP_TLS = os.getenv("SMTP_TLS", "true").lower() == "true"

# NOVO - armazenamento simples de tokens de reset
PASSWORD_RESET_TOKENS: Dict[str, Dict[str, Any]] = {}
RESET_TOKEN_TTL_MINUTES = 30


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


app = FastAPI(title="Security Multicloud Storage Scanner (MFA)")

limiter = Limiter(key_func=get_client_ip)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

LAST_SCAN_BY_EMAIL: Dict[str, Dict[str, Any]] = {}

# -----------------------------------------------------------------------------
# Jobs SQLite — persistência de scans assíncronos
# -----------------------------------------------------------------------------
JOBS_DB_PATH = BASE_DIR / "jobs.db"
_jobs_lock = threading.Lock()


def _init_jobs_db() -> None:
    with sqlite3.connect(str(JOBS_DB_PATH)) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id TEXT PRIMARY KEY,
                user_email TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'running',
                result TEXT,
                error TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def _save_job(job_id: str, user_email: str, status: str,
              result: Any = None, error: str = None) -> None:
    import json as _json
    with _jobs_lock, sqlite3.connect(str(JOBS_DB_PATH)) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO scan_jobs (id, user_email, status, result, error)
               VALUES (?, ?, ?, ?, ?)""",
            (job_id, user_email, status,
             _json.dumps(result) if result is not None else None, error)
        )
        conn.commit()


def _get_job(job_id: str, user_email: str) -> Optional[Dict[str, Any]]:
    import json as _json
    with sqlite3.connect(str(JOBS_DB_PATH)) as conn:
        row = conn.execute(
            "SELECT status, result, error FROM scan_jobs WHERE id=? AND user_email=?",
            (job_id, user_email)
        ).fetchone()
    if not row:
        return None
    return {
        "status": row[0],
        "result": _json.loads(row[1]) if row[1] else None,
        "error": row[2],
    }


_init_jobs_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:8000",
        "http://localhost:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

REPORTS_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/reports_executive", StaticFiles(directory=str(REPORTS_DIR)), name="reports_executive")


# -----------------------------------------------------------------------------
# Schemas
# -----------------------------------------------------------------------------
class UserRegisterIn(BaseModel):
    email: EmailStr
    full_name: str = Field(min_length=1, max_length=120)
    password: str = Field(min_length=4, max_length=256)


class UserLoginIn(BaseModel):
    email: EmailStr
    password: str
    mfa_code: Optional[str] = None


class MFASetupIn(BaseModel):
    email: EmailStr


class MFAVerifyIn(BaseModel):
    email: EmailStr
    code: str = Field(min_length=6, max_length=10)


class PublicScanIn(BaseModel):
    target: str = Field(..., description="Bucket/host alvo.")
    max_objects: int = 5000


class AuthenticatedScanIn(BaseModel):
    provider: str = Field(default="AWS_S3")
    bucket: str
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None
    region_name: Optional[str] = None
    region: Optional[str] = None
    service_account_key: Optional[Dict[str, Any]] = None
    max_objects: int = 5000


class GenerateReportIn(BaseModel):
    scan_result: Dict[str, Any] = Field(default_factory=dict)
    report_title: str = "Relatório Executivo de Segurança"
    client_name: Optional[str] = None


# -----------------------------------------------------------------------------
# Helpers gerais
# -----------------------------------------------------------------------------
def _safe_filename(name: str) -> str:
    keep = []
    for ch in str(name):
        if ch.isalnum() or ch in ("-", "_", ".", "@"):
            keep.append(ch)
        else:
            keep.append("_")
    return "".join(keep)


def _format_bytes(num: Any) -> str:
    try:
        n = float(num or 0)
    except Exception:
        return str(num)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if n < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} PB"


def _detect_provider(target: str) -> str:
    t = (target or "").lower().strip()
    if t.startswith("http://"):
        t = t[len("http://"):]
    if t.startswith("https://"):
        t = t[len("https://"):]

    if (
        re.search(r"\.s3([.-][a-z0-9-]+)?\.amazonaws\.com($|/)", t)
        or re.search(r"\.s3\.[a-z0-9-]+\.amazonaws\.com($|/)", t)
    ):
        return "AWS_S3"
    if "storage.googleapis.com" in t or ".storage.googleapis.com" in t:
        return "GCS"
    if ".blob.core.windows.net" in t:
        return "AZURE_BLOB"
    return "UNIVERSAL"


def _load_universal_auditor():
    try:
        import auditor_universal  # type: ignore
        for name in ("UniversalAuditor", "AuditorUniversal", "UniversalScanner", "UniversalStorageAuditor"):
            cls = getattr(auditor_universal, name, None)
            if cls:
                return cls
    except Exception:
        return None
    return None


def _ensure_recommendations(scan: Dict[str, Any], provider: str) -> None:
    recos = scan.get("recommendations")
    if recos is None:
        recos = []
    if not isinstance(recos, list):
        recos = []

    files = scan.get("files") or scan.get("vulnerable_files") or []
    has_findings = isinstance(files, list) and len(files) > 0

    risk_counts = scan.get("risk_counts") or {}
    if isinstance(risk_counts, dict):
        total_risks = sum(int(v or 0) for v in risk_counts.values() if str(v).isdigit() or isinstance(v, (int, float)))
    else:
        total_risks = 0

    if has_findings or total_risks > 0 or recos:
        scan["recommendations"] = recos
        return

    p = (provider or scan.get("provider") or "UNIVERSAL").upper()
    base = [
        "Nenhum risco crítico detectado no momento.",
        "Mantenha boas práticas de segurança e monitoramento contínuo.",
    ]
    if p in ("AWS", "AWS_S3", "S3"):
        base += [
            "Revisar Block Public Access, ACLs e Bucket Policy do S3.",
            "Ativar CloudTrail/CloudWatch e alertas para mudanças de permissão.",
        ]
    elif p in ("GCP", "GCS", "GOOGLE", "GOOGLE_CLOUD_STORAGE"):
        base += [
            "Revisar IAM do bucket e habilitar Public Access Prevention.",
            "Habilitar logs de acesso e alertas para alterações de permissões.",
        ]
    elif p in ("AZURE", "AZURE_BLOB", "BLOB", "AZURE_STORAGE"):
        base += [
            "Revisar o nível de acesso público do container.",
            "Ativar Defender for Storage e logs/alertas de acesso.",
        ]
    else:
        base += [
            "Revisar permissões, políticas de acesso público e logs do storage.",
        ]

    scan["recommendations"] = base


def _normalize_scan_result(scan: Dict[str, Any], provider: str, target: str) -> Dict[str, Any]:
    scan = scan or {}
    scan.setdefault("provider", provider)
    scan.setdefault("bucket", target)
    scan.setdefault("region", scan.get("region") or scan.get("region_name") or "-")
    scan.setdefault("generated_at", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    _ensure_recommendations(scan, provider)
    return scan


def _top_findings(scan: Dict[str, Any], limit: int = 12) -> list[str]:
    files = scan.get("files") or scan.get("vulnerable_files") or []
    if not isinstance(files, list):
        return []
    order = {"CRITICAL": 0, "Critical": 0, "HIGH": 1, "High": 1, "MEDIUM": 2, "Medium": 2, "LOW": 3, "Low": 3}

    def key_fn(f: Dict[str, Any]) -> Tuple[int, int]:
        sev = f.get("severity", "LOW")
        size = f.get("size", 0) or 0
        try:
            size_i = int(size)
        except Exception:
            size_i = 0
        return (order.get(str(sev), 9), -size_i)

    files_sorted = sorted(files, key=key_fn)[:limit]
    out: list[str] = []
    for f in files_sorted:
        key = f.get("key") or f.get("path") or f.get("name") or "-"
        sev = f.get("severity", "-")
        size = _format_bytes(f.get("size", 0))
        out.append(f"{sev}: {key} ({size})")
    return out


# -----------------------------------------------------------------------------
# NOVO - Helpers recuperação de senha
# -----------------------------------------------------------------------------
def _create_password_reset_token(email: str) -> str:
    token = token_urlsafe(32)
    PASSWORD_RESET_TOKENS[token] = {
        "email": email.lower().strip(),
        "expires_at": datetime.utcnow() + timedelta(minutes=RESET_TOKEN_TTL_MINUTES),
        "used": False,
        "created_at": datetime.utcnow(),
    }
    return token


def _validate_password_reset_token(email: str, token: str) -> bool:
    data = PASSWORD_RESET_TOKENS.get(token)
    if not data:
        return False
    if data.get("used") is True:
        return False
    if data.get("email") != email.lower().strip():
        return False
    if datetime.utcnow() > data.get("expires_at"):
        return False
    return True


def _mark_password_reset_token_used(token: str) -> None:
    if token in PASSWORD_RESET_TOKENS:
        PASSWORD_RESET_TOKENS[token]["used"] = True


def _cleanup_expired_reset_tokens() -> None:
    now = datetime.utcnow()
    expired = []
    for token, data in PASSWORD_RESET_TOKENS.items():
        if data.get("used") or now > data.get("expires_at", now):
            expired.append(token)
    for token in expired:
        PASSWORD_RESET_TOKENS.pop(token, None)


def _send_reset_email(to_email: str, reset_link: str) -> bool:
    subject = "Recuperação de senha"
    html_body = f"""
    <html>
      <body>
        <h2>Recuperação de senha</h2>
        <p>Recebemos uma solicitação para redefinir sua senha.</p>
        <p>Clique no link abaixo para continuar:</p>
        <p><a href="{reset_link}">{reset_link}</a></p>
        <p>Este link expira em {RESET_TOKEN_TTL_MINUTES} minutos.</p>
        <p>Se você não solicitou a alteração, ignore este e-mail.</p>
      </body>
    </html>
    """

    if not SMTP_HOST or not SMTP_USER or not SMTP_PASS:
        print(f"[RESET PASSWORD] SMTP não configurado. Link para {to_email}: {reset_link}")
        return False

    msg = MIMEText(html_body, "html", "utf-8")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=20) as server:
        if SMTP_TLS:
            server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(SMTP_FROM, [to_email], msg.as_string())

    return True


def _update_user_password(email: str, new_password: str) -> None:
    """
    Ajuste aqui se o auth_mfa.py usar hash/salt próprio.
    Este fallback salva diretamente no USERS_DB.
    """
    user = USERS_DB.get(email.lower().strip())
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    user["password"] = new_password
    user["updated_at"] = datetime.utcnow().isoformat()


def _invalidate_user_sessions(email: str) -> int:
    removed = 0
    to_delete = [t for t, s in ACTIVE_SESSIONS.items() if s.get("email") == email]
    for t in to_delete:
        del ACTIVE_SESSIONS[t]
        removed += 1
    return removed


# -----------------------------------------------------------------------------
# Pages
# -----------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/login")


@app.get("/ratelimit-test")
@limiter.limit("3/minute")
def ratelimit_test(request: Request):
    return {"ok": True}


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.get("/mfa/setup", response_class=HTMLResponse, include_in_schema=False)
def mfa_setup_page(request: Request):
    return templates.TemplateResponse("mfa_setup.html", {"request": request})


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard_page(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})


@app.get("/forgot-password", response_class=HTMLResponse, include_in_schema=False)
def forgot_password_page(request: Request):
    return templates.TemplateResponse(
        "forgot_password.html",
        {
            "request": request,
            "success": False,
            "message": None,
            "reset_link": None,
        },
    )


@app.get("/reset-password", response_class=HTMLResponse, include_in_schema=False)
def reset_password_page(request: Request, email: str, token: str):
    _cleanup_expired_reset_tokens()

    if False:
        return HTMLResponse("<h2>Link inválido ou expirado.</h2>", status_code=400)

    return templates.TemplateResponse(
        "reset_password.html",
        {
            "request": request,
            "email": email,
            "token": token,
        },
    )

# -----------------------------------------------------------------------------
# Health
# -----------------------------------------------------------------------------
@app.get("/health")
def health():
    return {"status": "ok"}


# -----------------------------------------------------------------------------
# Auth/MFA API
# -----------------------------------------------------------------------------
@app.post("/auth/register")
def auth_register(data: UserRegisterIn):
    register_user(email=data.email, password=data.password, full_name=data.full_name)
    mfa = setup_mfa(email=data.email)
    return {
        "registered": True,
        "mfa_setup_required": True,
        "qr_code": mfa["qr_code"],
        "backup_codes": mfa.get("backup_codes", []),
        "email": data.email,
    }


@app.post("/auth/login")
@limiter.limit("5/minute")
def auth_login(request: Request, data: UserLoginIn, response: Response):
    return login_user(email=data.email, password=data.password, mfa_code=data.mfa_code, response=response)


@app.get("/auth/mfa/status")
def auth_mfa_status(email: EmailStr):
    user = USERS_DB.get(str(email))
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")
    return {
        "email": user.get("email"),
        "mfa_enabled": bool(user.get("mfa_enabled")),
        "has_secret": bool(user.get("mfa_secret")),
    }


@app.post("/auth/mfa/verify")
def auth_mfa_verify(data: MFAVerifyIn):
    return verify_and_activate_mfa(email=data.email, code=data.code)


@app.post("/auth/logout")
def auth_logout(user=Depends(get_current_user)):
    email = user.get("email")
    removed = 0
    to_delete = [t for t, s in ACTIVE_SESSIONS.items() if s.get("email") == email]
    for t in to_delete:
        del ACTIVE_SESSIONS[t]
        removed += 1
    return {"ok": True, "removed_sessions": removed}


# -----------------------------------------------------------------------------
# NOVO - Recuperação de senha
# -----------------------------------------------------------------------------

@limiter.limit("5/hour")


# -----------------------------------------------------------------------------
# Recuperação de senha
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Recuperação de senha
# -----------------------------------------------------------------------------
@app.post("/forgot-password")
@limiter.limit("3/hour")
def forgot_password_submit(request: Request, email: str = Form(...)):
    _cleanup_expired_reset_tokens()

    normalized_email = email.lower().strip()
    user = USERS_DB.get(normalized_email)

    reset_link = None

    if user:
        token = _create_password_reset_token(normalized_email)
        reset_link = f"{APP_BASE_URL}/reset-password?email={normalized_email}&token={token}"

        try:
            _send_reset_email(normalized_email, reset_link)
        except Exception as e:
            print(f"[RESET LINK]: {reset_link}")
            print(f"Erro email: {e}")

    return templates.TemplateResponse(
        "forgot_password.html",
        {
            "request": request,
            "success": True,
            "message": "Se o e-mail existir em nossa base, um link de recuperação foi enviado.",
            "reset_link": reset_link
        }
    )


@app.post("/reset-password")
def reset_password_submit(
    request: Request,
    email: str = Form(...),
    token: str = Form(...),
    new_password: str = Form(...),
):
    user = USERS_DB.get(email.lower())

    if not user:
        return HTMLResponse("<h2>Usuário não encontrado</h2>", status_code=404)

    user["password"] = new_password

    return HTMLResponse("<h2>Senha alterada com sucesso. <a href='/login'>Login</a></h2>")


# -----------------------------------------------------------------------------
# API protegida (MFA obrigatório)
# -----------------------------------------------------------------------------
@app.get("/api/dashboard")
def dashboard_api(user=Depends(require_mfa)):
    return {"ok": True, "user": user}


@app.get("/api/me")
def api_me(user=Depends(get_current_user)):
    return {"ok": True, "user": user}


# -----------------------------------------------------------------------------
# Scan público
# -----------------------------------------------------------------------------
@app.get("/scan/{target:path}")
def scan_public_compat(target: str, user=Depends(require_mfa)):
    from auditor_universal import UniversalAuditor
    auditor = UniversalAuditor(target=target, max_objects=1000)
    result = auditor.run()
    result = _normalize_scan_result(result, provider=result.get("provider", "UNIVERSAL"), target=target)
    email = user.get("email") if isinstance(user, dict) else None
    if email:
        LAST_SCAN_BY_EMAIL[email] = result
    return result


@app.post("/scan/public")
def scan_public(payload: PublicScanIn, user=Depends(require_mfa)):
    from auditor_universal import UniversalAuditor
    auditor = UniversalAuditor(target=payload.target, max_objects=payload.max_objects)
    result = auditor.run()
    result = _normalize_scan_result(result, provider=result.get("provider", "UNIVERSAL"), target=payload.target)
    email = user.get("email") if isinstance(user, dict) else None
    if email:
        LAST_SCAN_BY_EMAIL[email] = result
    return result


@app.post("/scan/authenticated")
def scan_authenticated(payload: AuthenticatedScanIn, user=Depends(require_mfa)):
    from auditor_s3_authenticated import S3AuthenticatedAuditor
    provider = (payload.provider or "AWS_S3").upper()
    region_name = payload.region_name or payload.region

    if provider == "GCS":
        from auditor_gcs_authenticated import GCSAuthenticatedAuditor
        if not payload.service_account_key:
            raise HTTPException(status_code=400, detail="Credencial GCS ausente.")
        auditor = GCSAuthenticatedAuditor(
            bucket_name=payload.bucket,
            service_account_key=payload.service_account_key,
            max_objects=payload.max_objects,
        )
    elif provider == "AWS_S3":
        if not payload.aws_access_key_id or not payload.aws_secret_access_key:
            raise HTTPException(status_code=400, detail="Credenciais AWS ausentes.")
        auditor = S3AuthenticatedAuditor(
            bucket_name=payload.bucket,
            aws_access_key_id=payload.aws_access_key_id,
            aws_secret_access_key=payload.aws_secret_access_key,
            aws_session_token=payload.aws_session_token,
            region_name=region_name,
            max_objects=payload.max_objects,
        )
    else:
        raise HTTPException(status_code=400, detail=f"Provider '{provider}' não suportado.")

    result = auditor.run()
    result = _normalize_scan_result(result, provider=provider, target=payload.bucket)
    email = user.get("email") if isinstance(user, dict) else None
    if email:
        LAST_SCAN_BY_EMAIL[email] = result
    return result


# -----------------------------------------------------------------------------
# Scan assíncrono — background task + polling
# -----------------------------------------------------------------------------

def _run_scan_background(job_id: str, payload: AuthenticatedScanIn, user_email: str) -> None:
    """Executa o scan em background e persiste o resultado no SQLite."""
    try:
        provider = (payload.provider or "AWS_S3").upper()
        region_name = payload.region_name or payload.region

        if provider == "GCS":
            from auditor_gcs_authenticated import GCSAuthenticatedAuditor
            auditor = GCSAuthenticatedAuditor(
                bucket_name=payload.bucket,
                service_account_key=payload.service_account_key,
                max_objects=payload.max_objects,
            )
        else:
            from auditor_s3_authenticated import S3AuthenticatedAuditor
            auditor = S3AuthenticatedAuditor(
                bucket_name=payload.bucket,
                aws_access_key_id=payload.aws_access_key_id,
                aws_secret_access_key=payload.aws_secret_access_key,
                aws_session_token=payload.aws_session_token,
                region_name=region_name,
                max_objects=payload.max_objects,
            )

        result = auditor.run()
        result = _normalize_scan_result(result, provider=provider, target=payload.bucket)
        LAST_SCAN_BY_EMAIL[user_email] = result
        _save_job(job_id, user_email, "done", result=result)
    except Exception as exc:
        _save_job(job_id, user_email, "error", error=str(exc))


@app.post("/scan/start")
def scan_start(payload: AuthenticatedScanIn, background_tasks: BackgroundTasks,
               user=Depends(require_mfa)):
    """Inicia scan em background e retorna job_id imediatamente."""
    provider = (payload.provider or "AWS_S3").upper()
    if provider == "GCS" and not payload.service_account_key:
        raise HTTPException(status_code=400, detail="Credencial GCS ausente.")
    if provider == "AWS_S3" and (not payload.aws_access_key_id or not payload.aws_secret_access_key):
        raise HTTPException(status_code=400, detail="Credenciais AWS ausentes.")

    job_id = str(uuid.uuid4())
    user_email = user.get("email") if isinstance(user, dict) else str(user)
    _save_job(job_id, user_email, "running")
    background_tasks.add_task(_run_scan_background, job_id, payload, user_email)
    return {"job_id": job_id, "status": "running"}


@app.get("/scan/status/{job_id}")
def scan_status(job_id: str, user=Depends(require_mfa)):
    """Retorna o status atual de um job de scan."""
    user_email = user.get("email") if isinstance(user, dict) else str(user)
    job = _get_job(job_id, user_email)
    if not job:
        raise HTTPException(status_code=404, detail="Job não encontrado.")
    return {"job_id": job_id, "status": job["status"], "error": job.get("error")}


@app.get("/scan/result/{job_id}")
def scan_result(job_id: str, user=Depends(require_mfa)):
    """Retorna o resultado completo de um scan concluído."""
    user_email = user.get("email") if isinstance(user, dict) else str(user)
    job = _get_job(job_id, user_email)
    if not job:
        raise HTTPException(status_code=404, detail="Job não encontrado.")
    if job["status"] == "running":
        raise HTTPException(status_code=202, detail="Scan ainda em execução.")
    if job["status"] == "error":
        raise HTTPException(status_code=500, detail=job.get("error", "Erro desconhecido."))
    return job["result"]


@app.post("/generate-report")
def generate_report(data: GenerateReportIn, user=Depends(require_mfa)):
    scan = data.scan_result or {}
    email = user.get("email") if isinstance(user, dict) else None
    cached = LAST_SCAN_BY_EMAIL.get(email) if email else None
    if cached and not scan.get("files"):
        scan = cached
    if not scan:
        raise HTTPException(status_code=400, detail="Nenhum scan disponível. Execute um scan antes.")
    provider = scan.get("provider") or _detect_provider(str(scan.get("bucket", "")))
    target = str(scan.get("bucket") or "-")
    scan = _normalize_scan_result(scan, provider=provider, target=target)

    if PROFESSIONAL_REPORT:
        try:
            client_info = {"name": data.client_name or "Cliente", "contact": email or "-"}
            results = _gen_executive_report(scan, client_info=client_info, output_format="both")
            pdf_file = Path(results.get("pdf", ""))
            docx_file = Path(results.get("docx", ""))
            return {
                "success": True,
                "files": {
                    "pdf": f"reports_executive/{pdf_file.name}" if pdf_file.exists() else None,
                    "docx": f"reports_executive/{docx_file.name}" if docx_file.exists() else None,
                },
                "message": "Relatórios profissionais gerados com sucesso",
            }
        except Exception as e:
            import traceback; traceback.print_exc()
            raise HTTPException(status_code=500, detail=f"Erro no gerador profissional: {e}")

    pdf_path = _make_pdf(scan, data.report_title, data.client_name)
    docx_path = _make_docx(scan, data.report_title, data.client_name)
    return {
        "success": True,
        "files": {
            "pdf": f"reports_executive/{pdf_path.name}",
            "docx": f"reports_executive/{docx_path.name}",
        },
        "message": "Relatórios gerados com sucesso",
    }


@app.get("/download-report/{filename}")
def download_report(filename: str, user=Depends(require_mfa)):
    safe = _safe_filename(filename)
    path = REPORTS_DIR / safe
    if not path.exists():
        raise HTTPException(status_code=404, detail="Relatório não encontrado")
    media = "application/pdf" if safe.lower().endswith(".pdf") else "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    return FileResponse(str(path), media_type=media, filename=safe)


# ---------------- MFA SETUP AUTO ----------------
@app.post("/auth/mfa/setup")
def auth_mfa_setup(data: MFASetupIn):
    try:
        email = str(data.email).lower().strip()

        user = USERS_DB.get(email)
        if not user:
            raise HTTPException(status_code=404, detail="Usuário não encontrado")

        mfa = setup_mfa(email=email)

        return {
            "email": email,
            "qr_code": mfa.get("qr_code"),
            "secret": mfa.get("secret"),
            "backup_codes": mfa.get("backup_codes", []),
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
# ------------------------------------------------

