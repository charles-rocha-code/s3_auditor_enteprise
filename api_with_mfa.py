from __future__ import annotations

import logging
import os
import re
import smtplib
import time
from collections import defaultdict

from dotenv import load_dotenv

load_dotenv()
from email.mime.text import MIMEText
from datetime import datetime, timedelta
from pathlib import Path
from secrets import token_urlsafe
from typing import Any, Dict, Optional, Tuple

from fastapi import Depends, FastAPI, HTTPException, Request, Response, Form
from fastapi.exceptions import RequestValidationError
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
    hash_password,
    login_user,
    register_user,
    require_mfa,
    setup_mfa,
    sync_from_s3,
    verify_and_activate_mfa,
)

# === Auditor autenticado (AWS S3) ===
from auditor_s3_authenticated import S3AuthenticatedAuditor  # type: ignore

# === Auditor Kubernetes (opcional) ===
try:
    from auditor_k8s_authenticated import K8sAuthenticatedAuditor  # type: ignore
    K8S_AUDITOR_AVAILABLE = True
except Exception as _e:
    K8S_AUDITOR_AVAILABLE = False
    print(f"⚠️ K8s auditor indisponível: {_e}")

# === Histórico de scans + IA (Claude) ===
from scan_history import save_scan, list_scans, load_recent  # type: ignore
try:
    import ai_analyzer  # type: ignore
    AI_AVAILABLE = True
except Exception as _ai_e:
    AI_AVAILABLE = False
    print(f"⚠️ ai_analyzer indisponível: {_ai_e}")
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.middleware import SlowAPIMiddleware
from slowapi.errors import RateLimitExceeded

# === PDF/DOCX Profissional (lazy: matplotlib só carrega ao gerar relatório) ===
PROFESSIONAL_REPORT: Optional[bool] = None
_gen_executive_report = None


def _ensure_report_loaded() -> bool:
    """Carrega generate_report sob demanda (matplotlib é pesado no import)."""
    global PROFESSIONAL_REPORT, _gen_executive_report
    if PROFESSIONAL_REPORT is not None:
        return PROFESSIONAL_REPORT
    try:
        from generate_report import generate_executive_report as _gen
        _gen_executive_report = _gen
        PROFESSIONAL_REPORT = True
        print("✅ Gerador de relatórios profissional carregado (lazy)")
    except ImportError as e:
        PROFESSIONAL_REPORT = False
        logging.warning("generate_report.py indisponível: %s", e)
    return PROFESSIONAL_REPORT


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

@app.on_event("startup")
async def startup_sync():
    """Sincroniza users_db e sessions_db do S3 ao iniciar — garante consistência no ASG."""
    try:
        sync_from_s3()
    except Exception as e:
        print(f"⚠️  startup sync_from_s3: {e}")

limiter = Limiter(key_func=get_client_ip)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    errors = exc.errors()
    print(f"❌ 422 em {request.method} {request.url.path}: {errors}")
    return JSONResponse(status_code=422, content={"detail": errors})

# Rate limiting manual para /auth/login — @limiter.limit encadeados corrompem
# a inspeção de assinatura do FastAPI e causam 422 "Field required"
_login_ts_minute: Dict[str, list] = defaultdict(list)
_login_ts_hour: Dict[str, list] = defaultdict(list)

def _check_login_rate(ip: str) -> None:
    now = time.time()
    _login_ts_minute[ip] = [t for t in _login_ts_minute[ip] if now - t < 60]
    _login_ts_hour[ip]   = [t for t in _login_ts_hour[ip]   if now - t < 3600]
    if len(_login_ts_minute[ip]) >= 3:
        raise HTTPException(status_code=429, detail="Muitas tentativas. Aguarde 1 minuto.")
    if len(_login_ts_hour[ip]) >= 10:
        raise HTTPException(status_code=429, detail="Limite por hora atingido.")
    _login_ts_minute[ip].append(now)
    _login_ts_hour[ip].append(now)

LAST_SCAN_BY_EMAIL: Dict[str, Dict[str, Any]] = {}

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
        logging.warning("[RESET PASSWORD] SMTP não configurado; e-mail não enviado.")
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

    user["password"] = hash_password(new_password)
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
    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={"request": request},
    )


@app.get("/mfa/setup", response_class=HTMLResponse, include_in_schema=False)
def mfa_setup_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="mfa_setup.html",
        context={"request": request},
    )


@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
def dashboard_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={"request": request},
    )


@app.get("/forgot-password", response_class=HTMLResponse, include_in_schema=False)
def forgot_password_page(request: Request):
    return templates.TemplateResponse(
        request=request,
        name="forgot_password.html",
        context={
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
        request=request,
        name="reset_password.html",
        context={
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
def auth_login(request: Request, data: UserLoginIn, response: Response):
    _check_login_rate(get_client_ip(request))
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
            logging.exception("Erro ao enviar e-mail de reset para %s: %s", normalized_email, e)

    return templates.TemplateResponse(
        request=request,
        name="forgot_password.html",
        context={
            "request": request,
            "success": True,
            "message": "Se o e-mail existir em nossa base, um link de recuperação foi enviado.",
            "reset_link": None,
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

    user["password"] = hash_password(new_password)

    return templates.TemplateResponse(
        request=request,
        name="reset_password.html",
        context={
            "request": request,
            "success": "Senha alterada com sucesso",
            "email": email,
            "token": "",
        },
    )


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


@app.get("/api/dashboard")
def dashboard_api(user=Depends(require_mfa)):
    return {
        "ok": True,
        "user": user
    }


# ================= GERAÇÃO DE RELATÓRIO =================

class GenerateReportIn(BaseModel):
    scan_data: Dict[str, Any]
    client_name: Optional[str] = None
    client_contact: Optional[str] = None
    output_format: str = "both"  # "pdf" | "docx" | "both"


@app.post("/generate-report")
def generate_report_endpoint(data: GenerateReportIn, user=Depends(require_mfa)):
    """Gera relatório PDF/DOCX executivo a partir do scan_data."""
    if not _ensure_report_loaded():
        raise HTTPException(status_code=503, detail="Gerador de relatório indisponível.")

    client_info = None
    if data.client_name or data.client_contact:
        client_info = {"name": data.client_name or "", "contact": data.client_contact or ""}

    try:
        results = _gen_executive_report(
            scan_data=data.scan_data,
            client_info=client_info,
            output_format=data.output_format,
        )
    except Exception as e:
        logging.exception("Erro ao gerar relatório: %s", e)
        raise HTTPException(status_code=500, detail=f"Erro ao gerar relatório: {e}")

    files: Dict[str, str] = {}
    for fmt in ("pdf", "docx"):
        path = results.get(fmt)
        if path:
            files[fmt] = str(path)

    if not files:
        raise HTTPException(status_code=500, detail="Nenhum arquivo gerado.")

    return {"ok": True, "files": files}


@app.get("/download-report/{filename}")
def download_report(filename: str, user=Depends(require_mfa)):
    """Baixa um relatório gerado em reports_executive/."""
    safe = Path(filename).name  # bloqueia path traversal
    target = REPORTS_DIR / safe
    if not target.exists() or not target.is_file():
        raise HTTPException(status_code=404, detail="Relatório não encontrado.")
    return FileResponse(path=str(target), filename=safe)


# ================= KUBERNETES SCAN =================

class K8sScanIn(BaseModel):
    kubeconfig: str = Field(..., description="Conteúdo YAML do kubeconfig")
    context: Optional[str] = None
    namespace: Optional[str] = None
    max_resources: int = 1000


@app.post("/scan/k8s")
def scan_k8s(data: K8sScanIn, user=Depends(require_mfa)):
    """Audita cluster Kubernetes a partir de kubeconfig fornecido."""
    if not K8S_AUDITOR_AVAILABLE:
        raise HTTPException(
            status_code=503,
            detail="Auditor Kubernetes indisponível. Instale: pip install kubernetes>=29.0.0",
        )

    import tempfile
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False)
    try:
        tmp.write(data.kubeconfig)
        tmp.flush()
        tmp.close()

        auditor = K8sAuthenticatedAuditor(
            kubeconfig_path=tmp.name,
            context=data.context,
            namespace=data.namespace,
            max_resources=data.max_resources,
        )
        result = auditor.run()
        email = user.get("email") if isinstance(user, dict) else None
        if email:
            LAST_SCAN_BY_EMAIL[email] = result
            save_scan(email, "kubernetes", result)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logging.exception("Erro no scan k8s: %s", e)
        raise HTTPException(status_code=500, detail=f"Erro no scan: {e}")
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass


# ================= IAM SCANS (AWS / GCP / AZURE) =================

class IamScanIn(BaseModel):
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_session_token: Optional[str] = None
    region_name: str = "us-east-1"

@app.post("/scan/iam")
def scan_iam(payload: IamScanIn, user=Depends(require_mfa)):
    from auditor_iam import AWSIAMAuditor
    auditor = AWSIAMAuditor(
        aws_access_key_id=payload.aws_access_key_id,
        aws_secret_access_key=payload.aws_secret_access_key,
        aws_session_token=payload.aws_session_token,
        region_name=payload.region_name,
    )
    result = auditor.run()
    email = user.get("email") if isinstance(user, dict) else None
    if email:
        LAST_SCAN_BY_EMAIL[email] = result
        save_scan(email, "aws_iam", result)
    return result

class GcpIamScanIn(BaseModel):
    service_account_key: dict

@app.post("/scan/iam/gcp")
def scan_iam_gcp(payload: GcpIamScanIn, user=Depends(require_mfa)):
    from auditor_iam_gcp import GCPIAMAuditor
    auditor = GCPIAMAuditor(service_account_key=payload.service_account_key)
    result = auditor.run()
    email = user.get("email") if isinstance(user, dict) else None
    if email:
        LAST_SCAN_BY_EMAIL[email] = result
        save_scan(email, "gcp_iam", result)
    return result

class AzureIamScanIn(BaseModel):
    tenant_id: str
    client_id: str
    client_secret: str
    subscription_id: str

@app.post("/scan/iam/azure")
def scan_iam_azure(payload: AzureIamScanIn, user=Depends(require_mfa)):
    from auditor_iam_azure import AzureIAMAuditor
    auditor = AzureIAMAuditor(
        tenant_id=payload.tenant_id,
        client_id=payload.client_id,
        client_secret=payload.client_secret,
        subscription_id=payload.subscription_id,
    )
    result = auditor.run()
    email = user.get("email") if isinstance(user, dict) else None
    if email:
        LAST_SCAN_BY_EMAIL[email] = result
        save_scan(email, "azure_iam", result)
    return result


# ================= S3 / STORAGE SCAN (autenticado com MFA) =================

class S3ScanIn(BaseModel):
    bucket: str
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_session_token: Optional[str] = None
    region_name: Optional[str] = "us-east-1"
    max_objects: int = 5000

@app.post("/scan/s3")
def scan_s3(payload: S3ScanIn, user=Depends(require_mfa)):
    """Scan autenticado de bucket S3 com persistência de histórico."""
    auditor = S3AuthenticatedAuditor(
        bucket_name=payload.bucket,
        aws_access_key_id=payload.aws_access_key_id,
        aws_secret_access_key=payload.aws_secret_access_key,
        aws_session_token=payload.aws_session_token,
        region_name=payload.region_name,
        max_objects=payload.max_objects,
    )
    result = auditor.run()
    email = user.get("email") if isinstance(user, dict) else None
    if email:
        LAST_SCAN_BY_EMAIL[email] = result
        save_scan(email, "aws_s3", result)
    return result


# ================= HISTÓRICO DE SCANS =================

@app.get("/scan/history")
def scan_history(
    provider: Optional[str] = None,
    limit: int = 20,
    user=Depends(require_mfa),
):
    """Lista os últimos scans do usuário logado. Filtre por provider opcional."""
    email = user.get("email") if isinstance(user, dict) else None
    if not email:
        raise HTTPException(status_code=401, detail="Usuário não identificado.")
    scans = list_scans(email, provider=provider, limit=limit)
    return {"email": email, "total": len(scans), "scans": scans}


# ================= IA — ANÁLISE COM CLAUDE =================

class AiAskIn(BaseModel):
    question: str
    use_history: bool = True
    provider: Optional[str] = None

@app.post("/ai/analyze")
def ai_analyze(user=Depends(require_mfa)):
    """Análise executiva do último scan com Claude."""
    if not AI_AVAILABLE:
        raise HTTPException(status_code=503, detail="ai_analyzer indisponível.")
    email = user.get("email") if isinstance(user, dict) else None
    scan  = LAST_SCAN_BY_EMAIL.get(email) if email else None
    if not scan:
        raise HTTPException(status_code=404, detail="Nenhum scan encontrado. Realize um scan primeiro.")
    try:
        analysis = ai_analyzer.analyze(scan)
        return {"analysis": analysis}
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logging.exception("Erro ai_analyze: %s", e)
        raise HTTPException(status_code=500, detail=f"Erro na análise: {e}")


@app.post("/ai/compare")
def ai_compare(user=Depends(require_mfa), provider: Optional[str] = None):
    """Compara o scan atual com o histórico e retorna análise de evolução."""
    if not AI_AVAILABLE:
        raise HTTPException(status_code=503, detail="ai_analyzer indisponível.")
    email = user.get("email") if isinstance(user, dict) else None
    scan  = LAST_SCAN_BY_EMAIL.get(email) if email else None
    if not scan:
        raise HTTPException(status_code=404, detail="Nenhum scan encontrado. Realize um scan primeiro.")
    history = load_recent(email, provider=provider, n=3) if email else []
    try:
        comparison = ai_analyzer.compare(scan, history)
        return {"comparison": comparison, "history_scans_used": len(history)}
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logging.exception("Erro ai_compare: %s", e)
        raise HTTPException(status_code=500, detail=f"Erro na comparação: {e}")


@app.post("/ai/ask")
def ai_ask(body: AiAskIn, user=Depends(require_mfa)):
    """Responde uma pergunta livre sobre o scan atual e/ou histórico."""
    if not AI_AVAILABLE:
        raise HTTPException(status_code=503, detail="ai_analyzer indisponível.")
    email = user.get("email") if isinstance(user, dict) else None
    scan  = LAST_SCAN_BY_EMAIL.get(email) if email else None
    if not scan:
        raise HTTPException(status_code=404, detail="Nenhum scan encontrado. Realize um scan primeiro.")
    history = []
    if body.use_history and email:
        history = load_recent(email, provider=body.provider, n=3)
    try:
        answer = ai_analyzer.ask(body.question, scan, history)
        return {"answer": answer, "history_scans_used": len(history)}
    except RuntimeError as e:
        raise HTTPException(status_code=503, detail=str(e))
    except Exception as e:
        logging.exception("Erro ai_ask: %s", e)
        raise HTTPException(status_code=500, detail=f"Erro ao responder: {e}")


# ================= RESET PASSWORD =================

class ResetPasswordIn(BaseModel):
    email: str
    token: str
    new_password: str

def reset_password(data: ResetPasswordIn):
    email = data.email.lower().strip()
    token = data.token
    new_password = data.new_password

    user = USERS_DB.get(email)
    if not user:
        raise HTTPException(status_code=404, detail="Usuário não encontrado")

    # valida token
    if user.get("reset_token") != token:
        raise HTTPException(status_code=401, detail="Token inválido")

    # atualiza senha
    user["password"] = hash_password(new_password)

    # invalida token
    user["reset_token"] = None

    return {"success": True, "message": "Senha atualizada com sucesso"}

# ==================================================




