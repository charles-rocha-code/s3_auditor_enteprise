"""
auth_mfa.py - Módulo de Autenticação MFA com PERSISTÊNCIA
Integrado ao Security Multicloud Storage Scanner

VERSÃO COM PERSISTÊNCIA:
- Dados salvos em users_db.json (não são perdidos ao reiniciar)
- Sessões salvas em sessions_db.json
- Suporte a Bearer token (API REST)
- Suporte a Cookie (páginas HTML)
"""

from fastapi import HTTPException, Depends, status, Request, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from typing import Optional, Dict, Any
import pyotp
import qrcode
import io
import base64
from datetime import datetime, timedelta
import secrets
import hashlib
import json
import os

# ==================== CONFIGURAÇÃO ====================

# Arquivos de persistência
USERS_DB_FILE = "users_db.json"
SESSIONS_DB_FILE = "sessions_db.json"

# Carregar dados existentes ou criar novos
def load_db(filename: str) -> Dict:
    """Carrega banco de dados do arquivo JSON"""
    if os.path.exists(filename):
        try:
            with open(filename, 'r') as f:
                return json.load(f)
        except:
            return {}
    return {}

def save_db(filename: str, data: Dict):
    """Salva banco de dados no arquivo JSON"""
    with open(filename, 'w') as f:
        json.dump(data, f, indent=2)

# Carregar bancos de dados
USERS_DB: Dict[str, Dict[str, Any]] = load_db(USERS_DB_FILE)
ACTIVE_SESSIONS: Dict[str, Dict[str, Any]] = load_db(SESSIONS_DB_FILE)

print(f"✅ Banco de dados carregado: {len(USERS_DB)} usuário(s)")

security = HTTPBearer(auto_error=False)

# Configurações do Cookie
COOKIE_NAME = "scanner_session"
COOKIE_MAX_AGE = 86400  # 24 horas

# ==================== MODELOS ====================

class UserRegister(BaseModel):
    """Modelo de registro de usuário"""
    email: EmailStr
    password: str
    full_name: Optional[str] = None

class UserLogin(BaseModel):
    """Modelo de login"""
    email: EmailStr
    password: str
    mfa_code: Optional[str] = None

class MFASetup(BaseModel):
    """Modelo para configuração de MFA"""
    email: EmailStr
    password: str

class MFAVerify(BaseModel):
    """Modelo para verificação de MFA"""
    email: EmailStr
    code: str

class MFAToggle(BaseModel):
    """Modelo para ativar/desativar MFA"""
    email: EmailStr
    password: str
    code: Optional[str] = None

class MFARegenerateBackup(BaseModel):
    """Modelo para regenerar backup codes"""
    email: EmailStr
    password: str
    code: str

# ==================== FUNÇÕES AUXILIARES ====================

def hash_password(password: str) -> str:
    """Hash de senha - use bcrypt em produção"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica senha"""
    return hash_password(plain_password) == hashed_password

def generate_mfa_secret() -> str:
    """Gera secret aleatório para TOTP"""
    return pyotp.random_base32()

def generate_backup_codes(count: int = 10) -> list[str]:
    """Gera códigos de backup"""
    return [secrets.token_hex(4).upper() for _ in range(count)]

def generate_qr_code(email: str, secret: str, issuer: str = "Security Scanner") -> str:
    """Gera QR code para Google Authenticator"""
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(
        name=email,
        issuer_name=issuer
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    img_str = base64.b64encode(buffer.getvalue()).decode()
    
    return f"data:image/png;base64,{img_str}"

def verify_totp_code(secret: str, code: str, window: int = 1) -> bool:
    """Verifica código TOTP"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=window)

def verify_backup_code(user_backup_codes: list[str], code: str) -> tuple[bool, Optional[list[str]]]:
    """Verifica código de backup e remove se válido"""
    code_upper = code.upper().replace("-", "").replace(" ", "")
    
    if code_upper in user_backup_codes:
        updated_codes = [c for c in user_backup_codes if c != code_upper]
        return True, updated_codes
    
    return False, user_backup_codes

def create_session_token(email: str) -> str:
    """Cria token de sessão"""
    token = f"scanner_session_{secrets.token_hex(32)}"
    ACTIVE_SESSIONS[token] = {
        "email": email,
        "created_at": datetime.now().isoformat(),
        "authenticated": True,
        "mfa_verified": True
    }
    # PERSISTIR SESSÕES
    save_db(SESSIONS_DB_FILE, ACTIVE_SESSIONS)
    return token

# ==================== DEPENDÊNCIAS ====================

def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> Dict[str, Any]:
    """
    Aceita Bearer token (Authorization header) OU cookie de sessão.
    """
    token: Optional[str] = None

    if credentials:
        token = credentials.credentials
    else:
        token = request.cookies.get(COOKIE_NAME)

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token não fornecido",
        )

    if token not in ACTIVE_SESSIONS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado",
        )

    session = ACTIVE_SESSIONS[token]
    email = session["email"]

    if email not in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário não encontrado",
        )

    user = USERS_DB[email]

    if user.get("mfa_enabled") and not session.get("mfa_verified"):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA não verificado",
        )

    return {
        "email": email,
        "full_name": user.get("full_name"),
        "mfa_enabled": user.get("mfa_enabled", False),
        "session": session,
    }


def get_current_user_from_cookie(request: Request) -> Dict[str, Any]:
    """
    Middleware para verificar autenticação via Cookie
    USADO POR: Páginas HTML (/dashboard, etc.)
    """
    # Pegar token do cookie
    token = request.cookies.get(COOKIE_NAME)
    
    if not token:
        print(f"❌ Cookie '{COOKIE_NAME}' não encontrado")
        print(f"   Cookies disponíveis: {list(request.cookies.keys())}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    print(f"✅ Cookie encontrado: {token[:20]}...")
    
    if token not in ACTIVE_SESSIONS:
        print(f"❌ Token não existe em ACTIVE_SESSIONS")
        print(f"   Sessões ativas: {len(ACTIVE_SESSIONS)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    session = ACTIVE_SESSIONS[token]
    email = session["email"]
    
    print(f"✅ Sessão válida para: {email}")
    
    if email not in USERS_DB:
        print(f"❌ Usuário {email} não existe em USERS_DB")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    
    user = USERS_DB[email]
    
    # Verificar se MFA está ativado e foi verificado
    if user.get("mfa_enabled") and not session.get("mfa_verified"):
        print(f"❌ MFA não verificado para {email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="MFA não verificado"
        )
    
    print(f"✅ Autenticação completa para: {email}")
    
    return {
        "email": email,
        "full_name": user.get("full_name"),
        "mfa_enabled": user.get("mfa_enabled", False),
        "session": session
    }


def require_mfa(user: Dict[str, Any] = Depends(get_current_user)) -> Dict[str, Any]:
    """Requer que MFA esteja ativado"""
    if not user.get("mfa_enabled"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA necessário para esta operação"
        )
    return user


# ==================== FUNÇÕES DE AUTENTICAÇÃO ====================

def register_user(email: str, password: str, full_name: Optional[str] = None) -> Dict[str, Any]:
    """Registra novo usuário"""
    if email in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Usuário já existe"
        )
    
    USERS_DB[email] = {
        "email": email,
        "password": hash_password(password),
        "full_name": full_name,
        "mfa_secret": None,
        "mfa_enabled": False,
        "backup_codes": [],
        "created_at": datetime.now().isoformat()
    }
    
    # PERSISTIR USUÁRIOS
    save_db(USERS_DB_FILE, USERS_DB)
    print(f"✅ Usuário registrado: {email}")
    
    return {
        "message": "Usuário criado com sucesso",
        "email": email
    }


def login_user(email: str, password: str, mfa_code: Optional[str] = None, response: Optional[Response] = None) -> Dict[str, Any]:
    """Login de usuário"""
    if email not in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas"
        )
    
    user = USERS_DB[email]

    # Verificar senha
    if not verify_password(password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas"
        )
    
    # Se MFA está ativado
    if user["mfa_enabled"]:
        if not mfa_code:
            return {
                "message": "MFA requerido",
                "mfa_required": True,
                "authenticated": False
            }
        
        # Verificar código TOTP
        if verify_totp_code(user["mfa_secret"], mfa_code):
            token = create_session_token(email)
            
            # Criar cookie
            if response:
                response.set_cookie(
                    key=COOKIE_NAME,
                    value=token,
                    max_age=COOKIE_MAX_AGE,
                    httponly=True,
                    samesite="lax",
                    secure=False
                )
                print(f"✅ Cookie criado para {email}: {token[:20]}...")
            
            return {
                "message": "Login bem-sucedido",
                "authenticated": True,
                "email": email,
                "full_name": user.get("full_name"),
                "token": token,
                "mfa_enabled": True
            }
        
        # Verificar backup code
        is_valid, updated_codes = verify_backup_code(user["backup_codes"], mfa_code)
        
        if is_valid:
            user["backup_codes"] = updated_codes
            # PERSISTIR MUDANÇA
            save_db(USERS_DB_FILE, USERS_DB)
            
            token = create_session_token(email)
            
            if response:
                response.set_cookie(
                    key=COOKIE_NAME,
                    value=token,
                    max_age=COOKIE_MAX_AGE,
                    httponly=True,
                    samesite="lax",
                    secure=False
                )
                print(f"✅ Cookie criado para {email}: {token[:20]}...")
            
            return {
                "message": "Login bem-sucedido (backup code usado)",
                "authenticated": True,
                "email": email,
                "full_name": user.get("full_name"),
                "token": token,
                "mfa_enabled": True,
                "warning": f"Você tem {len(updated_codes)} backup codes restantes"
            }
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código MFA inválido"
        )
    
    # Login sem MFA
    token = create_session_token(email)
    
    if response:
        response.set_cookie(
            key=COOKIE_NAME,
            value=token,
            max_age=COOKIE_MAX_AGE,
            httponly=True,
            samesite="lax",
            secure=False
        )
        print(f"✅ Cookie criado para {email}: {token[:20]}...")
    
    return {
        "message": "Login bem-sucedido",
        "authenticated": True,
        "email": email,
        "full_name": user.get("full_name"),
        "token": token,
        "mfa_enabled": False
    }


def setup_mfa(email: str, regenerate: bool = False) -> Dict[str, Any]:
    """Configura MFA para usuário.

    Se o usuário já tem um secret salvo e MFA ainda não foi ativado,
    reusa o mesmo secret para evitar invalidar QR já escaneado.
    Passe regenerate=True para forçar geração de novo secret.
    """
    if email not in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )

    user = USERS_DB[email]

    existing_secret = user.get("mfa_secret")
    mfa_enabled = user.get("mfa_enabled", False)

    if existing_secret and not mfa_enabled and not regenerate:
        secret = existing_secret
        backup_codes = user.get("backup_codes") or generate_backup_codes()
        user["backup_codes"] = backup_codes
    else:
        secret = generate_mfa_secret()
        backup_codes = generate_backup_codes()
        user["mfa_secret"] = secret
        user["backup_codes"] = backup_codes
        save_db(USERS_DB_FILE, USERS_DB)

    qr_code = generate_qr_code(email, secret)
    totp = pyotp.TOTP(secret)
    provisioning_uri = totp.provisioning_uri(name=email, issuer_name="Security Scanner")

    print(f"✅ MFA setup retornado para {email}")

    return {
        "secret": secret,
        "qr_code": qr_code,
        "backup_codes": backup_codes,
        "provisioning_uri": provisioning_uri
    }


def verify_and_activate_mfa(email: str, code: str) -> Dict[str, Any]:
    """Verifica código e ativa MFA"""
    if email not in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    user = USERS_DB[email]
    
    if not user.get("mfa_secret"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA não configurado. Execute setup primeiro"
        )
    
    # Log de debug
    print(f"🔍 Verificando MFA para {email}")
    print(f"   Secret: {user['mfa_secret']}")
    print(f"   Código recebido: {code}")
    print(f"   Código esperado: {pyotp.TOTP(user['mfa_secret']).now()}")
    
    # Verificar código
    if verify_totp_code(user["mfa_secret"], code):
        user["mfa_enabled"] = True
        # PERSISTIR MUDANÇA
        save_db(USERS_DB_FILE, USERS_DB)
        print(f"✅ MFA ativado para {email}")
        
        return {
            "message": "MFA ativado com sucesso!",
            "mfa_enabled": True
        }
    else:
        print(f"❌ Código inválido para {email}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código inválido"
        )


def disable_mfa(email: str, password: str, code: str) -> Dict[str, Any]:
    """Desativa MFA"""
    if email not in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    user = USERS_DB[email]
    
    # Verificar senha
    if not verify_password(password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Senha incorreta"
        )
    
    # Verificar código MFA
    if not verify_totp_code(user["mfa_secret"], code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código MFA inválido"
        )
    
    # Desativar
    user["mfa_enabled"] = False
    user["mfa_secret"] = None
    user["backup_codes"] = []
    
    # PERSISTIR MUDANÇA
    save_db(USERS_DB_FILE, USERS_DB)
    print(f"✅ MFA desativado para {email}")
    
    return {"message": "MFA desativado com sucesso"}


def get_mfa_status(email: str) -> Dict[str, Any]:
    """Retorna status MFA do usuário"""
    if email not in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    user = USERS_DB[email]
    
    return {
        "email": email,
        "mfa_enabled": user.get("mfa_enabled", False),
        "backup_codes_remaining": len(user.get("backup_codes", []))
    }


def regenerate_backup_codes(email: str, password: str, code: str) -> Dict[str, Any]:
    """Regenera backup codes"""
    if email not in USERS_DB:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    user = USERS_DB[email]
    
    # Verificar senha
    if not verify_password(password, user["password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Senha incorreta"
        )
    
    # Verificar código MFA
    if not verify_totp_code(user["mfa_secret"], code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Código MFA inválido"
        )
    
    # Gerar novos códigos
    new_codes = generate_backup_codes()
    user["backup_codes"] = new_codes
    
    # PERSISTIR MUDANÇA
    save_db(USERS_DB_FILE, USERS_DB)
    
    return {
        "message": "Backup codes regenerados",
        "backup_codes": new_codes
    }


def logout_user(token: str, response: Optional[Response] = None) -> Dict[str, Any]:
    """Logout - invalida token"""
    if token in ACTIVE_SESSIONS:
        del ACTIVE_SESSIONS[token]
        # PERSISTIR MUDANÇA
        save_db(SESSIONS_DB_FILE, ACTIVE_SESSIONS)
    
    # Remover cookie
    if response:
        response.delete_cookie(key=COOKIE_NAME)
        print(f"✅ Cookie removido")
    
    return {"message": "Logout realizado com sucesso"}


# ==================== INFORMAÇÕES ====================

def get_system_stats() -> Dict[str, Any]:
    """Retorna estatísticas do sistema"""
    return {
        "total_users": len(USERS_DB),
        "users_with_mfa": sum(1 for u in USERS_DB.values() if u.get("mfa_enabled")),
        "active_sessions": len(ACTIVE_SESSIONS)
    }
