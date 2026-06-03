#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_FILE="$APP_DIR/api_with_mfa.py"
TS="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="${TARGET_FILE}.bak.fixslowapi.${TS}"

echo "========================================"
echo " Fix debug do slowapi"
echo " Diretório: $APP_DIR"
echo " Arquivo:   $TARGET_FILE"
echo "========================================"

if [[ ! -f "$TARGET_FILE" ]]; then
  echo "[ERRO] Arquivo não encontrado: $TARGET_FILE"
  exit 1
fi

cp "$TARGET_FILE" "$BACKUP_FILE"
echo "[OK] Backup criado: $BACKUP_FILE"

python - "$TARGET_FILE" <<'PY'
from pathlib import Path
import re
import sys

p = Path(sys.argv[1])
text = p.read_text(encoding="utf-8")

original = text

# 1) Garantir import do handler oficial
if "from slowapi import Limiter, _rate_limit_exceeded_handler" not in text:
    if "from slowapi import Limiter" in text:
        text = text.replace(
            "from slowapi import Limiter",
            "from slowapi import Limiter, _rate_limit_exceeded_handler",
            1
        )
    else:
        raise SystemExit("Import 'from slowapi import Limiter' não encontrado.")

# 2) Remover handler customizado, se existir
custom_handler_pattern = re.compile(
    r'\n@app\.exception_handler\(RateLimitExceeded\)\n'
    r'async def rate_limit_handler\(request: Request, exc: RateLimitExceeded\):\n'
    r'(?:    .*\n)+',
    flags=re.M
)
text = custom_handler_pattern.sub("\n", text)

# 3) Garantir add_exception_handler oficial logo após app.state.limiter
if "app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)" not in text:
    marker = "app.state.limiter = limiter"
    if marker not in text:
        raise SystemExit("Linha 'app.state.limiter = limiter' não encontrada.")
    text = text.replace(
        marker,
        marker + "\napp.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)",
        1
    )

# 4) Ajustar login para 1/minute temporariamente
old_block = '''@app.post("/auth/login")
@limiter.limit("10/hour")
@limiter.limit("3/minute")'''
new_block = '''@app.post("/auth/login")
@limiter.limit("1/minute")'''
if old_block in text:
    text = text.replace(old_block, new_block, 1)
else:
    # fallback: se já tiver só o app.post seguido de algum limit, reescreve o bloco
    pat = re.compile(
        r'@app\.post\("/auth/login"\)\n(?:@limiter\.limit\([^\n]+\)\n)+',
        flags=re.M
    )
    if pat.search(text):
        text = pat.sub('@app.post("/auth/login")\n@limiter.limit("1/minute")\n', text, count=1)
    else:
        raise SystemExit("Bloco de decorators do /auth/login não encontrado.")

# 5) Adicionar rota temporária de teste
if '@app.get("/ratelimit-test")' not in text:
    route = '''

@app.get("/ratelimit-test")
@limiter.limit("3/minute")
def ratelimit_test(request: Request):
    return {"ok": True}
'''
    # inserir antes da primeira rota /login, se existir
    m = re.search(r'\n@app\.get\("/login"', text)
    if m:
        text = text[:m.start()] + route + text[m.start():]
    else:
        text += route

p.write_text(text, encoding="utf-8")
print("Patch aplicado com sucesso.")
PY

python -m py_compile "$TARGET_FILE"
echo "[OK] Sintaxe validada"

echo
echo "[INFO] Linhas relevantes:"
grep -n 'Limiter\|_rate_limit_exceeded_handler\|add_exception_handler\|ratelimit-test\|@app.post("/auth/login")\|@limiter.limit' "$TARGET_FILE" || true

echo
echo "========================================"
echo " Correção aplicada"
echo "========================================"
echo "Próximo passo:"
echo "1) source venv/bin/activate"
echo "2) uvicorn api_with_mfa:app --host 127.0.0.1 --port 8000 --reload"
echo "3) testar:"
echo '   for i in {1..10}; do curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/ratelimit-test; done'
echo '   for i in {1..5}; do curl -s -o /dev/null -w "%{http_code}\n" -X POST http://127.0.0.1:8000/auth/login -H "Content-Type: application/json" -d '"'"'{"email":"teste@email.com","password":"senha","mfa_code":""}'"'"'; done'
