#!/usr/bin/env bash
set -Eeuo pipefail

APP_DIR="$(cd "$(dirname "$0")" && pwd)"
TARGET_FILE="$APP_DIR/api_with_mfa.py"

TS="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="${TARGET_FILE}.bak.final.${TS}"
TMP_FILE="${TARGET_FILE}.tmp.${TS}"

echo "========================================"
echo " Finalizando rate limit para produção"
echo "========================================"

if [[ ! -f "$TARGET_FILE" ]]; then
  echo "[ERRO] Arquivo não encontrado: $TARGET_FILE"
  exit 1
fi

cp "$TARGET_FILE" "$BACKUP_FILE"
echo "[OK] Backup criado: $BACKUP_FILE"

restore() {
  echo "[ROLLBACK] Restaurando backup..."
  cp "$BACKUP_FILE" "$TARGET_FILE"
}

trap 'echo "[ERRO] Falha detectada"; restore' ERR

echo "[1/5] Aplicando ajustes finais..."

python - "$TARGET_FILE" "$TMP_FILE" <<'PY'
import re
import sys
from pathlib import Path

src = Path(sys.argv[1])
tmp = Path(sys.argv[2])

text = src.read_text()

# -----------------------------------------
# 1. Remover rota /ratelimit-test
# -----------------------------------------
text = re.sub(
    r'\n@app\.get\("/ratelimit-test"\)\n@limiter\.limit\("3/minute"\)\ndef ratelimit_test\(.*?\n(?:    .*\n)*',
    '\n',
    text,
    flags=re.S
)

# -----------------------------------------
# 2. Restaurar limites do login
# -----------------------------------------
pattern_login = re.compile(
    r'@app\.post\("/auth/login"\)\n@limiter\.limit\("1/minute"\)'
)

replacement_login = (
    '@app.post("/auth/login")\n'
    '@limiter.limit("10/hour")\n'
    '@limiter.limit("3/minute")'
)

text = pattern_login.sub(replacement_login, text)

# -----------------------------------------
# 3. Garantir rate limit no /login
# -----------------------------------------
if '@app.get("/login"' in text and '@limiter.limit("30/minute")' not in text:
    text = text.replace(
        '@app.get("/login"',
        '@app.get("/login"\n@limiter.limit("30/minute")'
    )

tmp.write_text(text)
print("Patch aplicado com sucesso.")
PY

echo "[2/5] Validando sintaxe..."
python -m py_compile "$TMP_FILE"

echo "[3/5] Substituindo arquivo..."
mv "$TMP_FILE" "$TARGET_FILE"

echo "[4/5] Validando final..."
python -m py_compile "$TARGET_FILE"

echo "[5/5] Verificação:"
grep -n 'ratelimit-test\|limiter.limit\|auth/login\|@app.get("/login"' "$TARGET_FILE" || true

trap - ERR

echo
echo "========================================"
echo " Ajuste final concluído"
echo "========================================"
echo "Agora reinicie a aplicação"
