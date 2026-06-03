#!/bin/bash

set -e

KEY=./multcloud_security-scanner-key.pem
HOST=ubuntu@3.23.103.146
REMOTE_DIR=/home/ubuntu/security-multicloud-scanner

echo "🚀 Iniciando deploy MFA..."

echo "📦 Backup remoto..."
ssh -i "$KEY" "$HOST" << 'EOF'
cd /home/ubuntu/security-multicloud-scanner
mkdir -p backup_mfa
cp api_with_mfa.py backup_mfa/api_with_mfa_$(date +%Y%m%d_%H%M%S).py 2>/dev/null || true
cp auth_mfa.py backup_mfa/auth_mfa_$(date +%Y%m%d_%H%M%S).py 2>/dev/null || true
EOF

echo "📤 Enviando arquivos..."
scp -i "$KEY" api_with_mfa.py auth_mfa.py requirements.txt "$HOST:$REMOTE_DIR/"

echo "📂 Sincronizando templates..."
rsync -avz -e "ssh -i $KEY" templates/ "$HOST:$REMOTE_DIR/templates/"

echo "🔄 Reiniciando aplicação..."
ssh -i "$KEY" "$HOST" << 'EOF'
cd /home/ubuntu/security-multicloud-scanner
source venv/bin/activate

pkill -f uvicorn || true

nohup venv/bin/uvicorn api_with_mfa:app --host 0.0.0.0 --port 8000 > logs/mfa_deploy.log 2>&1 &

sleep 5

ps aux | grep uvicorn | grep -v grep
tail -n 20 logs/mfa_deploy.log
EOF

echo "✅ Deploy concluído!"

