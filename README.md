# 🛡️ Security Multicloud Scanner — Enterprise Edition

Auditoria avançada de segurança para **AWS S3**, **Google Cloud Storage**, **Azure Blob Storage** e **Kubernetes** com autenticação MFA, dashboard web interativo e geração de relatórios executivos.

---

## 🚀 Features

- ☁️ **Multicloud:** AWS S3, GCS, Azure Blob Storage
- ☸️ **Kubernetes:** Scan autenticado de clusters (EKS, GKE, AKS, on-prem)
- 🔐 **Dual Mode:** Scan público (sem credenciais) + autenticado (com credenciais)
- 🔑 **Autenticação MFA:** Login com OTP via TOTP (Google Authenticator)
- 📊 **Risk Scoring:** 0–100 com níveis CRITICAL / HIGH / MEDIUM / LOW
- ⚖️ **Compliance:** CIS, PCI-DSS, HIPAA, NIST, ISO 27001
- 📄 **Relatórios Executivos:** Geração automática em PDF e DOCX
- 🎨 **Dashboard Web:** Interface moderna com histórico de scans

---

## 📦 Instalação

```bash
# Clone o repositório
git clone https://github.com/charles-rocha-code/s3_auditor_enteprise.git
cd s3_auditor_enteprise

# Criar ambiente virtual
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Instalar dependências
pip install -r requirements.txt
```

---

## 🔧 Iniciando o Servidor

O servidor principal é o `api_with_mfa.py`, que inclui autenticação MFA.

```bash
# Ativar ambiente virtual
source venv/bin/activate

# Iniciar servidor com MFA
python3 api_with_mfa.py

# Acessar dashboard
# http://localhost:8000/dashboard
```

> ⚠️ O arquivo `api.py` é o servidor base sem MFA. Para uso em produção use sempre `api_with_mfa.py`.

---

## 👤 Gerenciamento de Usuários

### Resetar banco de usuários

```bash
./reset_users.sh
```

Este script para a API, faz backup do banco atual, zera os usuários e reinicia o servidor.

### Primeiro acesso

1. Acesse `http://localhost:8000/dashboard`
2. Clique em **Login**
3. Cadastre seu usuário e configure o MFA via QR Code
4. Use o Google Authenticator ou similar para gerar o OTP

---

## 📊 API Endpoints

| Método | Endpoint | Descrição |
|--------|----------|-----------|
| `GET` | `/health` | Health check |
| `GET` | `/dashboard` | Dashboard web |
| `GET` | `/scan/{bucket}` | Scan público (200 objetos) |
| `POST` | `/scan/public` | Scan público via body |
| `POST` | `/scan/authenticated` | Scan autenticado — S3, GCS, Azure, **Kubernetes** |
| `POST` | `/generate-report` | Gera relatório PDF + DOCX |
| `GET` | `/download-report/{filename}` | Download do relatório |
| `GET` | `/reports/list` | Lista relatórios gerados |

---

## 🔐 Scan Autenticado

O campo `provider` é **obrigatório** para identificar o provedor corretamente, especialmente quando o nome do bucket não contém a URL completa.

### AWS S3

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <seu_token>" \
  -d '{
    "bucket": "meu-bucket",
    "provider": "AWS_S3",
    "aws_access_key_id": "AKIA...",
    "aws_secret_access_key": "xxxxx",
    "region": "us-east-1",
    "max_objects": 1000
  }'
```

### Google Cloud Storage

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <seu_token>" \
  -d '{
    "bucket": "meu-bucket-gcs",
    "provider": "GCS",
    "service_account_key": {
      "type": "service_account",
      "project_id": "meu-projeto",
      "private_key_id": "...",
      "private_key": "-----BEGIN PRIVATE KEY-----\n...",
      "client_email": "sa@projeto.iam.gserviceaccount.com",
      ...
    },
    "max_objects": 1000
  }'
```

> 💡 O JSON da `service_account_key` é gerado no **GCP Console → IAM & Admin → Service Accounts → Criar chave → JSON**.

### Azure Blob Storage

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <seu_token>" \
  -d '{
    "bucket": "myaccount.blob.core.windows.net",
    "provider": "AZURE_BLOB",
    "azure_connection_string": "DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...;EndpointSuffix=core.windows.net",
    "max_objects": 1000
  }'
```

### Kubernetes

```bash
curl -X POST http://localhost:8000/scan/authenticated \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <seu_token>" \
  -d '{
    "bucket": "meu-cluster",
    "provider": "KUBERNETES",
    "kubeconfig_path": "/home/user/.kube/config",
    "context": "meu-contexto",
    "namespace": "production",
    "max_objects": 1000
  }'
```

> 💡 Para clusters EKS/GKE/AKS, use o kubeconfig gerado pelo provider (ex: `aws eks update-kubeconfig`, `gcloud container clusters get-credentials`).  
> Para rodar **dentro do cluster**, omita `kubeconfig_path` e defina `"in_cluster": true`.

---

## ☸️ Kubernetes — Checks de Segurança

O auditor `auditor_k8s_authenticated.py` conecta ao cluster via kubeconfig e executa 5 categorias de verificação:

### 1. Workload Security (Pods e Containers)

| Severidade | Check |
|---|---|
| `CRITICAL` | Container com `privileged: true` |
| `HIGH` | `hostNetwork: true` — compartilha rede do nó |
| `HIGH` | `hostPID: true` — acessa processos do nó |
| `HIGH` | `hostIPC: true` |
| `HIGH` | Container rodando como root (`runAsUser: 0` ou sem `runAsNonRoot`) |
| `MEDIUM` | Container sem `resources.limits` (CPU/memory) |

### 2. RBAC

| Severidade | Check |
|---|---|
| `CRITICAL` | `ClusterRole` com `verbs: ["*"]` e `resources: ["*"]` (permissão total) |

### 3. Secrets e ConfigMaps

| Severidade | Check |
|---|---|
| `CRITICAL` | `ConfigMap` com chaves sensíveis em plaintext (`password`, `secret`, `token`, `apikey`, `private_key`, etc.) |
| `MEDIUM` | `Secret` montado como variável de ambiente (vaza em logs) |

### 4. Exposição de Rede

| Severidade | Check |
|---|---|
| `MEDIUM` | Service do tipo `LoadBalancer` ou `NodePort` exposto externamente |
| `HIGH` | Namespace sem `NetworkPolicy` (tráfego pod-a-pod totalmente liberado) |

### 5. Autenticação Anônima no API Server

| Severidade | Check |
|---|---|
| `CRITICAL` | `ClusterRoleBinding` para `system:anonymous` ou `system:unauthenticated` |

### Score de Risco Kubernetes

```
risk_score = min(100, CRITICAL×25 + HIGH×10 + MEDIUM×3 + LOW×1)
```

### Payload de retorno

```json
{
  "provider": "KUBERNETES",
  "cluster": "1.29",
  "platform": "linux/amd64",
  "namespace_filter": "production",
  "summary": { "namespaces_scanned": 5, "findings_total": 12 },
  "files": [
    {
      "key": "default/Container/nginx/app",
      "severity": "CRITICAL",
      "category": "Workload Security",
      "reason": "Container rodando como privileged",
      "recommendation": "Remover privileged=true; usar capabilities específicas se necessário."
    }
  ],
  "severity_distribution": { "CRITICAL": 2, "HIGH": 4, "MEDIUM": 6, "LOW": 0 },
  "risk_score": 72,
  "recommendations": ["Remover privileged=true...", "Aplicar NetworkPolicy..."],
  "errors": []
}
```

---

## 🌐 Scan Público (sem credenciais)

Detecta o provider automaticamente pela URL.

```bash
# AWS S3
curl http://localhost:8000/scan/meu-bucket

# GCS (URL completa)
curl http://localhost:8000/scan/meu-bucket.storage.googleapis.com

# Azure
curl http://localhost:8000/scan/myaccount.blob.core.windows.net
```

---

## 🏗️ Arquitetura

### Aplicação

![Arquitetura da Aplicação — Security Multicloud Scanner](docs/app-architecture.png)

### Infraestrutura AWS

![Infraestrutura AWS — Security Multicloud Scanner (HA)](docs/aws-architecture.png)

> Alta disponibilidade em `us-east-2` · WAF v2 · ALB · Auto Scaling Group (2–4 EC2) · TLS 1.3 via ACM · Terraform IaC

```
FastAPI Server (api_with_mfa.py)
│
├── Autenticação MFA
│   ├── auth_mfa.py                  — TOTP + JWT
│   ├── templates/login.html         — Tela de login
│   ├── templates/forgot_password.html
│   └── templates/reset_password.html
│
├── Scan Público (200 objetos)
│   ├── auditor.py                   — AWS S3
│   ├── auditor_gcs.py               — GCS
│   └── auditor_azure.py             — Azure Blob
│
├── Scan Autenticado (1000 objetos)
│   ├── auditor_s3_authenticated.py
│   ├── auditor_gcs_authenticated.py
│   ├── auditor_azure_authenticated.py
│   └── auditor_k8s_authenticated.py — ☸️ Kubernetes
│
├── Roteador Universal
│   └── auditor_universal.py         — Detecta provider pela URL
│
├── Risk Engine
│   └── engine_risk.py               — Scoring + Compliance
│
├── Relatórios
│   └── generate_report.py           — PDF + DOCX com gráficos
│
└── Dashboard
    └── templates/dashboard.html
```

---

## 🗂️ Estrutura de Arquivos

```
s3_auditor_enteprise/
├── api_with_mfa.py                 # Servidor principal (com MFA) ← usar este
├── api.py                          # Servidor base (sem MFA)
├── auth_mfa.py                     # Módulo de autenticação MFA
├── auditor_universal.py            # Roteador de providers por URL
├── auditor.py                      # Auditor AWS S3 público
├── auditor_gcs.py                  # Auditor GCS público
├── auditor_azure.py                # Auditor Azure público
├── auditor_s3_authenticated.py     # Auditor AWS S3 autenticado
├── auditor_gcs_authenticated.py    # Auditor GCS autenticado
├── auditor_azure_authenticated.py  # Auditor Azure autenticado
├── auditor_k8s_authenticated.py    # ☸️ Auditor Kubernetes autenticado
├── engine_risk.py                  # Motor de risco e compliance
├── generate_report.py              # Gerador de relatórios PDF/DOCX
├── requirements.txt                # Dependências Python
├── deploy_mfa.sh                   # Deploy com MFA
├── reset_users.sh                  # Reset de usuários
├── install.sh                      # Instalação
└── templates/
    ├── dashboard.html              # Dashboard principal
    ├── login.html                  # Tela de login MFA
    ├── mfa_setup.html              # Configuração do MFA
    ├── forgot_password.html        # Recuperação de senha
    └── reset_password.html         # Reset de senha
```

---

## ⚙️ Variáveis e Configuração

O sistema usa arquivos JSON locais para persistência:

| Arquivo | Descrição |
|---------|-----------|
| `users_db.json` | Banco de usuários (não subir no git) |
| `sessions_db.json` | Sessões ativas (não subir no git) |
| `reports_executive/` | Relatórios gerados (não subir no git) |

---

## 🔒 Segurança

- Credenciais **nunca são armazenadas** — usadas apenas durante o scan
- Tokens JWT com expiração configurável
- MFA obrigatório para scans autenticados
- `.gitignore` configurado para excluir dados sensíveis

---

## 📝 License

MIT License

---

## 👤 Autor

Desenvolvido por **Charles Rocha** para auditoria de segurança em ambientes multicloud.
