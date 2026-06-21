"""
auditor_iam.py — AWS IAM Security Auditor (CSPM)

Checks cobertos (CIS AWS Benchmark v1.4):
  1.2  Root MFA habilitado
  1.3  Root sem access keys ativas
  1.4  Password policy configurada e forte
  1.10 MFA para usuários com acesso ao console
  1.14 Access keys rotacionadas em < 90 dias
  1.16 AdministratorAccess não atribuído diretamente a usuários
  1.22 Políticas IAM sem wildcard Action=* Resource=*
  Extra: cross-account trust aberta, keys nunca usadas, usuários inativos
"""
from __future__ import annotations

import csv
import io
import json
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

KEY_AGE_HIGH_DAYS = 90
KEY_AGE_WARN_DAYS = 45
INACTIVE_DAYS = 90

SEVERITY_SCORE = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5}


class IAMAuditor:
    def __init__(
        self,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        aws_session_token: Optional[str] = None,
        region_name: str = "us-east-1",
    ):
        session = boto3.Session(
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            **({"aws_session_token": aws_session_token} if aws_session_token else {}),
        )
        self.iam = session.client("iam", region_name=region_name)
        self.sts = session.client("sts", region_name=region_name)
        self.region = region_name
        self._findings: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add(
        self,
        entity_type: str,
        entity_name: str,
        check: str,
        severity: str,
        detail: str,
        remediation: str = "",
    ) -> None:
        self._findings.append({
            "key": f"{entity_type}/{entity_name} — {check}",
            "severity": severity,
            "size": 0,
            "reason": detail,
            "url": None,
            "entity_type": entity_type,
            "entity_name": entity_name,
            "check": check,
            "remediation": remediation,
        })

    def _account_id(self) -> str:
        try:
            return self.sts.get_caller_identity()["Account"]
        except Exception:
            return "unknown"

    # ------------------------------------------------------------------
    # Check 1 — Root account
    # ------------------------------------------------------------------

    def _check_root(self, summary: Dict) -> None:
        if summary.get("AccountMFAEnabled", 0) == 0:
            self._add(
                "root", "account", "MFA desabilitado",
                "CRITICAL",
                "Conta root não possui MFA — qualquer comprometimento de senha resulta em acesso total à conta.",
                "IAM Console → Security credentials → Activate MFA on root account",
            )
        if summary.get("AccountAccessKeysPresent", 0) > 0:
            self._add(
                "root", "account", "Access keys ativas na conta root",
                "CRITICAL",
                "A conta root possui access keys programáticas ativas (CIS 1.3) — remover imediatamente.",
                "IAM Console → Security credentials → Delete root access keys",
            )

    # ------------------------------------------------------------------
    # Check 2 — Password policy
    # ------------------------------------------------------------------

    def _check_password_policy(self) -> None:
        try:
            pol = self.iam.get_account_password_policy()["PasswordPolicy"]
        except ClientError as e:
            if "NoSuchEntity" in str(e):
                self._add(
                    "account", "password-policy", "Política de senha não configurada",
                    "HIGH",
                    "Nenhuma password policy — usuários podem criar senhas fracas (CIS 1.4).",
                    "IAM → Account settings → Set password policy",
                )
            return

        min_len = pol.get("MinimumPasswordLength", 0)
        if min_len < 14:
            self._add(
                "account", "password-policy", f"Comprimento mínimo insuficiente ({min_len} chars)",
                "MEDIUM",
                f"CIS 1.8 recomenda mínimo de 14 caracteres. Configurado: {min_len}.",
                "IAM → Account settings → Increase MinimumPasswordLength to 14",
            )
        max_age = pol.get("MaxPasswordAge")
        if not max_age or max_age > 90:
            self._add(
                "account", "password-policy", f"Expiração de senha > 90 dias (atual: {max_age or 'nunca'})",
                "MEDIUM",
                "CIS 1.11: senhas devem expirar em até 90 dias.",
                "Configurar MaxPasswordAge=90",
            )
        reuse = pol.get("PasswordReusePrevention", 0)
        if reuse < 24:
            self._add(
                "account", "password-policy", f"Prevenção de reuso baixa ({reuse} senhas)",
                "LOW",
                f"CIS 1.10 recomenda prevenir reuso das últimas 24 senhas. Configurado: {reuse}.",
                "Configurar PasswordReusePrevention=24",
            )

    # ------------------------------------------------------------------
    # Check 3 — Credential report (MFA, key age, inatividade)
    # ------------------------------------------------------------------

    def _check_credential_report(self) -> None:
        try:
            self.iam.generate_credential_report()
            time.sleep(2)
            resp = self.iam.get_credential_report()
            content = resp["Content"].decode("utf-8")
        except Exception:
            return

        now = datetime.now(timezone.utc)
        for row in csv.DictReader(io.StringIO(content)):
            user = row.get("user", "")
            if user == "<root_account>":
                continue

            has_console = row.get("password_enabled", "false").lower() == "true"
            mfa_active = row.get("mfa_active", "false").lower() == "true"

            # MFA ausente para usuário com console
            if has_console and not mfa_active:
                self._add(
                    "user", user, "MFA não configurado",
                    "HIGH",
                    f"'{user}' tem acesso ao console sem MFA (CIS 1.10).",
                    f"aws iam enable-mfa-device --user-name {user} --serial-number <MFA_ARN> --authentication-code1 <> --authentication-code2 <>",
                )

            # Senha inativa há > 90 dias
            pwd_last = row.get("password_last_used", "")
            if has_console and pwd_last not in ("N/A", "no_information", ""):
                try:
                    days_pwd = (now - datetime.fromisoformat(pwd_last.replace("Z", "+00:00"))).days
                    if days_pwd > INACTIVE_DAYS:
                        self._add(
                            "user", user, f"Console inativo há {days_pwd} dias",
                            "MEDIUM",
                            f"'{user}' não acessa o console há {days_pwd} dias — considere remover o acesso.",
                            f"aws iam update-login-profile --user-name {user} --password-reset-required",
                        )
                except Exception:
                    pass

            # Access keys
            for n in ("1", "2"):
                active = row.get(f"access_key_{n}_active", "false").lower() == "true"
                if not active:
                    continue

                rotated = row.get(f"access_key_{n}_last_rotated", "")
                last_used = row.get(f"access_key_{n}_last_used_date", "")

                if rotated not in ("N/A", "no_information", ""):
                    try:
                        age = (now - datetime.fromisoformat(rotated.replace("Z", "+00:00"))).days
                        if age >= KEY_AGE_HIGH_DAYS:
                            self._add(
                                "user", user, f"Access Key {n} sem rotação há {age} dias",
                                "HIGH",
                                f"Key {n} de '{user}' tem {age} dias sem rotação (CIS 1.14 recomenda < 90).",
                                f"aws iam create-access-key --user-name {user} && aws iam delete-access-key --user-name {user} --access-key-id <OLD_ID>",
                            )
                        elif age >= KEY_AGE_WARN_DAYS:
                            self._add(
                                "user", user, f"Access Key {n} próxima do vencimento ({age} dias)",
                                "MEDIUM",
                                f"Key {n} de '{user}' tem {age} dias — rotar antes de completar 90.",
                                f"aws iam create-access-key --user-name {user}",
                            )
                    except Exception:
                        pass

                if last_used in ("N/A", "no_information", ""):
                    self._add(
                        "user", user, f"Access Key {n} nunca utilizada",
                        "MEDIUM",
                        f"Key {n} de '{user}' foi criada mas nunca utilizada — possível key órfã.",
                        f"aws iam delete-access-key --user-name {user} --access-key-id <KEY_ID>",
                    )
                else:
                    try:
                        days_idle = (now - datetime.fromisoformat(last_used.replace("Z", "+00:00"))).days
                        if days_idle > INACTIVE_DAYS:
                            self._add(
                                "user", user, f"Access Key {n} inativa há {days_idle} dias",
                                "HIGH",
                                f"Key {n} de '{user}' não é usada há {days_idle} dias.",
                                f"aws iam delete-access-key --user-name {user} --access-key-id <KEY_ID>",
                            )
                    except Exception:
                        pass

    # ------------------------------------------------------------------
    # Check 4 — AdministratorAccess e wildcards em usuários e roles
    # ------------------------------------------------------------------

    def _check_policies(self) -> None:
        # Usuários
        paginator = self.iam.get_paginator("list_users")
        for page in paginator.paginate():
            for u in page["Users"]:
                uname = u["UserName"]

                # Managed policies diretamente no usuário
                try:
                    attached = self.iam.list_attached_user_policies(UserName=uname)["AttachedPolicies"]
                except Exception:
                    attached = []
                for pol in attached:
                    if pol["PolicyName"] == "AdministratorAccess":
                        self._add(
                            "user", uname, "AdministratorAccess diretamente no usuário",
                            "CRITICAL",
                            f"'{uname}' tem AdministratorAccess direta (CIS 1.16 — usar grupos/roles).",
                            f"aws iam detach-user-policy --user-name {uname} --policy-arn {pol['PolicyArn']}",
                        )

                # Inline policies com wildcard total
                try:
                    inline_names = self.iam.list_user_policies(UserName=uname)["PolicyNames"]
                except Exception:
                    inline_names = []
                for pol_name in inline_names:
                    try:
                        doc = self.iam.get_user_policy(UserName=uname, PolicyName=pol_name)["PolicyDocument"]
                        if isinstance(doc, str):
                            doc = json.loads(doc)
                        for stmt in doc.get("Statement", []):
                            if stmt.get("Effect") != "Allow":
                                continue
                            action = stmt.get("Action", [])
                            resource = stmt.get("Resource", [])
                            if isinstance(action, str): action = [action]
                            if isinstance(resource, str): resource = [resource]
                            if "*" in action and "*" in resource:
                                self._add(
                                    "user", uname, f"Inline policy '{pol_name}' com wildcard total (Action=* Resource=*)",
                                    "CRITICAL",
                                    f"Política inline '{pol_name}' de '{uname}' concede acesso irrestrito.",
                                    "Substituir por política com ações e recursos específicos (princípio do menor privilégio)",
                                )
                    except Exception:
                        pass

        # Roles (excluindo service-linked roles da AWS)
        paginator = self.iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                rname = role["RoleName"]
                if rname.startswith("AWSServiceRole") or "/aws-service-role/" in role.get("Path", ""):
                    continue

                # AdministratorAccess em role
                try:
                    attached = self.iam.list_attached_role_policies(RoleName=rname)["AttachedPolicies"]
                except Exception:
                    attached = []
                for pol in attached:
                    if pol["PolicyName"] == "AdministratorAccess":
                        self._add(
                            "role", rname, "AdministratorAccess na role",
                            "HIGH",
                            f"Role '{rname}' tem AdministratorAccess — revisar se realmente necessário.",
                            f"aws iam detach-role-policy --role-name {rname} --policy-arn {pol['PolicyArn']}",
                        )

                # Cross-account trust aberta
                trust = role.get("AssumeRolePolicyDocument", {})
                if isinstance(trust, str):
                    try: trust = json.loads(trust)
                    except: trust = {}
                for stmt in trust.get("Statement", []):
                    principal = stmt.get("Principal", {})
                    principals = []
                    if isinstance(principal, str):
                        principals = [principal]
                    elif isinstance(principal, dict):
                        aws_p = principal.get("AWS", [])
                        principals = [aws_p] if isinstance(aws_p, str) else aws_p
                    for p in principals:
                        if p == "*":
                            self._add(
                                "role", rname, "Trust policy com Principal=* (qualquer entidade pode assumir)",
                                "CRITICAL",
                                f"Role '{rname}' pode ser assumida por qualquer entidade AWS.",
                                f"Restringir Principal na trust policy da role '{rname}'",
                            )

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    def _severity_distribution(self) -> Dict[str, int]:
        c = Counter(f["severity"] for f in self._findings)
        return {"critical": c["CRITICAL"], "high": c["HIGH"], "medium": c["MEDIUM"], "low": c["LOW"]}

    def _risk_score(self) -> int:
        return min(sum(SEVERITY_SCORE.get(f["severity"], 0) for f in self._findings), 100)

    def _recommendations(self, score: int) -> List[str]:
        recs = []
        sev = self._severity_distribution()
        checks = [f["check"] for f in self._findings]

        if sev["critical"] > 0:
            recs.append("🚨 URGENTE: Findings CRITICAL presentes — resolver antes de qualquer deploy.")
        if any("root" == f["entity_type"] and "MFA" in f["check"] for f in self._findings):
            recs.append("Ativar MFA na conta root imediatamente (IAM Console → Security credentials).")
        if any("root" == f["entity_type"] and "access keys" in f["check"] for f in self._findings):
            recs.append("Deletar access keys da conta root — use roles e usuários IAM dedicados.")
        if any("MFA" in c for c in checks if "user" in next((f["entity_type"] for f in self._findings if f["check"]==c), "")):
            recs.append("Habilitar MFA para todos os usuários com acesso ao console (CIS 1.10).")
        if any("rotação" in c or ("Key" in c and "dias" in c) for c in checks):
            recs.append("Rotacionar access keys com mais de 90 dias — automatize com Lambda + EventBridge.")
        if any("AdministratorAccess" in c for c in checks):
            recs.append("Remover AdministratorAccess direta de usuários — use grupos e roles com menor privilégio.")
        if any("wildcard" in c.lower() or "Action=*" in c for c in checks):
            recs.append("Substituir políticas com wildcard total por permissões específicas por serviço.")
        if any("inativa" in c or "nunca utilizada" in c for c in checks):
            recs.append("Remover access keys inativas — keys não usadas são superfície de ataque desnecessária.")
        if score < 20:
            recs.append("✅ Postura IAM em bom nível — manter revisões periódicas (mínimo trimestral).")
        recs.append("Implementar AWS IAM Access Analyzer para detectar acessos externos automaticamente.")
        recs.append("Ativar AWS CloudTrail em todas as regiões para auditoria completa de ações IAM.")
        return recs

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        account_id = self._account_id()

        try:
            summary_map = self.iam.get_account_summary()["SummaryMap"]
        except Exception:
            summary_map = {}

        self._check_root(summary_map)
        self._check_password_policy()
        self._check_credential_report()
        self._check_policies()

        sev = self._severity_distribution()
        score = self._risk_score()

        if score >= 80:
            level = "CRITICAL"
        elif score >= 60:
            level = "HIGH"
        elif score >= 30:
            level = "MEDIUM"
        elif score > 0:
            level = "LOW"
        else:
            level = "NONE"

        users_no_mfa = len([f for f in self._findings if f["entity_type"] == "user" and "MFA" in f["check"]])
        keys_old = len([f for f in self._findings if "Key" in f.get("check", "") and "dias" in f.get("check", "")])

        return {
            "provider": "AWS_IAM",
            "target": f"account/{account_id}",
            "account_id": account_id,
            "region": self.region,
            "public_access": False,
            "risk_score": score,
            "risk_level": level,
            "severity_distribution": sev,
            "files": self._findings,
            "summary": {
                "objects_scanned": len(self._findings),
                "total_size_bytes": 0,
                "users_total": summary_map.get("Users", 0),
                "users_no_mfa": users_no_mfa,
                "keys_old": keys_old,
                "root_mfa": summary_map.get("AccountMFAEnabled", 0) == 1,
                "root_keys_active": summary_map.get("AccountAccessKeysPresent", 0) > 0,
            },
            "recommendations": self._recommendations(score),
            "errors": [],
        }
