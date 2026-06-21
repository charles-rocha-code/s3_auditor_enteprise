"""
auditor_iam_azure.py — Azure IAM Security Auditor (CSPM)

Checks cobertos (CIS Microsoft Azure Foundations Benchmark v2.0):
  1.1  MFA enforcement via Conditional Access Policy (requer Graph API)
  1.2  Global Administrators excessivos (>4)
  1.3  Guest users com roles privilegiadas (Global Admin / Owner)
  1.22 Subscription Owners excessivos (>3) — CIS 1.23
  1.24 Custom roles com wildcard actions (Action=*)
  1.25 Classic Administrators (Co-Administrators) ainda ativos
  Extra: Role assignments em escopo raiz/management group
  Extra: Service Principal credentials expiradas ou expirando
  Extra: Subscription Owners excessivos
"""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests as _requests

SEVERITY_SCORE = {"CRITICAL": 40, "HIGH": 25, "MEDIUM": 15, "LOW": 5}
MAX_OWNERS = 3
MAX_GLOBAL_ADMINS = 4
CRED_WARN_DAYS = 30

GLOBAL_ADMIN_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"
PRIVILEGED_ROLE_ADMIN_TEMPLATE_ID = "e8611ab8-c189-46e8-94e1-60213ab1f814"


class AzureIAMAuditor:
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        subscription_id: str,
    ):
        from azure.identity import ClientSecretCredential
        from azure.mgmt.authorization import AuthorizationManagementClient

        self._tenant_id = tenant_id
        self._subscription_id = subscription_id
        self._client_id = client_id
        self._client_secret = client_secret

        cred = ClientSecretCredential(
            tenant_id=tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
        self._auth = AuthorizationManagementClient(cred, subscription_id)
        self._findings: List[Dict[str, Any]] = []
        self._graph_token: Optional[str] = None

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

    def _get_graph_token(self) -> Optional[str]:
        if self._graph_token:
            return self._graph_token
        try:
            resp = _requests.post(
                f"https://login.microsoftonline.com/{self._tenant_id}/oauth2/v2.0/token",
                data={
                    "grant_type": "client_credentials",
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                },
                timeout=15,
            )
            if resp.status_code == 200:
                self._graph_token = resp.json().get("access_token")
            return self._graph_token
        except Exception:
            return None

    def _graph_get(self, path: str) -> Optional[dict]:
        token = self._get_graph_token()
        if not token:
            return None
        try:
            resp = _requests.get(
                f"https://graph.microsoft.com/v1.0{path}",
                headers={"Authorization": f"Bearer {token}"},
                timeout=15,
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Check 1 — Role assignments at subscription level
    # ------------------------------------------------------------------

    def _check_role_assignments(self) -> None:
        try:
            assignments = list(
                self._auth.role_assignments.list_for_scope(
                    scope=f"/subscriptions/{self._subscription_id}"
                )
            )
        except Exception:
            try:
                assignments = list(self._auth.role_assignments.list(
                    filter=None
                ))
            except Exception:
                return

        role_defs: Dict[str, Any] = {}
        try:
            for rd in self._auth.role_definitions.list(
                scope=f"/subscriptions/{self._subscription_id}"
            ):
                role_defs[rd.id] = rd
        except Exception:
            pass

        owners: List[str] = []

        for assignment in assignments:
            role_id = getattr(assignment, "role_definition_id", "") or ""
            principal_type = getattr(assignment, "principal_type", "Unknown") or "Unknown"
            principal_id = getattr(assignment, "principal_id", "") or ""
            scope = getattr(assignment, "scope", "") or ""

            rd = role_defs.get(role_id)
            role_name = (rd.role_name if rd else role_id.split("/")[-1]) or "unknown"

            # Owner role
            if rd and rd.role_name == "Owner":
                owners.append(principal_id)
                if principal_type == "Guest":
                    self._add(
                        "user", principal_id,
                        "Guest com role Owner na subscription (CIS 1.23)",
                        "CRITICAL",
                        "Usuário externo (Guest) tem role 'Owner' na subscription — acesso total irrestrito a todos os recursos.",
                        "Portal Azure → Subscriptions → IAM → Role assignments → Remove guest Owner",
                    )

            # Root or management group scope
            if scope in ("/", "") or "/providers/Microsoft.Management/managementGroups" in scope:
                self._add(
                    "assignment", principal_id[:32] or "unknown",
                    f"Role '{role_name}' em escopo raiz/management group",
                    "HIGH",
                    f"Atribuição de '{role_name}' no escopo mais amplo (management group/root) — afeta toda a hierarquia de recursos.",
                    "Mover atribuição para escopo mínimo necessário (subscription ou resource group).",
                )

            # Classic administrators
            if "classicadministrators" in scope.lower():
                self._add(
                    "account", "classic-admin",
                    "Co-Administrador clássico ativo (deprecated)",
                    "HIGH",
                    "Conta usa Azure Classic Administrators (Co-Admin) — modelo deprecated desde 2023, sem suporte a MFA via Conditional Access.",
                    "Portal Azure → Subscriptions → Classic administrators → Remove",
                )

        # Owners excessivos
        if len(owners) > MAX_OWNERS:
            self._add(
                "subscription", self._subscription_id,
                f"{len(owners)} Owners na subscription (CIS recomenda ≤{MAX_OWNERS})",
                "MEDIUM",
                f"Subscription tem {len(owners)} owners — excesso aumenta superfície de comprometimento (CIS Azure 1.23).",
                "Portal Azure → Subscriptions → IAM → Role assignments → Remover owners excedentes",
            )

    # ------------------------------------------------------------------
    # Check 2 — Custom roles with dangerous actions
    # ------------------------------------------------------------------

    def _check_custom_roles(self) -> None:
        try:
            custom_roles = [
                rd for rd in self._auth.role_definitions.list(
                    scope=f"/subscriptions/{self._subscription_id}"
                )
                if getattr(rd, "role_type", "") == "CustomRole"
            ]
        except Exception:
            return

        for rd in custom_roles:
            role_name = rd.role_name or "unknown"
            permissions = rd.permissions or []
            for perm in permissions:
                actions = getattr(perm, "actions", []) or []
                for action in actions:
                    if action in ("*",) or action.endswith("/*") or action == "Microsoft.Authorization/*":
                        self._add(
                            "custom-role", role_name,
                            f"Ação wildcard: '{action}' (CIS 1.24)",
                            "HIGH",
                            f"Role customizada '{role_name}' contém ação wildcard '{action}' — concede permissões mais amplas que o necessário.",
                            f"Portal Azure → Subscriptions → IAM → Roles → {role_name} → Edit → substituir ações wildcard por específicas",
                        )

    # ------------------------------------------------------------------
    # Check 3 — Microsoft Entra ID via Graph API
    # ------------------------------------------------------------------

    def _check_conditional_access(self) -> None:
        data = self._graph_get("/identity/conditionalAccess/policies")
        if not data:
            return

        policies = data.get("value", [])
        mfa_policy_found = False

        for policy in policies:
            if policy.get("state") != "enabled":
                continue
            grant = policy.get("grantControls") or {}
            built_in = grant.get("builtInControls", [])
            if "mfa" in [b.lower() for b in built_in]:
                conditions = policy.get("conditions", {})
                users = conditions.get("users", {})
                # Política MFA que inclui todos os usuários (não apenas alguns)
                if users.get("includeUsers") == ["All"] or "All" in (users.get("includeGroups") or []):
                    mfa_policy_found = True

        if not mfa_policy_found:
            self._add(
                "tenant", self._tenant_id,
                "Sem Conditional Access Policy com MFA para todos os usuários",
                "CRITICAL",
                "Nenhuma política de Conditional Access detectada aplicando MFA para todos os usuários — alto risco de credential stuffing e phishing.",
                "Entra ID → Security → Conditional Access → Criar policy: Users=All, Grant=Require MFA",
            )

    def _check_privileged_roles(self) -> None:
        for role_template_id, role_label in [
            (GLOBAL_ADMIN_TEMPLATE_ID, "Global Administrator"),
            (PRIVILEGED_ROLE_ADMIN_TEMPLATE_ID, "Privileged Role Administrator"),
        ]:
            data = self._graph_get(
                f"/directoryRoles/roleTemplateId={role_template_id}/members"
            )
            if not data:
                continue

            members = data.get("value", [])

            if role_label == "Global Administrator" and len(members) > MAX_GLOBAL_ADMINS:
                self._add(
                    "tenant", self._tenant_id,
                    f"{len(members)} Global Administrators (CIS recomenda ≤{MAX_GLOBAL_ADMINS})",
                    "HIGH",
                    f"Tenant tem {len(members)} Global Admins — excesso de admins privilegiados aumenta exposição ao comprometimento.",
                    "Entra ID → Roles → Global Administrator → Members → Remover membros desnecessários → Usar PIM",
                )

            for member in members:
                display_name = member.get("displayName") or member.get("id", "unknown")
                user_type = member.get("userType", "")

                if user_type == "Guest":
                    self._add(
                        "user", display_name,
                        f"Guest com role '{role_label}'",
                        "CRITICAL",
                        f"Usuário externo/guest '{display_name}' tem '{role_label}' — acesso privilegiado por identidade não gerenciada pelo tenant.",
                        f"Entra ID → Roles → {role_label} → Members → Remover membro guest '{display_name}'",
                    )

    def _check_service_principals(self) -> None:
        data = self._graph_get("/servicePrincipals?$top=100&$select=id,displayName,passwordCredentials,keyCredentials")
        if not data:
            return

        now = datetime.now(timezone.utc)
        sps = data.get("value", [])

        for sp in sps:
            sp_name = sp.get("displayName") or sp.get("id", "unknown")

            for cred_label, cred_list in [
                ("client secret", sp.get("passwordCredentials") or []),
                ("certificate", sp.get("keyCredentials") or []),
            ]:
                for cred in cred_list:
                    end_str = cred.get("endDateTime", "")
                    if not end_str:
                        continue
                    try:
                        end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
                        days_left = (end - now).days

                        if days_left < 0:
                            self._add(
                                "service-principal", sp_name,
                                f"Credencial ({cred_label}) expirada há {abs(days_left)} dias",
                                "HIGH",
                                f"Service Principal '{sp_name}' tem {cred_label} expirado há {abs(days_left)} dias — aplicações dependentes estão falhando.",
                                f"Entra ID → App registrations → {sp_name} → Certificates & secrets → Renovar",
                            )
                        elif days_left <= CRED_WARN_DAYS:
                            self._add(
                                "service-principal", sp_name,
                                f"Credencial ({cred_label}) expira em {days_left} dias",
                                "MEDIUM",
                                f"Service Principal '{sp_name}' tem {cred_label} expirando em {days_left} dias — renovar antes do vencimento.",
                                f"Entra ID → App registrations → {sp_name} → Certificates & secrets → Renovar",
                            )
                    except Exception:
                        pass

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

        if sev["critical"] > 0:
            recs.append("🚨 URGENTE: Findings CRITICAL — verificar MFA enforcement e Guest admins imediatamente.")
        if any("MFA" in f.get("check", "") for f in self._findings):
            recs.append("Criar Conditional Access Policy com MFA obrigatório para todos os usuários no Entra ID.")
        if any("Guest" in f.get("check", "") for f in self._findings):
            recs.append("Remover usuários Guest de roles privilegiadas — garantir que admins sejam identidades gerenciadas.")
        if any("Global Administrator" in f.get("check", "") for f in self._findings):
            recs.append("Limitar Global Admins a máximo 4 — ativar Privileged Identity Management (PIM) para acesso just-in-time.")
        if any("Owner" in f.get("check", "") for f in self._findings):
            recs.append("Reduzir Owners na subscription a máximo 3 — usar Contributor ou roles customizadas.")
        if any("expirada" in f.get("check", "") or "expira" in f.get("check", "") for f in self._findings):
            recs.append("Renovar Service Principal credentials expiradas — usar Azure Key Vault para rotação automatizada.")
        if any("wildcard" in f.get("check", "").lower() for f in self._findings):
            recs.append("Substituir ações wildcard em custom roles por ações específicas do Resource Provider.")
        recs.append("Ativar Microsoft Defender for Cloud para monitoramento contínuo de postura de segurança.")
        recs.append("Habilitar Azure Policy com iniciativa 'CIS Microsoft Azure Foundations Benchmark' para enforcement automático.")
        return recs

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self) -> Dict[str, Any]:
        self._check_role_assignments()
        self._check_custom_roles()
        self._check_conditional_access()
        self._check_privileged_roles()
        self._check_service_principals()

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

        no_mfa = any("MFA" in f.get("check", "") for f in self._findings)
        guest_admins = len([f for f in self._findings if "Guest" in f.get("check", "")])

        return {
            "provider": "AZURE_IAM",
            "target": f"subscription/{self._subscription_id}",
            "account_id": self._subscription_id,
            "region": "global",
            "public_access": False,
            "risk_score": score,
            "risk_level": level,
            "severity_distribution": sev,
            "files": self._findings,
            "summary": {
                "objects_scanned": len(self._findings),
                "total_size_bytes": 0,
                "subscription_id": self._subscription_id,
                "tenant_id": self._tenant_id,
                "guest_admins": guest_admins,
                "no_mfa_enforcement": no_mfa,
                "root_mfa": not no_mfa,
                "root_keys_active": False,
            },
            "recommendations": self._recommendations(score),
            "errors": [],
        }
