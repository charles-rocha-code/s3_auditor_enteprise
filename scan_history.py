"""
scan_history.py — Persiste e recupera histórico de scans no S3.
Usa o mesmo bucket que users_db/sessions_db (DB_S3_BUCKET).
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Optional

import boto3
from botocore.exceptions import ClientError

S3_BUCKET  = os.getenv("DB_BUCKET") or os.getenv("DB_S3_BUCKET", "security-scanner-db-442042548551")
REGION     = os.getenv("AWS_DEFAULT_REGION", "us-east-2")
PREFIX     = "scan-history/"


def _s3():
    return boto3.client("s3", region_name=REGION)


def _email_safe(email: str) -> str:
    return email.replace("@", "_at_").replace(".", "_").lower()


def save_scan(email: str, provider: str, result: dict) -> str:
    """Salva resultado de scan no S3. Retorna a chave S3 gerada."""
    if not S3_BUCKET or not email:
        return ""

    ts  = datetime.utcnow().strftime("%Y-%m-%dT%H-%M-%S")
    key = f"{PREFIX}{_email_safe(email)}/{provider.lower()}/{ts}.json"

    payload = {
        "email":     email,
        "provider":  provider,
        "timestamp": ts,
        "result":    result,
    }

    try:
        _s3().put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=json.dumps(payload, indent=2, default=str).encode("utf-8"),
            ContentType="application/json",
        )
        print(f"📦 Scan salvo: {key}")
        return key
    except Exception as e:
        print(f"⚠️  scan_history.save_scan error: {e}")
        return ""


def list_scans(email: str, provider: Optional[str] = None, limit: int = 20) -> list[dict]:
    """Lista metadados dos últimos N scans de um usuário (mais recente primeiro)."""
    if not S3_BUCKET or not email:
        return []

    prefix = f"{PREFIX}{_email_safe(email)}/"
    if provider:
        prefix += f"{provider.lower()}/"

    try:
        resp = _s3().list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix)
        objects = sorted(
            resp.get("Contents", []),
            key=lambda x: x["LastModified"],
            reverse=True,
        )[:limit]

        out = []
        for obj in objects:
            parts = obj["Key"].replace(PREFIX, "").split("/")
            out.append({
                "key":           obj["Key"],
                "provider":      parts[1] if len(parts) > 2 else "unknown",
                "timestamp":     (parts[2].replace(".json", "") if len(parts) > 2 else ""),
                "size_bytes":    obj["Size"],
                "last_modified": obj["LastModified"].isoformat(),
            })
        return out
    except Exception as e:
        print(f"⚠️  scan_history.list_scans error: {e}")
        return []


def load_scan(s3_key: str) -> dict:
    """Carrega um scan pelo S3 key."""
    resp = _s3().get_object(Bucket=S3_BUCKET, Key=s3_key)
    return json.loads(resp["Body"].read().decode("utf-8"))


def load_recent(email: str, provider: Optional[str] = None, n: int = 3) -> list[dict]:
    """Carrega os N scans mais recentes de um usuário."""
    metas  = list_scans(email, provider, limit=n)
    result = []
    for meta in metas:
        try:
            result.append(load_scan(meta["key"]))
        except Exception as e:
            print(f"⚠️  scan_history.load_recent error: {e}")
    return result
