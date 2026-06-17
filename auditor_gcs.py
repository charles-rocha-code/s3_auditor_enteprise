# auditor_gcs.py
from __future__ import annotations

import requests
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from engine_risk import classify_severity, build_severity_distribution, calculate_advanced_risk, build_recommendations


class GCSAuditor:
    """
    Auditor GCS sem credenciais:
      - Testa listagem pública via XML API (https://storage.googleapis.com/<bucket>/?prefix=&max-keys=...)
      - Extrai objetos expostos, monta URLs públicas
      - Classifica severidade
      - Calcula score avançado no backend
    """

    def __init__(self, bucket_or_url: str, max_objects: int = 200, timeout: int = 10):
        self.input = bucket_or_url.strip()
        self.max_objects = max_objects
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CloudSecurityScannerPRO/1.0"})

    def _parse_bucket(self) -> str:
        s = self.input

        if "://" in s:
            u = urlparse(s)
            host = u.netloc.lower()
            path = u.path

            # virtual hosted: bucket.storage.googleapis.com
            if host.endswith(".storage.googleapis.com"):
                return host.split(".storage.googleapis.com")[0]

            # storage.googleapis.com/bucket
            if host == "storage.googleapis.com":
                parts = [p for p in path.split("/") if p]
                if parts:
                    return parts[0]

            return host.split(":")[0]

        low = s.lower()
        if low.endswith(".storage.googleapis.com"):
            return low.split(".storage.googleapis.com")[0]
        if low.startswith("storage.googleapis.com/"):
            return low.split("storage.googleapis.com/")[1].split("/")[0]

        # se vier com domínio completo exemplo: qwe33.storage.googleapis.com
        if ".storage.googleapis.com" in low:
            return low.split(".storage.googleapis.com")[0]

        return s

    def _list_objects(self, bucket: str) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        files: List[Dict[str, Any]] = []
        last_error = None

        # endpoints possíveis
        bases = [
            f"https://storage.googleapis.com/{bucket}",
            f"https://{bucket}.storage.googleapis.com",
        ]

        for base in bases:
            url = f"{base}/?max-keys={min(self.max_objects, 5000)}"
            try:
                r = self.session.get(url, timeout=self.timeout)
                if r.status_code == 200 and r.text.strip().startswith("<"):
                    try:
                        root = ET.fromstring(r.text)
                        ns = ""
                        if root.tag.startswith("{"):
                            ns = root.tag.split("}")[0] + "}"

                        for c in root.findall(f".//{ns}Contents"):
                            key_el = c.find(f"{ns}Key")
                            size_el = c.find(f"{ns}Size")
                            if key_el is None:
                                continue
                            key = (key_el.text or "").strip()
                            size = int(size_el.text) if (size_el is not None and (size_el.text or "").isdigit()) else 0

                            sev, reason = classify_severity(key)
                            files.append({
                                "key": key,
                                "size": size,
                                "severity": sev,
                                "reason": reason,
                                "url": f"{base}/{key}"
                            })

                        return True, files, None
                    except Exception as e:
                        last_error = f"Falha ao parsear XML de listagem GCS: {e}"
                        continue

                if r.status_code in (403, 401):
                    return False, [], None

                if r.status_code == 404:
                    last_error = "Bucket não encontrado (404)."
                    continue

                last_error = f"Resposta inesperada ao listar objetos: HTTP {r.status_code}"
            except Exception as e:
                last_error = f"Erro ao consultar listagem: {e}"

        return False, [], last_error

    def run(self) -> Dict[str, Any]:
        bucket = self._parse_bucket()

        public_listing, files, list_error = self._list_objects(bucket)
        public_access = public_listing

        summary = {
            "objects_scanned": len(files),
            "total_size_bytes": sum(int(f.get("size") or 0) for f in files),
        }

        payload: Dict[str, Any] = {
            "provider": "GCS",
            "bucket": bucket,
            "region": "global",   # sem credenciais, localização não é confiável via HTTP público
            "account_id": "-",
            "public_access": public_access,
            "public_listing": public_listing,
            "summary": summary,
            "files": files,
            "errors": [] if not list_error else [list_error],
        }

        payload.update(calculate_advanced_risk(payload))
        payload["severity_distribution"] = build_severity_distribution(payload["files"])
        payload["recommendations"] = build_recommendations(payload)

        return payload
