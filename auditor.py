# auditor.py
from __future__ import annotations

import requests
import xml.etree.ElementTree as ET
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, quote

from engine_risk import classify_severity, build_severity_distribution, calculate_advanced_risk, build_recommendations


class S3Auditor:
    """
    Auditor S3 sem credenciais:
      - Descobre região via HEAD/GET (x-amz-bucket-region)
      - Testa listagem pública via ListObjectsV2 (XML)
      - Extrai alguns objetos (limitado) e monta urls públicas
      - Classifica severidade
      - Calcula score avançado no backend
    """

    def __init__(self, bucket_or_url: str, max_objects: int = 200, timeout: int = 10):
        self.input = bucket_or_url.strip()
        self.max_objects = max_objects
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CloudSecurityScannerPRO/1.0"
        })

    def _parse_bucket(self) -> str:
        s = self.input

        # se vier URL, extrair host/path
        if "://" in s:
            u = urlparse(s)
            host = u.netloc.lower()
            # virtual-hosted-style: bucket.s3.amazonaws.com
            if host.endswith(".s3.amazonaws.com"):
                return host.split(".s3.amazonaws.com")[0]
            # regional: bucket.s3.sa-east-1.amazonaws.com
            if ".s3." in host and host.endswith(".amazonaws.com"):
                return host.split(".s3.")[0]
            # path-style: s3.amazonaws.com/bucket
            if host.startswith("s3.") or host == "s3.amazonaws.com":
                parts = [p for p in u.path.split("/") if p]
                if parts:
                    return parts[0]
            # se veio só bucket como host (raro), tenta
            return host.split(":")[0]

        # se veio "bucket.s3.amazonaws.com" ou "bucket.s3-region.amazonaws.com"
        low = s.lower()
        
        # Formato: bucket.s3.amazonaws.com
        if low.endswith(".s3.amazonaws.com"):
            return low.split(".s3.amazonaws.com")[0]
        
        # Formato: bucket.s3-region.amazonaws.com (IMPORTANTE!)
        if ".s3-" in low and low.endswith(".amazonaws.com"):
            # Extrai apenas o nome do bucket antes de .s3-
            return low.split(".s3-")[0]
        
        # Formato: bucket.s3.region.amazonaws.com
        if ".s3." in low and low.endswith(".amazonaws.com"):
            return low.split(".s3.")[0]

        # senão, assume nome do bucket
        return s

    def _head_bucket_region(self, bucket: str) -> Optional[str]:
        """
        Tenta descobrir a região do bucket.
        Suporta formatos:
        - bucket.s3.amazonaws.com
        - bucket.s3.region.amazonaws.com
        - bucket.s3-region.amazonaws.com
        """
        # Se o input original já tinha região no formato s3-region, extrair
        if ".s3-" in self.input.lower() and ".amazonaws.com" in self.input.lower():
            try:
                # Extrai: cdn44.s3-ap-southeast-2.amazonaws.com → ap-southeast-2
                parts = self.input.lower().split(".s3-")[1].split(".amazonaws.com")[0]
                return parts
            except Exception:
                pass
        
        # Tenta endpoint global primeiro
        url = f"https://{bucket}.s3.amazonaws.com/"
        try:
            r = self.session.head(url, timeout=self.timeout, allow_redirects=False)
            reg = r.headers.get("x-amz-bucket-region")
            if reg:
                return reg
        except Exception:
            pass
        
        return None

    def _list_objects(self, bucket: str, region: Optional[str]) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
        """
        Retorna (public_listing, files, error)
        Tenta múltiplos formatos de endpoint S3
        """
        files: List[Dict[str, Any]] = []

        # Monta lista de endpoints a tentar
        endpoints = []
        
        if region:
            # Formato novo: bucket.s3.region.amazonaws.com
            endpoints.append(f"https://{bucket}.s3.{region}.amazonaws.com")
            # Formato antigo: bucket.s3-region.amazonaws.com
            endpoints.append(f"https://{bucket}.s3-{region}.amazonaws.com")
        
        # Sempre tenta global também
        endpoints.append(f"https://{bucket}.s3.amazonaws.com")
        
        # Path-style (fallback)
        if region:
            endpoints.append(f"https://s3.{region}.amazonaws.com/{bucket}")
        endpoints.append(f"https://s3.amazonaws.com/{bucket}")

        last_error = None

        for base in endpoints:
            separator = "" if base.endswith(f"/{bucket}") else "/"
            base_url = f"{base}{separator}?list-type=2&max-keys=1000"

            try:
                continuation_token = None
                page = 0

                while len(files) < self.max_objects:
                    url = base_url
                    if continuation_token:
                        url += f"&continuation-token={quote(continuation_token, safe='')}"

                    r = self.session.get(url, timeout=self.timeout, verify=True)

                    # 403 -> existe mas não lista publicamente
                    if r.status_code in (403, 401):
                        return False, [], None

                    # 404 -> bucket pode não existir neste endpoint
                    if r.status_code == 404:
                        last_error = f"Bucket não encontrado (404) no endpoint {base}"
                        break

                    # 301/302 redirecionamentos com region header
                    if r.status_code in (301, 302, 307, 308):
                        reg = r.headers.get("x-amz-bucket-region")
                        if reg and reg != region:
                            return self._list_objects(bucket, reg)
                        break

                    if r.status_code != 200 or not r.text.strip().startswith("<"):
                        last_error = f"Resposta inesperada: HTTP {r.status_code} no endpoint {base}"
                        break

                    try:
                        root = ET.fromstring(r.text)
                        ns = ""
                        if root.tag.startswith("{"):
                            ns = root.tag.split("}")[0] + "}"

                        for c in root.findall(f".//{ns}Contents"):
                            if len(files) >= self.max_objects:
                                break
                            key_el = c.find(f"{ns}Key")
                            size_el = c.find(f"{ns}Size")
                            if key_el is None:
                                continue
                            key = (key_el.text or "").strip()
                            size = int(size_el.text) if (size_el is not None and (size_el.text or "").isdigit()) else 0
                            sev, reason = classify_severity(key)
                            object_url = f"{base}/{key}"
                            files.append({"key": key, "size": size, "severity": sev, "reason": reason, "url": object_url})

                        # Verifica paginação
                        is_truncated_el = root.find(f".//{ns}IsTruncated")
                        is_truncated = is_truncated_el is not None and (is_truncated_el.text or "").lower() == "true"

                        if not is_truncated:
                            return True, files, None

                        next_token_el = root.find(f".//{ns}NextContinuationToken")
                        if next_token_el is None or not next_token_el.text:
                            return True, files, None

                        continuation_token = next_token_el.text
                        page += 1

                    except Exception as e:
                        last_error = f"Falha ao parsear XML de listagem (página {page}): {e}"
                        break

                if files:
                    return True, files, None

            except Exception as e:
                last_error = f"Erro ao consultar endpoint {base}: {str(e)[:100]}"

        return False, [], last_error

    def run(self) -> Dict[str, Any]:
        bucket = self._parse_bucket()

        region = self._head_bucket_region(bucket)
        account_id = "-"  # sem credenciais, não dá para obter com segurança

        public_listing, files, list_error = self._list_objects(bucket, region)

        public_access = public_listing  # no modo sem credenciais, tratamos exposição prática como listagem pública
        summary = {
            "objects_scanned": len(files),
            "total_size_bytes": sum(int(f.get("size") or 0) for f in files),
        }

        payload: Dict[str, Any] = {
            "provider": "AWS_S3",
            "bucket": bucket,
            "region": region or "-",
            "account_id": account_id,
            "public_access": public_access,
            "public_listing": public_listing,
            "summary": summary,
            "files": files,
            "errors": [] if not list_error else [list_error],
        }

        # Score avançado + distribuição + recomendações
        payload.update(calculate_advanced_risk(payload))
        payload["severity_distribution"] = build_severity_distribution(payload["files"])
        payload["recommendations"] = build_recommendations(payload)

        return payload
