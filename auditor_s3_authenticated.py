# auditor_s3_authenticated.py
from __future__ import annotations

import boto3
import json
from typing import Any, Dict, List, Optional
from botocore.exceptions import ClientError, NoCredentialsError

from engine_risk import classify_severity, build_severity_distribution, calculate_advanced_risk, build_recommendations


class S3AuthenticatedAuditor:
    """
    Auditor S3 COM credenciais (AWS Access Keys):
      - Usa boto3 para listar objetos
      - Verifica ACLs do bucket
      - Verifica políticas do bucket
      - Classifica severidade dos arquivos
      - Calcula risk score avançado
    """

    def __init__(
        self,
        bucket_name: str,
        aws_access_key_id: str,
        aws_secret_access_key: str,
        aws_session_token: Optional[str] = None,
        region_name: Optional[str] = None,
        max_objects: int = 5000,
        timeout: int = 30
    ):
        self.bucket = bucket_name.strip()
        self.max_objects = max_objects
        self.timeout = timeout
        
        # Configurar cliente S3 com credenciais
        session_config = {
            'aws_access_key_id': aws_access_key_id,
            'aws_secret_access_key': aws_secret_access_key,
        }
        
        if aws_session_token:
            session_config['aws_session_token'] = aws_session_token
            
        if region_name:
            session_config['region_name'] = region_name
        
        try:
            self.s3_client = boto3.client('s3', **session_config)
        except Exception as e:
            raise ValueError(f"Erro ao configurar cliente S3: {e}")

    def _parse_bucket_name(self) -> str:
        """Extrai nome do bucket de diferentes formatos"""
        s = self.bucket.lower()
        
        # Remove protocolo se houver
        if "://" in s:
            s = s.split("://")[1]
        
        # Remove .s3.amazonaws.com e variações
        if ".s3.amazonaws.com" in s:
            return s.split(".s3.amazonaws.com")[0]
        if ".s3-" in s and ".amazonaws.com" in s:
            return s.split(".s3-")[0]
        if ".s3." in s and ".amazonaws.com" in s:
            return s.split(".s3.")[0]
        
        # Remove trailing slash
        return s.rstrip('/')

    def _detect_region(self, bucket_name: str) -> Optional[str]:
        """Detecta região do bucket"""
        try:
            response = self.s3_client.get_bucket_location(Bucket=bucket_name)
            location = response.get('LocationConstraint')
            # us-east-1 retorna None
            return location if location else 'us-east-1'
        except Exception:
            return None

    def _check_bucket_acl(self, bucket_name: str) -> Dict[str, Any]:
        """Verifica ACL do bucket"""
        try:
            acl = self.s3_client.get_bucket_acl(Bucket=bucket_name)
            
            public_read = False
            public_write = False
            
            for grant in acl.get('Grants', []):
                grantee = grant.get('Grantee', {})
                permission = grant.get('Permission', '')
                
                # Verifica se é público (AllUsers ou AuthenticatedUsers)
                grantee_uri = grantee.get('URI', '')
                if 'AllUsers' in grantee_uri:
                    if permission in ['READ', 'FULL_CONTROL']:
                        public_read = True
                    if permission in ['WRITE', 'FULL_CONTROL']:
                        public_write = True
                elif 'AuthenticatedUsers' in grantee_uri:
                    if permission in ['READ', 'FULL_CONTROL']:
                        public_read = True
            
            return {
                'public_read': public_read,
                'public_write': public_write,
                'grants': acl.get('Grants', [])
            }
        except ClientError as e:
            return {'error': str(e), 'public_read': False, 'public_write': False}

    def _check_bucket_policy(self, bucket_name: str) -> Dict[str, Any]:
        """Verifica política do bucket"""
        try:
            policy_response = self.s3_client.get_bucket_policy(Bucket=bucket_name)
            policy_str = policy_response.get('Policy', '{}')
            policy = json.loads(policy_str)
            
            public_access = False
            
            # Analisa statements da política
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal', {})
                effect = statement.get('Effect', '')
                
                # Verifica se permite acesso público
                if effect == 'Allow':
                    if principal == '*' or principal == {'AWS': '*'}:
                        public_access = True
                        break
            
            return {
                'has_policy': True,
                'public_access': public_access,
                'policy': policy
            }
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                return {'has_policy': False, 'public_access': False}
            return {'error': str(e), 'has_policy': False, 'public_access': False}

    def _list_objects(self, bucket_name: str) -> List[Dict[str, Any]]:
        """Lista objetos do bucket"""
        files = []
        
        try:
            paginator = self.s3_client.get_paginator('list_objects_v2')
            page_iterator = paginator.paginate(
                Bucket=bucket_name,
                PaginationConfig={'MaxItems': self.max_objects}
            )
            
            for page in page_iterator:
                for obj in page.get('Contents', []):
                    key = obj.get('Key', '')
                    size = obj.get('Size', 0)
                    
                    # Classifica severidade
                    severity, reason = classify_severity(key)
                    
                    files.append({
                        'key': key,
                        'size': size,
                        'severity': severity,
                        'reason': reason,
                        'last_modified': obj.get('LastModified').isoformat() if obj.get('LastModified') else None
                    })
                    
                    # Limita quantidade
                    if len(files) >= self.max_objects:
                        break
                
                if len(files) >= self.max_objects:
                    break
        
        except ClientError as e:
            raise Exception(f"Erro ao listar objetos: {e}")
        
        return files

    def run(self) -> Dict[str, Any]:
        """Executa auditoria completa do bucket"""
        errors = []
        
        # Parse bucket name
        bucket_name = self._parse_bucket_name()
        
        # Detecta região
        region = self._detect_region(bucket_name)
        
        # Verifica ACL
        acl_info = self._check_bucket_acl(bucket_name)
        if 'error' in acl_info:
            errors.append(f"Erro ao verificar ACL: {acl_info['error']}")
        
        # Verifica política
        policy_info = self._check_bucket_policy(bucket_name)
        if 'error' in policy_info:
            errors.append(f"Erro ao verificar política: {policy_info['error']}")
        
        # Lista objetos
        try:
            files = self._list_objects(bucket_name)
        except Exception as e:
            errors.append(str(e))
            files = []
        
        # Determina se há acesso público
        public_access = (
            acl_info.get('public_read', False) or 
            acl_info.get('public_write', False) or 
            policy_info.get('public_access', False)
        )
        
        # Monta summary
        summary = {
            'objects_scanned': len(files),
            'total_size_bytes': sum(f.get('size', 0) for f in files),
        }
        
        # Monta payload
        payload: Dict[str, Any] = {
            'provider': 'AWS_S3',
            'bucket': bucket_name,
            'region': region or '-',
            'account_id': '-',  # Pode ser obtido via STS se necessário
            'public_access': public_access,
            'public_listing': acl_info.get('public_read', False),
            'acl_info': acl_info,
            'policy_info': policy_info,
            'summary': summary,
            'files': files,
            'errors': errors,
        }
        
        # Calcula risk score e recomendações
        payload.update(calculate_advanced_risk(payload))
        payload['severity_distribution'] = build_severity_distribution(payload['files'])
        payload['recommendations'] = build_recommendations(payload)
        
        return payload