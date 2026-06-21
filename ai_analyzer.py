"""
ai_analyzer.py — Análise de scans de segurança usando Claude (Anthropic).
Não usa RAG: o scan JSON é passado diretamente como contexto ao modelo.
"""
from __future__ import annotations

import json
import os
from typing import Optional

import anthropic

MODEL   = "claude-sonnet-4-6"
SYSTEM  = (
    "Você é um especialista sênior em segurança cloud (CSPM) com profundo conhecimento em "
    "CIS Benchmarks, ISO 27001, NIST 800-53, AWS Well-Architected, GCP Security Foundations "
    "e Microsoft Cloud Security Benchmark. "
    "Responda sempre em português. Seja técnico, direto e orientado a ação."
)


def _client() -> anthropic.Anthropic:
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        raise RuntimeError("ANTHROPIC_API_KEY não configurada no ambiente.")
    return anthropic.Anthropic(api_key=key)


def _scan_summary(scan: dict) -> dict:
    """Extrai campos relevantes para reduzir tokens."""
    r = scan.get("result", scan)
    return {
        "provider":              r.get("provider", "?"),
        "target":                r.get("bucket") or r.get("target") or r.get("account_id", "?"),
        "timestamp":             scan.get("timestamp", r.get("generated_at", "?")),
        "total_findings":        len(r.get("files", [])),
        "severity_distribution": r.get("severity_distribution", {}),
        "risk_score":            r.get("risk_score", 0),
        "summary":               r.get("summary", {}),
        "top_findings":          r.get("files", [])[:15],
    }


def analyze(scan: dict) -> str:
    """
    Análise executiva do scan atual.
    Retorna texto Markdown com avaliação, prioridades e timeline.
    """
    summary = _scan_summary(scan)
    provider = summary["provider"]
    total    = summary["total_findings"]
    sd       = summary["severity_distribution"]

    prompt = f"""Analise este resultado de scan de segurança cloud e forneça uma análise executiva completa.

**Provider:** {provider}
**Alvo:** {summary['target']}
**Total de findings:** {total}
**Severidade:** CRÍTICO={sd.get('critical',0)} | ALTO={sd.get('high',0)} | MÉDIO={sd.get('medium',0)} | BAIXO={sd.get('low',0)}
**Risk Score:** {summary['risk_score']}/100

**Summary do scan:**
{json.dumps(summary['summary'], indent=2, default=str, ensure_ascii=False)}

**Top findings:**
{json.dumps(summary['top_findings'], indent=2, default=str, ensure_ascii=False)}

---
Forneça:

## 1. Avaliação Executiva
(Estado geral da postura de segurança — 2 a 3 parágrafos)

## 2. Top 5 Ações Prioritárias
(Ordenadas por risco, com comandos específicos quando possível)

## 3. Timeline de Remediação
- **0–24 horas:** ações críticas
- **7 dias:** ações de alto risco
- **30 dias:** melhorias estruturais

## 4. Impacto em Conformidade
(CIS Benchmark, ISO 27001, NIST 800-53 — o que está sendo violado)
"""

    resp = _client().messages.create(
        model=MODEL,
        max_tokens=2500,
        system=SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text


def compare(current: dict, history: list[dict]) -> str:
    """
    Compara o scan atual com scans anteriores.
    Identifica novos findings, findings remediados e tendência.
    """
    if not history:
        return "Sem histórico disponível para comparação. Realize mais scans ao longo do tempo."

    current_summary  = _scan_summary(current)
    history_summaries = [_scan_summary(h) for h in history]

    prompt = f"""Compare a postura de segurança entre o scan atual e os scans anteriores.

**SCAN ATUAL ({current_summary['timestamp']}):**
{json.dumps(current_summary, indent=2, default=str, ensure_ascii=False)}

**HISTÓRICO ({len(history_summaries)} scan(s) anterior(es)):**
{json.dumps(history_summaries, indent=2, default=str, ensure_ascii=False)}

---
Forneça:

## 1. Evolução da Postura
(Melhorou, piorou ou estável? Com números concretos)

## 2. Novos Findings
(Findings que apareceram no scan atual e não existiam antes)

## 3. Findings Remediados
(Findings que existiam antes e não aparecem mais — positivo!)

## 4. Tendência
(Se continuar assim, qual o risco estimado em 30 dias?)

## 5. Próximos Passos
(Ações baseadas na tendência observada)
"""

    resp = _client().messages.create(
        model=MODEL,
        max_tokens=2000,
        system=SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text


def ask(question: str, scan: dict, history: Optional[list[dict]] = None) -> str:
    """
    Responde uma pergunta livre sobre o scan e/ou histórico.
    Ex: 'Qual finding é mais urgente?' ou 'Quais usuários estão sem MFA?'
    """
    current_summary = _scan_summary(scan)

    context = f"**Scan atual:**\n{json.dumps(current_summary, indent=2, default=str, ensure_ascii=False)}"

    if history:
        hist_summaries = [_scan_summary(h) for h in history[:3]]
        context += f"\n\n**Histórico ({len(hist_summaries)} scan(s)):**\n{json.dumps(hist_summaries, indent=2, default=str, ensure_ascii=False)}"

    prompt = f"""{context}

---
**Pergunta:** {question}"""

    resp = _client().messages.create(
        model=MODEL,
        max_tokens=1500,
        system=SYSTEM,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text
