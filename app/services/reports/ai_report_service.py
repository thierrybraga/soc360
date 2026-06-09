"""
AIReportService — geração de relatórios completos via IA.

Cada tipo de relatório (EXECUTIVE, TECHNICAL, RISK_ASSESSMENT, COMPLIANCE,
TREND, INCIDENT) usa UM prompt completo e específico para seu público-alvo.
O retorno do LLM (markdown) compõe todo o corpo do relatório e é armazenado
em ``Report.ai_summary``. Recomendações estruturadas vão para
``Report.ai_recommendations``.
"""
import json
import logging
import re
from typing import Dict, List, Optional
from openai import APIConnectionError, APIError, APITimeoutError, AuthenticationError, RateLimitError

from app.services.core.ai_service import get_ai_service

logger = logging.getLogger(__name__)


# ──────────────────────────────────────────────────────────────────────────
# System prompt (compartilhado, define persona e padrão de saída)
# ──────────────────────────────────────────────────────────────────────────
SYSTEM_PROMPT = """\
Você é um analista sênior de segurança cibernética da SOC360, especializado \
em geração de relatórios corporativos de vulnerabilidades. Produza sempre conteúdo:

- Em **português brasileiro**, tom profissional, objetivo e técnico-executivo
- Em **Markdown** bem formatado (títulos, listas, tabelas, blocos de código quando útil)
- Baseado **exclusivamente** nos dados fornecidos — nunca invente CVEs, ativos, números ou fatos
- **Sempre relacione CVEs aos ativos afetados** quando essa informação for fornecida
- Quando um dado estiver ausente, indique explicitamente: *Não informado* ou *Não aplicável*
- Quando o inventário estiver vazio, diga claramente que não há ativos cadastrados e oriente o cadastro
- Usando o formato oficial `CVE-AAAA-NNNNN` ao citar vulnerabilidades
- Com foco em **ações acionáveis** e priorização baseada em risco
"""


# ──────────────────────────────────────────────────────────────────────────
# Helpers compartilhados entre prompts
# ──────────────────────────────────────────────────────────────────────────

def _format_assets_overview(data: Dict) -> str:
    """Formata o resumo do inventário para injetar no prompt."""
    total_assets = data.get('total_assets', 0)
    assets_with_vulns = data.get('assets_with_vulns', 0)
    if total_assets == 0:
        return "**Inventario vazio** - nenhum ativo cadastrado para este usuario. Oriente o cadastro de ativos antes de relatorios acionaveis.\n"
    overview = data.get('assets_overview') or []
    lines = [
        f"- Total de ativos cadastrados: **{total_assets}**",
        f"- Ativos com vulnerabilidades associadas: **{assets_with_vulns}**",
    ]
    if overview:
        lines.append("")
        lines.append("**Amostra do inventario (ate 20 ativos):**")
        for a in overview[:20]:
            lines.append(
                f"- `{a.get('name')}` (crit={a.get('criticality')}, "
                f"env={a.get('environment')}, exp={a.get('exposure')}) "
                f"- {a.get('vulnerabilities')} vulnerabilidades"
            )
    return "\n".join(lines) + "\n"


def _format_affected_assets(cve_record: Dict, max_items: int = 5) -> str:
    """Linha compacta listando ativos afetados por uma CVE."""
    affected = cve_record.get('affected_assets') or []
    if not affected:
        return ""
    names = [a.get('asset_name', '?') for a in affected[:max_items]]
    suffix = f" (+{len(affected) - max_items})" if len(affected) > max_items else ""
    return f" | Ativos afetados: {', '.join(names)}{suffix}"


# ──────────────────────────────────────────────────────────────────────────
# Prompts específicos por tipo de relatório
# ──────────────────────────────────────────────────────────────────────────

def _prompt_executive(data: Dict, period_days: int) -> str:
    critical_list = "\n".join(
        f"- **{c.get('cve_id')}** (CVSS {c.get('cvss_score')}): {c.get('description','')[:180]}{_format_affected_assets(c)}"
        for c in (data.get('critical_recent') or [])
    ) or "*Nenhuma CVE crítica no periodo que afete o inventario.*"

    by_sev = data.get('by_severity') or {}
    by_sev_period = data.get('by_severity_period') or {}
    inventory_block = _format_assets_overview(data)

    return f"""\
Gere um **Relatório Executivo de Vulnerabilidades** completo para a alta liderança \
(C-level, diretoria de tecnologia e risco). A audiência **não é técnica** — priorize \
impacto de negócio, tendências, risco reputacional e decisões de investimento.

**Escopo:** o relatório cobre exclusivamente os **ativos cadastrados deste usuário** e \
as CVEs associadas a eles via inventário.

## Inventário analisado
{inventory_block}

## Contexto do período analisado
- Janela de análise: últimos **{period_days} dias**
- Total de CVEs afetando o inventário: **{data.get('total_cves', 0)}**
- CVEs publicadas no período afetando o inventário: **{data.get('recent_cves', 0)}**
- CVEs no catálogo CISA KEV (exploração ativa conhecida): **{data.get('cisa_kev', 0)}**

### Distribuição total por severidade
- Crítica: {by_sev.get('CRITICAL', 0)}
- Alta: {by_sev.get('HIGH', 0)}
- Média: {by_sev.get('MEDIUM', 0)}
- Baixa: {by_sev.get('LOW', 0)}

### Distribuição no período
- Crítica: {by_sev_period.get('CRITICAL', 0)}
- Alta: {by_sev_period.get('HIGH', 0)}
- Média: {by_sev_period.get('MEDIUM', 0)}
- Baixa: {by_sev_period.get('LOW', 0)}

### Top 5 CVEs críticas recentes
{critical_list}

---

## Estrutura obrigatória do relatório (use exatamente estes títulos H2)

## Sumário Executivo
Parágrafo denso (4–6 linhas) respondendo: qual o cenário atual, qual a variação no \
período, o que demanda atenção imediata da liderança.

## Principais Achados
Lista de 4–6 bullets com os fatos mais relevantes e sua implicação de negócio.

## Indicadores-Chave
Tabela Markdown com as métricas principais (total, período, CRÍTICAS, CISA KEV, \
variação) e uma coluna “Interpretação” de uma frase por linha.

## Top Riscos Identificados
Para cada CVE crítica listada: nome, por que importa (impacto de negócio), \
urgência sugerida. Máximo 5 itens.

## Recomendações Estratégicas
3–5 recomendações **priorizadas** (alta/média/baixa), cada uma com objetivo, \
ação macro e prazo sugerido.

## Conclusão
Parágrafo fechando com mensagem clara para a liderança: status geral, risco \
residual e próximo marco de reavaliação.
"""


def _prompt_technical(data: Dict, period_days: int) -> str:
    exploit_list = "\n".join(
        f"- **{e.get('cve_id')}** | CVSS {e.get('cvss_score')} | {e.get('base_severity')} "
        f"| patch={e.get('patch_available')} | KEV={e.get('is_in_cisa_kev')}\n  "
        f"{e.get('description','')[:200]}{_format_affected_assets(e)}"
        for e in (data.get('exploitable_top') or [])
    ) or "*Nenhuma CVE exploravel identificada afetando o inventario no periodo.*"

    total = data.get('period_cves', 0)
    with_exploit = data.get('with_exploit', 0)
    with_patch = data.get('with_patch', 0)
    exploit_rate = f"{(with_exploit / total * 100):.1f}%" if total else "0%"
    patch_rate = f"{(with_patch / total * 100):.1f}%" if total else "0%"
    inventory_block = _format_assets_overview(data)

    return f"""\
Gere um **Relatório Técnico de Vulnerabilidades** completo para equipes de \
segurança ofensiva, blue team e engenharia. Audiência **técnica** — pode e \
deve incluir detalhes de exploitabilidade, vetores, CWEs, mitigações táticas.

**Escopo:** apenas as CVEs associadas aos **ativos cadastrados deste usuário**.

## Inventário analisado
{inventory_block}

## Dados do período
- Janela: últimos **{period_days} dias**
- CVEs do inventário publicadas no período: **{total}**
- CVEs com exploit público: **{with_exploit}** ({exploit_rate})
- CVEs com patch disponível: **{with_patch}** ({patch_rate})
- CVEs no CISA KEV: **{data.get('cisa_kev', 0)}**

### Top 10 CVEs exploráveis (CRÍTICA/ALTA com exploit disponível)
{exploit_list}

---

## Estrutura obrigatória do relatório (use exatamente estes títulos H2)

## Visão Geral Técnica
Parágrafo com panorama do período: volume, concentração por severidade, \
proporção explorável vs. sem correção disponível.

## Análise de Exploitabilidade
- Discussão da janela de exposição (CVEs com exploit mas sem patch)
- Padrões observados nos vetores de ataque mais comuns
- Indicadores que sugerem campanhas ativas (CISA KEV, CVSS alto + exploit)

## CVEs Prioritárias para Ação
Tabela Markdown com colunas: **CVE**, **CVSS**, **Severidade**, **Vetor provável**, \
**Ação imediata** — cubra as 5 a 10 CVEs mais relevantes da lista fornecida.

## Recomendações Técnicas
Agrupadas em:
- **Patch Management** (passos práticos para as CVEs com patch)
- **Mitigações compensatórias** (WAF rules, segmentação, disable features)
- **Detecção & Monitoramento** (SIEM queries, IOCs, behaviors a observar)

## Plano de Remediação
Lista ordenada com 5–8 passos executáveis em sequência, com responsável sugerido \
(ex.: SecOps, DevOps, NetEng) e prazo realista.

## Referências Técnicas
Links para NVD, CISA KEV, vendor advisories e base de conhecimento interna.
"""


def _prompt_risk_assessment(data: Dict, period_days: int) -> str:
    high_risk = data.get('high_risk_assets') or []
    scored = data.get('scored_assets') or []
    assets_list = "\n".join(
        f"- **{a.get('name')}** (crit={a.get('criticality')}, env={a.get('environment')}, "
        f"exp={a.get('exposure')}) — score **{a.get('risk_score')}** | max CVSS {a.get('max_cvss')} "
        f"| {a.get('vulnerabilities')} vulnerabilidades"
        for a in high_risk
    ) or "*Nenhum ativo classificado como alto risco.*"

    # tabela compacta de todos os ativos scored (top 15) para o LLM usar
    ranking_list = "\n".join(
        f"| {a.get('name')} | {a.get('risk_score')} | {a.get('max_cvss')} | {a.get('vulnerabilities')} | {a.get('criticality')} | {a.get('environment')} |"
        for a in scored[:15]
    )

    total = data.get('total_assets', 0)
    with_vulns = data.get('assets_with_vulns', 0)
    coverage = f"{(with_vulns / total * 100):.1f}%" if total else "0%"

    return f"""\
Gere uma **Avaliação de Risco de Ativos** completa para o CISO e gestores de \
risco. Foco: exposição por ativo, priorização de mitigação e aceitação de risco.

## Inventário avaliado
- Total de ativos cadastrados: **{total}**
- Ativos com vulnerabilidades: **{with_vulns}** ({coverage} do inventário)
- Ativos classificados como ALTO RISCO (score > 7.0): **{len(high_risk)}**

### Ativos de alto risco (score > 7.0)
{assets_list}

### Ranking dos ativos por score de risco (top 15)
| Ativo | Score | Max CVSS | # Vulns | Criticidade | Ambiente |
| --- | --- | --- | --- | --- | --- |
{ranking_list or '| - | - | - | - | - | - |'}

---

## Estrutura obrigatória do relatório (use exatamente estes títulos H2)

## Resumo da Postura de Risco
Parágrafo com visão geral: cobertura do inventário, concentração de risco, \
principais vetores de exposição.

## Ranking de Ativos Críticos
Tabela Markdown: **Ativo**, **Score**, **# Vulnerabilidades**, **Nível de Risco** \
(Crítico/Alto/Médio), **Ação Recomendada**.

## Análise dos Fatores de Risco
Discuta os principais drivers que elevam o score:
- Severidade média das vulnerabilidades
- Exposição externa (se inferível dos dados)
- Criticidade de negócio dos ativos afetados

## Matriz de Priorização
Agrupe os ativos em 3 faixas de ação:
- **Ação imediata (≤ 7 dias)**
- **Ação de curto prazo (≤ 30 dias)**
- **Monitoramento contínuo**
Para cada faixa, liste os ativos e justifique a classificação.

## Recomendações de Mitigação
5–7 recomendações acionáveis, cada uma amarrada a um conjunto de ativos e com \
critério objetivo de sucesso (ex.: “score < 5.0 em 30 dias”).

## Considerações para Aceitação de Risco
Ativos onde a correção é inviável no curto prazo: quais compensações mínimas \
são aceitáveis, quem deve aprovar, periodicidade de reavaliação.
"""


def _prompt_compliance(data: Dict, period_days: int) -> str:
    total = (data.get('total_open', 0) + data.get('total_mitigated', 0)
             + data.get('total_accepted', 0) + data.get('total_resolved', 0))
    by_sev = data.get('by_severity') or {}
    inventory_block = _format_assets_overview(data)

    # lista de CVEs em aberto com ativos afetados para dar contexto à auditoria
    open_cves = data.get('open_cves_sample') or []
    open_cves_list = "\n".join(
        f"- **{c.get('cve_id')}** | CVSS {c.get('cvss_score')} | {c.get('base_severity')} "
        f"| status={c.get('status','OPEN')}{_format_affected_assets(c)}"
        for c in open_cves[:10]
    ) or "*Nenhuma pendência destacada.*"

    return f"""\
Gere um **Relatório de Conformidade e Remediação** para auditoria interna, \
GRC (Governança, Risco e Conformidade) e apresentação a frameworks como \
ISO 27001, NIST CSF e CIS Controls.

**Escopo:** exclusivamente os **ativos cadastrados deste usuário** e suas CVEs associadas.

## Inventário sob gestão
{inventory_block}

## Dados de conformidade
- Total de itens sob gestão: **{total}**
- Em aberto (OPEN): **{data.get('total_open', 0)}**
- Mitigadas (MITIGATED): **{data.get('total_mitigated', 0)}**
- Aceitas (ACCEPTED): **{data.get('total_accepted', 0)}**
- Resolvidas (RESOLVED): **{data.get('total_resolved', 0)}**
- **Taxa de remediação: {data.get('remediation_rate_pct', 0)}%**

### Top pendências em aberto (com ativos afetados)
{open_cves_list}

### Distribuição total por severidade
- Crítica: {by_sev.get('CRITICAL', 0)}
- Alta: {by_sev.get('HIGH', 0)}
- Média: {by_sev.get('MEDIUM', 0)}
- Baixa: {by_sev.get('LOW', 0)}

---

## Estrutura obrigatória do relatório (use exatamente estes títulos H2)

## Sumário de Conformidade
Parágrafo com status geral: taxa de remediação vs. meta esperada (≥ 85% para \
CRÍTICA/ALTA é referência típica), pendências relevantes.

## Indicadores de Remediação
Tabela Markdown com: **Status**, **Quantidade**, **% do total**, **Observação**.

## Aderência a Frameworks
Para cada framework abaixo, comente o que os dados evidenciam:
- **ISO/IEC 27001 — A.12.6.1** (Gestão de vulnerabilidades técnicas)
- **NIST CSF — ID.RA, PR.IP-12, DE.CM-8**
- **CIS Controls — Control 7** (Continuous Vulnerability Management)

## Lacunas Identificadas
Liste as 3–5 principais lacunas de conformidade observáveis nos dados e seu \
impacto para auditorias e certificações.

## Plano de Ação Corretiva
Lista numerada de ações com: objetivo, responsável sugerido, prazo, indicador \
de sucesso mensurável.

## Evidências e Próximos Passos
Como usar este relatório em auditoria, cadência recomendada de reavaliação, \
artefatos a manter arquivados.
"""


def _prompt_trend(data: Dict, period_days: int) -> str:
    timeline = data.get('timeline') or {}
    # serializar timeline como tabela para o prompt
    months = sorted(timeline.keys())
    timeline_lines = []
    for m in months:
        sevs = timeline[m]
        timeline_lines.append(
            f"- **{m}** → CRITICAL: {sevs.get('CRITICAL', 0)} | "
            f"HIGH: {sevs.get('HIGH', 0)} | MEDIUM: {sevs.get('MEDIUM', 0)} | "
            f"LOW: {sevs.get('LOW', 0)}"
        )
    timeline_block = "\n".join(timeline_lines) or "*Sem dados no período.*"
    by_sev = data.get('by_severity') or {}
    inventory_block = _format_assets_overview(data)

    return f"""\
Gere um **Relatório de Análise de Tendências** para o time de threat intelligence \
e liderança de segurança. Foco: identificar padrões temporais, projeções e \
antecipação de riscos.

**Escopo:** tendências observadas nas CVEs associadas aos **ativos cadastrados deste usuário**.

## Inventário analisado
{inventory_block}

## Dados temporais (últimos {period_days} dias)
- Total de CVEs no período afetando o inventário: **{data.get('total_period', 0)}**

### Distribuição do período por severidade
- Crítica: {by_sev.get('CRITICAL', 0)}
- Alta: {by_sev.get('HIGH', 0)}
- Média: {by_sev.get('MEDIUM', 0)}
- Baixa: {by_sev.get('LOW', 0)}

### Linha do tempo mensal
{timeline_block}

---

## Estrutura obrigatória do relatório (use exatamente estes títulos H2)

## Panorama do Período
Parágrafo resumindo o comportamento geral: volume, aceleração/desaceleração, \
concentração de severidades.

## Análise da Linha do Tempo
- Identifique picos e vales mensais
- Compare meses consecutivos (variação % quando relevante)
- Destaque qualquer mudança de padrão na distribuição de severidades

## Padrões Detectados
Bullets com 3–5 padrões observáveis (ex.: “crescimento constante de CRITICAL”, \
“queda abrupta em HIGH sugere…”, etc.). Cada padrão com uma hipótese plausível.

## Projeção para o Próximo Ciclo
Com base nos dados históricos, projete qualitativamente o que esperar nos \
próximos 30–60 dias e quais condições poderiam validar ou invalidar a projeção.

## Recomendações Proativas
3–5 ações preparatórias alinhadas às tendências detectadas (ex.: reforço de \
capacidade de patching antes de um pico esperado).

## Métricas para Acompanhamento
Lista de 4–6 KPIs objetivos que a organização deve monitorar ciclo a ciclo \
para validar ou ajustar esta análise.
"""


def _prompt_incident(data: Dict, period_days: int) -> str:
    cves = data.get('incident_cves') or []
    cves_list = "\n".join(
        f"- **{c.get('cve_id')}** | CVSS {c.get('cvss_score')} | {c.get('base_severity')} "
        f"| KEV: {c.get('is_in_cisa_kev')} | Exploit: {c.get('exploit_available')}\n  "
        f"{c.get('description','')[:220]}{_format_affected_assets(c)}"
        for c in cves[:15]
    ) or "*Sem CVEs elegíveis para resposta a incidente no período.*"
    inventory_block = _format_assets_overview(data)

    return f"""\
Gere um **Relatório de Resposta a Incidente** (IR briefing) para o time de \
SOC/CSIRT. Foco: consolidar o contexto de ameaças ativas e orientar resposta \
tática imediata.

**Escopo:** CVEs recentes de severidade CRÍTICA/ALTA associadas aos \
**ativos cadastrados deste usuário**.

## Inventário afetado
{inventory_block}

## Escopo do incidente
- Janela analisada: últimos **{period_days} dias**
- CVEs CRÍTICA/ALTA recentes avaliadas: **{data.get('total_incident_cves', 0)}**
- CRÍTICAS: **{data.get('critical_count', 0)}** | ALTAS: **{data.get('high_count', 0)}**

### CVEs priorizadas (top 15)
{cves_list}

---

## Estrutura obrigatória do relatório (use exatamente estes títulos H2)

## Situação Atual
Parágrafo denso descrevendo o quadro de ameaças: quantas CVEs são de \
exploração ativa conhecida, concentração de severidades, nível de urgência.

## CVEs Alvo
Tabela Markdown com colunas: **CVE**, **CVSS**, **KEV?**, **Exploit?**, \
**Ativos Afetados**, **Ação de contenção inicial**. Priorize CVEs com `KEV=True` ou `Exploit=True` \
e ative primeiro ativos `PRODUCTION`/`CRITICAL`.

## Indicadores de Comprometimento (IOCs)
Para as principais CVEs da tabela, sugira categorias de IOCs a monitorar \
(com base no que é inferível da descrição): user-agents suspeitos, paths, \
portas, hashes, TTPs do MITRE ATT&CK quando aplicável. Se não houver \
informação suficiente, declare “IOCs específicos não disponíveis na base — \
coletar via vendor advisory”.

## Plano de Resposta Imediato
Lista numerada com ações nas primeiras **24 horas**:
1. Contenção (bloqueios, isolamento)
2. Erradicação (patch, hardening)
3. Recuperação (validação, monitoramento)
4. Comunicação (quem notificar, cadência)

## Plano de 7 Dias
Ações de médio prazo após contenção: hardening estrutural, revisão de \
políticas, threat hunting retroativo.

## Lições e Ajustes
Recomendações de 3–5 ajustes ao programa de segurança baseados no que este \
incidente evidencia (ex.: encurtar SLA de patching para CISA KEV).
"""


# ──────────────────────────────────────────────────────────────────────────
# Mapa tipo → construtor de prompt
# ──────────────────────────────────────────────────────────────────────────
_PROMPT_BUILDERS = {
    'EXECUTIVE': _prompt_executive,
    'TECHNICAL': _prompt_technical,
    'RISK_ASSESSMENT': _prompt_risk_assessment,
    'COMPLIANCE': _prompt_compliance,
    'TREND': _prompt_trend,
    'INCIDENT': _prompt_incident,
}


# ──────────────────────────────────────────────────────────────────────────
# Service
# ──────────────────────────────────────────────────────────────────────────
class AIReportService:
    """Orquestra a geração de relatórios via IA."""

    def __init__(self):
        self.service = get_ai_service()
        self.model = getattr(self.service, 'model', 'unknown')

    def generate(self, report_type: str, data: Dict, period_days: int = 30) -> Dict:
        """
        Gera o relatório completo para o tipo informado.

        Retorna dict com:
            - markdown: texto markdown completo (vai para ai_summary)
            - recommendations: lista de recomendações extraídas (ai_recommendations)
            - model: modelo usado
        """
        report_type = (report_type or '').upper().strip()
        builder = _PROMPT_BUILDERS.get(report_type)
        if not builder:
            raise ValueError(f"Tipo de relatório não suportado: {report_type}")

        user_prompt = builder(data or {}, period_days)

        # monta mensagens com system prompt + user prompt
        messages = [
            {'role': 'system', 'content': SYSTEM_PROMPT},
            {'role': 'user', 'content': user_prompt},
        ]

        max_tokens = int(getattr(self.service, 'max_tokens', 2048))
        # relatórios precisam de mais espaço que uma resposta de chat
        max_tokens = max(max_tokens, 3000)
        temperature = float(getattr(self.service, 'temperature', 0.5))

        logger.info(
            "AIReportService: gerando %s com modelo %s (max_tokens=%d)",
            report_type, self.model, max_tokens
        )

        try:
            if hasattr(self.service, 'generate_completion'):
                markdown = self.service.generate_completion(
                    messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    fallback_message=user_prompt,
                )
            else:
                client = getattr(self.service, 'client', None)
                if not client:
                    raise RuntimeError("Cliente de IA indisponível")
                resp = client.chat.completions.create(
                    model=self.model,
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                markdown = (resp.choices[0].message.content or '').strip()
        except AuthenticationError as exc:
            raise RuntimeError("Falha de autenticação no provedor de IA") from exc
        except RateLimitError as exc:
            raise RuntimeError("Limite de requisições do provedor de IA atingido") from exc
        except APITimeoutError as exc:
            raise RuntimeError("Timeout na geração de relatório via IA") from exc
        except APIConnectionError as exc:
            raise RuntimeError("Erro de rede ao conectar com o provedor de IA") from exc
        except APIError as exc:
            status = getattr(exc, 'status_code', 'desconhecido')
            raise RuntimeError(f"Erro interno da API de IA ({status})") from exc

        markdown = (markdown or '').strip()
        if not markdown:
            raise RuntimeError("Provedor de IA retornou resposta vazia para o relatório")
        markdown = self._strip_code_fences(markdown)

        recommendations = self._extract_recommendations(markdown)

        logger.info(
            "AIReportService: %s gerado (%d chars, %d recomendações)",
            report_type, len(markdown), len(recommendations)
        )

        return {
            'markdown': markdown,
            'recommendations': recommendations,
            'model': self.model,
        }

    # ── helpers ───────────────────────────────────────────────────────────

    @staticmethod
    def _strip_code_fences(text: str) -> str:
        """Remove cercas ```markdown …``` que alguns LLMs envolvem a resposta."""
        return re.sub(r"^```(?:markdown)?\s*\n?([\s\S]*?)\n?```\s*$", r"\1", text.strip())

    @staticmethod
    def _extract_recommendations(markdown: str) -> List[Dict]:
        """
        Extrai itens das seções de recomendação do markdown.

        Procura blocos sob títulos como "Recomendações", "Plano de Ação", etc.,
        aceitando múltiplos estilos de cabeçalho (## H2, **bold**, setext ===).
        """
        rec_headers = [
            r'Recomendações Estratégicas',
            r'Recomendações Técnicas',
            r'Recomendações de Mitigação',
            r'Recomendações Proativas',
            r'Plano de Ação Corretiva',
            r'Plano de Remediação',
            r'Plano de Resposta Imediato',
            r'Recomendações',
        ]
        header_alt = '|'.join(rec_headers)
        # Aceita: "## Header", "**Header**", "Header\n---" ou "Header\n==="
        section_start = re.compile(
            rf'^(?:'
            rf'#{{1,6}}\s+(?:{header_alt})\s*:?\s*$'
            rf'|\*\*(?:{header_alt})\*\*\s*:?\s*$'
            rf'|(?:{header_alt})\s*\n[-=]{{3,}}\s*$'
            rf')',
            re.MULTILINE | re.IGNORECASE
        )
        # delimitador de fim: próximo heading/bold-heading/setext ou EOF
        section_end = re.compile(
            r'^(?:#{1,6}\s+\S|\*\*[^*\n]{3,80}\*\*\s*:?\s*$|\S[^\n]*\n[-=]{3,}\s*$)',
            re.MULTILINE
        )

        recommendations: List[Dict] = []
        for m in section_start.finditer(markdown):
            start = m.end()
            tail = markdown[start:]
            nxt = section_end.search(tail)
            section = tail[:nxt.start()] if nxt else tail
            # bullets: "- foo" ou "* foo" ou "1. foo"
            items = re.findall(
                r'^\s*(?:[-*]|\d+\.)\s+(.+?)(?=\n\s*(?:[-*]|\d+\.)|\n\s*\n|\Z)',
                section,
                re.MULTILINE | re.DOTALL,
            )
            for raw in items:
                text = re.sub(r'\s+', ' ', raw).strip()
                if not text:
                    continue
                priority = AIReportService._infer_priority(text)
                title = text.split('.')[0][:120]
                recommendations.append({
                    'title': title,
                    'description': text,
                    'priority': priority,
                })

        # dedup mantendo ordem
        seen = set()
        unique: List[Dict] = []
        for r in recommendations:
            key = r['title'].lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(r)
        return unique[:20]  # cap razoável

    @staticmethod
    def _infer_priority(text: str) -> str:
        low = text.lower()
        if any(k in low for k in ['imediat', 'crítica', 'critico', 'urgente', 'alta priorid', '≤ 7 dias', 'alta']):
            return 'HIGH'
        if any(k in low for k in ['média', 'medio', 'curto prazo', '≤ 30 dias']):
            return 'MEDIUM'
        return 'LOW'


def generate_ai_report(report_type: str, data: Dict, period_days: int = 30) -> Dict:
    """Função utilitária — conveniência para uso do controller."""
    return AIReportService().generate(report_type, data, period_days)
