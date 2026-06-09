"""
OllamaService — integração com Ollama via API compatível com OpenAI.

Ollama expõe /v1/chat/completions igual à OpenAI, então reutilizamos o
SDK openai já instalado apontando para localhost:11434.
"""
import logging
from typing import List, Dict, Optional

from openai import OpenAI
from flask import current_app

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """\
Você é o SecuriBot, assistente especializado em segurança cibernética e vulnerabilidades CVE.

Responsabilidades:
1. Fornecer informações precisas sobre CVEs e vulnerabilidades
2. Explicar conceitos de segurança de forma clara e técnica
3. Sugerir medidas de mitigação e remediação
4. Analisar riscos e impactos de vulnerabilidades
5. Responder **sempre em português brasileiro**

Diretrizes:
- Seja preciso e técnico, mas acessível
- Use listas, títulos e blocos de código quando ajudar na leitura
- Quando citar CVEs, use o formato exato: CVE-AAAA-NNNNN
- Se não tiver certeza, admita e indique onde buscar informações confiáveis (NVD, CISA, vendor advisories)
- Mantenha tom profissional e objetivo
"""


class OllamaService:
    """
    Serviço de chat IA usando Ollama local.
    Usa a API OpenAI-compatible do Ollama (http://host:port/v1).
    """

    def __init__(self):
        self.base_url  = current_app.config.get('OLLAMA_BASE_URL', 'http://localhost:11434/v1')
        self.model     = current_app.config.get('OLLAMA_MODEL', 'gemma4:e4b')
        self.max_tokens = int(current_app.config.get('OLLAMA_MAX_TOKENS', 2048))
        self.temperature = float(current_app.config.get('OLLAMA_TEMPERATURE', 0.7))

        try:
            # api_key é obrigatório no SDK mas ignorado pelo Ollama
            self.client = OpenAI(base_url=self.base_url, api_key='ollama')
            logger.info(f"OllamaService iniciado — modelo: {self.model} @ {self.base_url}")
        except Exception as exc:
            logger.error(f"Falha ao inicializar OllamaService: {exc}")
            self.client = None

    # ── public ────────────────────────────────────────────────────────────

    def generate_chat_response(
        self,
        user_message: str,
        context: Optional[str] = None,
        conversation_history: Optional[List[Dict[str, str]]] = None,
    ) -> str:
        messages = self._build_messages(user_message, context, conversation_history)
        return self.generate_completion(messages)

    def generate_completion(
        self,
        messages: List[Dict[str, str]],
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        fallback_message: Optional[str] = None,
        fallback_context: Optional[str] = None,
    ) -> str:
        """Gera resposta a partir de mensagens no formato chat."""
        if not self.client:
            return "Ollama não está disponível no momento. Verifique se o servidor está em execução."

        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=max_tokens or self.max_tokens,
                temperature=self.temperature if temperature is None else temperature,
            )
            content = resp.choices[0].message.content
            logger.info(f"OllamaService: resposta gerada ({len(content)} chars)")
            return content
        except Exception as exc:
            logger.error(f"OllamaService erro na geração: {exc}")
            raise

    def generate_cve_summary(self, cve_data: Dict) -> str:
        """Gera resumo estruturado de uma CVE."""
        prompt = (
            f"Analise a vulnerabilidade abaixo e forneça um resumo estruturado em português.\n\n"
            f"CVE ID: {cve_data.get('cve_id', 'N/A')}\n"
            f"Descrição: {cve_data.get('description', 'N/A')}\n"
            f"Severidade: {cve_data.get('base_severity', 'N/A')}\n"
            f"CVSS Score: {cve_data.get('cvss_score', 'N/A')}\n"
            f"Publicado em: {cve_data.get('published_date', 'N/A')}\n\n"
            "Inclua: resumo, impacto, sistemas afetados, mitigação e prioridade de correção."
        )
        return self.generate_chat_response(prompt)

    def check_health(self) -> dict:
        """Verifica se o Ollama está acessível e retorna info do modelo."""
        if not self.client:
            return {'ok': False, 'error': 'client not initialized'}
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[{'role': 'user', 'content': 'ok'}],
                max_tokens=3,
            )
            return {'ok': True, 'model': self.model, 'base_url': self.base_url}
        except Exception as exc:
            return {'ok': False, 'error': str(exc)}

    # ── private ───────────────────────────────────────────────────────────

    def _build_messages(
        self,
        user_message: str,
        context: Optional[str],
        history: Optional[List[Dict[str, str]]],
    ) -> List[Dict[str, str]]:
        system = SYSTEM_PROMPT
        if context:
            system += f"\n\nContexto adicional:\n{context}"

        messages = [{'role': 'system', 'content': system}]

        if history:
            for msg in history[-10:]:
                messages.append({
                    'role': msg.get('role', 'user'),
                    'content': msg.get('content', ''),
                })

        messages.append({'role': 'user', 'content': user_message})
        return messages
