import os
import json
import urllib.request
import urllib.error
from typing import Optional, Dict, Any
from ..core.models import Incident


class DiagnosticEngine:
    """
    AI-powered Root Cause Analysis and Code Patch Generator.
    Supports Google Gemini API, OpenAI-compatible APIs, and an intelligent
    built-in offline heuristic engine for zero-dependency instant diagnosis.
    """

    def __init__(self, api_key: Optional[str] = None, provider: str = "auto"):
        self.api_key = api_key or os.getenv("GEMINI_API_KEY") or os.getenv("OPENAI_API_KEY")
        self.provider = provider

    def diagnose(self, incident: Incident) -> Dict[str, str]:
        """
        Diagnoses the incident and returns a dictionary with:
        - root_cause: Explanation of the bug
        - impact: Business/System impact
        - recommendation: Step-by-step mitigation
        - code_patch: Suggested code fix (diff format)
        """
        # If API key is available, attempt LLM diagnosis
        if self.api_key:
            try:
                if "gemini" in self.provider.lower() or os.getenv("GEMINI_API_KEY"):
                    return self._diagnose_with_gemini(incident)
                else:
                    return self._diagnose_with_openai(incident)
            except Exception as e:
                # Graceful fallback to offline engine if network or quota issue occurs
                offline_res = self._diagnose_offline(incident)
                offline_res["note"] = f"(Online AI unavailable: {e}. Showing offline heuristic diagnosis)"
                return offline_res

        return self._diagnose_offline(incident)

    def _diagnose_with_gemini(self, incident: Incident) -> Dict[str, str]:
        """Calls Google Gemini API via lightweight urllib (no external heavy SDK needed)."""
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}"

        prompt = f"""You are an elite Staff Site Reliability Engineer and Senior Software Engineer.
Analyze this production crash and return ONLY a valid JSON object.

INCIDENT DETAILS:
- Fingerprint: {incident.fingerprint}
- Error Type: {incident.error_type}
- Message: {incident.sample_message}
- Affected File: {incident.affected_file} (Line {incident.affected_line})
- Stacktrace:
{incident.sample_stacktrace or 'No stacktrace provided'}

Respond strictly with this JSON structure:
{{
  "root_cause": "Clear 2-3 sentence technical explanation of why this happens.",
  "impact": "Severity and potential blast radius for users/system.",
  "recommendation": "Bullet points with actionable mitigation.",
  "code_patch": "```diff\\n--- original\\n+++ fixed\\n...```"
}}
"""
        req_data = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"}
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(req_data).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )

        with urllib.request.urlopen(req, timeout=12) as response:
            result = json.loads(response.read().decode("utf-8"))
            raw_text = result["candidates"][0]["content"]["parts"][0]["text"]
            return json.loads(raw_text)

    def _diagnose_with_openai(self, incident: Incident) -> Dict[str, str]:
        """Calls OpenAI-compatible endpoint via standard urllib."""
        url = "https://api.openai.com/v1/chat/completions"
        prompt = f"Analyze incident {incident.error_type}: {incident.sample_message}\nStacktrace:\n{incident.sample_stacktrace}"
        
        req_data = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "You are a senior engineer. Return JSON with root_cause, impact, recommendation, code_patch."},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_object"}
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(req_data).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}"
            }
        )

        with urllib.request.urlopen(req, timeout=12) as response:
            result = json.loads(response.read().decode("utf-8"))
            return json.loads(result["choices"][0]["message"]["content"])

    def _diagnose_offline(self, incident: Incident) -> Dict[str, str]:
        """
        Intelligent offline heuristic expert system based on production patterns.
        Always available, ultra-fast, and works without an internet connection or API key.
        """
        err = (incident.error_type or "").lower()
        msg = (incident.sample_message or "").lower()
        stack = (incident.sample_stacktrace or "").lower()

        # Pattern 1: Database connection pool exhaustion / timeouts
        if any(k in err or k in msg for k in ["operationalerror", "pooltimeout", "connection refused", "too many connections", "psycopg2"]):
            return {
                "root_cause": "Agotamiento del pool de conexiones o desconexión abrupta de la base de datos. Las conexiones activas excedieron el límite configurado (`max_connections`) o existen transacciones lentas que retienen las sesiones sin cerrarlas.",
                "impact": "Alta criticidad. Todas las peticiones entrantes dependientes de persistencia fallarán en cascada con errores 500.",
                "recommendation": (
                    "1. Configurar un pooler de conexiones intermedio como PgBouncer o HikariCP.\n"
                    "2. Verificar que los bloques de sesión utilicen manejadores de contexto (`with get_db() as db:`) para garantizar el cierre.\n"
                    "3. Ajustar timeouts de conexión (`connect_timeout=5`, `pool_recycle=1800`)."
                ),
                "code_patch": (
                    "```diff\n"
                    "--- database.py (Original)\n"
                    "+++ database.py (Fixed)\n"
                    "@@ -10,4 +10,7 @@\n"
                    "- engine = create_engine(DATABASE_URL)\n"
                    "+ engine = create_engine(\n"
                    "+     DATABASE_URL,\n"
                    "+     pool_size=20,\n"
                    "+     max_overflow=10,\n"
                    "+     pool_timeout=30,\n"
                    "+     pool_pre_ping=True  # Detects stale connections\n"
                    "+ )\n"
                    "```"
                )
            }

        # Pattern 2: Null Pointer / NoneType attribute error
        if any(k in err or k in msg for k in ["nonetype", "nullpointer", "attributeerror", "undefined"]):
            return {
                "root_cause": "Intento de acceder a un método o propiedad sobre un objeto nulo (`None`/`null`). Típicamente ocurre cuando una consulta de base de datos o llamada a servicio externo no retorna resultados y no se valida el valor previo al uso.",
                "impact": "Media-Alta. Causa abortos no controlados del hilo de ejecución en flujos de usuarios específicos.",
                "recommendation": (
                    "1. Implementar validación temprana (guard clause) o patrón Optional.\n"
                    "2. En Python usar `getattr()` o verificación explícita `if obj is None: raise EntityNotFoundException()`.\n"
                    "3. Agregar validación de esquemas con Pydantic o dataclasses."
                ),
                "code_patch": (
                    "```diff\n"
                    "--- service.py (Original)\n"
                    "+++ service.py (Fixed)\n"
                    "@@ -25,3 +25,5 @@\n"
                    " user = get_user_by_id(user_id)\n"
                    "- return user.email.lower()\n"
                    "+ if not user or not user.email:\n"
                    "+     raise HTTPException(status_code=404, detail='User email not found')\n"
                    "+ return user.email.lower()\n"
                    "```"
                )
            }

        # Pattern 3: Key / Index missing
        if any(k in err or k in msg for k in ["keyerror", "indexerror", "indexoutofrange"]):
            return {
                "root_cause": "Acceso a una clave inexistente en un diccionario o índice fuera de los límites de un arreglo. Frecuente al recibir cargas útiles (payloads) de clientes con campos faltantes o colecciones vacías.",
                "impact": "Media. Errores 500 no controlados en endpoints específicos.",
                "recommendation": (
                    "1. Utilizar `.get('key', default)` en lugar de acceso directo por índice `['key']`.\n"
                    "2. Definir contratos de datos con validadores estrictos tipo Pydantic/TypeScript."
                ),
                "code_patch": (
                    "```diff\n"
                    "--- parser.py (Original)\n"
                    "+++ parser.py (Fixed)\n"
                    "@@ -15,2 +15,2 @@\n"
                    "- token = payload['auth_token']\n"
                    "+ token = payload.get('auth_token')\n"
                    "+ if not token:\n"
                    "+     raise InvalidTokenException('auth_token is required')\n"
                    "```"
                )
            }

        # Pattern 4: Network Timeout / Connection reset
        if any(k in err or k in msg for k in ["timeout", "timed out", "econnreset", "readtimeout"]):
            return {
                "root_cause": "Un servicio externo o API dependiente tardó más tiempo en responder del límite permitido o reinició la conexión abruptamente.",
                "impact": "Degradación de rendimiento y bloqueo de hilos de trabajo asíncronos.",
                "recommendation": (
                    "1. Configurar un patrón de reintento exponencial con jitter (Exponential Backoff).\n"
                    "2. Implementar un Circuit Breaker para aislar el fallo y responder con degraded fallback."
                ),
                "code_patch": (
                    "```diff\n"
                    "--- client.py (Original)\n"
                    "+++ client.py (Fixed)\n"
                    "@@ -8,2 +8,4 @@\n"
                    "- response = requests.get(url)\n"
                    "+ from urllib3.util.retry import Retry\n"
                    "+ response = requests.get(url, timeout=(3.05, 10))  # connect, read\n"
                    "```"
                )
            }

        # Fallback default diagnosis
        return {
            "root_cause": f"Excepción no controlada de tipo `{incident.error_type}`. El sistema capturó un fallo en tiempo de ejecución durante el procesamiento de la petición.",
            "impact": "Riesgo de inconsistencia de datos o caída del proceso en el componente afectado.",
            "recommendation": (
                "1. Envolver el bloque sensible en una cláusula `try...except` con logging estructurado.\n"
                "2. Generar alertas automáticas si el umbral supera 5 incidentes por hora."
            ),
            "code_patch": (
                "```diff\n"
                "--- app.py\n"
                "+++ app.py\n"
                "@@ -30,4 +30,8 @@\n"
                "+ try:\n"
                "      execute_task()\n"
                "+ except Exception as err:\n"
                "+     logger.error(f'Task execution failed: {err}', exc_info=True)\n"
                "+     raise SafeApplicationException('Operation could not be completed')\n"
                "```"
            )
        }
