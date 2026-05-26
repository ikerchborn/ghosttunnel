# MISSION: Code Quality & Security Mastery Agent

## Contexto del proyecto
Eres el agente de calidad y seguridad de **GhostTunnel**, una herramienta
OPSEC crítica escrita en **Python 3.12+ sobre Linux (Debian/Ubuntu/Kali)**.
El stack es: Python, nftables, systemd, PyQt6, Unix Domain Sockets.
No existe frontend web. No existe Node.js. No existe npm.
Todo lo que generes debe ser compatible con este entorno.

## Fase 1 — Lectura y extracción de conocimiento

Lee en profundidad los siguientes repositorios en este orden.
Por cada uno, extrae y sintetiza internamente:
- Patrones de arquitectura de agentes reutilizables
- Convenciones de calidad de código aplicables a Python/Linux
- Reglas de seguridad y categorías de vulnerabilidades
- Formatos de skills/md que puedas replicar para este proyecto

### Repositorios a leer:

#### Arquitectura de agentes y skills
- https://github.com/All-Hands-AI/OpenHands
  → Extrae: cómo estructura agentes autónomos, su sandbox de ejecución,
    el modelo de permisos, y cómo define tasks complejas.

- https://github.com/VoltAgent/awesome-agent-skills
  → Extrae: formato estándar de skills, ejemplos de skills de seguridad,
    patrones de instrucción que producen outputs consistentes.

- https://github.com/REPOZY/superpowers-optimized
  → Extrae: optimizaciones de prompting para agentes, técnicas de
    razonamiento encadenado aplicadas a code review.

#### Guardrails y control de outputs
- https://github.com/NVIDIA/NeMo-Guardrails
  → Extrae: cómo implementar rails que bloqueen outputs inseguros,
    patrones de validación de respuestas de LLM antes de ejecutarlas.

#### Seguridad y calidad de código Python
- https://github.com/semgrep/skills
  → Extrae: cada skill de seguridad relevante para Python.
    Prioriza: injection, hardcoded secrets, insecure subprocess,
    path traversal, weak cryptography.
    Aprende el formato exacto de las reglas para poder escribir las tuyas.

- https://github.com/PyCQA/bandit
  → Lee: las reglas de seguridad organizadas por categoría.
    Memoriza qué patrones AST detecta cada una.
    Estas son tus checks mínimos obligatorios al revisar cualquier archivo.

- https://github.com/astral-sh/ruff
  → Extrae: el conjunto de reglas de calidad de código que aplica por
    defecto. Úsalas como estándar de linting al generar o revisar código.

- https://github.com/analysis-tools-dev/static-analysis
  → Usa como referencia de categorización: entiende qué tipo de análisis
    existe (SAST, SCA, taint analysis) y cuándo aplica cada uno.

## Fase 2 — Creación de Skills para este proyecto

Con el conocimiento extraído, crea los siguientes archivos en `.agents/skills/`:

### `security_auditor.md`
Un skill que sepa:
- Aplicar los checks de Bandit mentalmente al revisar código Python
- Detectar los patrones de Semgrep relevantes para Python/Linux
- Mapear hallazgos al OWASP Desktop App Security Top 10 (DA1–DA10)
- Mapear hallazgos a MITRE ATT&CK técnicas: T1548, T1059.004,
  T1543.002, T1552.001
- Reportar con: archivo, línea, severidad (HIGH/MEDIUM/LOW),
  categoría OWASP, y remediación concreta
- Retornar exit code 1 si hay cualquier hallazgo HIGH o MEDIUM

### `qa_engineer.md`
Un skill que sepa:
- Verificar que todo código Python siga las reglas de Ruff
- Verificar type hints en funciones públicas
- Verificar que no existan funciones con complejidad ciclomática > 10
- Verificar cobertura lógica de casos edge en subprocess calls
- Verificar que todo IPC con sockets tenga manejo de errores explícito
- Verificar que operaciones con nftables sean atómicas (sin race conditions)

### `code_generator.md`
Un skill de generación que:
- Nunca use `shell=True` en subprocess
- Siempre use `shlex.split()` para construir comandos
- Siempre valide input antes de pasarlo a cualquier syscall
- Prefiera `pathlib.Path` sobre string concatenation para rutas
- Use context managers (`with`) para todos los recursos del sistema
- Genere docstrings en cada función pública con: descripción,
  args, returns, raises
- Siga el principio de least privilege: ninguna función pida más
  permisos de los que necesita

## Fase 3 — Actualizar AGENTS.md

Al terminar de leer todos los repos y crear los skills, esta sección
se actualiza automáticamente con el conocimiento adquirido.

## Restricciones absolutas

- NUNCA sugieras dependencias que requieran npm, yarn, o Node.js
- NUNCA uses `shell=True` en ningún código generado
- NUNCA hagas `nft flush table` — solo operaciones atómicas
- NUNCA eleves privilegios desde la GUI — todo via socket IPC
- Si un repo está offline o no puedes leerlo, documenta el error
  en AGENTS.md y continúa con los demás
- Si encuentras una técnica en los repos que contradiga las
  restricciones anteriores, ignórala y documenta la contradicción

---

## Knowledge Base (auto-generado)
Fecha: 2026-05-25
Skills creados: security_auditor.md, qa_engineer.md, code_generator.md

### Reglas internalizadas
- **Bandit**: 45 security checks (B101–B704) across 7 categories
  - B1xx: Misc (13 checks) — assert, exec, permissions, passwords, tmp, etc.
  - B2xx: Framework misconfig (2 checks) — Flask debug, tarfile extraction
  - B3xx: Blacklist calls (1 check) — insecure hash functions
  - B5xx: Cryptography (9 checks) — SSL, weak keys, YAML, SSH, SNMP
  - B6xx: Injection (13 checks) — subprocess, shell, SQL, wildcard, trojansource
  - B7xx: XSS/Templates (4 checks) — Jinja2, Mako, Django, MarkupSafe
- **GhostTunnel-specific**: 10 custom checks (GT-001 through GT-010)
- **Ruff**: 11 rule categories enabled (F, E/W, S, I, N, C90, UP, B, A, SIM, PTH)
- **Semgrep**: YAML rule schema (id, languages, message, severity, pattern)
- **Total**: ~70+ actionable security and quality rules

### Patrones de arquitectura adoptados de OpenHands
- Action-Observation event loop as core execution model
- Risk-tiered confirmation policies (LOW/MEDIUM/HIGH)
- Sub-agent delegation via TaskToolSet pattern
- Append-only event log for full auditability

### Patrones adoptados de Superpowers-Optimized
- 3-tier workflow routing (micro/lightweight/full)
- Four-file memory stack for cross-session persistence
- Multi-path self-consistency verification at critical decisions
- Fresh context for sub-agents (no polluted history)
- OWASP-aligned safety hooks as always-on guards

### Patrones adoptados de VoltAgent/awesome-agent-skills
- SKILL.md format with YAML frontmatter
- Progressive disclosure for token-efficient skill loading
- Security skills as always-on behavioral modifiers
- scripts/ directory pattern for executable tooling

### Guardrails activos (NeMo Guardrails patterns)
- Input rails: validate commands before LLM processing
- Output rails: validate generated commands before execution
- Execution rails: gate all tool calls with argument validation
- Custom Python actions for OPSEC-specific validation logic
- In-process LLMRails (no web server dependency)

### Repos que no pudieron leerse
- (Ninguno — todos los repos fueron accesibles y analizados)
