# Copyright 2026 GoCloudForge, Inc. All rights reserved.
# Proprietary and confidential.
"""Shared constants for AI Runtime Monitor.

Single source of truth for all constants used by both monitor.py and watch.py.
"""

# ─────────────────────────────────────────────────────────────
# AI Process Detection
# ─────────────────────────────────────────────────────────────

# Exact process name matches (case-sensitive)
AI_PROCESS_EXACT = {
    "claude",
    "Claude",
    "ChatGPT",
    "ChatGPTHelper",
    "Ollama",
    "ollama",
    "Cursor",
    "Windsurf",
    "openclaw-gateway",
}

# Substring pattern matching with exclusions
AI_PROCESS_PATTERNS = {
    "claude": {"exclude": []},
    "anthropic": {"exclude": []},
    "chatgpt": {"exclude": []},
    "ollama": {"exclude": []},
    "copilot": {"exclude": ["CursorUIViewService"]},
    "cursor": {"exclude": ["CursorUIViewService"]},
    "aider": {"exclude": []},
    "openai": {"exclude": []},
    "lmstudio": {"exclude": []},
    "cody": {"exclude": []},
    "gemini": {"exclude": []},
    "bedrock": {"exclude": []},
    "codex": {"exclude": []},
    "windsurf": {"exclude": []},
    "openclaw": {"exclude": []},
    "moltbot": {"exclude": []},
    "clawdbot": {"exclude": []},
}

# ─────────────────────────────────────────────────────────────
# Browser AI Patterns (Chrome history matching)
# ─────────────────────────────────────────────────────────────

BROWSER_AI_PATTERNS = {
    "chatgpt.com": "ChatGPT",
    "chat.openai.com": "ChatGPT",
    "gemini.google.com": "Gemini",
    "claude.ai": "Claude Web",
    "perplexity.ai": "Perplexity",
    "copilot.microsoft.com": "Copilot",
    "aistudio.google.com": "AI Studio",
    "deepseek.com": "DeepSeek",
}

# ─────────────────────────────────────────────────────────────
# AI Hosts — merged superset from monitor.py and watch.py
# ─────────────────────────────────────────────────────────────

# Domains for selective SSL inspection (mitmproxy allow_hosts).
# Only these domains are decrypted — everything else passes through untouched.
#
# Browser-facing UI sites (claude.ai, chatgpt.com, gemini.google.com,
# perplexity.ai) are intentionally EXCLUDED from the proxy's allow_hosts.
# They are handled by the Chrome extension, which captures content from
# the rendered DOM. The proxy targets API endpoints only. This avoids
# two failure modes that the new-laptop install verification surfaced:
#
#   1. The cert-error UX hit. Browsers maintain stricter intermediate
#      validation for popular AI properties (HSTS pre-loaded). When the
#      proxy intercepts these sites and the CA is even momentarily not
#      fully trusted, the browser shows a scary "connection not private"
#      error that can't be clicked through. Excluding browser UIs from
#      proxy scope removes the failure mode entirely.
#   2. Duplicate capture work. The Chrome extension already captures
#      browser AI usage from the DOM (richer, includes formatted output).
#      Having the proxy also intercept these hosts means two systems
#      processing the same flow with different fidelity.
#
# AI_API_DOMAINS — proxied (selective SSL inspection, full body parse)
# AI_BROWSER_DOMAINS — handled by Chrome extension, NOT by the proxy.
#                      Kept here for use by BROWSER_AI_PATTERNS and Chrome
#                      history matching, but no longer in AI_PROXY_DOMAINS.

AI_API_DOMAINS = [
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
    "api.cursor.sh",
    "copilot-proxy.githubusercontent.com",
    "api.githubcopilot.com",
    "api.cohere.ai",
    "api.mistral.ai",
    "api-inference.huggingface.co",
    "api.groq.com",
    "api.together.xyz",
    "api.fireworks.ai",
    "api.deepseek.com",
    "api.perplexity.ai",
]

# Browser-facing AI web UIs. NOT proxied — see the long comment above.
# The Chrome extension handles capture for these via DOM observation.
AI_BROWSER_DOMAINS = [
    "claude.ai",
    "chatgpt.com",
    "chat.openai.com",
    "gemini.google.com",
    "perplexity.ai",
]

# AI_PROXY_DOMAINS is exactly AI_API_DOMAINS today. Kept as a separate
# name so callers that need "what does the proxy inspect" don't have to
# care about the API/browser split — they just import this list.
AI_PROXY_DOMAINS = AI_API_DOMAINS

AI_HOSTS = {
    # Anthropic
    "api.anthropic.com": "anthropic_api",
    "statsig.anthropic.com": "anthropic_telemetry",
    "console.anthropic.com": "anthropic_console",
    # OpenAI / ChatGPT / Copilot
    "api.openai.com": "openai_api",
    "chatgpt.com": "chatgpt_web",
    "copilot.githubusercontent.com": "github_copilot",
    "copilot-proxy.githubusercontent.com": "github_copilot",
    "githubcopilot.com": "github_copilot",
    "api.githubcopilot.com": "github_copilot",
    # Google
    "generativelanguage.googleapis.com": "gemini_api",
    "aistudio.google.com": "google_aistudio",
    "aiplatform.googleapis.com": "vertex_ai",
    # AWS
    "bedrock.amazonaws.com": "aws_bedrock",
    "bedrock-runtime.amazonaws.com": "aws_bedrock",
    # Mistral
    "api.mistral.ai": "mistral_api",
    # Cohere
    "api.cohere.ai": "cohere_api",
    "api.cohere.com": "cohere_api",
    # Groq
    "api.groq.com": "groq_api",
    # Together AI
    "api.together.xyz": "together_api",
    # Perplexity
    "api.perplexity.ai": "perplexity_api",
    # DeepSeek
    "api.deepseek.com": "deepseek_api",
    # xAI / Grok
    "api.x.ai": "xai_grok_api",
    # HuggingFace
    "api-inference.huggingface.co": "huggingface_api",
    "huggingface.co": "huggingface_web",
    # Replicate
    "api.replicate.com": "replicate_api",
    # Fireworks
    "api.fireworks.ai": "fireworks_api",
    # Ollama (local)
    "localhost:11434": "ollama_local",
    "127.0.0.1:11434": "ollama_local",
    # LM Studio (local)
    "localhost:1234": "lmstudio_local",
    "127.0.0.1:1234": "lmstudio_local",
    # OpenClaw (local)
    "localhost:18789": "openclaw_local",
    "127.0.0.1:18789": "openclaw_local",
    # OpenRouter
    "openrouter.ai": "openrouter_api",
    # Azure OpenAI
    "openai.azure.com": "azure_openai",
    # Telemetry / analytics
    "sentry.io": "error_reporting",
    "ingest.sentry.io": "error_reporting",
    "featuregates.cloud": "statsig_telemetry",
    "api.statsig.com": "statsig_telemetry",
    "events.statsig.com": "statsig_telemetry",
    "api.segment.io": "segment_telemetry",
    "api.amplitude.com": "amplitude_telemetry",
}

# ─────────────────────────────────────────────────────────────
# Service Classification (reverse DNS → service name)
# ─────────────────────────────────────────────────────────────

SERVICE_CLASSIFICATION = {
    ".1e100.net": "Google APIs",
    ".googleapis.com": "Google APIs",
    ".anthropic.com": "Anthropic",
    ".openai.com": "OpenAI",
    ".azure.com": "Azure",
    ".amazonaws.com": "AWS",
    ".github.com": "GitHub",
    ".sentry.io": "Sentry",
    ".segment.io": "Segment",
    ".statsig.com": "Statsig",
    ".googleusercontent.com": "Anthropic API",
    ".bc.googleusercontent.com": "Anthropic API",
}

# Known Anthropic API IP prefixes (GCP-hosted)
ANTHROPIC_IP_PREFIXES = (
    "160.79.",
    "137.66.",
    "35.185.",
    "34.8.",
    "34.49.",
)

# ─────────────────────────────────────────────────────────────
# Sensitive Data Patterns (with severity and category)
# ─────────────────────────────────────────────────────────────

SENSITIVE_PATTERNS = {
    # CRITICAL — immediate credential exposure
    "aws_key": {"pattern": r"(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}", "severity": "critical", "category": "credential"},
    "aws_secret": {
        "pattern": r"(?i)aws.{0,20}secret.{0,20}['\"][A-Za-z0-9/+=]{40}['\"]",
        "severity": "critical",
        "category": "credential",
    },
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
        "severity": "critical",
        "category": "credential",
    },
    "anthropic_key": {"pattern": r"sk-ant-[A-Za-z0-9\-_]{40,}", "severity": "critical", "category": "credential"},
    "openai_key": {"pattern": r"sk-[A-Za-z0-9]{32,}", "severity": "critical", "category": "credential"},
    "github_token": {"pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}", "severity": "critical", "category": "credential"},
    "slack_webhook": {
        "pattern": r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",
        "severity": "critical",
        "category": "credential",
    },
    "discord_webhook": {
        "pattern": r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]+",
        "severity": "critical",
        "category": "credential",
    },
    "stripe_key": {
        "pattern": r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}",
        "severity": "critical",
        "category": "credential",
    },
    # HIGH — secrets and tokens
    "jwt_token": {
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+",
        "severity": "high",
        "category": "credential",
    },
    "bearer_token": {
        "pattern": r"(?i)(?:Authorization|Bearer)\s*[:=]\s*['\"]?Bearer\s+[A-Za-z0-9_\-\.]{20,}",
        "severity": "high",
        "category": "credential",
    },
    "password_in_code": {
        "pattern": r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]",
        "severity": "high",
        "category": "credential",
    },
    "api_key_generic": {
        "pattern": r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{20,}",
        "severity": "high",
        "category": "credential",
    },
    "db_connection": {
        "pattern": r"(?i)(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^\s'\"]{10,}",
        "severity": "high",
        "category": "credential",
    },
    "base64_secret": {
        "pattern": r"(?i)(?:secret|token|key|auth)\s*[:=]\s*['\"]?[A-Za-z0-9+/]{40,}={0,2}['\"]?",
        "severity": "high",
        "category": "credential",
    },
    # MEDIUM — PII and sensitive data
    "ssn": {"pattern": r"\b\d{3}-\d{2}-\d{4}\b", "severity": "medium", "category": "pii"},
    "credit_card": {
        "pattern": r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{3,4}\b",
        "severity": "medium",
        "category": "pii",
    },
    "phone_number": {
        "pattern": r"\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b",
        "severity": "medium",
        "category": "pii",
    },
    "email_bulk": {
        "pattern": r"(?:[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\s*[,;\n]\s*){3,}",
        "severity": "medium",
        "category": "pii",
    },
    # LOW — informational / policy
    "env_file": {"pattern": r"\.env(?:\.[a-z]+)?", "severity": "low", "category": "policy"},
    "internal_url": {
        "pattern": r"https?://(?:internal|staging|dev|local|corp|intranet)\.[a-z0-9.-]+",
        "severity": "low",
        "category": "policy",
    },
    "ip_address_private": {
        "pattern": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
        "severity": "low",
        "category": "policy",
    },
}

# Severity ordering for display
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# Known example/test secrets that should never trigger alerts
KNOWN_EXAMPLE_SECRETS = {
    "aws_key": {
        "AKIAIOSFODNN7EXAMPLE",
        "AKIAI44QH8DHBEXAMPLE",
        "AKIAEXAMPLEKEYID1234",
    },
    "aws_secret": set(),
    "github_token": set(),
    "anthropic_key": set(),
    "openai_key": set(),
    "stripe_key": set(),
}

# ─────────────────────────────────────────────────────────────
# MCP Server Monitoring
# ─────────────────────────────────────────────────────────────

# Known/trusted MCP servers (user can extend via config)
MCP_KNOWN_SERVERS: set[str] = set()

# ─────────────────────────────────────────────────────────────
# Agent Type Detection & Colors
# ─────────────────────────────────────────────────────────────

# Path pattern -> agent type (checked against cwd and jsonl_path)
AGENT_TYPE_MAP = {
    ".openclaw": "openclaw",
    ".claude": "claude_code",
    ".cursor": "cursor",
    ".codex": "codex",
}

# Agent type -> (color hex, display label)
AGENT_TYPE_COLORS = {
    "openclaw": ("#238636", "OpenClaw"),
    "claude_code": ("#2563eb", "Claude Code"),
    "cursor": ("#7c3aed", "Cursor"),
    "codex": ("#ea580c", "Codex"),
    "chatgpt": ("#ea580c", "ChatGPT"),
    "claude_web": ("#2563eb", "Claude Web"),
    "copilot": ("#0891b2", "Copilot"),
    "unknown": ("#6b7280", "Unknown"),
}

# Browser service -> agent type
BROWSER_SERVICE_AGENT_MAP = {
    "ChatGPT": "chatgpt",
    "Gemini": "gemini",
    "Claude Web": "claude_web",
    "Perplexity": "perplexity",
    "Copilot": "copilot",
    "AI Studio": "ai_studio",
    "DeepSeek": "deepseek",
}

# ─────────────────────────────────────────────────────────────
# Tool Risk Assessment
# ─────────────────────────────────────────────────────────────

# Tool name -> (risk_level, description)
TOOL_RISK_MAP = {
    "exec": ("critical", "Shell command execution"),
    "Bash": ("critical", "Shell command execution"),
    "bash": ("critical", "Shell command execution"),
    "write": ("high", "File creation/overwrite"),
    "Write": ("high", "File creation/overwrite"),
    "edit": ("high", "File modification"),
    "Edit": ("high", "File modification"),
    "read": ("medium", "File read access"),
    "Read": ("medium", "File read access"),
    "web_fetch": ("medium", "External URL fetch"),
    "WebFetch": ("medium", "External URL fetch"),
    "web_search": ("low", "Search query"),
    "WebSearch": ("low", "Search query"),
    "memory_search": ("low", "Agent memory search"),
    "memory_get": ("low", "Agent memory read"),
    "sessions_spawn": ("high", "Sub-agent spawning"),
    "Agent": ("high", "Sub-agent spawning"),
    "Glob": ("low", "File pattern search"),
    "Grep": ("low", "Content search"),
}

# Subscription plan token limits (approximate monthly)
PLAN_LIMITS = {
    "max_20x": {"monthly_tokens": 900_000_000, "label": "Max 20x"},
    "max_5x": {"monthly_tokens": 225_000_000, "label": "Max 5x"},
    "max": {"monthly_tokens": 45_000_000, "label": "Max"},
    "pro": {"monthly_tokens": 45_000_000, "label": "Pro"},
    "free": {"monthly_tokens": 5_000_000, "label": "Free"},
}

# ─────────────────────────────────────────────────────────────
# claude-watch Specific Constants
# ─────────────────────────────────────────────────────────────

# Claude Code tool names to track
TOOL_NAMES = {
    "bash",
    "computer",
    "str_replace_editor",
    "str_replace_based_edit_tool",
    "read_file",
    "write_file",
    "create_file",
    "list_directory",
    "web_search",
    "web_fetch",
    "execute_code",
    "file_editor",
    "TodoRead",
    "TodoWrite",
    "Task",
    "mcp__",
}

# CSV columns for watch.py traffic capture
CSV_COLUMNS = [
    "timestamp",
    "session_id",
    "turn_id",
    "turn_number",
    "destination_host",
    "destination_service",
    "endpoint_path",
    "http_method",
    "http_status",
    "model",
    "stream",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "estimated_cost_usd",
    "request_size_bytes",
    "response_size_bytes",
    "latency_ms",
    "num_messages",
    "system_prompt_chars",
    "last_user_msg_preview",
    "assistant_msg_preview",
    "tool_calls",
    "tool_call_count",
    "bash_commands",
    "files_read",
    "files_written",
    "urls_fetched",
    "sensitive_patterns",
    "sensitive_pattern_count",
    "content_types_sent",
    "stop_reason",
    "request_id",
    "raw_request_hash",
]
