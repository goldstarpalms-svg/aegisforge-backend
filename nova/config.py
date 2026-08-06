"""Nova Core configuration."""
import os

# AI Provider settings
AI_PROVIDER = os.getenv("AI_PROVIDER", "openai").lower()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
AI_MODEL = os.getenv("AI_MODEL", "gpt-4o-mini")

# Provider endpoints
PROVIDERS = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "key_env": "OPENAI_API_KEY",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "key_env": "OPENROUTER_API_KEY",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "key_env": "ANTHROPIC_API_KEY",
    },
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "key_env": "GOOGLE_API_KEY",
    },
}

# Agent definitions
AGENTS = {
    "product": {
        "name": "Nova Product Agent",
        "icon": "🧠",
        "description": "Plans software.",
        "trigger": ["idea", "blueprint", "plan", "architecture", "requirements"],
    },
    "builder": {
        "name": "Nova Builder Agent",
        "icon": "💻",
        "description": "Writes production-ready applications.",
        "trigger": ["build", "code", "generate", "create", "implement"],
    },
    "security": {
        "name": "Nova Security Agent",
        "icon": "🛡",
        "description": "Protects applications.",
        "trigger": ["scan", "security", "vulnerability", "headers", "ssl", "https"],
    },
    "deploy": {
        "name": "Nova Deploy Agent",
        "icon": "🚀",
        "description": "Ships software.",
        "trigger": ["deploy", "ship", "launch", "publish", "release"],
    },
    "growth": {
        "name": "Nova Growth Agent",
        "icon": "📈",
        "description": "Improves products after launch.",
        "trigger": ["analytics", "optimize", "improve", "scale", "monitor"],
    },
}

# Standard workflow order
WORKFLOW_ORDER = ["product", "builder", "security", "deploy", "growth"]

# Supabase tables for Nova
NOVA_MEMORY_TABLE = os.getenv("NOVA_MEMORY_TABLE", "nova_memory")
NOVA_ACTIONS_TABLE = os.getenv("NOVA_ACTIONS_TABLE", "nova_actions")
BLUEPRINTS_TABLE = os.getenv("BLUEPRINTS_TABLE", "blueprints")
SECURITY_REPORTS_TABLE = os.getenv("SECURITY_REPORTS_TABLE", "security_reports")
PROJECTS_TABLE = os.getenv("PROJECTS_TABLE", "projects")
