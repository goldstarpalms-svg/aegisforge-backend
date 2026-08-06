"""Nova Memory — Persistent context and conversation system."""
import json
import httpx
import os
from datetime import datetime, timezone
from .config import NOVA_MEMORY_TABLE, NOVA_ACTIONS_TABLE

SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_KEY")


def _sb_headers(extra=None):
    h = {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
    }
    if extra:
        h.update(extra)
    return h


def _sb_ok():
    return bool(SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY)


class NovaMemory:
    """Nova's brain. Remembers projects, conversations, decisions, preferences.

    Never ask the user the same question twice.
    """

    @staticmethod
    async def get_context(user_id: str = None, project_id: str = None) -> dict:
        """Retrieve Nova's memory for a user/project."""
        if not _sb_ok():
            return {"conversation_history": [], "decisions": [], "preferred_stack": {}}

        params = {"limit": "1", "order": "updated_at.desc"}
        if user_id:
            params["user_id"] = f"eq.{user_id}"
        if project_id:
            params["project_id"] = f"eq.{project_id}"

        try:
            async with httpx.AsyncClient(timeout=10) as c:
                r = await c.get(
                    f"{SUPABASE_URL}/rest/v1/{NOVA_MEMORY_TABLE}",
                    headers=_sb_headers(),
                    params=params,
                )
                r.raise_for_status()
                rows = r.json()
                if rows:
                    return rows[0]
        except Exception:
            pass
        return {"conversation_history": [], "decisions": [], "preferred_stack": {}}

    @staticmethod
    async def save_context(
        user_id: str,
        project_id: str = None,
        prompt: str = None,
        decision: dict = None,
        architecture: dict = None,
        preferences: dict = None,
    ) -> bool:
        """Update Nova's memory with new information."""
        if not _sb_ok():
            return False

        # Get existing memory
        existing = await NovaMemory.get_context(user_id, project_id)
        memory_id = existing.get("id")

        # Build updates
        updates = {"updated_at": datetime.now(timezone.utc).isoformat()}

        if prompt:
            history = existing.get("conversation_history", [])
            if isinstance(history, str):
                history = json.loads(history)
            history.append({"role": "user", "content": prompt, "ts": updates["updated_at"]})
            # Keep last 50 entries
            updates["conversation_history"] = history[-50:]

        if decision:
            decisions = existing.get("decisions", [])
            if isinstance(decisions, str):
                decisions = json.loads(decisions)
            decisions.append({**decision, "ts": updates["updated_at"]})
            updates["decisions"] = decisions[-100:]

        if architecture:
            updates["architecture_choices"] = architecture

        if preferences:
            existing_prefs = existing.get("user_preferences", {})
            if isinstance(existing_prefs, str):
                existing_prefs = json.loads(existing_prefs)
            existing_prefs.update(preferences)
            updates["user_preferences"] = existing_prefs

        try:
            async with httpx.AsyncClient(timeout=10) as c:
                if memory_id:
                    # Update existing
                    r = await c.patch(
                        f"{SUPABASE_URL}/rest/v1/{NOVA_MEMORY_TABLE}",
                        headers=_sb_headers({"Prefer": "return=minimal"}),
                        params={"id": f"eq.{memory_id}"},
                        json=updates,
                    )
                    r.raise_for_status()
                else:
                    # Create new
                    row = {
                        "user_id": user_id,
                        "conversation_history": updates.get("conversation_history", []),
                        "decisions": updates.get("decisions", []),
                        "user_preferences": updates.get("user_preferences", {}),
                    }
                    if project_id:
                        row["project_id"] = project_id
                    if architecture:
                        row["architecture_choices"] = architecture
                    r = await c.post(
                        f"{SUPABASE_URL}/rest/v1/{NOVA_MEMORY_TABLE}",
                        headers=_sb_headers({"Prefer": "return=minimal"}),
                        json=row,
                    )
                    r.raise_for_status()
            return True
        except Exception:
            return False

    @staticmethod
    async def log_action(
        agent: str,
        action: str,
        input_data: dict = None,
        output_data: dict = None,
        duration_ms: int = None,
        model: str = None,
        provider: str = None,
        success: bool = True,
        error: str = None,
        user_id: str = None,
        project_id: str = None,
    ) -> bool:
        """Log every Nova action for audit and traceability."""
        if not _sb_ok():
            return False

        row = {
            "agent": agent,
            "action": action,
            "input": input_data or {},
            "output": output_data or {},
            "duration_ms": duration_ms,
            "model": model,
            "provider": provider,
            "success": success,
            "error": error,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        if user_id:
            row["user_id"] = user_id
        if project_id:
            row["project_id"] = project_id

        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.post(
                    f"{SUPABASE_URL}/rest/v1/{NOVA_ACTIONS_TABLE}",
                    headers=_sb_headers({"Prefer": "return=minimal"}),
                    json=row,
                )
                r.raise_for_status()
            return True
        except Exception:
            return False
