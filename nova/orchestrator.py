"""Nova Orchestrator — The central brain that routes work through agents."""
import time
import json
import re
import httpx
from datetime import datetime, timezone
from .router import AgentRouter
from .memory import NovaMemory
from .config import AI_PROVIDER, OPENAI_API_KEY, OPENROUTER_API_KEY, AI_MODEL, AGENTS

# ── System Prompts per Agent ──
AGENT_PROMPTS = {
    "product": """You are Nova Product Agent, an expert software architect. Given an idea, produce a detailed product blueprint as JSON:
- summary (string, 2-3 sentences)
- suggested_name (catchy product name)
- roles (array of strings)
- features (array of strings, 6-10)
- pages (array of strings, 5-8)
- database_tables (array of strings)
- api_endpoints (array of objects with path, method, description)
- security_checklist (array of strings, 4-6)
- deployment_plan (array of strings, 4-5)
- monetization (array of strings, 2-4)
- tech_stack (object with frontend, backend, database, hosting)
Be practical and specific. Valid JSON only, no markdown.""",

    "builder": """You are Nova Builder Agent. Given a product blueprint, generate the technical implementation plan as JSON:
- file_structure (array of objects with path, description)
- dependencies (object with frontend, backend)
- key_components (array of objects with name, description, code_outline)
- api_design (array of objects with endpoint, method, request, response)
- database_schema (array of objects with table, columns, relationships)
Be production-ready. Valid JSON only.""",

    "security": """You are Nova Security Agent. Given a project description, generate a security assessment as JSON:
- risk_level (low/medium/high/critical)
- vulnerabilities (array of objects with name, severity, description, fix)
- headers_needed (array of objects with header, value, reason)
- ssl_recommendations (array of strings)
- auth_strategy (string describing recommended approach)
- compliance_notes (array of strings)
Be thorough. Valid JSON only.""",

    "deploy": """You are Nova Deploy Agent. Given a project, generate a deployment plan as JSON:
- platform (recommended platform)
- steps (array of objects with step, command, description)
- env_variables (array of objects with name, description, required)
- monitoring (array of objects with tool, purpose)
- rollback_plan (string)
- estimated_cost (string, monthly estimate)
Be specific. Valid JSON only.""",

    "growth": """You are Nova Growth Agent. Given a deployed project, generate growth recommendations as JSON:
- metrics_to_track (array of objects with metric, tool, goal)
- optimization_ideas (array of objects with area, suggestion, impact)
- ab_tests (array of objects with name, hypothesis, variant_a, variant_b)
- scaling_triggers (array of objects with metric, threshold, action)
Be data-driven. Valid JSON only.""",
}


async def _call_ai(system_prompt: str, user_prompt: str) -> str:
    """Call the configured AI provider."""
    if AI_PROVIDER == "openrouter" and OPENROUTER_API_KEY:
        base_url = "https://openrouter.ai/api/v1"
        api_key = OPENROUTER_API_KEY
    elif OPENAI_API_KEY:
        base_url = "https://api.openai.com/v1"
        api_key = OPENAI_API_KEY
    else:
        raise RuntimeError("No AI provider configured")

    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(
            f"{base_url}/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json={
                "model": AI_MODEL,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "temperature": 0.7,
                "max_tokens": 2500,
            },
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]


def _parse_json(raw: str) -> dict:
    """Parse AI response, stripping markdown fences."""
    text = raw.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{[\s\S]*\}", text)
        if match:
            return json.loads(match.group())
        raise


class NovaOrchestrator:
    """Nova Core — Orchestrates the full idea → deployment workflow.

    Users never manually select modules. Nova automatically routes work.
    """

    @staticmethod
    async def process_prompt(
        prompt: str,
        user_id: str = None,
        project_id: str = None,
        audience: str = None,
        platform: str = None,
        budget: str = None,
    ) -> dict:
        """Main entry point. Process a user prompt through Nova.

        Returns:
            {
                "intent": ...,
                "agents_activated": [...],
                "results": { "product": {...}, ... },
                "nova_context": {...},
                "duration_ms": int
            }
        """
        start = time.time()

        # Step 1: Route to agents
        routing = AgentRouter.classify(prompt)

        # Step 2: Load memory
        memory = await NovaMemory.get_context(user_id, project_id)
        preferred_stack = memory.get("preferred_stack", {})
        if isinstance(preferred_stack, str):
            preferred_stack = json.loads(preferred_stack)

        # Step 3: Save prompt to memory
        await NovaMemory.save_context(user_id, project_id, prompt=prompt)

        # Step 4: Execute agents
        results = {}
        context = {"prompt": prompt, "routing": routing}

        # Build enriched prompt
        parts = [f"User idea: {prompt}"]
        if audience:
            parts.append(f"Target audience: {audience}")
        if platform:
            parts.append(f"Platform: {platform}")
        if budget:
            parts.append(f"Budget/stage: {budget}")
        if preferred_stack:
            parts.append(f"User's preferred stack: {json.dumps(preferred_stack)}")
        enriched = "\n".join(parts)

        for agent_name in routing["agents"]:
            agent_start = time.time()
            try:
                system_prompt = AGENT_PROMPTS.get(agent_name, AGENT_PROMPTS["product"])

                # If we have results from previous agents, include them
                if results:
                    prev_summary = {}
                    for k, v in results.items():
                        if isinstance(v, dict):
                            prev_summary[k] = {key: val for key, val in v.items() if key in (
                                "summary", "suggested_name", "features", "risk_level",
                                "platform", "steps"
                            )}
                    enriched += f"\n\nPrevious agent outputs: {json.dumps(prev_summary, default=str)[:1000]}"

                raw = await _call_ai(system_prompt, enriched)
                agent_result = _parse_json(raw)
                results[agent_name] = agent_result

                # Log successful action
                await NovaMemory.log_action(
                    agent=agent_name,
                    action="generate",
                    input_data={"prompt": prompt[:200]},
                    output_data=agent_result,
                    duration_ms=int((time.time() - agent_start) * 1000),
                    model=AI_MODEL,
                    provider=AI_PROVIDER,
                    success=True,
                    user_id=user_id,
                    project_id=project_id,
                )

                # Save decision to memory
                await NovaMemory.save_context(
                    user_id, project_id,
                    decision={"agent": agent_name, "action": "generate", "result_keys": list(agent_result.keys())}
                )

            except Exception as e:
                results[agent_name] = {"error": str(e)}
                await NovaMemory.log_action(
                    agent=agent_name,
                    action="generate",
                    input_data={"prompt": prompt[:200]},
                    success=False,
                    error=str(e),
                    duration_ms=int((time.time() - agent_start) * 1000),
                    model=AI_MODEL,
                    provider=AI_PROVIDER,
                    user_id=user_id,
                    project_id=project_id,
                )

        duration_ms = int((time.time() - start) * 1000)

        return {
            "intent": routing["intent"],
            "agents_activated": routing["agents"],
            "primary_agent": routing["primary_agent"],
            "workflow": routing["workflow"],
            "confidence": routing["confidence"],
            "results": results,
            "nova_context": context,
            "model": AI_MODEL,
            "provider": AI_PROVIDER,
            "duration_ms": duration_ms,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
