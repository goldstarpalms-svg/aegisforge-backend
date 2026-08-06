"""Nova Agent Router — automatically decides which agents to activate."""
import re
from .config import AGENTS, WORKFLOW_ORDER


class AgentRouter:
    """Routes user intent to the right Nova agents automatically.

    Users never manually choose agents. Nova decides based on:
    1. Keyword analysis of the prompt
    2. Project context / state
    3. Workflow position
    """

    # Intent classification patterns
    INTENT_PATTERNS = {
        "blueprint": [
            r"\b(build|create|make|design|plan|architect)\b.*\b(app|application|software|product|platform|website|site|dashboard|saas|marketplace|store|tool)\b",
            r"\b(i want|i need|help me)\b.*\b(build|create|make|design|launch)\b",
            r"\bwhat do you want to build\b",
        ],
        "scan": [
            r"\b(scan|check|audit|analyze|test|inspect)\b.*\b(security|vuln|website|url|domain|site)\b",
            r"\b(is .+ secure|how secure|security score)\b",
            r"\b(ssl|https|headers|cookie|dns)\b.*\b(check|scan|test)\b",
        ],
        "build": [
            r"\b(generate|write|code|implement|develop)\b.*\b(code|app|feature|component|api)\b",
            r"\b(build it|code it|generate code|write code)\b",
        ],
        "deploy": [
            r"\b(deploy|ship|launch|publish|release|go live)\b",
            r"\b(push to|upload to|host on)\b",
        ],
        "optimize": [
            r"\b(optimize|improve|scale|monitor|analytics|perf)\b",
            r"\b(speed up|make faster|reduce|increase)\b",
        ],
    }

    @classmethod
    def classify(cls, prompt: str, project_state: dict = None) -> dict:
        """Classify user intent and return agent activation plan.

        Returns:
            {
                "intent": "blueprint" | "scan" | "build" | "deploy" | "optimize" | "general",
                "agents": ["product", "builder", ...],  # ordered list of agents to activate
                "primary_agent": "product",
                "workflow": "full" | "partial",
                "confidence": "high" | "medium" | "low"
            }
        """
        text = prompt.lower().strip()
        scores = {}

        for intent, patterns in cls.INTENT_PATTERNS.items():
            score = 0
            for pattern in patterns:
                if re.search(pattern, text, re.IGNORECASE):
                    score += 2
            # Also check trigger words from AGENTS config
            for agent_name, agent_conf in AGENTS.items():
                if intent in ("blueprint",) and agent_name == "product":
                    for trigger in agent_conf["trigger"]:
                        if trigger in text:
                            score += 1
                elif intent in ("scan",) and agent_name == "security":
                    for trigger in agent_conf["trigger"]:
                        if trigger in text:
                            score += 1
                elif intent in ("build",) and agent_name == "builder":
                    for trigger in agent_conf["trigger"]:
                        if trigger in text:
                            score += 1
                elif intent in ("deploy",) and agent_name == "deploy":
                    for trigger in agent_conf["trigger"]:
                        if trigger in text:
                            score += 1
                elif intent in ("optimize",) and agent_name == "growth":
                    for trigger in agent_conf["trigger"]:
                        if trigger in text:
                            score += 1
            scores[intent] = score

        # Determine primary intent
        best = max(scores, key=scores.get)
        has_match = scores[best] > 0

        if not has_match:
            # Default: treat as a blueprint/product request
            return {
                "intent": "blueprint",
                "agents": ["product"],
                "primary_agent": "product",
                "workflow": "partial",
                "confidence": "medium",
            }

        # Map intent to agents
        intent_agent_map = {
            "blueprint": ["product"],
            "scan": ["security"],
            "build": ["product", "builder", "security"],
            "deploy": ["deploy"],
            "optimize": ["growth"],
        }

        agents = intent_agent_map.get(best, ["product"])
        confidence = "high" if scores[best] >= 3 else "medium"

        # If the prompt mentions multiple intents, expand agents
        if scores.get("blueprint", 0) > 0 and scores.get("scan", 0) > 0:
            agents = ["product", "security"]
        if scores.get("build", 0) > 0 and scores.get("deploy", 0) > 0:
            agents = ["product", "builder", "security", "deploy"]

        return {
            "intent": best,
            "agents": agents,
            "primary_agent": agents[0],
            "workflow": "full" if len(agents) >= 3 else "partial",
            "confidence": confidence,
        }

    @classmethod
    def full_workflow(cls) -> list:
        """Return the standard Nova workflow: all 5 agents in order."""
        return WORKFLOW_ORDER[:]
