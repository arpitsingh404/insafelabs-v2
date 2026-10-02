"""InsafeLabs-AI Agent — gives the LLM control over the app's own tools.

Flow:
  1) the operator gives an instruction + target,
  2) the LLM plans a sequence of the app's tools,
  3) the app executes them (in-process, all safety guards still apply),
  4) the LLM writes the final report.

Tool-calling is a JSON plan so it works with any text LLM (no provider-specific
function-calling API required).
"""
import json

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

import ai
from routers import toolreg

router = APIRouter(prefix="/ai/agent", tags=["ai-agent"])

MAX_STEPS = 8

SYSTEM_PLAN = """You are InsafeLabs-AI, an AUTONOMOUS authorized security-testing agent.
Given an instruction and a target, pick the MINIMUM useful sequence of tools from the catalog.

CATALOG:
{catalog}

Rules:
- Only use tools listed above. Never invent tools.
- Provide the exact required params for each tool (the target goes in the matching param).
- Keep it to at most {max_steps} steps. Prefer breadth: recon -> web checks -> deep checks.
- Respond with ONLY minified JSON:
  {{"plan":[{{"tool":"web_scan","args":{{"url":"https://x"}},"why":"..."}}]}}
- If the instruction needs no tool (pure question), respond {{"plan":[]}}.
"""

SYSTEM_REPORT = """You are InsafeLabs-AI. You just ran tools for an operator.
Write a concise, professional security report in Markdown with sections:
## Summary
## Findings (grouped by severity, with evidence)
## Recommended next steps
Be factual; only use the provided tool results. Do not invent findings.
"""


class AgentBody(BaseModel):
    instruction: str = Field(min_length=3, max_length=2000)
    target: str = ""
    max_steps: int = MAX_STEPS


@router.get("/tools")
async def agent_tools():
    reg = toolreg.registry()
    return {"tools": [{"name": n, "desc": t["desc"], "params": t["params"]} for n, t in reg.items()]}


@router.post("/run")
async def agent_run(body: AgentBody):
    reg = toolreg.registry()
    steps_cap = max(1, min(int(body.max_steps or MAX_STEPS), MAX_STEPS))

    user = f"Instruction: {body.instruction}"
    if body.target:
        user += f"\nTarget: {body.target}"

    plan_prompt = SYSTEM_PLAN.format(catalog=toolreg.catalog_text(reg), max_steps=steps_cap)
    try:
        plan_raw = await ai.complete("ai-agent-plan", plan_prompt, user)
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"AI planning failed: {str(e)[:150]}")

    try:
        plan = ai.parse_json(plan_raw).get("plan", [])
    except Exception:
        plan = []
    plan = [p for p in plan if isinstance(p, dict) and p.get("tool")][:steps_cap]

    steps = []
    for p in plan:
        name = str(p.get("tool"))
        args = p.get("args") or {}
        res = await toolreg.exec_tool(name, args, reg)
        steps.append({"tool": name, "args": args, "why": p.get("why", ""),
                      "summary": toolreg.summarize(name, res), "result": res})

    results_text = json.dumps([{"tool": s["tool"], "args": s["args"], "summary": s["summary"], "result": s["result"]} for s in steps],
                              default=str)[:60000]
    report_prompt = f"{SYSTEM_REPORT}\n\nOperator instruction: {body.instruction}\nTarget: {body.target or '(n/a)'}"
    try:
        final = await ai.complete("ai-agent-report", report_prompt, f"Tool results (JSON):\n{results_text}")
    except Exception:
        final = "_Report generation failed — see raw tool results below._"

    return {"instruction": body.instruction, "target": body.target,
            "plan": [{"tool": p.get("tool"), "args": p.get("args"), "why": p.get("why", "")} for p in plan],
            "steps": steps, "final_report": final}
