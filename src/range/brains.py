"""Provider-agnostic "operator decision" calls for the agent range.

Every operated site (:class:`~src.range.agent_site.AgentSite`) and society agent
makes the same shape of call: hand the model ONE structured tool and force it to
fill that tool in, then read the arguments back as a decision dict. This module
hides the per-provider differences (Anthropic / OpenAI / Google) behind two
functions:

    operator_decision(model, system, tool, messages, *, max_tokens, client) -> dict
    check_model_access(model) -> (ok: bool, reason: str)

``tool`` is ``{"name", "description", "input_schema"}`` (input_schema is JSON
Schema). ``messages`` is a list of ``{"role": "user"|"assistant", "text": str}``.
The provider is resolved from the model id via :data:`agents.MODEL_CHOICES`
(with a name-prefix fallback), so the rest of the range never imports a vendor
SDK directly.

Only the Anthropic adapter is exercised in this repo's tests; the OpenAI and
Google adapters are written to each SDK's documented shape but need a real key
to verify. They lazy-import their SDK and raise a clear install/key message.
"""

from __future__ import annotations

import json
from typing import Any


def provider_for(model: str) -> str:
    """Which provider serves ``model`` - from the registry, else a name guess."""
    try:
        from src.range.agents import MODEL_CHOICES
        for m in MODEL_CHOICES:
            if m.get("id") == model:
                return m.get("provider", "anthropic")
    except Exception:
        pass
    low = (model or "").lower()
    if low.startswith(("gpt", "o1", "o3", "o4", "chatgpt")):
        return "openai"
    if low.startswith(("gemini", "models/gemini")):
        return "google"
    return "anthropic"


def error_reason(e: Exception) -> str:
    """Best clean human message out of a provider SDK error."""
    body = getattr(e, "body", None)
    if isinstance(body, dict) and isinstance(body.get("error"), dict):
        msg = body["error"].get("message")
        if msg:
            return str(msg)
    return getattr(e, "message", None) or str(e)


def _usage(resp, in_attr, out_attr) -> dict:
    """Normalize a provider response's token usage to input/output counts."""
    u = getattr(resp, "usage", None) or getattr(resp, "usage_metadata", None)
    if u is None:
        return {}
    return {"input_tokens": int(getattr(u, in_attr, 0) or 0),
            "output_tokens": int(getattr(u, out_attr, 0) or 0)}


# --- per-provider adapters: (...) -> (decision dict, usage dict)


def _anthropic(model, system, tool, messages, max_tokens, client):
    import anthropic
    client = client or anthropic.Anthropic()
    resp = client.messages.create(
        model=model, max_tokens=max_tokens,
        system=[{"type": "text", "text": system,
                 "cache_control": {"type": "ephemeral"}}],
        tools=[{"name": tool["name"], "description": tool["description"],
                "input_schema": tool["input_schema"]}],
        tool_choice={"type": "tool", "name": tool["name"],
                     "disable_parallel_tool_use": True},
        messages=[{"role": m["role"],
                   "content": [{"type": "text", "text": m["text"]}]}
                  for m in messages])
    action = next((b.input or {} for b in resp.content
                   if getattr(b, "type", None) == "tool_use"), {})
    return action, _usage(resp, "input_tokens", "output_tokens")


def _openai(model, system, tool, messages, max_tokens, client):
    try:
        import openai
    except ImportError as e:
        raise RuntimeError("OpenAI models need the 'openai' package "
                           "(pip install openai).") from e
    client = client if _is_openai(client) else openai.OpenAI()
    msgs = [{"role": "system", "content": system}]
    msgs += [{"role": m["role"], "content": m["text"]} for m in messages]
    resp = client.chat.completions.create(
        model=model, max_tokens=max_tokens, messages=msgs,
        tools=[{"type": "function", "function": {
            "name": tool["name"], "description": tool["description"],
            "parameters": tool["input_schema"]}}],
        tool_choice={"type": "function", "function": {"name": tool["name"]}})
    calls = resp.choices[0].message.tool_calls or []
    action = json.loads(calls[0].function.arguments or "{}") if calls else {}
    return action, _usage(resp, "prompt_tokens", "completion_tokens")


def _google(model, system, tool, messages, max_tokens, client):
    try:
        from google import genai
        from google.genai import types
    except ImportError as e:
        raise RuntimeError("Gemini models need the 'google-genai' package "
                           "(pip install google-genai).") from e
    client = client if _is_genai(client) else genai.Client()
    fn = types.FunctionDeclaration(
        name=tool["name"], description=tool["description"],
        parameters=tool["input_schema"])
    config = types.GenerateContentConfig(
        system_instruction=system, max_output_tokens=max_tokens,
        tools=[types.Tool(function_declarations=[fn])],
        tool_config=types.ToolConfig(
            function_calling_config=types.FunctionCallingConfig(
                mode="ANY", allowed_function_names=[tool["name"]])))
    contents = [types.Content(
        role=("user" if m["role"] == "user" else "model"),
        parts=[types.Part(text=m["text"])]) for m in messages]
    resp = client.models.generate_content(
        model=model, contents=contents, config=config)
    usage = _usage(resp, "prompt_token_count", "candidates_token_count")
    for cand in (resp.candidates or []):
        for part in (getattr(cand.content, "parts", None) or []):
            call = getattr(part, "function_call", None)
            if call is not None:
                return dict(call.args or {}), usage
    return {}, usage


def _is_openai(client) -> bool:
    return client is not None and type(client).__module__.split(".")[0] == "openai"


def _is_genai(client) -> bool:
    return client is not None and type(client).__module__.split(".")[0] == "google"


_ADAPTERS = {"anthropic": _anthropic, "openai": _openai, "google": _google}


def operator_decision(model: str, system: str, tool: dict[str, Any],
                      messages: list[dict[str, str]], *, max_tokens: int = 900,
                      client: Any = None) -> tuple[dict[str, Any], dict[str, int]]:
    """Force ``model`` to fill ``tool`` once; return ``(decision, usage)``.

    ``decision`` is the tool arguments as a dict; ``usage`` is normalized
    ``{"input_tokens", "output_tokens"}`` (empty if the provider didn't report
    it). ``client`` is an optional pre-built/injected client (e.g. a replay
    client) used only when it matches the resolved provider; otherwise a
    provider client is built from the environment.
    """
    adapter = _ADAPTERS.get(provider_for(model), _anthropic)
    action, usage = adapter(model, system, tool, messages, max_tokens, client)
    return (action or {}), (usage or {})


_PING_TOOL = {
    "name": "ack",
    "description": "Acknowledge you can run by calling this once.",
    "input_schema": {"type": "object",
                     "properties": {"ok": {"type": "boolean"}},
                     "required": ["ok"]},
}


def check_model_access(model: str) -> tuple[bool, str]:
    """One tiny forced call so a model that cannot actually run (no credit,
    bad/missing key, no access, package missing) fails before any agent starts.
    Returns ``(ok, reason)``; ``reason`` is a clean human message on failure.
    """
    try:
        operator_decision(model, "Reply by calling the ack tool.",
                          _PING_TOOL, [{"role": "user", "text": "ping"}],
                          max_tokens=16)
        return True, ""
    except Exception as e:  # noqa: BLE001 - any provider/SDK failure
        return False, error_reason(e)
