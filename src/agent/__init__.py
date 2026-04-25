"""Reference self-hosting harness for `.obscura` services.

Provides a small wrapper around :mod:`src.core.hidden_service` that
brings up a local HTTP application and exposes it on a `.obscura`
address in one step. Also ships a minimal HTTP client that dials
other `.obscura` services through a local Obscura HTTP CONNECT proxy.

The pieces are intentionally small. They exist as a starting point
for anyone who wants to publish an HTTP API as a hidden service
without writing the descriptor / rendezvous / circuit plumbing by
hand.
"""

from src.agent.app import AgentApp, Request, Response, StreamingResponse, serve_app
from src.agent.client import AgentClient, AgentResponse, ToolCallError
from src.agent.runtime import AgentRuntime
from src.agent.tools import (
    PROTOCOL_VERSION,
    ParamSpec,
    Tool,
    ToolError,
    ToolRegistry,
    Topic,
)

__all__ = [
    "AgentApp",
    "AgentClient",
    "AgentResponse",
    "AgentRuntime",
    "PROTOCOL_VERSION",
    "ParamSpec",
    "Request",
    "Response",
    "StreamingResponse",
    "Tool",
    "ToolCallError",
    "ToolError",
    "ToolRegistry",
    "Topic",
    "serve_app",
]
