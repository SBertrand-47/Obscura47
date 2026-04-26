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
from src.agent.ledger import (
    LEDGER_PROTOCOL_VERSION,
    LedgerClient,
    LedgerError,
    LedgerState,
    Transaction,
    build_ledger_app,
)
from src.agent.observatory import (
    OBSERVATORY_PROTOCOL_VERSION,
    Event,
    EventSink,
    JsonlSink,
    MemorySink,
    MultiSink,
    NullSink,
    Observer,
    ObservatoryState,
    RemoteSink,
    build_observatory_app,
    build_observer_from_flags,
    new_session_id,
)
from src.agent.runtime import AgentRuntime
from src.agent.sandbox import Sandbox, SandboxPolicy, SandboxViolation
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
    "Event",
    "EventSink",
    "JsonlSink",
    "LEDGER_PROTOCOL_VERSION",
    "LedgerClient",
    "LedgerError",
    "LedgerState",
    "MemorySink",
    "MultiSink",
    "NullSink",
    "OBSERVATORY_PROTOCOL_VERSION",
    "ObservatoryState",
    "Observer",
    "PROTOCOL_VERSION",
    "ParamSpec",
    "RemoteSink",
    "Request",
    "Response",
    "Sandbox",
    "SandboxPolicy",
    "SandboxViolation",
    "StreamingResponse",
    "Tool",
    "ToolCallError",
    "ToolError",
    "ToolRegistry",
    "Topic",
    "Transaction",
    "build_ledger_app",
    "build_observatory_app",
    "build_observer_from_flags",
    "new_session_id",
    "serve_app",
]
