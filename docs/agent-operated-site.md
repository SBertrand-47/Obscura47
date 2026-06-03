# An AI agent operating a website on Obscura

The vision in one demo you can show anyone: **a real AI model runs a live
website on Obscura, and a dashboard shows its mind** - every visitor, every
response it decided, and why.

This is not a mock. The hosting is the same path the network already uses to
publish services (`AgentRuntime` over a running node); what is new is the
*operator* - a model behind the routes that decides each response, and a
`site.serve` event recording what it decided and the reasoning behind it.

## See it (no API key)

```bash
OBSCURA_MODE=range python -m src.range agentsite --html agent-site.html
```

That replays a built-in session - "The Stacks", an AI archivist running a
reading-room - and writes the dashboard. A committed copy lives at
[`sample/agent-site-dashboard.html`](sample/agent-site-dashboard.html).

The dashboard's **Operated website** panel shows every request as a recorded
decision:

| request | visitor | status | operator rationale |
| --- | --- | --- | --- |
| `GET /essays/on-silence` | ada | 200 | "ada asked for a specific essay; I serve it - this is what the archive is for." |
| `GET /../../etc/passwd` | cy | 400 | "A path-traversal probe - not a reader, an intruder testing the walls. I refuse and note it." |
| `GET /admin` | cy | 403 | "Same visitor fishing for an admin panel; consistent with reconnaissance, so I hold the line." |

The point lands immediately: the operator serves genuine readers, recognises a
probe for what it is, refuses it, and *says why* - and all of that is
attributable, visitor by visitor, because the site is observable by
construction.

## How it works

`src/range/agent_site.py` adds one class, `AgentSite`:

* a catch-all `AgentApp` route hands every request to the model with the
  request and the site's running memory as context;
* the model calls one tool, `serve`, returning the response body, a status, a
  one-line **rationale**, and optionally something to **remember** for future
  visitors;
* the operator emits a `site.serve` research event under the visitor's session
  id, alongside the `request.in` / `response.out` the app already emits - so
  the operator's decision and the traffic it produced share one timeline.

Because the events use the same plane as everything else in the range,
`src/range/crossplane.py` joins them with no special case: a site-operation
lens (`_operated_site`), a narrative line, and the dashboard panel. The model
client is injectable, so the whole thing replays deterministically with no key
(that is what the demo does).

## Run it live on the overlay

On a machine with a running node and an `ANTHROPIC_API_KEY`:

```bash
OBSCURA_MODE=range python -m src.range agentsite --serve \
    --name the-stacks --persona "You run a reading-room on Obscura..." \
    --jsonl the-stacks-events.jsonl
```

This publishes a real `.obscura` address anyone on the overlay can visit; each
visit is decided by the model and logged to `the-stacks-events.jsonl`. Render
the live dashboard from that log at any time with `python -m src.range
observe`. Host and visitors are naturally on different machines here, which is
exactly the multi-machine setup hidden-service round-trips need.

## Why this is the go-to-market piece

It is the vision made visible and shareable: an autonomous agent doing real
work on a network, with full observability of what it is doing and why -
including the moment it catches someone probing it. That is a screenshot and a
short clip, not a paragraph. See [`live-society.md`](live-society.md) for the
two-plane observability architecture this sits on, and
[`agent-security-range.md`](agent-security-range.md) for the broader product.
