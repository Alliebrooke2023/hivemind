# Effort Tiers

One dial for how hard an agent thinks.

## The problem

"How much reasoning should this agent spend?" was previously spread across four
unrelated settings, each configured separately per agent:

| Knob | Where it lived |
|---|---|
| Model strength | `llm_model`, or `ModelRouter`'s task detection when set to `auto` |
| Extended thinking | `thinking_enabled` + `thinking_budget_tokens` |
| Tool-call ceiling | `tool_loop_config.circuit_breaker_threshold` |
| Wall-clock ceiling | the `TOOL_LOOP_TIMEOUT` env var (global, not per agent) |

These are correlated in practice — an agent worth giving a top model is usually
also worth giving thinking budget and a longer leash — but nothing tied them
together. Setting them individually meant four decisions per agent, and easy to
get inconsistent: a top-tier model with a 12-call ceiling wastes the model, and a
cheap model with a 30-minute timeout just fails slowly.

An effort tier quantizes that continuum into four named steps.

## The tiers

| Tier | Model | Thinking | Tool calls | Turn timeout |
|---|---|---|---|---|
| **Quick** | capped at cheap | forced off | 12 | 60s |
| **Standard** | task detection decides | agent's own setting | 100 | 300s |
| **Deep** | floor of mid | on, ≥10k tokens | 150 | 900s |
| **Max** | pinned to top | on, ≥32k tokens | 250 | 1800s |

**Quick** — triage, formatting, status checks. Anything you'd rather have
answered in seconds than perfectly.

**Standard** — the default, and deliberately identical to how Hivemind behaved
before tiers existed. Existing agents are backfilled to it, so this change is a
no-op until you move an agent off it.

**Deep** — multi-file changes, debugging, design work.

**Max** — architecture, security review, migrations. Jobs where a wrong answer
costs more than the tokens.

## How it resolves

First match wins:

1. An explicit `effort:` argument (a one-off override for a single run)
2. `session.metadata["effort"]` (per-conversation override)
3. `agent.effort` (the agent's configured default)
4. `"standard"`

An unknown value anywhere in that chain falls back to `standard` rather than
raising — a bad tier name can't break a chat turn.

## What it does and doesn't override

A tier is a **baseline, not a mandate**. `Agent#effective_tool_loop_config`
layers three sources:

```
DEFAULT_LOOP_CONFIG  →  effort tier  →  the agent's own tool_loop_config
```

The agent's explicit config is merged last, so an agent hand-tuned before tiers
existed keeps every setting it had. Set `history_size` explicitly and the tier
won't touch it — but the tier still supplies the keys you didn't set.

Two deliberate exceptions, where the tier does win:

- **`TOOL_LOOP_TIMEOUT` stays authoritative.** It's an infrastructure guard —
  don't hold a Sidekiq thread too long — so a tier can only lower the ceiling,
  never raise it past what an operator set. `Max` on a box configured with
  `TOOL_LOOP_TIMEOUT=120` gets 120 seconds, not 1800.
- **`Quick` forces thinking off** even if the agent enables it. That's the
  point of the tier; if you want thinking, you don't want quick.

For model selection, effort **clamps** rather than dictates, so `ModelRouter`'s
task detection stays meaningful:

```ruby
Agents::EffortTier.clamp_model_tier("cheap", "deep")  # => "mid"   (floor raised)
Agents::EffortTier.clamp_model_tier("top",   "deep")  # => "top"   (detection kept)
Agents::EffortTier.clamp_model_tier("top",   "quick") # => "cheap" (ceiling applied)
```

Clamping only applies when the agent's `llm_model` is `auto`. A pinned model
stays pinned — effort still drives thinking, tool ceiling, and timeout.

## Usage

**Per agent** — the Effort section on the agent form, or:

```ruby
agent.update!(effort: "deep")
```

**Per conversation** — write to session metadata:

```ruby
session.update!(metadata: session.metadata.merge("effort" => "max"))
```

**Per run** — pass it through `llm_options`:

```ruby
Agents::ToolLoop.call(..., options: { effort: "quick" })
```

**Inspecting a resolution:**

```ruby
agent.effective_effort(session: session)          # => "deep"
agent.effort_profile(session: session)            # => the full tier hash
Agents::EffortTier.thinking_for(agent, "deep")    # => { enabled: true, budget_tokens: 10_000 }
```

## Swarm import/export

`effort` round-trips through swarm files as a per-agent key, omitted when it's
`standard` so exports stay diff-friendly:

```yaml
agents:
  - name: Architect
    role: Staff Engineer
    effort: max
```

Invalid values are rejected at validation time with the list of valid names.

## Adding or retuning a tier

Everything lives in `TIERS` in `app/services/agents/effort_tier.rb`. Each entry
needs `model_tier_floor`/`model_tier_ceiling` (or `nil`), a `thinking` mode
(`:on`, `:off`, `:inherit`), `thinking_budget_tokens`, `loop_timeout_seconds`,
and a `tool_loop_config` hash. Adding a key to `TIERS` is enough — the form
select, swarm validation, and the resolver all read from it.

Keep `standard` matching `Agent::DEFAULT_LOOP_CONFIG`. That equality is what
makes the feature backward-compatible, and there's a spec asserting it.
