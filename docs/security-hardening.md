# Security Hardening

What this change closes, what it deliberately does not, and what you still
need to decide.

## The hole

An agent tool call could reach the Docker Engine API and, from there, take
root on the host. The chain:

1. `docker-compose.yml` runs a `docker-proxy` service that uses `socat` to
   expose the **entire Docker socket as plaintext TCP** on `internal:2375` —
   no TLS, no authentication. Full Docker API access is equivalent to root on
   the host.
2. `app`, `worker-system` and `worker-agents` all sit on that `internal`
   network and are given `DOCKER_HOST=tcp://docker-proxy:2375`.
3. `http_request` is a **builtin** tool (so it needs no approval), permits
   `POST`, runs inside those containers, and is enabled in 16 of the 160
   shipped agent templates.
4. Its only guard tried to parse the *hostname itself* as an IP literal:

   ```ruby
   ip = IPAddr.new(host) rescue nil
   return false unless ip   # any hostname => "not private" => allowed
   ```

   `IPAddr.new("docker-proxy")` raises, so the method returned `false`,
   meaning "not a private IP", and the request proceeded.
5. The guard was additionally wrapped in `if Rails.env.production?`, and
   `docker-compose.dev.yml` sets `RAILS_ENV=development` — so under
   `bin/dev-up` even the broken check never ran.
6. The second layer, `NetworkEgress::PolicyCheck`, is correctly centralised in
   `Tools::Executor`, but `agents.egress_policy` defaults to `{}` and the
   policy treated a blank mode as allow-all. Opt-in, off by default.

The part that matters most: no human is in that loop. A prompt injection in a
web page, email or chat message that the agent reads is enough.

## What changed

**`NetworkEgress::AddressGuard`** (new) resolves a URL to its actual
destination addresses and decides in two tiers:

| Tier | Covers | Overridable? |
|---|---|---|
| **Hard** | Docker Engine API ports (2375/2376), non-HTTP schemes, unparseable URLs | **No** — by any policy |
| **Soft** | loopback, RFC1918, link-local (incl. `169.254.169.254`), CGNAT, multicast, IPv6 ULA/link-local, IPv4-mapped equivalents | Yes, by an explicit allowlist entry |

Three properties worth stating plainly:

- **It resolves DNS.** Hostnames are looked up and *every* returned address is
  checked, so a name with one public and one private record does not pass on
  the public one.
- **It fails closed.** A name that cannot be resolved is denied. The old code
  had two `rescue … false` paths that failed open.
- **Hard denials are absolute.** You cannot allowlist your way into the Docker
  socket, because there is no configuration where that is legitimate.

**`PolicyCheck`** now runs the guard *before and independently of* the
per-agent policy, so an agent with nothing configured is still protected. Guard
denials are always written to the audit log, regardless of the policy's
`log_blocked` flag, because they are security events.

**`custom_script` no longer runs in the application container.** It previously
called `Open3.capture3("bash", "-c", command)` in the Rails/Sidekiq process —
next to `DOCKER_HOST`. It now runs inside the `workspace` container via
`docker exec`, the same way `shell` always has. When that container is
unreachable it **refuses** rather than falling back to local execution; a
fallback in the app container would reintroduce the escape.

**The script scanner** (`Agents::ToolCreator::FORBIDDEN_PATTERNS`) had no
container-runtime patterns at all — it blocked `curl … | bash` while
`curl -X POST http://docker-proxy:2375/…` scanned clean. Added `docker`,
`docker.sock`, `DOCKER_HOST`, ports 2375/2376, and other runtimes.

**Mission Control binds to loopback by default.** `ports:` published on
`0.0.0.0`, exposing a dashboard with no network-level auth to the whole LAN.
Override with `APP_BIND=0.0.0.0` if you need LAN access.

## Behaviour change you may notice

Agents can no longer reach private or loopback addresses by default. If you
were deliberately pointing a tool at an internal API, give that agent an
explicit allowlist entry:

```json
{
  "mode": "allowlist",
  "rules": [{ "pattern": "10.1.2.3" }, { "pattern": "*.internal.example" }],
  "log_blocked": true
}
```

Only the soft tier can be overridden this way. The Docker API cannot.

## Not fixed here — decide deliberately

- **`docker-proxy` still exposes the raw socket.** This change blocks the
  paths agents use to reach it, but the socket is still sitting there
  unauthenticated on the internal network, so any future code-execution bug in
  the app container is still host compromise. The durable fix is a filtering
  proxy (e.g. `tecnativa/docker-socket-proxy`) exposing only the endpoints
  Hivemind actually needs — container list/inspect and exec, for
  `ShellExecutor` and `Platform::*` — or moving `docker-proxy` onto a network
  `worker-agents` cannot reach. That is a deployment change with real
  blast radius, so it is called out rather than done silently.
- **`ShellExecutor`'s local fallback.** When Docker is unavailable it still
  falls back to running the command in the app container. Left alone to avoid
  breaking single-container setups, but it is the same class of risk as the
  `custom_script` issue.
- **The connector port** (`3002`) is still published on all interfaces,
  because some messaging channels need inbound webhooks. Restrict it at your
  firewall if you only use polling-based channels.
- **Postgres** uses hardcoded `hivemind:hivemind`, but `db` publishes no
  ports, so it is internal-only. Do not add a port mapping without changing
  the password.
- **Dependency CVEs were not audited.** `bin/bundler-audit` and
  `bin/brakeman` ship with the repo and should be run in CI.

## What was already sound

Worth recording so the above lands in proportion: secrets hygiene is clean
(`.gitignore` covers `.env*`, `config/master.key`, `config/*.key`; only
`.env.example` is tracked, and no live-looking keys appear in tracked files).
The internal API (`Internal::ToolsController`) is fail-closed and uses
`ActiveSupport::SecurityUtils.secure_compare`. The vault uses ActiveRecord
encryption and the script scanner blocks scripts mentioning vault/token/secret.
The `workspace` container's passwordless `sudo` is fine — it has no
`DOCKER_HOST`, which is exactly the right design.
