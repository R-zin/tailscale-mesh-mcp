# tailscale-mesh-mcp

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue.svg)](https://www.typescriptlang.org/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-1.30-purple.svg)](https://modelcontextprotocol.io/)
[![CI](https://github.com/R-zin/tailscale-mesh-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/R-zin/tailscale-mesh-mcp/actions/workflows/ci.yml)

A production-grade, zero-trust **Model Context Protocol (MCP)** server providing AI assistants direct, authenticated control over a private Tailscale / WireGuard mesh network.

Built with **TypeScript**, `@modelcontextprotocol/sdk`, and **Zod**, featuring a dual-backend architecture that unifies the local `tailscale` CLI engine with the Tailscale v2 REST API.

---

## Architecture Overview

```
                      +---------------------------------------+
                      |   AI Host (Claude, Cursor, AGY, etc.) |
                      +---------------------------------------+
                                          |
                                   JSON-RPC (stdio)
                                          |
                      +---------------------------------------+
                      |          tailscale-mesh-mcp           |
                      +---------------------------------------+
                             /                         \
         (Local Fast-Path / CLI)              (Fallback / Remote Admin)
                           /                             \
                          v                               v
             +-----------------------+       +------------------------+
             | tailscale daemon/CLI  |       | Tailscale REST API v2  |
             | (execFile argument-vec|       | (Bearer auth fetch)    |
             +-----------------------+       +------------------------+
                          |                               |
                          +---------------+---------------+
                                          |
                                          v
                              +-----------------------+
                              | Tailscale Mesh Tailnet|
                              +-----------------------+
```

### Key Engineering Tenets
- **Stdio Protocol Isolation**: Strictly streams structured diagnostics to `process.stderr`, preserving `process.stdout` exclusively for JSON-RPC message framing.
- **Dual-Engine Auto-Discovery**: Queries the local `tailscale` binary by default (zero cloud rate limits, sub-millisecond status), transparently falling back to the Tailscale REST API when running on remote instances or when daemon access is unavailable.
- **Zero Command Injection**: Disallows shell interpolation. All binary executions utilize `execFile` with sanitized argument vectors (`string[]`) and RFC 1123 / IP validation.
- **Strict Security Guardrails**: Built-in port protection blocks unauthenticated exposure of internal databases (e.g. Postgres 5432, Redis 6379, MySQL 3306) and daemon ports unless explicitly overridden. Destructive resets require confirmation flags.
- **Safe Dry-Run Modes**: Operators and AI agents can simulate network operations, latency checks, and configuration alterations before affecting live node state.

---

## Directory Layout

```
tailscale-mesh-mcp/
├── .github/
│   └── workflows/
│       └── ci.yml            # Automated CI pipeline (lint, test, build, smoke-test)
├── .env.example              # Template for environment configuration
├── .gitignore                # Git ignore rules
├── package.json              # Dependencies and build scripts
├── tsconfig.json             # TypeScript compiler settings (NodeNext)
├── tsup.config.ts            # Fast ESM bundle configuration
├── README.md                 # Project documentation
├── tests/                    # Automated unit & integration tests
│   └── acl.test.ts           # Test suite for HuJSON, ACL auditing, and diffs
└── src/
    ├── index.ts              # MCP Server entrypoint & tool schema registration
    ├── tailscale/
    │   ├── acl.ts            # Zero-trust policy auditor and security rule engine
    │   ├── client.ts         # Unified dual-engine Tailscale client (CLI + REST)
    │   ├── diff.ts           # Unified diff generator & semantic risk change detector
    │   ├── hujson.ts         # Zero-dependency HuJSON tokenizer and parser
    │   └── types.ts          # Strongly typed domain models (Device, Funnel, ACL)
    └── utils/
        ├── logger.ts         # Safe stderr-only logger for MCP Stdio compatibility
        └── validator.ts      # Hostname, IPv4, IPv6, Funnel, and Port security validation
```

---

## Available Tools

### 1. `list_devices`
Discovers all nodes across the mesh tailnet with connectivity status, OS details, IP allocations, and latency telemetry.

- **Parameters**:
  - `source` (`"auto"` | `"cli"` | `"api"`): Select data backend (default: `"auto"`).
  - `status` (`"all"` | `"online"` | `"offline"`): Filter nodes by presence (default: `"all"`).

### 2. `check_connectivity`
Performs active network diagnostics across mesh peers using latency probes (`tailscale ping`), TCP socket reachability checks, or safe SSH validation.

- **Parameters**:
  - `type` (`"ping"` | `"port"` | `"ssh"`): Probe type.
  - `target`: Target node Tailscale IP (e.g. `100.100.1.2`), MagicDNS name (`node.tailnet.ts.net`), or hostname.
  - `port` (number, 1-65535): Required when `type` is `"port"`.
  - `count` (number, 1-10): Ping packet count (default: `3`).
  - `timeoutMs` (number, 500-30000): Probe timeout in ms (default: `5000`).
  - `sshCommand` (string): Safe command executed via Tailscale SSH (default: `"exit 0"`).
  - `dryRun` (boolean): Simulates the check and validates arguments without initiating network packets.

### 3. `manage_funnel`
Inspects, exposes, unexposes, or resets public endpoints via Tailscale Funnel. Routes public internet traffic directly to local services with automatic Let's Encrypt TLS certificates.

- **Parameters**:
  - `action` (`"status"` | `"expose"` | `"unexpose"` | `"reset"`): Operation to perform.
  - `localPort` (number): Local backend service port (required for `expose`, e.g. `3000`, `8080`).
  - `publicPort` (`443` | `8443` | `10000`): Allowed public listening port (default: `443`).
  - `path` (string): Public URL mount path prefix (default: `"/"`).
  - `targetHost` (string): Local service host (default: `"127.0.0.1"`).
  - `protocol` (`"http"` | `"https"`): Backend service protocol (default: `"http"`).
  - `allowDangerousPorts` (boolean): Required override when attempting to expose sensitive ports (Postgres 5432, Redis 6379, MySQL 3306, MongoDB 27017, SSH 22, Docker 2375).
  - `confirm` (boolean): Required confirmation flag when executing destructive `reset`.
  - `dryRun` (boolean): Preview configuration and public URL without executing changes.

### 4. `audit_acl_rules`
Deeply parses HuJSON Tailscale ACL policies, performs static zero-trust security audits, detects wildcard exposures and unowned tags, generates unified diff previews, and validates policies against Tailscale's official compiler API.

- **Parameters**:
  - `policy` (string, optional): Raw HuJSON or JSON policy text to audit. If omitted, automatically fetches the active tailnet policy via Tailscale REST API v2.
  - `proposedPolicy` (string, optional): Proposed HuJSON policy to compare against the active or base policy. Computes git-style unified diffs and semantic risk factor deltas.
  - `source` (`"auto"` | `"api"` | `"provided"`): Base policy source (default: `"auto"`).
  - `validateWithApi` (boolean): If `true`, submits policy to Tailscale REST API `/acl/validate` compiler (requires `TAILSCALE_API_KEY`).
  - `strict` (boolean): Returns `isError: true` if critical or high severity security vulnerabilities are discovered.
  - `formatOutput` (boolean): Includes canonical, formatted HuJSON output in response (default: `true`).

- **Security & Integrity Checks**:
  - **Full-Mesh Wildcard Exposure**: Detects `*:* -> *:*` or unrestricted peer-to-peer rules.
  - **Sensitive Port Leaks**: Detects member-wide access to database and daemon ports (Postgres 5432, Redis 6379, MySQL 3306, MongoDB 27017, SSH 22, Docker 2375, Kubernetes 6443).
  - **TagOwners & Group Validation**: Detects unowned tags and undefined groups referenced across ACL rules and SSH policies.
  - **Tailscale SSH Posture**: Flags unchecked root access (`users: ["root"]` without `action: "check"`).
  - **Global Funnel Exposure**: Flags wildcard `nodeAttrs` granting Funnel public access to all members.
  - **Redundancy & Shadowing**: Detects duplicated or shadowed rules eclipsed by earlier entries.
  - **Zero-Trust Score**: Computes 0-100 security rating (A-F) based on security findings.

---

## Getting Started

### Prerequisites
- Node.js >= 18.0.0
- Tailscale installed and running on the host machine
- Tailscale Funnel attribute enabled in ACL policy (`nodeAttrs` with attribute `"funnel"`) and HTTPS enabled for public exposures

### Installation & Build

```bash
git clone https://github.com/R-zin/tailscale-mesh-mcp.git
cd tailscale-mesh-mcp

# Install dependencies
npm install

# Compile TypeScript and bundle ESM binary
npm run build
```

### Environment Variables

| Variable | Description | Default |
| :--- | :--- | :--- |
| `TAILSCALE_API_KEY` | Tailscale API access token (`tskey-api-...`) | _Optional (required for REST fallback)_ |
| `TAILSCALE_TAILNET` | Tailnet name or `-` for default | `-` |
| `TAILSCALE_CLI_PATH`| Explicit path to `tailscale` binary | Auto-detected from PATH / OS locations |
| `LOG_LEVEL` | Logging level (`debug`, `info`, `warn`, `error`) | `info` |

---

## MCP Client Configuration

### Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "tailscale": {
      "command": "node",
      "args": ["/absolute/path/to/tailscale-mesh-mcp/dist/index.js"],
      "env": {
        "TAILSCALE_API_KEY": "tskey-api-...",
        "TAILSCALE_TAILNET": "-"
      }
    }
  }
}
```

---

## Roadmap

- [x] **Phase 1**: Core runtime, CLI/REST dual-engine client, `list_devices`, `check_connectivity`.
- [x] **Phase 2**: `manage_funnel` (dynamic port exposure & unexposure with safety controls).
- [x] **Phase 3**: `audit_acl_rules` (HuJSON ACL parser, policy validation, diff preview).
- [ ] **Phase 4**: NetBird mesh VPN provider adapter.

---

## License

[Apache-2.0](LICENSE)
