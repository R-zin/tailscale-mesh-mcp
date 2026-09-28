# tailscale-mesh-mcp

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-blue.svg)](https://www.typescriptlang.org/)
[![Model Context Protocol](https://img.shields.io/badge/MCP-1.30-purple.svg)](https://modelcontextprotocol.io/)

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
- **Safe Dry-Run Modes**: Operators and AI agents can simulate network operations, latency checks, and configuration alterations before affecting live node state.

---

## Directory Layout

```
tailscale-mesh-mcp/
├── .env.example              # Template for environment configuration
├── .gitignore                # Git ignore rules
├── package.json              # Dependencies and build scripts
├── tsconfig.json             # TypeScript compiler settings (NodeNext)
├── tsup.config.ts            # Fast ESM bundle configuration
├── README.md                 # Project documentation
└── src/
    ├── index.ts              # MCP Server entrypoint & tool schema registration
    ├── tailscale/
    │   ├── client.ts         # Unified dual-engine Tailscale client (CLI + REST)
    │   └── types.ts          # Strongly typed domain models (Device, Peer, API)
    └── utils/
        ├── logger.ts         # Safe stderr-only logger for MCP Stdio compatibility
        └── validator.ts      # Hostname, IPv4, IPv6, and Port security validation
```

---

## Available Tools (Phase 1)

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

---

## Getting Started

### Prerequisites
- Node.js >= 18.0.0
- A Tailscale account and/or local `tailscale` CLI installed

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
- [ ] **Phase 2**: `manage_funnel` (dynamic port exposure & unexposure with safety controls).
- [ ] **Phase 3**: `audit_acl_rules` (HuJSON ACL parser, policy validation, diff preview).
- [ ] **Phase 4**: NetBird mesh VPN provider adapter.

---

## License

[Apache-2.0](LICENSE)
