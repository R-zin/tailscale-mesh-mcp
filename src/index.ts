import process from "node:process";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { TailscaleClient } from "./tailscale/client.js";
import { logger } from "./utils/logger.js";

// Initialize the Tailscale client using environment configurations
const tailscale = new TailscaleClient();

// Create the Model Context Protocol (MCP) server instance
const server = new McpServer({
  name: "tailscale-mesh-mcp",
  version: "0.3.0",
});

/**
 * Tool: list_devices
 * Lists devices across the Tailscale mesh network with their status, IPs, OS, and metadata.
 */
server.tool(
  "list_devices",
  "List nodes on the Tailscale mesh network with online status, OS, Tailscale IPv4/IPv6 addresses, tags, and last seen timestamps.",
  {
    source: z
      .enum(["auto", "cli", "api"])
      .optional()
      .default("auto")
      .describe("Backend query source: 'cli' (local daemon), 'api' (Tailscale REST API v2), or 'auto' (tries CLI, falls back to API)"),
    status: z
      .enum(["all", "online", "offline"])
      .optional()
      .default("all")
      .describe("Filter devices by connectivity status ('all', 'online', or 'offline')"),
  },
  async ({ source, status }) => {
    logger.info(`Invoking list_devices with source: ${source}, status: ${status}`);

    try {
      const allDevices = await tailscale.listDevices(source);

      const filtered = allDevices.filter((dev) => {
        if (status === "online") return dev.online === true;
        if (status === "offline") return dev.online === false;
        return true;
      });

      const summary = {
        total: allDevices.length,
        filtered: filtered.length,
        onlineCount: allDevices.filter((d) => d.online).length,
        offlineCount: allDevices.filter((d) => !d.online).length,
        source: allDevices[0]?.source || source,
        devices: filtered,
      };

      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(summary, null, 2),
          },
        ],
      };
    } catch (error: any) {
      logger.error("Failed to execute list_devices", error);
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Error querying Tailscale devices: ${error.message}\n\nTroubleshooting tips:\n1. Ensure Tailscale is installed and tailscaled is running.\n2. Or provide TAILSCALE_API_KEY and TAILSCALE_TAILNET in the environment.\n3. If tailscale binary is in a non-standard path, specify TAILSCALE_CLI_PATH.`,
          },
        ],
      };
    }
  }
);

/**
 * Tool: check_connectivity
 * Executes internal latency pings, port reachability tests, or SSH checks across mesh nodes.
 */
server.tool(
  "check_connectivity",
  "Execute internal network latency pings (tailscale ping), TCP port tests, or SSH health checks across mesh nodes.",
  {
    type: z
      .enum(["ping", "port", "ssh"])
      .describe("Check type: 'ping' for WireGuard/DERP latency, 'port' for TCP socket test, or 'ssh' for Tailscale SSH verification"),
    target: z
      .string()
      .min(1)
      .describe("Target node Tailscale IP address (100.x.y.z), MagicDNS name (node.tailnet.ts.net), or hostname"),
    port: z
      .number()
      .int()
      .min(1)
      .max(65535)
      .optional()
      .describe("Target TCP port number (required if type is 'port')"),
    count: z
      .number()
      .int()
      .min(1)
      .max(10)
      .optional()
      .default(3)
      .describe("Number of ping packets to send (for ping type, default 3)"),
    timeoutMs: z
      .number()
      .int()
      .min(500)
      .max(30000)
      .optional()
      .default(5000)
      .describe("Timeout in milliseconds for the connectivity probe (default 5000ms)"),
    sshCommand: z
      .string()
      .optional()
      .default("exit 0")
      .describe("Safe command to execute over Tailscale SSH (for ssh type, default: 'exit 0')"),
    dryRun: z
      .boolean()
      .optional()
      .default(false)
      .describe("Simulate the connectivity check without executing network commands or connections"),
  },
  async (params) => {
    logger.info(`Invoking check_connectivity (${params.type} -> ${params.target})`);

    // Strict validation
    if (params.type === "port" && !params.port) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: "Validation Error: The 'port' parameter is required when check type is 'port'.",
          },
        ],
      };
    }

    try {
      const result = await tailscale.checkConnectivity(params);

      return {
        isError: !result.success && !result.dryRun,
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error: any) {
      logger.error("Failed to execute check_connectivity", error);
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Connectivity check error: ${error.message}`,
          },
        ],
      };
    }
  }
);

/**
 * Tool: manage_funnel
 * Dynamically expose or unexpose local ports and services to the public internet using Tailscale Funnel.
 */
server.tool(
  "manage_funnel",
  "Manage Tailscale Funnel: inspect status, dynamically expose local ports to the public internet, unexpose public ports, or reset configuration.",
  {
    action: z
      .enum(["status", "expose", "unexpose", "reset"])
      .describe("Operation to perform: 'status' (view active public endpoints), 'expose' (route public web traffic to a local port), 'unexpose' (disable public routing for a port), or 'reset' (clear all funnel/serve routes)"),
    localPort: z
      .number()
      .int()
      .min(1)
      .max(65535)
      .optional()
      .describe("Local backend service port to expose (required when action is 'expose', e.g. 3000, 8080)"),
    publicPort: z
      .union([z.literal(443), z.literal(8443), z.literal(10000)])
      .optional()
      .default(443)
      .describe("Public listening port permitted by Tailscale Funnel: 443 (default), 8443, or 10000"),
    path: z
      .string()
      .optional()
      .default("/")
      .describe("Public URL mount path prefix (default: '/')"),
    targetHost: z
      .string()
      .optional()
      .default("127.0.0.1")
      .describe("Target host running the local service (default: '127.0.0.1')"),
    protocol: z
      .enum(["http", "https"])
      .optional()
      .default("http")
      .describe("Backend service protocol (default: 'http')"),
    allowDangerousPorts: z
      .boolean()
      .optional()
      .default(false)
      .describe("Bypass safety guardrails when exposing sensitive ports (e.g. database ports 5432, 6379, 3306 or SSH 22)"),
    confirm: z
      .boolean()
      .optional()
      .default(false)
      .describe("Explicit confirmation required for destructive actions like 'reset'"),
    dryRun: z
      .boolean()
      .optional()
      .default(false)
      .describe("Simulate the funnel operation without modifying daemon state or exposing routes"),
  },
  async (params) => {
    logger.info(`Invoking manage_funnel (action: ${params.action})`);

    if (params.action === "expose" && !params.localPort) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: "Validation Error: 'localPort' is required when action is 'expose'.",
          },
        ],
      };
    }

    try {
      const result = await tailscale.manageFunnel(params);

      return {
        isError: !result.success && !result.dryRun,
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error: any) {
      logger.error("Failed to execute manage_funnel", error);
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `Funnel management error: ${error.message}`,
          },
        ],
      };
    }
  }
);

/**
 * Tool: audit_acl_rules
 * Parses HuJSON ACL files, audits security policies for zero-trust posture, detects vulnerabilities, and previews diffs.
 */
server.tool(
  "audit_acl_rules",
  "Audit Tailscale ACL rules: parse HuJSON policy, check zero-trust security postures, detect wildcard risks and sensitive port leaks, validate against API, and preview semantic diffs.",
  {
    policy: z
      .string()
      .optional()
      .describe(
        "HuJSON or JSON text of the Tailscale ACL policy to audit. If omitted, fetches active policy from Tailscale REST API."
      ),
    proposedPolicy: z
      .string()
      .optional()
      .describe(
        "Proposed HuJSON policy to compare against the active or provided policy. Generates unified diff and semantic risk analysis."
      ),
    source: z
      .enum(["auto", "api", "provided"])
      .optional()
      .default("auto")
      .describe(
        "Source for base policy: 'auto' (prefers provided policy, falls back to API), 'api' (fetches from Tailscale REST API), or 'provided'"
      ),
    validateWithApi: z
      .boolean()
      .optional()
      .default(false)
      .describe(
        "Submit policy to Tailscale REST API v2 validate endpoint (/acl/validate) for official compiler verification (requires TAILSCALE_API_KEY)"
      ),
    strict: z
      .boolean()
      .optional()
      .default(false)
      .describe(
        "If true, returns isError: true when critical or high severity security findings are detected"
      ),
    formatOutput: z
      .boolean()
      .optional()
      .default(true)
      .describe("Include formatted HuJSON output in response"),
  },
  async (params) => {
    logger.info("Invoking audit_acl_rules tool");

    try {
      const result = await tailscale.auditAclRules(params);

      return {
        isError: !result.valid,
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error: any) {
      logger.error("Failed to execute audit_acl_rules", error);
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `ACL audit error: ${error.message}\n\nTips:\n1. If querying live tailnet ACLs, ensure TAILSCALE_API_KEY is configured in the environment.\n2. Or provide the policy text directly via the 'policy' parameter.\n3. Verify that the input conforms to HuJSON / JSON syntax.`,
          },
        ],
      };
    }
  }
);

/**
 * Main application entrypoint
 */
async function main() {
  logger.info("Starting tailscale-mesh-mcp server over Stdio transport...");

  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info("tailscale-mesh-mcp server is active and listening on stdio.");
}

// Global lifecycle error handlers
process.on("SIGINT", () => {
  logger.info("Received SIGINT, shutting down gracefully...");
  process.exit(0);
});

process.on("SIGTERM", () => {
  logger.info("Received SIGTERM, shutting down gracefully...");
  process.exit(0);
});

process.on("uncaughtException", (error: Error) => {
  logger.error("Uncaught exception in server process", error);
  process.exit(1);
});

process.on("unhandledRejection", (reason: unknown) => {
  logger.error("Unhandled promise rejection in server process", reason instanceof Error ? reason : { reason });
});

// Run server
main().catch((error: Error) => {
  logger.error("Fatal startup error in main()", error);
  process.exit(1);
});
