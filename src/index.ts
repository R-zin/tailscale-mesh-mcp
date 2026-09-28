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
  version: "0.1.0",
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
