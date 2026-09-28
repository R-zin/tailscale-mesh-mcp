import process from "node:process";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { Socket } from "node:net";
import { existsSync } from "node:fs";
import {
  TailscaleConfig,
  TailscaleDevice,
  TailscaleCliStatus,
  TailscaleApiDevicesResponse,
  ConnectivityCheckParams,
  ConnectivityCheckResult,
  CliExecutionResult,
} from "./types.js";
import { logger } from "../utils/logger.js";
import { isValidTarget, isValidPort, sanitizeCliArg } from "../utils/validator.js";

const execFileAsync = promisify(execFile);

/**
 * Standard known paths for the tailscale CLI across operating systems
 */
const DEFAULT_CLI_PATHS: string[] = [
  "tailscale", // System PATH
  "/Applications/Tailscale.app/Contents/MacOS/Tailscale", // macOS Standalone GUI App
  "/opt/homebrew/bin/tailscale", // macOS Apple Silicon Homebrew
  "/usr/local/bin/tailscale", // macOS Intel Homebrew / Linux manual install
  "/usr/bin/tailscale", // Standard Linux package
  "C:\\Program Files\\Tailscale\\tailscale.exe", // Windows standard installer
];

export class TailscaleClient {
  private readonly apiKey?: string;
  private readonly tailnet: string;
  private readonly apiBaseUrl: string;
  private readonly timeoutMs: number;
  private cliPath?: string;
  private cliPathResolved: boolean = false;

  constructor(config: TailscaleConfig = {}) {
    this.apiKey = config.apiKey || process.env.TAILSCALE_API_KEY;
    this.tailnet = config.tailnet || process.env.TAILSCALE_TAILNET || "-";
    this.apiBaseUrl = (config.apiBaseUrl || process.env.TAILSCALE_API_BASE_URL || "https://api.tailscale.com/api/v2").replace(/\/+$/, "");
    this.cliPath = config.cliPath || process.env.TAILSCALE_CLI_PATH;
    this.timeoutMs = config.timeoutMs || 15000;
  }

  /**
   * Resolves the working tailscale CLI executable path
   */
  public async resolveCliPath(): Promise<string> {
    if (this.cliPathResolved && this.cliPath) {
      return this.cliPath;
    }

    const candidatePaths = this.cliPath
      ? [this.cliPath, ...DEFAULT_CLI_PATHS]
      : DEFAULT_CLI_PATHS;

    for (const candidate of candidatePaths) {
      try {
        if (candidate !== "tailscale" && !existsSync(candidate)) {
          continue;
        }

        const { stdout } = await execFileAsync(candidate, ["version"], {
          timeout: 3000,
          windowsHide: true,
        });

        if (stdout && stdout.length > 0) {
          logger.debug(`Found functional Tailscale CLI at: ${candidate}`);
          this.cliPath = candidate;
          this.cliPathResolved = true;
          return candidate;
        }
      } catch {
        // Probe next candidate
      }
    }

    throw new Error(
      "Tailscale CLI binary not found. Ensure Tailscale is installed, in your PATH, or set TAILSCALE_CLI_PATH."
    );
  }

  /**
   * Safely executes local tailscale CLI command with strict argument vectors
   */
  public async executeCli(
    args: string[],
    options: { timeoutMs?: number; signal?: AbortSignal } = {}
  ): Promise<CliExecutionResult> {
    const binary = await this.resolveCliPath();
    const timeout = options.timeoutMs ?? this.timeoutMs;
    const sanitizedArgs = args.map(sanitizeCliArg);

    logger.debug(`Executing: ${binary} ${sanitizedArgs.join(" ")}`);

    try {
      const { stdout, stderr } = await execFileAsync(binary, sanitizedArgs, {
        timeout,
        signal: options.signal,
        windowsHide: true,
        maxBuffer: 10 * 1024 * 1024, // 10MB
      });

      return {
        stdout: stdout.toString().trim(),
        stderr: stderr.toString().trim(),
        exitCode: 0,
      };
    } catch (error: any) {
      logger.warn(`CLI command failed: ${binary} ${sanitizedArgs.join(" ")}`, {
        exitCode: error.code,
        stderr: error.stderr?.toString(),
      });

      return {
        stdout: error.stdout ? error.stdout.toString().trim() : "",
        stderr: error.stderr ? error.stderr.toString().trim() : error.message,
        exitCode: typeof error.code === "number" ? error.code : 1,
      };
    }
  }

  /**
   * Performs an authenticated request to the Tailscale REST API v2
   */
  public async fetchApi<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    if (!this.apiKey) {
      throw new Error(
        "Tailscale API key missing. Set TAILSCALE_API_KEY environment variable to use REST API features."
      );
    }

    const cleanEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
    const url = `${this.apiBaseUrl}${cleanEndpoint}`;

    logger.debug(`REST API Request: ${options.method || "GET"} ${url}`);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          Accept: "application/json",
          "Content-Type": "application/json",
          "User-Agent": "tailscale-mesh-mcp/0.1.0",
          ...options.headers,
        },
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => "");
        throw new Error(
          `Tailscale API error (${response.status} ${response.statusText}): ${errorText || "No response body"}`
        );
      }

      return (await response.json()) as T;
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * Retrieves parsed output from local `tailscale status --json`
   */
  public async getCliStatus(): Promise<TailscaleCliStatus> {
    const res = await this.executeCli(["status", "--json"]);
    if (res.exitCode !== 0) {
      throw new Error(`Failed to fetch local tailscale status: ${res.stderr || "Unknown error"}`);
    }

    try {
      return JSON.parse(res.stdout) as TailscaleCliStatus;
    } catch (err: any) {
      throw new Error(`Failed to parse Tailscale CLI JSON output: ${err.message}`);
    }
  }

  /**
   * List devices from either local CLI, remote REST API, or automatic fallback
   */
  public async listDevices(source: "auto" | "cli" | "api" = "auto"): Promise<TailscaleDevice[]> {
    if (source === "cli") {
      return this.listDevicesFromCli();
    }

    if (source === "api") {
      return this.listDevicesFromApi();
    }

    // "auto" strategy: Attempt local CLI first (zero API rate-limits), fallback to REST API
    try {
      return await this.listDevicesFromCli();
    } catch (cliErr: any) {
      logger.warn(`Local CLI device query failed, attempting REST API fallback: ${cliErr.message}`);

      if (this.apiKey) {
        return await this.listDevicesFromApi();
      }

      throw new Error(
        `Unable to query Tailscale devices. Local CLI error: ${cliErr.message}. REST API fallback unavailable (TAILSCALE_API_KEY is not set).`
      );
    }
  }

  /**
   * List and normalize devices using local CLI status
   */
  private async listDevicesFromCli(): Promise<TailscaleDevice[]> {
    const status = await this.getCliStatus();
    const devices: TailscaleDevice[] = [];

    // Normalize self node
    if (status.Self) {
      const self = status.Self;
      const ips = self.TailscaleIPs || [];
      devices.push({
        id: self.ID,
        name: self.DNSName ? self.DNSName.replace(/\.$/, "") : self.HostName,
        hostname: self.HostName,
        os: self.OS,
        online: self.Online,
        ipv4: ips.find((ip) => ip.includes(".")) || null,
        ipv6: ips.find((ip) => ip.includes(":")) || null,
        addresses: ips,
        tags: self.Tags || [],
        lastSeen: self.LastSeen || new Date().toISOString(),
        clientVersion: status.Version,
        isSelf: true,
        source: "cli",
        rxBytes: self.RxBytes,
        txBytes: self.TxBytes,
        curAddr: self.CurAddr,
        relay: self.Relay,
      });
    }

    // Normalize peer nodes
    if (status.Peer) {
      for (const peer of Object.values(status.Peer)) {
        const ips = peer.TailscaleIPs || [];
        devices.push({
          id: peer.ID,
          name: peer.DNSName ? peer.DNSName.replace(/\.$/, "") : peer.HostName,
          hostname: peer.HostName,
          os: peer.OS,
          online: peer.Online,
          ipv4: ips.find((ip) => ip.includes(".")) || null,
          ipv6: ips.find((ip) => ip.includes(":")) || null,
          addresses: ips,
          tags: peer.Tags || [],
          lastSeen: peer.LastSeen,
          clientVersion: null,
          isSelf: false,
          source: "cli",
          rxBytes: peer.RxBytes,
          txBytes: peer.TxBytes,
          curAddr: peer.CurAddr,
          relay: peer.Relay,
        });
      }
    }

    return devices;
  }

  /**
   * List and normalize devices using Tailscale REST API v2
   */
  private async listDevicesFromApi(): Promise<TailscaleDevice[]> {
    const data = await this.fetchApi<TailscaleApiDevicesResponse>(
      `/tailnet/${encodeURIComponent(this.tailnet)}/devices`
    );

    return (data.devices || []).map((d) => {
      const ips = d.addresses || [];
      return {
        id: d.id,
        name: d.name,
        hostname: d.hostname,
        os: d.os,
        online: d.authorized && !d.isExternal, // API reports authorized status
        ipv4: ips.find((ip) => ip.includes(".")) || null,
        ipv6: ips.find((ip) => ip.includes(":")) || null,
        addresses: ips,
        tags: d.tags || [],
        lastSeen: d.lastSeen,
        clientVersion: d.clientVersion || null,
        isSelf: false,
        source: "api",
      };
    });
  }

  /**
   * Performs latency ping, TCP port probe, or SSH health-check against mesh nodes
   */
  public async checkConnectivity(params: ConnectivityCheckParams): Promise<ConnectivityCheckResult> {
    const { type, target, port, count = 3, timeoutMs = 5000, sshCommand, dryRun = false } = params;

    if (!isValidTarget(target)) {
      throw new Error(`Invalid network target: "${target}". Must be a valid IPv4, IPv6, or hostname.`);
    }

    if (type === "port" && (!port || !isValidPort(port))) {
      throw new Error(`Invalid or missing port: "${port}". Must be an integer between 1 and 65535.`);
    }

    if (dryRun) {
      logger.info(`Dry-run requested for connectivity check: ${type} -> ${target}`);
      return {
        target,
        type,
        port,
        dryRun: true,
        success: true,
        output: `[DRY-RUN] Connectivity check simulated. Target: ${target}, Type: ${type}${port ? `, Port: ${port}` : ""}`,
      };
    }

    switch (type) {
      case "ping":
        return this.executePingCheck(target, count, timeoutMs);
      case "port":
        return this.executePortCheck(target, port!, timeoutMs);
      case "ssh":
        return this.executeSshCheck(target, sshCommand, timeoutMs);
      default:
        throw new Error(`Unsupported connectivity check type: ${(type as any)}`);
    }
  }

  /**
   * Internal ping check using `tailscale ping`
   */
  private async executePingCheck(
    target: string,
    count: number,
    timeoutMs: number
  ): Promise<ConnectivityCheckResult> {
    const timeoutSec = Math.max(1, Math.ceil(timeoutMs / 1000));
    const args = ["ping", "-c", String(count), "--timeout", `${timeoutSec}s`, target];

    const result = await this.executeCli(args, { timeoutMs: timeoutMs + 2000 });
    const output = `${result.stdout}\n${result.stderr}`.trim();

    if (result.exitCode !== 0 && !output.includes("pong")) {
      return {
        target,
        type: "ping",
        success: false,
        output,
        error: `Ping to ${target} failed with exit code ${result.exitCode}`,
      };
    }

    // Extract latency and relay status from ping response
    // E.g.: "pong from worker-1 (100.100.1.2) via [203.0.113.1]:41641 in 14ms"
    // or:   "pong from worker-1 (100.100.1.2) via DERP(fra) in 32ms"
    const latencyMatch = output.match(/in\s+([0-9.]+)(ms|µs|s)/i);
    let latencyMs: number | null = null;

    if (latencyMatch) {
      const val = parseFloat(latencyMatch[1]);
      const unit = latencyMatch[2].toLowerCase();
      if (unit === "ms") latencyMs = val;
      else if (unit === "µs") latencyMs = Math.round((val / 1000) * 100) / 100;
      else if (unit === "s") latencyMs = val * 1000;
    }

    const isDirect = !output.includes("via DERP(");
    const derpMatch = output.match(/via\s+(DERP\([a-zA-Z0-9_-]+\))/i);

    return {
      target,
      type: "ping",
      success: true,
      latencyMs,
      direct: isDirect,
      relay: derpMatch ? derpMatch[1] : null,
      output,
    };
  }

  /**
   * Internal TCP port socket connectivity test
   */
  private executePortCheck(
    target: string,
    port: number,
    timeoutMs: number
  ): Promise<ConnectivityCheckResult> {
    return new Promise((resolve) => {
      const socket = new Socket();
      let isResolved = false;

      const finish = (success: boolean, open: boolean, message: string, error?: string) => {
        if (isResolved) return;
        isResolved = true;
        socket.destroy();
        resolve({
          target,
          type: "port",
          port,
          success,
          open,
          output: message,
          error,
        });
      };

      socket.setTimeout(timeoutMs);

      socket.on("connect", () => {
        finish(true, true, `Port ${port} on ${target} is OPEN and reachable.`);
      });

      socket.on("timeout", () => {
        finish(false, false, `Connection to ${target}:${port} timed out after ${timeoutMs}ms.`);
      });

      socket.on("error", (err: any) => {
        const isOpen = false;
        let msg = `Port ${port} on ${target} is unreachable: ${err.message}`;
        if (err.code === "ECONNREFUSED") {
          msg = `Port ${port} on ${target} is CLOSED (connection refused).`;
        }
        finish(false, isOpen, msg, err.code || err.message);
      });

      try {
        socket.connect(port, target);
      } catch (err: any) {
        finish(false, false, `Failed to initialize connection: ${err.message}`, err.message);
      }
    });
  }

  /**
   * Internal Tailscale SSH connectivity test
   */
  private async executeSshCheck(
    target: string,
    sshCommand: string = "exit 0",
    timeoutMs: number
  ): Promise<ConnectivityCheckResult> {
    const args = [
      "ssh",
      "-o",
      "BatchMode=yes",
      "-o",
      `ConnectTimeout=${Math.max(1, Math.ceil(timeoutMs / 1000))}`,
      target,
      "--",
      sshCommand,
    ];

    const result = await this.executeCli(args, { timeoutMs: timeoutMs + 2000 });
    const output = `${result.stdout}\n${result.stderr}`.trim();
    const success = result.exitCode === 0;

    return {
      target,
      type: "ssh",
      success,
      output: output || (success ? "SSH connection verified successfully." : "SSH command returned non-zero exit code."),
      error: success ? undefined : `SSH check failed with exit code ${result.exitCode}`,
    };
  }
}
