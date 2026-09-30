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
  FunnelStatus,
  FunnelManageParams,
  FunnelManageResult,
  FunnelEndpoint,
  TailscaleServeStatusJson,
  TailscaleAclPolicy,
  AclAuditResult,
  AuditAclParams,
  AclApiValidationResult,
  AclSemanticDiff,
} from "./types.js";
import { logger } from "../utils/logger.js";
import { parseHuJson, formatHuJson, huJsonToJson } from "./hujson.js";
import { createUnifiedDiff, analyzePolicyDiff } from "./diff.js";
import { auditAclPolicy } from "./acl.js";
import {
  isValidTarget,
  isValidPort,
  isValidFunnelPort,
  getDangerousPortWarning,
  isValidMountPath,
  isLocalHost,
  sanitizeCliArg,
} from "../utils/validator.js";

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
   * Performs an authenticated request to Tailscale REST API returning raw text and headers
   */
  public async fetchApiText(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<{ text: string; etag: string | null; status: number }> {
    if (!this.apiKey) {
      throw new Error(
        "Tailscale API key missing. Set TAILSCALE_API_KEY environment variable to use REST API features."
      );
    }

    const cleanEndpoint = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
    const url = `${this.apiBaseUrl}${cleanEndpoint}`;

    logger.debug(`REST API Request (Text): ${options.method || "GET"} ${url}`);

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const response = await fetch(url, {
        ...options,
        signal: controller.signal,
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "User-Agent": "tailscale-mesh-mcp/0.3.0",
          ...options.headers,
        },
      });

      const text = await response.text();
      if (!response.ok) {
        throw new Error(
          `Tailscale API error (${response.status} ${response.statusText}): ${text || "No response body"}`
        );
      }

      return {
        text,
        etag: response.headers.get("etag"),
        status: response.status,
      };
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

  /**
   * Queries the current status of Tailscale Funnel / Serve on the local node
   */
  public async getFunnelStatus(): Promise<FunnelStatus> {
    let rawOutput: TailscaleServeStatusJson | null = null;
    let nodeDnsName: string | null = null;

    // Retrieve node's DNS name for constructing accurate public URLs
    try {
      const cliStatus = await this.getCliStatus();
      if (cliStatus.Self?.DNSName) {
        nodeDnsName = cliStatus.Self.DNSName.replace(/\.$/, "");
      }
    } catch {
      // Continue even if getCliStatus fails
    }

    // Try `tailscale funnel status --json` first, then fallback to `tailscale serve status --json`
    let res = await this.executeCli(["funnel", "status", "--json"]);
    if (res.exitCode !== 0 || !res.stdout.trim()) {
      res = await this.executeCli(["serve", "status", "--json"]);
    }

    if (res.stdout.trim()) {
      try {
        rawOutput = JSON.parse(res.stdout) as TailscaleServeStatusJson;
      } catch {
        logger.debug("Funnel status output was not valid JSON, returning raw text status");
      }
    }

    const endpoints: FunnelEndpoint[] = [];

    if (rawOutput && rawOutput.Web) {
      for (const [hostPort, config] of Object.entries(rawOutput.Web)) {
        const [domain, portStr] = hostPort.split(":");
        const publicPort = portStr ? parseInt(portStr, 10) : 443;
        const funnelEnabled = !!(rawOutput.AllowFunnel && (rawOutput.AllowFunnel[hostPort] || rawOutput.AllowFunnel[domain]));

        if (domain && !nodeDnsName) {
          nodeDnsName = domain;
        }

        if (config.Handlers) {
          for (const [path, handler] of Object.entries(config.Handlers)) {
            const target = handler.Proxy || handler.Path || handler.Text || "unknown";
            const portSuffix = publicPort === 443 ? "" : `:${publicPort}`;
            const cleanPath = path.startsWith("/") ? path : `/${path}`;

            endpoints.push({
              publicPort,
              url: `https://${domain || nodeDnsName || "localhost"}${portSuffix}${cleanPath}`,
              path: cleanPath,
              target,
              protocol: "https",
              funnelEnabled,
            });
          }
        }
      }
    }

    const isFunnelActive = endpoints.some((e) => e.funnelEnabled);

    return {
      active: isFunnelActive,
      nodeDnsName,
      endpoints,
      raw: rawOutput,
    };
  }

  /**
   * Manages Tailscale Funnel: status, expose, unexpose, or reset
   */
  public async manageFunnel(params: FunnelManageParams): Promise<FunnelManageResult> {
    const { action, dryRun = false } = params;

    switch (action) {
      case "status":
        return this.handleFunnelStatus();
      case "expose":
        return this.handleFunnelExpose(params, dryRun);
      case "unexpose":
        return this.handleFunnelUnexpose(params, dryRun);
      case "reset":
        return this.handleFunnelReset(params, dryRun);
      default:
        throw new Error(`Unsupported funnel action: ${action}`);
    }
  }

  private async handleFunnelStatus(): Promise<FunnelManageResult> {
    const status = await this.getFunnelStatus();
    return {
      action: "status",
      success: true,
      status,
      message: status.active
        ? `Tailscale Funnel is ACTIVE with ${status.endpoints.filter((e) => e.funnelEnabled).length} public endpoint(s).`
        : "Tailscale Funnel is currently INACTIVE on this node.",
    };
  }

  private async handleFunnelExpose(
    params: FunnelManageParams,
    dryRun: boolean
  ): Promise<FunnelManageResult> {
    const {
      localPort,
      publicPort = 443,
      path = "/",
      targetHost = "127.0.0.1",
      protocol = "http",
      allowDangerousPorts = false,
    } = params;

    if (!localPort || !isValidPort(localPort)) {
      throw new Error(`Invalid localPort: "${localPort}". Must be an integer between 1 and 65535.`);
    }

    if (!isValidFunnelPort(publicPort)) {
      throw new Error(
        `Invalid publicPort: ${publicPort}. Tailscale Funnel only supports public ports: 443, 8443, or 10000.`
      );
    }

    if (!isValidMountPath(path)) {
      throw new Error(
        `Invalid path: "${path}". Mount path must start with '/' and cannot contain traversal characters (e.g. '..').`
      );
    }

    const securityWarnings: string[] = [];

    // Check sensitive / dangerous ports
    const danger = getDangerousPortWarning(localPort);
    if (danger) {
      if (!allowDangerousPorts) {
        throw new Error(
          `Security Guardrail: Port ${localPort} is identified as ${danger}. Exposing databases or admin interfaces to the public web via Funnel is high-risk. Set allowDangerousPorts: true if this exposure is intentionally approved.`
        );
      }
      securityWarnings.push(
        `SECURITY WARNING: Port ${localPort} (${danger}) is being exposed publicly. Ensure strong authentication is configured.`
      );
    }

    // Check target host
    if (!isLocalHost(targetHost)) {
      securityWarnings.push(
        `Target host "${targetHost}" is non-loopback. Funnel will proxy traffic across local subnet.`
      );
    }

    const targetUrl = `${protocol}://${targetHost}:${localPort}`;

    // Construct CLI command arguments
    // e.g. tailscale funnel --bg --https=443 --set-path=/ http://127.0.0.1:3000
    const args = ["funnel", "--bg"];
    if (publicPort !== 443) {
      args.push(`--https=${publicPort}`);
    } else {
      args.push("--https=443");
    }

    if (path !== "/") {
      args.push(`--set-path=${path}`);
    }

    args.push(targetUrl);

    // Resolve domain for public URL preview
    let nodeDnsName = "your-node.tailnet.ts.net";
    try {
      const currentStatus = await this.getFunnelStatus();
      if (currentStatus.nodeDnsName) {
        nodeDnsName = currentStatus.nodeDnsName;
      }
    } catch {
      // Ignore
    }

    const portSuffix = publicPort === 443 ? "" : `:${publicPort}`;
    const cleanPath = path.startsWith("/") ? path : `/${path}`;
    const expectedPublicUrl = `https://${nodeDnsName}${portSuffix}${cleanPath}`;

    if (dryRun) {
      logger.info(`Simulating funnel exposure for ${targetUrl} via ${expectedPublicUrl}`);
      return {
        action: "expose",
        success: true,
        dryRun: true,
        command: `tailscale ${args.join(" ")}`,
        publicUrl: expectedPublicUrl,
        message: `[DRY-RUN] Funnel exposure plan verified. Would map ${expectedPublicUrl} -> ${targetUrl}.`,
        securityWarnings: securityWarnings.length > 0 ? securityWarnings : undefined,
      };
    }

    logger.info(`Executing Funnel exposure: tailscale ${args.join(" ")}`);
    const res = await this.executeCli(args);

    if (res.exitCode !== 0) {
      const errLower = (res.stderr || res.stdout).toLowerCase();
      let errorHelp = res.stderr || "Unknown CLI error";

      if (errLower.includes("funnel") && (errLower.includes("not enabled") || errLower.includes("nodeattr"))) {
        errorHelp +=
          "\nTroubleshooting: Tailscale Funnel must be enabled in your Tailscale ACL policy. Add the 'funnel' attribute to nodeAttrs:\n" +
          `"nodeAttrs": [{"target": ["autogroup:members"], "attr": ["funnel"]}]`;
      } else if (errLower.includes("https") && errLower.includes("not enabled")) {
        errorHelp +=
          "\nTroubleshooting: HTTPS certificates must be enabled in your Tailnet Admin Console under DNS settings.";
      }

      return {
        action: "expose",
        success: false,
        error: errorHelp,
        command: `tailscale ${args.join(" ")}`,
        message: `Failed to expose port ${localPort} via Tailscale Funnel.`,
        securityWarnings: securityWarnings.length > 0 ? securityWarnings : undefined,
      };
    }

    const newStatus = await this.getFunnelStatus();
    return {
      action: "expose",
      success: true,
      command: `tailscale ${args.join(" ")}`,
      publicUrl: expectedPublicUrl,
      status: newStatus,
      message: `Successfully exposed ${targetUrl} to public web at ${expectedPublicUrl}`,
      securityWarnings: securityWarnings.length > 0 ? securityWarnings : undefined,
    };
  }

  private async handleFunnelUnexpose(
    params: FunnelManageParams,
    dryRun: boolean
  ): Promise<FunnelManageResult> {
    const { publicPort = 443 } = params;

    if (!isValidFunnelPort(publicPort)) {
      throw new Error(
        `Invalid publicPort: ${publicPort}. Tailscale Funnel only supports public ports: 443, 8443, or 10000.`
      );
    }

    const args = ["funnel", `--https=${publicPort}`, "off"];

    if (dryRun) {
      return {
        action: "unexpose",
        success: true,
        dryRun: true,
        command: `tailscale ${args.join(" ")}`,
        message: `[DRY-RUN] Unexpose simulated. Would terminate public Funnel traffic on HTTPS port ${publicPort}.`,
      };
    }

    logger.info(`Unexposing Funnel on port ${publicPort}: tailscale ${args.join(" ")}`);
    const res = await this.executeCli(args);

    if (res.exitCode !== 0) {
      return {
        action: "unexpose",
        success: false,
        command: `tailscale ${args.join(" ")}`,
        error: res.stderr || "Failed to turn off funnel.",
        message: `Failed to unexpose Funnel on port ${publicPort}.`,
      };
    }

    const newStatus = await this.getFunnelStatus();
    return {
      action: "unexpose",
      success: true,
      command: `tailscale ${args.join(" ")}`,
      status: newStatus,
      message: `Successfully unexposed public Funnel on HTTPS port ${publicPort}.`,
    };
  }

  private async handleFunnelReset(
    params: FunnelManageParams,
    dryRun: boolean
  ): Promise<FunnelManageResult> {
    const { confirm = false } = params;

    if (!confirm && !dryRun) {
      throw new Error(
        "Destructive Action Blocked: Resetting Tailscale Funnel terminates all active public proxies and mount points. Pass confirm: true to proceed."
      );
    }

    const args = ["funnel", "reset"];

    if (dryRun) {
      return {
        action: "reset",
        success: true,
        dryRun: true,
        command: `tailscale ${args.join(" ")}`,
        message: "[DRY-RUN] Reset simulated. Would tear down all active Tailscale Funnel and Serve configurations.",
      };
    }

    logger.warn("Executing full reset of Tailscale Funnel routes");
    const res = await this.executeCli(args);

    if (res.exitCode !== 0) {
      return {
        action: "reset",
        success: false,
        command: `tailscale ${args.join(" ")}`,
        error: res.stderr || "Failed to reset funnel.",
        message: "Failed to reset Tailscale Funnel configuration.",
      };
    }

    const newStatus = await this.getFunnelStatus();
    return {
      action: "reset",
      success: true,
      command: `tailscale ${args.join(" ")}`,
      status: newStatus,
      message: "Successfully reset all Tailscale Funnel and Serve configurations.",
    };
  }

  /**
   * Retrieves the current tailnet ACL policy file from Tailscale REST API v2
   */
  public async getAcl(options: { format?: "hujson" | "json" } = {}): Promise<{
    hujson: string;
    policy: TailscaleAclPolicy;
    etag: string | null;
  }> {
    const acceptHeader =
      options.format === "json"
        ? "application/json"
        : "application/hujson, application/json;q=0.9, text/plain;q=0.8";

    const res = await this.fetchApiText(
      `/tailnet/${encodeURIComponent(this.tailnet)}/acl`,
      {
        headers: {
          Accept: acceptHeader,
        },
      }
    );

    const policy = parseHuJson<TailscaleAclPolicy>(res.text);
    return {
      hujson: res.text,
      policy,
      etag: res.etag,
    };
  }

  /**
   * Submits HuJSON policy to Tailscale REST API v2 validate endpoint (/acl/validate)
   */
  public async validateAclWithApi(hujson: string): Promise<AclApiValidationResult> {
    try {
      const res = await this.fetchApiText(
        `/tailnet/${encodeURIComponent(this.tailnet)}/acl/validate`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/hujson",
            Accept: "application/json",
          },
          body: hujson,
        }
      );

      // Tailscale returns {} or empty on valid
      if (res.status === 200) {
        let warnings: string[] = [];
        try {
          const parsed = JSON.parse(res.text);
          if (parsed.warnings && Array.isArray(parsed.warnings)) {
            warnings = parsed.warnings;
          }
        } catch {
          // Empty or non-JSON 200 response means valid
        }
        return {
          valid: true,
          message: "Policy validated successfully by Tailscale API compiler.",
          warnings: warnings.length > 0 ? warnings : undefined,
        };
      }

      return {
        valid: false,
        message: `Tailscale API validation returned status ${res.status}`,
        errors: [res.text],
      };
    } catch (err: any) {
      return {
        valid: false,
        message: `Tailscale API validation failed: ${err.message}`,
        errors: [err.message],
      };
    }
  }

  /**
   * Audits Tailscale ACL rules, validating syntax, evaluating zero-trust posture, and previewing diffs
   */
  public async auditAclRules(params: AuditAclParams = {}): Promise<AclAuditResult> {
    const {
      policy: inputPolicy,
      proposedPolicy: inputProposedPolicy,
      source = "auto",
      validateWithApi = false,
      strict = false,
      formatOutput = true,
    } = params;

    let rawHuJson = "";
    let policySource: "provided" | "api" = "provided";

    // 1. Resolve base policy
    if (inputPolicy && inputPolicy.trim().length > 0) {
      rawHuJson = inputPolicy.trim();
      policySource = "provided";
    } else if (source === "api" || (source === "auto" && this.apiKey)) {
      try {
        const remoteAcl = await this.getAcl();
        rawHuJson = remoteAcl.hujson;
        policySource = "api";
      } catch (err: any) {
        throw new Error(
          `Failed to fetch active ACL policy from Tailscale API: ${err.message}. Alternatively, provide policy text in 'policy' parameter.`
        );
      }
    } else {
      throw new Error(
        "No ACL policy provided and TAILSCALE_API_KEY is not configured. Provide policy HuJSON in 'policy' parameter or set TAILSCALE_API_KEY in environment."
      );
    }

    // 2. Parse base policy
    let parsedPolicy: TailscaleAclPolicy;
    try {
      parsedPolicy = parseHuJson<TailscaleAclPolicy>(rawHuJson);
    } catch (parseErr: any) {
      return {
        valid: false,
        policySource,
        securityScore: 0,
        securityRating: "F",
        stats: {
          aclsCount: 0,
          groupsCount: 0,
          tagOwnersCount: 0,
          hostsCount: 0,
          testsCount: 0,
          sshRulesCount: 0,
          grantsCount: 0,
          nodeAttrsCount: 0,
        },
        findings: [
          {
            id: "HUJSON_PARSE_ERROR",
            severity: "critical",
            category: "syntax",
            title: "HuJSON / JSON Syntax Error",
            message: parseErr.message,
            recommendation:
              "Ensure valid HuJSON syntax with matching brackets, valid comments, and proper string quoting.",
          },
        ],
        summary: {
          critical: 1,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
          total: 1,
          headline: "Policy failed to parse due to HuJSON syntax error.",
        },
        rawHuJson,
      };
    }

    // 3. Run static security audit
    const auditRes = auditAclPolicy(parsedPolicy);

    // 4. Optional Diff Preview against proposed policy
    let diff: AclSemanticDiff | undefined;
    if (inputProposedPolicy && inputProposedPolicy.trim().length > 0) {
      try {
        const proposedParsed = parseHuJson<TailscaleAclPolicy>(inputProposedPolicy);
        const formattedBase = formatHuJson(rawHuJson);
        const formattedProposed = formatHuJson(inputProposedPolicy);
        const unifiedDiff = createUnifiedDiff(formattedBase, formattedProposed);
        diff = analyzePolicyDiff(parsedPolicy, proposedParsed, unifiedDiff);
      } catch (propErr: any) {
        auditRes.findings.push({
          id: "PROPOSED_POLICY_PARSE_ERROR",
          severity: "high",
          category: "syntax",
          title: "Proposed Policy Syntax Error",
          message: `Proposed policy could not be parsed for diff preview: ${propErr.message}`,
          recommendation: "Fix syntax errors in proposed policy.",
        });
      }
    }

    // 5. Optional API validation
    let apiValidation: AclApiValidationResult | undefined;
    if (validateWithApi) {
      if (this.apiKey) {
        apiValidation = await this.validateAclWithApi(rawHuJson);
        if (!apiValidation.valid && apiValidation.errors) {
          for (const err of apiValidation.errors) {
            auditRes.findings.push({
              id: "TAILSCALE_API_VALIDATION_ERROR",
              severity: "critical",
              category: "syntax",
              title: "Tailscale API Compiler Validation Error",
              message: err,
              recommendation: "Address Tailscale official policy compiler error.",
            });
          }
        }
      } else {
        apiValidation = {
          valid: false,
          message:
            "API validation skipped: TAILSCALE_API_KEY environment variable is not configured.",
        };
      }
    }

    // Summary counts
    const critical = auditRes.findings.filter((f) => f.severity === "critical").length;
    const high = auditRes.findings.filter((f) => f.severity === "high").length;
    const medium = auditRes.findings.filter((f) => f.severity === "medium").length;
    const low = auditRes.findings.filter((f) => f.severity === "low").length;
    const info = auditRes.findings.filter((f) => f.severity === "info").length;

    let headline = `Security Rating: ${auditRes.securityRating} (${auditRes.securityScore}/100). Found ${auditRes.findings.length} findings (${critical} critical, ${high} high, ${medium} medium).`;
    if (critical > 0) {
      headline = `SECURITY ALERT: ${critical} critical vulnerabilities found in Tailscale ACL policy! Score: ${auditRes.securityScore}/100 (Rating ${auditRes.securityRating}).`;
    } else if (high > 0) {
      headline = `SECURITY WARNING: ${high} high-risk findings detected in Tailscale ACL policy. Score: ${auditRes.securityScore}/100 (Rating ${auditRes.securityRating}).`;
    } else if (auditRes.findings.length === 0) {
      headline =
        "EXCELLENT: Tailscale ACL policy conforms strictly to zero-trust standards with 0 findings.";
    }

    let isValid = auditRes.valid;
    if (strict && (critical > 0 || high > 0)) {
      isValid = false;
    }

    return {
      valid: isValid,
      policySource,
      securityScore: auditRes.securityScore,
      securityRating: auditRes.securityRating,
      stats: auditRes.stats,
      findings: auditRes.findings,
      summary: {
        critical,
        high,
        medium,
        low,
        info,
        total: auditRes.findings.length,
        headline,
      },
      diff,
      apiValidation,
      formattedHuJson: formatOutput ? formatHuJson(rawHuJson) : undefined,
      rawHuJson: formatOutput ? undefined : rawHuJson,
    };
  }
}
