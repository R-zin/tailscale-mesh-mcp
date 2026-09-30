/**
 * Configuration options for the Tailscale client
 */
export interface TailscaleConfig {
  /** Tailscale API access key (tskey-api-...) */
  apiKey?: string;
  /** Tailnet name or '-' for default */
  tailnet?: string;
  /** Explicit path to local tailscale binary */
  cliPath?: string;
  /** Base URL for Tailscale REST API (default: https://api.tailscale.com/api/v2) */
  apiBaseUrl?: string;
  /** Global execution timeout in milliseconds */
  timeoutMs?: number;
}

/**
 * Normalized Tailscale Device model across both CLI and REST API sources
 */
export interface TailscaleDevice {
  id: string;
  name: string;
  hostname: string;
  os: string;
  online: boolean;
  ipv4: string | null;
  ipv6: string | null;
  addresses: string[];
  tags: string[];
  lastSeen: string | null;
  clientVersion: string | null;
  isSelf: boolean;
  source: "cli" | "api";
  rxBytes?: number;
  txBytes?: number;
  curAddr?: string;
  relay?: string;
}

/**
 * Output format of `tailscale status --json`
 */
export interface TailscaleCliPeer {
  ID: string;
  PublicKey: string;
  HostName: string;
  DNSName: string;
  OS: string;
  UserID: number;
  TailscaleIPs: string[];
  Tags?: string[];
  Online: boolean;
  LastSeen: string;
  RxBytes?: number;
  TxBytes?: number;
  CurAddr?: string;
  Relay?: string;
  ExitNode?: boolean;
  ExitNodeOption?: boolean;
  Active?: boolean;
}

export interface TailscaleCliSelf extends TailscaleCliPeer {
  Capabilities?: string[];
}

export interface TailscaleCliStatus {
  Version: string;
  TUN: boolean;
  BackendState: string;
  AuthURL?: string;
  TailscaleIPs?: string[];
  Self?: TailscaleCliSelf;
  Peer?: Record<string, TailscaleCliPeer>;
  User?: Record<string, { ID: number; LoginName: string; DisplayName: string }>;
  MagicDNSSuffix?: string;
}

/**
 * REST API response schema for GET /api/v2/tailnet/{tailnet}/devices
 */
export interface TailscaleApiDevice {
  id: string;
  nodeId: string;
  name: string;
  hostname: string;
  user: string;
  os: string;
  clientVersion: string;
  addresses: string[];
  tags?: string[];
  authorized: boolean;
  isExternal: boolean;
  updateAvailable: boolean;
  lastSeen: string;
  created: string;
  nodeKey: string;
  keyExpiryDisabled: boolean;
  expires: string;
}

export interface TailscaleApiDevicesResponse {
  devices: TailscaleApiDevice[];
}

/**
 * Parameters for connectivity checks
 */
export interface ConnectivityCheckParams {
  type: "ping" | "port" | "ssh";
  target: string;
  port?: number;
  count?: number;
  timeoutMs?: number;
  sshCommand?: string;
  dryRun?: boolean;
}

/**
 * Results of connectivity check operations
 */
export interface ConnectivityCheckResult {
  target: string;
  type: "ping" | "port" | "ssh";
  success: boolean;
  latencyMs?: number | null;
  direct?: boolean;
  relay?: string | null;
  port?: number;
  open?: boolean;
  output: string;
  dryRun?: boolean;
  error?: string;
}

/**
 * Output format of `tailscale funnel status --json` or `tailscale serve status --json`
 */
export interface TailscaleServeStatusJson {
  TCP?: Record<string, { HTTPS?: boolean; TCP?: boolean }>;
  Web?: Record<
    string,
    {
      Handlers?: Record<string, { Proxy?: string; Path?: string; Text?: string }>;
    }
  >;
  AllowFunnel?: Record<string, boolean>;
}

/**
 * Funnel actions supported by the manage_funnel tool
 */
export type FunnelAction = "status" | "expose" | "unexpose" | "reset";

/**
 * Normalized public endpoint exposed via Funnel
 */
export interface FunnelEndpoint {
  publicPort: number;
  url: string;
  path: string;
  target: string;
  protocol: string;
  funnelEnabled: boolean;
}

/**
 * Normalized status of Funnel and Serve on local node
 */
export interface FunnelStatus {
  active: boolean;
  nodeDnsName: string | null;
  endpoints: FunnelEndpoint[];
  raw?: TailscaleServeStatusJson | null;
}

/**
 * Parameters for manage_funnel tool
 */
export interface FunnelManageParams {
  action: FunnelAction;
  localPort?: number;
  publicPort?: 443 | 8443 | 10000;
  path?: string;
  targetHost?: string;
  protocol?: "http" | "https";
  allowDangerousPorts?: boolean;
  confirm?: boolean;
  dryRun?: boolean;
}

/**
 * Result of manage_funnel operations
 */
export interface FunnelManageResult {
  action: FunnelAction;
  success: boolean;
  message: string;
  publicUrl?: string;
  command?: string;
  status?: FunnelStatus;
  securityWarnings?: string[];
  dryRun?: boolean;
  error?: string;
}

/**
 * Result of local CLI execution
 */
export interface CliExecutionResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}
