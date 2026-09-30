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

/**
 * Standard Tailscale ACL Rule
 */
export interface TailscaleAclRule {
  action: "accept";
  src: string[];
  dst: string[];
  users?: string[];
  proto?: string;
}

/**
 * Tailscale SSH Access Rule
 */
export interface TailscaleSshRule {
  action: "accept" | "check";
  src: string[];
  dst: string[];
  users: string[];
  checkPeriod?: string;
}

/**
 * Tailscale Node Attributes (e.g. Funnel permissions)
 */
export interface TailscaleNodeAttr {
  target: string[];
  attr: string[];
  app?: Record<string, unknown>;
}

/**
 * Tailscale Grant Rule (modern ACL syntax)
 */
export interface TailscaleGrantRule {
  src: string[];
  dst: string[];
  app?: Record<string, unknown>;
  ip?: string[];
}

/**
 * Tailscale ACL Unit Test definition
 */
export interface TailscaleAclTest {
  src: string;
  accept?: string[];
  deny?: string[];
}

/**
 * Tailscale Access Control Policy File model (HuJSON structure)
 */
export interface TailscaleAclPolicy {
  acls?: TailscaleAclRule[];
  groups?: Record<string, string[]>;
  tagOwners?: Record<string, string[]>;
  hosts?: Record<string, string>;
  tests?: TailscaleAclTest[];
  autoApprovers?: {
    routes?: Record<string, string[]>;
    exitNode?: string[];
  };
  nodeAttrs?: TailscaleNodeAttr[];
  ssh?: TailscaleSshRule[];
  grants?: TailscaleGrantRule[];
  postures?: Record<string, unknown>;
  defaultSrcPosture?: string[];
  derpMap?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Severity ranking for security findings
 */
export type AclSeverity = "critical" | "high" | "medium" | "low" | "info";

/**
 * Specific security or syntax finding detected during ACL audit
 */
export interface AclFinding {
  id: string;
  severity: AclSeverity;
  category: "security" | "syntax" | "best_practice" | "shadowing";
  title: string;
  message: string;
  ruleIndex?: number;
  rule?: unknown;
  recommendation: string;
}

/**
 * Structural metrics and telemetry for an ACL policy
 */
export interface AclPolicyStats {
  aclsCount: number;
  groupsCount: number;
  tagOwnersCount: number;
  hostsCount: number;
  testsCount: number;
  sshRulesCount: number;
  grantsCount: number;
  nodeAttrsCount: number;
}

/**
 * Semantic differences and security impact analysis between two policies
 */
export interface AclSemanticDiff {
  unifiedDiff: string;
  hasChanges: boolean;
  addedRulesCount: number;
  removedRulesCount: number;
  modifiedRulesCount: number;
  riskDelta: "increased" | "decreased" | "neutral";
  riskFactors: string[];
  summary: string;
}

/**
 * Result of submitting policy to Tailscale REST API v2 validate endpoint
 */
export interface AclApiValidationResult {
  valid: boolean;
  message?: string;
  warnings?: string[];
  errors?: string[];
  raw?: unknown;
}

/**
 * Complete result output of audit_acl_rules
 */
export interface AclAuditResult {
  valid: boolean;
  policySource: "provided" | "api";
  securityScore: number; // 0 - 100
  securityRating: "A" | "B" | "C" | "D" | "F";
  stats: AclPolicyStats;
  findings: AclFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
    headline: string;
  };
  diff?: AclSemanticDiff;
  apiValidation?: AclApiValidationResult;
  formattedHuJson?: string;
  rawHuJson?: string;
}

/**
 * Parameters for the audit_acl_rules tool
 */
export interface AuditAclParams {
  policy?: string;
  proposedPolicy?: string;
  source?: "auto" | "api" | "provided";
  validateWithApi?: boolean;
  strict?: boolean;
  formatOutput?: boolean;
}

