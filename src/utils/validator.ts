/**
 * Security validation helpers for network parameters and Funnel safeguards
 */

const HOSTNAME_REGEX =
  /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.?$/;

const IPV4_REGEX =
  /^(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

const IPV6_REGEX =
  /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

/**
 * Tailscale Funnel is infrastructure-restricted to these public ports only.
 */
export const ALLOWED_FUNNEL_PORTS = [443, 8443, 10000] as const;
export type AllowedFunnelPort = (typeof ALLOWED_FUNNEL_PORTS)[number];

/**
 * Ports with severe security implications if exposed to public internet unauthenticated.
 */
export const DANGEROUS_PORTS: Record<number, string> = {
  22: "SSH (Remote shell)",
  2375: "Docker Daemon (Unauthenticated remote execution)",
  2376: "Docker Daemon TLS",
  2379: "etcd client",
  2380: "etcd peer",
  3306: "MySQL Database",
  5432: "PostgreSQL Database",
  6379: "Redis (Typically unauthenticated)",
  6443: "Kubernetes API Server",
  9090: "Prometheus Metrics (Telemetry / internal network leak)",
  9200: "Elasticsearch",
  11211: "Memcached",
  27017: "MongoDB Database",
  41641: "Tailscale WireGuard default listen port",
};

/**
 * Validates that a string is a safe network target (IPv4, IPv6, or valid RFC hostname)
 */
export function isValidTarget(target: string): boolean {
  if (!target || typeof target !== "string") return false;
  const trimmed = target.trim();
  if (trimmed.length > 253) return false;
  return IPV4_REGEX.test(trimmed) || IPV6_REGEX.test(trimmed) || HOSTNAME_REGEX.test(trimmed);
}

/**
 * Validates TCP/UDP port range
 */
export function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

/**
 * Checks whether a port is one of Tailscale Funnel's supported public ports
 */
export function isValidFunnelPort(port: number): port is AllowedFunnelPort {
  return (ALLOWED_FUNNEL_PORTS as readonly number[]).includes(port);
}

/**
 * Returns security risk description if port is considered sensitive
 */
export function getDangerousPortWarning(port: number): string | null {
  return DANGEROUS_PORTS[port] || null;
}

/**
 * Validates URL mount path for Funnel/Serve
 */
export function isValidMountPath(path: string): boolean {
  if (!path || typeof path !== "string") return false;
  const trimmed = path.trim();
  if (!trimmed.startsWith("/")) return false;
  if (trimmed.includes("..") || trimmed.includes("\0")) return false;
  return true;
}

/**
 * Checks if target host is a safe loopback / local address
 */
export function isLocalHost(host: string): boolean {
  const normalized = host.trim().toLowerCase();
  return (
    normalized === "localhost" ||
    normalized === "127.0.0.1" ||
    normalized === "::1" ||
    normalized === "0.0.0.0"
  );
}

/**
 * Sanitize shell arguments to prevent flag injection
 */
export function sanitizeCliArg(arg: string): string {
  return arg.replace(/[\0\r\n]/g, "").trim();
}
