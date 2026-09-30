import {
  TailscaleAclPolicy,
  TailscaleAclRule,
  AclFinding,
  AclPolicyStats,
  AclSeverity,
} from "./types.js";
import { DANGEROUS_PORTS } from "../utils/validator.js";

/**
 * Parses target host or tag and port from destination string (e.g. "tag:server:80,443" or "*:*")
 */
export function parseDestination(dst: string): { target: string; ports: (number | "*")[] } {
  const lastColon = dst.lastIndexOf(":");
  if (lastColon === -1) {
    return { target: dst, ports: [] };
  }

  const target = dst.slice(0, lastColon);
  const portStr = dst.slice(lastColon + 1);

  if (portStr === "*") {
    return { target, ports: ["*"] };
  }

  const ports: (number | "*")[] = [];
  for (const part of portStr.split(",")) {
    const trimmed = part.trim();
    if (trimmed === "*") {
      ports.push("*");
    } else if (trimmed.includes("-")) {
      const [start, end] = trimmed.split("-").map(Number);
      if (!isNaN(start) && !isNaN(end) && start <= end) {
        for (let p = start; p <= Math.min(end, start + 50); p++) {
          ports.push(p);
        }
      }
    } else {
      const num = Number(trimmed);
      if (!isNaN(num)) {
        ports.push(num);
      }
    }
  }

  return { target, ports };
}

/**
 * Extracts pure tag name from a target token (e.g. "tag:prod-db:5432" -> "tag:prod-db")
 */
function extractTag(token: string): string | null {
  const clean = token.split(":")[0] + (token.includes(":") ? `:${token.split(":")[1]}` : "");
  if (clean.startsWith("tag:")) {
    return clean.split(":")[0] + ":" + clean.split(":")[1];
  }
  return null;
}

/**
 * Performs deep static security analysis and structural audit on a Tailscale ACL policy
 */
export function auditAclPolicy(policy: TailscaleAclPolicy): {
  valid: boolean;
  findings: AclFinding[];
  stats: AclPolicyStats;
  securityScore: number;
  securityRating: "A" | "B" | "C" | "D" | "F";
} {
  const findings: AclFinding[] = [];

  const acls = policy.acls || [];
  const groups = policy.groups || {};
  const tagOwners = policy.tagOwners || {};
  const hosts = policy.hosts || {};
  const tests = policy.tests || [];
  const sshRules = policy.ssh || [];
  const grants = policy.grants || [];
  const nodeAttrs = policy.nodeAttrs || [];

  const stats: AclPolicyStats = {
    aclsCount: acls.length,
    groupsCount: Object.keys(groups).length,
    tagOwnersCount: Object.keys(tagOwners).length,
    hostsCount: Object.keys(hosts).length,
    testsCount: tests.length,
    sshRulesCount: sshRules.length,
    grantsCount: grants.length,
    nodeAttrsCount: nodeAttrs.length,
  };

  const definedGroups = new Set(Object.keys(groups));
  const declaredTags = new Set(Object.keys(tagOwners));
  const definedHosts = new Set(Object.keys(hosts));

  // 1. Validate Group definitions
  for (const [groupName, members] of Object.entries(groups)) {
    if (!groupName.startsWith("group:")) {
      findings.push({
        id: "GROUP_NAME_FORMAT",
        severity: "medium",
        category: "syntax",
        title: `Invalid Group Name Prefix (${groupName})`,
        message: `Group '${groupName}' does not start with the required 'group:' prefix.`,
        recommendation: `Rename group key to 'group:${groupName}'.`,
      });
    }

    if (!Array.isArray(members) || members.length === 0) {
      findings.push({
        id: "EMPTY_GROUP",
        severity: "low",
        category: "best_practice",
        title: `Empty Group Definition (${groupName})`,
        message: `Group '${groupName}' has no members declared.`,
        recommendation: `Add user email addresses to the group or remove unused group definition.`,
      });
    }
  }

  // 2. Validate TagOwners
  for (const [tagName, owners] of Object.entries(tagOwners)) {
    if (!tagName.startsWith("tag:")) {
      findings.push({
        id: "TAG_NAME_FORMAT",
        severity: "medium",
        category: "syntax",
        title: `Invalid Tag Name Prefix (${tagName})`,
        message: `Tag '${tagName}' does not start with the required 'tag:' prefix.`,
        recommendation: `Rename tag key to 'tag:${tagName}'.`,
      });
    }

    if (!Array.isArray(owners) || owners.length === 0) {
      findings.push({
        id: "EMPTY_TAG_OWNERS",
        severity: "medium",
        category: "security",
        title: `Unassignable Tag (${tagName})`,
        message: `Tag '${tagName}' has no owners assigned. Nodes cannot be tagged with this tag.`,
        recommendation: `Assign admin users or groups as owners for '${tagName}'.`,
      });
    } else {
      for (const owner of owners) {
        if (owner.startsWith("group:") && !definedGroups.has(owner)) {
          findings.push({
            id: "UNDEFINED_GROUP_IN_TAG_OWNERS",
            severity: "medium",
            category: "syntax",
            title: `Undefined Group Referenced in TagOwners (${owner})`,
            message: `Tag '${tagName}' lists owner '${owner}', but '${owner}' is not defined in groups.`,
            recommendation: `Define '${owner}' under groups or update tagOwners.`,
          });
        }
      }
    }
  }

  // 3. Audit ACL Rules
  const seenRuleHashes = new Set<string>();

  for (let idx = 0; idx < acls.length; idx++) {
    const rule = acls[idx];
    const ruleHash = JSON.stringify(rule);

    // Structural check: Action must be accept
    if ((rule.action as string) !== "accept") {
      findings.push({
        id: "INVALID_ACL_ACTION",
        severity: "critical",
        category: "syntax",
        title: `Invalid ACL Action in Rule #${idx + 1}`,
        message: `Rule action '${rule.action}' is invalid. Tailscale ACLs are default-deny and only support action 'accept'.`,
        ruleIndex: idx,
        rule,
        recommendation: "Change action to 'accept' or use 'tests' to define deny assertions.",
      });
    }

    // Duplicate check
    if (seenRuleHashes.has(ruleHash)) {
      findings.push({
        id: "DUPLICATE_ACL_RULE",
        severity: "low",
        category: "shadowing",
        title: `Duplicate ACL Rule Entry (Rule #${idx + 1})`,
        message: `Rule #${idx + 1} is an identical duplicate of an earlier rule.`,
        ruleIndex: idx,
        rule,
        recommendation: "Remove duplicate rule to reduce policy complexity.",
      });
    }
    seenRuleHashes.add(ruleHash);

    const isWildcardSrc =
      rule.src.includes("*") || rule.src.includes("autogroup:member");
    const isWildcardDst = rule.dst.includes("*:*");

    // Critical: Full mesh wildcard access
    if (isWildcardSrc && isWildcardDst) {
      findings.push({
        id: "CRITICAL_WILDCARD_FULL_ACCESS",
        severity: "critical",
        category: "security",
        title: `Unrestricted Full-Mesh Wildcard Rule (*:* -> *:*) (Rule #${idx + 1})`,
        message: `Rule #${idx + 1} permits all tailnet nodes unrestricted access to every port across all machines. Zero-Trust is effectively bypassed.`,
        ruleIndex: idx,
        rule,
        recommendation: "Replace '*:*' with explicit target tags, hostnames, and required application ports.",
      });
    }

    // Inspect destinations
    for (const dst of rule.dst) {
      const { target, ports } = parseDestination(dst);

      // Check wildcard port
      if (ports.includes("*") && !isWildcardDst && isWildcardSrc) {
        findings.push({
          id: "WILDCARD_PORT_EXPOSURE",
          severity: "high",
          category: "security",
          title: `Broad Source with Wildcard Port Access on ${target} (Rule #${idx + 1})`,
          message: `Rule #${idx + 1} allows broad access from '${rule.src.join(", ")}' to ALL ports on '${target}'.`,
          ruleIndex: idx,
          rule,
          recommendation: `Explicitly enumerate permitted ports on ${target} (e.g. '${target}:80,443').`,
        });
      }

      // Check dangerous ports
      for (const p of ports) {
        if (typeof p === "number" && DANGEROUS_PORTS[p] && isWildcardSrc) {
          findings.push({
            id: `DANGEROUS_PORT_${p}`,
            severity: "high",
            category: "security",
            title: `Broad Access to Sensitive Port ${p} (${DANGEROUS_PORTS[p]}) (Rule #${idx + 1})`,
            message: `Rule #${idx + 1} grants global or member-wide access to sensitive service port ${p} (${DANGEROUS_PORTS[p]}).`,
            ruleIndex: idx,
            rule,
            recommendation: `Restrict access to port ${p} to dedicated admin tags (e.g. tag:db-admin) instead of broad sources.`,
          });
        }
      }

      // Check unowned tag in destination
      const dstTag = extractTag(target);
      if (dstTag && !declaredTags.has(dstTag)) {
        findings.push({
          id: "UNOWNED_TAG_IN_DST",
          severity: "medium",
          category: "syntax",
          title: `Unowned Tag in Rule Destination (${dstTag}) (Rule #${idx + 1})`,
          message: `Destination references tag '${dstTag}', which is not declared under tagOwners.`,
          ruleIndex: idx,
          rule,
          recommendation: `Declare '${dstTag}' in tagOwners or correct the destination name.`,
        });
      }
    }

    // Inspect sources
    for (const src of rule.src) {
      if (src.startsWith("group:") && !definedGroups.has(src)) {
        findings.push({
          id: "UNDEFINED_GROUP_IN_SRC",
          severity: "medium",
          category: "syntax",
          title: `Undefined Group Referenced in Source (${src}) (Rule #${idx + 1})`,
          message: `Rule #${idx + 1} source references '${src}', but it is not defined in groups.`,
          ruleIndex: idx,
          rule,
          recommendation: `Declare '${src}' under groups with members.`,
        });
      }

      const srcTag = extractTag(src);
      if (srcTag && !declaredTags.has(srcTag)) {
        findings.push({
          id: "UNOWNED_TAG_IN_SRC",
          severity: "medium",
          category: "syntax",
          title: `Unowned Tag in Rule Source (${srcTag}) (Rule #${idx + 1})`,
          message: `Source references tag '${srcTag}', which is not declared under tagOwners.`,
          ruleIndex: idx,
          rule,
          recommendation: `Declare '${srcTag}' in tagOwners or correct the source name.`,
        });
      }
    }

    // Shadowing detection: Check if earlier rule already satisfies this rule
    for (let prevIdx = 0; prevIdx < idx; prevIdx++) {
      const prevRule = acls[prevIdx];
      const prevHasBroadSrc = prevRule.src.includes("*");
      const prevHasBroadDst = prevRule.dst.includes("*:*");

      if (prevHasBroadSrc && prevHasBroadDst) {
        findings.push({
          id: "SHADOWED_ACL_RULE",
          severity: "medium",
          category: "shadowing",
          title: `Shadowed ACL Rule (Rule #${idx + 1} eclipsed by Rule #${prevIdx + 1})`,
          message: `Rule #${idx + 1} is completely shadowed by earlier wildcard rule #${prevIdx + 1} and will never take unique effect.`,
          ruleIndex: idx,
          rule,
          recommendation: `Reorganize rule order or remove earlier catch-all wildcard rule.`,
        });
        break;
      }
    }
  }

  // 4. Audit Tailscale SSH Rules
  for (let idx = 0; idx < sshRules.length; idx++) {
    const ssh = sshRules[idx];
    const isRootOrWildcard =
      ssh.users.includes("root") || ssh.users.includes("*");

    if (isRootOrWildcard && ssh.action === "accept") {
      findings.push({
        id: "UNCHECKED_ROOT_SSH",
        severity: "high",
        category: "security",
        title: `Unchecked Root / Wildcard SSH Access (SSH Rule #${idx + 1})`,
        message: `SSH rule #${idx + 1} permits '${ssh.users.join(", ")}' login with action 'accept' without periodic Identity Provider re-authentication.`,
        ruleIndex: idx,
        rule: ssh,
        recommendation: `Set action to 'check' with a checkPeriod (e.g. '12h') to enforce periodic MFA re-auth for privileged SSH sessions.`,
      });
    }

    if (ssh.src.includes("*")) {
      findings.push({
        id: "SSH_WILDCARD_SOURCE",
        severity: "medium",
        category: "security",
        title: `Tailscale SSH Source Allowed for Everyone (*) (SSH Rule #${idx + 1})`,
        message: `SSH rule #${idx + 1} allows any device in the tailnet to initiate SSH sessions.`,
        ruleIndex: idx,
        rule: ssh,
        recommendation: `Restrict SSH source to specific admin groups (e.g. 'group:devops') or user emails.`,
      });
    }
  }

  // 5. Audit NodeAttrs (Funnel exposure)
  for (const attr of nodeAttrs) {
    if (attr.attr?.includes("funnel")) {
      const isGlobal =
        attr.target.includes("*") || attr.target.includes("autogroup:member");
      if (isGlobal) {
        findings.push({
          id: "GLOBAL_FUNNEL_NODE_ATTR",
          severity: "high",
          category: "security",
          title: "Global Funnel Public Exposure Permission in nodeAttrs",
          message: "nodeAttrs grants the 'funnel' attribute to all tailnet nodes or members. Any device can publish unauthenticated local services to the public internet.",
          rule: attr,
          recommendation: "Restrict the 'funnel' attribute to designated gateway tags (e.g. ['tag:public-ingress']).",
        });
      }
    }
  }

  // 6. Audit Unit Tests
  if (acls.length > 2 && tests.length === 0) {
    findings.push({
      id: "NO_ACL_TESTS",
      severity: "low",
      category: "best_practice",
      title: "No Automated ACL Unit Tests Defined",
      message: `Policy file defines ${acls.length} ACL rules but contains 0 test assertions in the 'tests' block.`,
      recommendation: "Add 'tests' entries with 'accept' and 'deny' assertions to catch accidental access regressions.",
    });
  }

  // Calculate Zero-Trust Score
  let score = 100;
  for (const f of findings) {
    if (f.severity === "critical") score -= 35;
    else if (f.severity === "high") score -= 15;
    else if (f.severity === "medium") score -= 5;
    else if (f.severity === "low") score -= 2;
  }
  score = Math.max(0, Math.min(100, score));

  let securityRating: "A" | "B" | "C" | "D" | "F" = "F";
  if (score >= 90) securityRating = "A";
  else if (score >= 80) securityRating = "B";
  else if (score >= 70) securityRating = "C";
  else if (score >= 60) securityRating = "D";

  const criticalOrSyntaxErrors = findings.some(
    (f) => f.severity === "critical" || f.category === "syntax"
  );

  return {
    valid: !criticalOrSyntaxErrors,
    findings,
    stats,
    securityScore: score,
    securityRating,
  };
}
