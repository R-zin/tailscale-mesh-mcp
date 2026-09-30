import { TailscaleAclPolicy, AclSemanticDiff, TailscaleAclRule } from "./types.js";
import { DANGEROUS_PORTS } from "../utils/validator.js";

/**
 * Computes a standard unified line-by-line diff between two text strings
 */
export function createUnifiedDiff(
  originalText: string,
  newText: string,
  oldHeader: string = "current-policy.hujson",
  newHeader: string = "proposed-policy.hujson"
): string {
  const oldLines = originalText.split(/\r?\n/);
  const newLines = newText.split(/\r?\n/);

  // Simple LCS-based diff implementation
  const matrix: number[][] = Array.from({ length: oldLines.length + 1 }, () =>
    new Array(newLines.length + 1).fill(0)
  );

  for (let i = 1; i <= oldLines.length; i++) {
    for (let j = 1; j <= newLines.length; j++) {
      if (oldLines[i - 1] === newLines[j - 1]) {
        matrix[i][j] = matrix[i - 1][j - 1] + 1;
      } else {
        matrix[i][j] = Math.max(matrix[i - 1][j], matrix[i][j - 1]);
      }
    }
  }

  // Backtrack to find edits
  const edits: { type: "keep" | "add" | "delete"; line: string }[] = [];
  let i = oldLines.length;
  let j = newLines.length;

  while (i > 0 || j > 0) {
    if (i > 0 && j > 0 && oldLines[i - 1] === newLines[j - 1]) {
      edits.unshift({ type: "keep", line: oldLines[i - 1] });
      i--;
      j--;
    } else if (j > 0 && (i === 0 || matrix[i][j - 1] >= matrix[i - 1][j])) {
      edits.unshift({ type: "add", line: newLines[j - 1] });
      j--;
    } else if (i > 0 && (j === 0 || matrix[i][j - 1] < matrix[i - 1][j])) {
      edits.unshift({ type: "delete", line: oldLines[i - 1] });
      i--;
    }
  }

  // Check if there are any changes
  const hasChanges = edits.some((e) => e.type !== "keep");
  if (!hasChanges) {
    return "No changes detected.";
  }

  // Generate unified diff output
  const output: string[] = [
    `--- ${oldHeader}`,
    `+++ ${newHeader}`,
    `@@ -1,${oldLines.length} +1,${newLines.length} @@`,
  ];

  for (const edit of edits) {
    if (edit.type === "keep") {
      output.push(`  ${edit.line}`);
    } else if (edit.type === "delete") {
      output.push(`- ${edit.line}`);
    } else if (edit.type === "add") {
      output.push(`+ ${edit.line}`);
    }
  }

  return output.join("\n");
}

/**
 * Extracts port numbers referenced in an ACL rule destination string (e.g. "tag:server:5432" or "*:*")
 */
function extractPortsFromDst(dst: string): (number | "*")[] {
  const parts = dst.split(":");
  if (parts.length < 2) return [];
  const portPart = parts[parts.length - 1];

  if (portPart === "*") return ["*"];

  return portPart
    .split(",")
    .flatMap((p) => {
      if (p.includes("-")) {
        const [start, end] = p.split("-").map(Number);
        if (!isNaN(start) && !isNaN(end) && start <= end) {
          const list: number[] = [];
          for (let port = start; port <= Math.min(end, start + 100); port++) {
            list.push(port);
          }
          return list;
        }
      }
      const num = Number(p);
      return isNaN(num) ? [] : [num];
    });
}

/**
 * Analyzes semantic and security differences between current policy and proposed policy
 */
export function analyzePolicyDiff(
  basePolicy: TailscaleAclPolicy,
  proposedPolicy: TailscaleAclPolicy,
  unifiedDiff: string
): AclSemanticDiff {
  const baseAcls: TailscaleAclRule[] = basePolicy.acls || [];
  const proposedAcls: TailscaleAclRule[] = proposedPolicy.acls || [];

  const baseRulesJson = baseAcls.map((r) => JSON.stringify(r));
  const proposedRulesJson = proposedAcls.map((r) => JSON.stringify(r));

  const addedRules = proposedAcls.filter(
    (r) => !baseRulesJson.includes(JSON.stringify(r))
  );
  const removedRules = baseAcls.filter(
    (r) => !proposedRulesJson.includes(JSON.stringify(r))
  );

  const riskFactors: string[] = [];
  let riskScoreDelta = 0; // Positive = higher risk, Negative = lower risk

  // Check newly added rules for dangerous patterns
  for (const rule of addedRules) {
    const isWildcardSrc = rule.src.includes("*") || rule.src.includes("autogroup:member");
    const isWildcardDst = rule.dst.includes("*:*");

    if (isWildcardSrc && isWildcardDst) {
      riskFactors.push("CRITICAL: Proposed policy introduces global wildcard rule (*:* -> *:*)");
      riskScoreDelta += 30;
    }

    for (const dst of rule.dst) {
      const ports = extractPortsFromDst(dst);
      if (ports.includes("*") && isWildcardSrc) {
        riskFactors.push(`HIGH RISK: Proposed rule allows wildcard port access on ${dst} from broad source`);
        riskScoreDelta += 15;
      }

      for (const p of ports) {
        if (typeof p === "number" && DANGEROUS_PORTS[p] && isWildcardSrc) {
          riskFactors.push(
            `HIGH RISK: Proposed rule grants broad access to sensitive port ${p} (${DANGEROUS_PORTS[p]})`
          );
          riskScoreDelta += 10;
        }
      }
    }
  }

  // Check Funnel exposures in nodeAttrs
  const baseFunnelTargets = (basePolicy.nodeAttrs || [])
    .filter((n) => n.attr?.includes("funnel"))
    .flatMap((n) => n.target || []);

  const proposedFunnelTargets = (proposedPolicy.nodeAttrs || [])
    .filter((n) => n.attr?.includes("funnel"))
    .flatMap((n) => n.target || []);

  const newFunnelTargets = proposedFunnelTargets.filter(
    (t) => !baseFunnelTargets.includes(t)
  );

  if (newFunnelTargets.length > 0) {
    if (newFunnelTargets.includes("*") || newFunnelTargets.includes("autogroup:member")) {
      riskFactors.push(
        "CRITICAL: Proposed policy expands Tailscale Funnel attribute to all nodes (* / autogroup:member)"
      );
      riskScoreDelta += 25;
    } else {
      riskFactors.push(
        `ELEVATED RISK: Proposed policy grants Funnel public access to new targets: ${newFunnelTargets.join(", ")}`
      );
      riskScoreDelta += 10;
    }
  }

  // Check removed rules that tightened security
  for (const rule of removedRules) {
    const isWildcardSrc = rule.src.includes("*");
    const isWildcardDst = rule.dst.includes("*:*");
    if (isWildcardSrc && isWildcardDst) {
      riskFactors.push("SECURITY IMPROVEMENT: Removed wide-open wildcard rule (*:* -> *:*)");
      riskScoreDelta -= 30;
    }
  }

  // Determine overall risk delta
  let riskDelta: "increased" | "decreased" | "neutral" = "neutral";
  if (riskScoreDelta > 0) {
    riskDelta = "increased";
  } else if (riskScoreDelta < 0) {
    riskDelta = "decreased";
  }

  const hasChanges = unifiedDiff !== "No changes detected.";

  // Formulate summary
  const summaryParts: string[] = [];
  summaryParts.push(
    `Rule changes: +${addedRules.length} added, -${removedRules.length} removed.`
  );
  if (riskDelta === "increased") {
    summaryParts.push("Security risk has INCREASED with proposed changes.");
  } else if (riskDelta === "decreased") {
    summaryParts.push("Security risk has DECREASED (tighter Zero-Trust posture).");
  } else {
    summaryParts.push("Risk posture remains NEUTRAL.");
  }

  return {
    unifiedDiff,
    hasChanges,
    addedRulesCount: addedRules.length,
    removedRulesCount: removedRules.length,
    modifiedRulesCount: 0,
    riskDelta,
    riskFactors,
    summary: summaryParts.join(" "),
  };
}
