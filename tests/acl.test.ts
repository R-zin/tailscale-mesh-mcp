import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { parseHuJson, huJsonToJson, formatHuJson } from "../src/tailscale/hujson.js";
import { auditAclPolicy, parseDestination } from "../src/tailscale/acl.js";
import { createUnifiedDiff, analyzePolicyDiff } from "../src/tailscale/diff.js";
import { TailscaleClient } from "../src/tailscale/client.js";
import { TailscaleAclPolicy } from "../src/tailscale/types.js";

describe("HuJSON Parser", () => {
  it("should parse standard JSON", () => {
    const input = '{"name": "test", "active": true, "count": 42}';
    const parsed = parseHuJson<{ name: string; active: boolean; count: number }>(input);
    assert.equal(parsed.name, "test");
    assert.equal(parsed.active, true);
    assert.equal(parsed.count, 42);
  });

  it("should strip single-line and multi-line comments", () => {
    const input = `
      // Tailscale ACL configuration
      {
        /* Primary groups definition */
        "groups": {
          "group:devs": ["alice@example.com"], // DevOps team
        },
        "acls": [
          /* Allow web traffic */
          { "action": "accept", "src": ["group:devs"], "dst": ["tag:server:80"] },
        ],
      }
    `;
    const parsed = parseHuJson<TailscaleAclPolicy>(input);
    assert.deepEqual(parsed.groups?.["group:devs"], ["alice@example.com"]);
    assert.equal(parsed.acls?.length, 1);
  });

  it("should preserve strings with slashes and commas", () => {
    const input = `{
      "url": "https://example.com/api//v2",
      "text": "Hello, world! // not a comment",
      "escaped": "Quote: \\"hello\\"",
    }`;
    const parsed = parseHuJson<{ url: string; text: string; escaped: string }>(input);
    assert.equal(parsed.url, "https://example.com/api//v2");
    assert.equal(parsed.text, "Hello, world! // not a comment");
    assert.equal(parsed.escaped, 'Quote: "hello"');
  });

  it("should format HuJSON cleanly into canonical JSON", () => {
    const input = `{// Comment\n "a": 1, \n}`;
    const formatted = formatHuJson(input, 2);
    assert.equal(formatted, '{\n  "a": 1\n}');
  });

  it("should throw informative error on syntax errors", () => {
    const input = `{"a": 1, "unclosed: 2}`;
    assert.throws(() => parseHuJson(input), /HuJSON Syntax Error/);
  });
});

describe("Destination Parsing", () => {
  it("should parse single port, ranges, and wildcards", () => {
    assert.deepEqual(parseDestination("tag:server:80"), {
      target: "tag:server",
      ports: [80],
    });
    assert.deepEqual(parseDestination("tag:server:80,443"), {
      target: "tag:server",
      ports: [80, 443],
    });
    assert.deepEqual(parseDestination("*:*"), {
      target: "*",
      ports: ["*"],
    });
    assert.deepEqual(parseDestination("100.64.0.1:8000-8002"), {
      target: "100.64.0.1",
      ports: [8000, 8001, 8002],
    });
  });
});

describe("ACL Security Auditor", () => {
  it("should detect critical full-mesh wildcard rule (*:* -> *:*)", () => {
    const policy: TailscaleAclPolicy = {
      acls: [{ action: "accept", src: ["*"], dst: ["*:*"] }],
    };

    const res = auditAclPolicy(policy);
    assert.equal(res.valid, false);
    assert.ok(res.securityScore < 70);
    const critical = res.findings.find((f) => f.id === "CRITICAL_WILDCARD_FULL_ACCESS");
    assert.ok(critical);
    assert.equal(critical.severity, "critical");
  });

  it("should detect broad access to dangerous database ports (5432, 6379)", () => {
    const policy: TailscaleAclPolicy = {
      tagOwners: {
        "tag:db": ["autogroup:admin"],
      },
      acls: [
        {
          action: "accept",
          src: ["autogroup:member"],
          dst: ["tag:db:5432,6379"],
        },
      ],
    };

    const res = auditAclPolicy(policy);
    const pg = res.findings.find((f) => f.id === "DANGEROUS_PORT_5432");
    const redis = res.findings.find((f) => f.id === "DANGEROUS_PORT_6379");
    assert.ok(pg, "Should detect PostgreSQL exposure");
    assert.ok(redis, "Should detect Redis exposure");
  });

  it("should detect unowned tags and undefined groups", () => {
    const policy: TailscaleAclPolicy = {
      acls: [
        {
          action: "accept",
          src: ["group:engineering"],
          dst: ["tag:unowned-service:443"],
        },
      ],
    };

    const res = auditAclPolicy(policy);
    const unownedTag = res.findings.find((f) => f.id === "UNOWNED_TAG_IN_DST");
    const undefGroup = res.findings.find((f) => f.id === "UNDEFINED_GROUP_IN_SRC");

    assert.ok(unownedTag, "Should detect unowned tag in destination");
    assert.ok(undefGroup, "Should detect undefined group in source");
  });

  it("should detect unchecked root SSH access", () => {
    const policy: TailscaleAclPolicy = {
      ssh: [
        {
          action: "accept",
          src: ["*"],
          dst: ["tag:prod-servers"],
          users: ["root"],
        },
      ],
    };

    const res = auditAclPolicy(policy);
    const uncheckedRoot = res.findings.find((f) => f.id === "UNCHECKED_ROOT_SSH");
    assert.ok(uncheckedRoot);
    assert.equal(uncheckedRoot.severity, "high");
  });

  it("should detect global Funnel attribute in nodeAttrs", () => {
    const policy: TailscaleAclPolicy = {
      nodeAttrs: [
        {
          target: ["*"],
          attr: ["funnel"],
        },
      ],
    };

    const res = auditAclPolicy(policy);
    const funnelFinding = res.findings.find((f) => f.id === "GLOBAL_FUNNEL_NODE_ATTR");
    assert.ok(funnelFinding);
    assert.equal(funnelFinding.severity, "high");
  });

  it("should give high zero-trust rating to well-scoped policy", () => {
    const securePolicy: TailscaleAclPolicy = {
      groups: {
        "group:developers": ["alice@example.com", "bob@example.com"],
      },
      tagOwners: {
        "tag:web": ["group:developers"],
        "tag:api": ["group:developers"],
      },
      acls: [
        {
          action: "accept",
          src: ["group:developers"],
          dst: ["tag:web:443", "tag:api:8443"],
        },
      ],
      tests: [
        {
          src: "alice@example.com",
          accept: ["tag:web:443"],
          deny: ["tag:web:22"],
        },
      ],
    };

    const res = auditAclPolicy(securePolicy);
    assert.equal(res.valid, true);
    assert.equal(res.securityRating, "A");
    assert.ok(res.securityScore >= 90);
    assert.equal(res.findings.length, 0);
  });
});

describe("Diff Preview and Semantic Analysis", () => {
  it("should generate unified diff and detect increased risk", () => {
    const basePolicy: TailscaleAclPolicy = {
      groups: { "group:admin": ["admin@example.com"] },
      tagOwners: { "tag:db": ["group:admin"] },
      acls: [
        { action: "accept", src: ["group:admin"], dst: ["tag:db:5432"] },
      ],
    };

    const proposedPolicy: TailscaleAclPolicy = {
      groups: { "group:admin": ["admin@example.com"] },
      tagOwners: { "tag:db": ["group:admin"] },
      acls: [
        { action: "accept", src: ["group:admin"], dst: ["tag:db:5432"] },
        { action: "accept", src: ["*"], dst: ["*:*"] }, // Introduced wildcard
      ],
    };

    const baseHuJson = JSON.stringify(basePolicy, null, 2);
    const proposedHuJson = JSON.stringify(proposedPolicy, null, 2);

    const diffOutput = createUnifiedDiff(baseHuJson, proposedHuJson);
    assert.ok(diffOutput.includes("+") && diffOutput.includes('"*:*"'));

    const analysis = analyzePolicyDiff(basePolicy, proposedPolicy, diffOutput);
    assert.equal(analysis.addedRulesCount, 1);
    assert.equal(analysis.riskDelta, "increased");
    assert.ok(analysis.riskFactors.some((rf) => rf.includes("global wildcard rule")));
  });
});

describe("TailscaleClient auditAclRules End-to-End", () => {
  const client = new TailscaleClient();

  it("should audit provided HuJSON policy directly", async () => {
    const hujson = `
      // Sample Tailscale ACL
      {
        "groups": {
          "group:ops": ["ops@example.com"],
        },
        "tagOwners": {
          "tag:server": ["group:ops"],
        },
        "acls": [
          { "action": "accept", "src": ["*"], "dst": ["*:*"] }, // Critical risk
        ],
      }
    `;

    const result = await client.auditAclRules({ policy: hujson });
    assert.equal(result.valid, false); // Critical finding makes valid false
    assert.equal(result.policySource, "provided");
    assert.ok(result.securityScore < 70);
    assert.ok(result.findings.some((f) => f.id === "CRITICAL_WILDCARD_FULL_ACCESS"));
    assert.ok(result.formattedHuJson);
  });

  it("should compare policy with proposedPolicy and return diff", async () => {
    const base = `{"acls": [{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:80"]}]}`;
    const proposed = `{"acls": [{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:80"]}, {"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`;

    const result = await client.auditAclRules({
      policy: base,
      proposedPolicy: proposed,
    });

    assert.ok(result.diff);
    assert.equal(result.diff.hasChanges, true);
    assert.equal(result.diff.addedRulesCount, 1);
    assert.equal(result.diff.riskDelta, "increased");
  });
});
