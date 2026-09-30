/**
 * HuJSON (Human JSON / JSON with Comments) parser and tokenizer.
 * Handles Tailscale's standard HuJSON ACL format:
 * - Single-line comments (// ...)
 * - Multi-line comments (/ * ... * /)
 * - Trailing commas in arrays and objects
 * - Preserves string content containing // or commas safely
 */

export interface HuJsonParseOptions {
  /** If true, keeps empty objects when input is blank instead of throwing */
  allowEmpty?: boolean;
}

/**
 * Strips single-line and multi-line comments from HuJSON text while preserving
 * newlines (maintaining line numbers) and ignoring comments within quoted strings.
 */
export function stripHuJsonComments(input: string): string {
  if (!input) return "";

  let output = "";
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;
  let escapeNext = false;

  for (let i = 0; i < input.length; i++) {
    const char = input[i];
    const nextChar = i + 1 < input.length ? input[i + 1] : "";

    // Handle escape character inside strings
    if (escapeNext) {
      output += char;
      escapeNext = false;
      continue;
    }

    if (inString) {
      if (char === "\\") {
        escapeNext = true;
        output += char;
      } else if (char === '"') {
        inString = false;
        output += char;
      } else {
        output += char;
      }
      continue;
    }

    if (inLineComment) {
      if (char === "\n" || char === "\r") {
        inLineComment = false;
        output += char; // Keep newline to preserve line numbers
      }
      continue;
    }

    if (inBlockComment) {
      if (char === "*" && nextChar === "/") {
        inBlockComment = false;
        i++; // Skip closing slash
      } else if (char === "\n") {
        output += "\n"; // Keep newline to preserve line numbers
      }
      continue;
    }

    // Currently outside string and comments
    if (char === '"') {
      inString = true;
      output += char;
      continue;
    }

    if (char === "/" && nextChar === "/") {
      inLineComment = true;
      i++; // Skip second slash
      continue;
    }

    if (char === "/" && nextChar === "*") {
      inBlockComment = true;
      i++; // Skip asterisk
      continue;
    }

    output += char;
  }

  return output;
}

/**
 * Strips trailing commas from JSON-like structures:
 * e.g. [1, 2, ] -> [1, 2 ] and {"a": 1, } -> {"a": 1 }
 * Preserves commas inside strings.
 */
export function stripTrailingCommas(input: string): string {
  let output = "";
  let inString = false;
  let escapeNext = false;

  for (let i = 0; i < input.length; i++) {
    const char = input[i];

    if (escapeNext) {
      output += char;
      escapeNext = false;
      continue;
    }

    if (inString) {
      if (char === "\\") {
        escapeNext = true;
      } else if (char === '"') {
        inString = false;
      }
      output += char;
      continue;
    }

    if (char === '"') {
      inString = true;
      output += char;
      continue;
    }

    if (char === ",") {
      // Look ahead to check if the next non-whitespace character is a closing delimiter
      let j = i + 1;
      while (j < input.length && /\s/.test(input[j])) {
        j++;
      }
      if (j < input.length && (input[j] === "}" || input[j] === "]")) {
        // Trailing comma found, omit this comma
        continue;
      }
    }

    output += char;
  }

  return output;
}

/**
 * Converts HuJSON text to standard JSON text.
 */
export function huJsonToJson(input: string): string {
  const noComments = stripHuJsonComments(input);
  return stripTrailingCommas(noComments);
}

/**
 * Parses HuJSON text into a typed JavaScript/TypeScript object.
 */
export function parseHuJson<T = unknown>(input: string, options: HuJsonParseOptions = {}): T {
  if (!input || !input.trim()) {
    if (options.allowEmpty) {
      return {} as T;
    }
    throw new Error("Cannot parse empty HuJSON content.");
  }

  const cleanJson = huJsonToJson(input);

  try {
    return JSON.parse(cleanJson) as T;
  } catch (err: any) {
    // Provide enhanced context around the parse error
    const match = err.message.match(/at position (\d+)/);
    let positionInfo = "";
    if (match && match[1]) {
      const pos = parseInt(match[1], 10);
      const lines = cleanJson.slice(0, pos).split("\n");
      const lineNum = lines.length;
      const colNum = lines[lines.length - 1].length + 1;
      positionInfo = ` (at line ${lineNum}, column ${colNum})`;
    }

    throw new Error(`HuJSON Syntax Error${positionInfo}: ${err.message}`);
  }
}

/**
 * Formats/standardizes a HuJSON string into canonical indented JSON/HuJSON.
 */
export function formatHuJson(input: string, indent: number = 2): string {
  const parsed = parseHuJson(input);
  return JSON.stringify(parsed, null, indent);
}
