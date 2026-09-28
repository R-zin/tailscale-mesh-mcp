import process from "node:process";

export type LogLevel = "debug" | "info" | "warn" | "error";

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const currentLevel: LogLevel = (process.env.LOG_LEVEL as LogLevel) || "info";

export const logger = {
  debug(message: string, context?: Record<string, unknown>): void {
    if (LOG_LEVELS[currentLevel] <= LOG_LEVELS.debug) {
      writeLog("DEBUG", message, context);
    }
  },
  info(message: string, context?: Record<string, unknown>): void {
    if (LOG_LEVELS[currentLevel] <= LOG_LEVELS.info) {
      writeLog("INFO", message, context);
    }
  },
  warn(message: string, context?: Record<string, unknown>): void {
    if (LOG_LEVELS[currentLevel] <= LOG_LEVELS.warn) {
      writeLog("WARN", message, context);
    }
  },
  error(message: string, context?: Record<string, unknown> | Error): void {
    if (LOG_LEVELS[currentLevel] <= LOG_LEVELS.error) {
      if (context instanceof Error) {
        writeLog("ERROR", message, {
          name: context.name,
          message: context.message,
          stack: context.stack,
        });
      } else {
        writeLog("ERROR", message, context);
      }
    }
  },
};

/**
 * MCP Stdio servers MUST output exclusively to stderr.
 * Outputting to stdout corrupts JSON-RPC frame parsing.
 */
function writeLog(
  level: string,
  message: string,
  context?: Record<string, unknown>
): void {
  const timestamp = new Date().toISOString();
  const contextStr = context ? ` ${JSON.stringify(context)}` : "";
  process.stderr.write(`[${timestamp}] [tailscale-mcp] [${level}] ${message}${contextStr}\n`);
}
