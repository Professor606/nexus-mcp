/**
 * Strip noise from raw tool output before parsing or sending to the LLM.
 * All transformations are pure — no side effects.
 */

/** Strip ANSI escape sequences, progress bars, carriage returns, and excess blank lines. */
export function cleanOutput(raw: string, maxChars = 6000): string {
  return raw
    // ANSI color/style codes  e.g. \x1b[32m \x1b[0m
    .replace(/\x1b\[[0-9;]*[a-zA-Z]/g, "")
    // OSC sequences  e.g. \x1b]0;title\x07
    .replace(/\x1b\][^\x07]*\x07/g, "")
    // Carriage-return overwrite lines (progress spinners)
    .replace(/\r(?!\n)/g, "\n")
    // Progress bars:  [=====>    ]  [####      ]
    .replace(/\[[\s=#>\-*]+\]/g, "")
    // Collapse 3+ consecutive blank lines → double newline
    .replace(/\n{3,}/g, "\n\n")
    .trim()
    .slice(0, maxChars);
}

/**
 * Rough token count estimate: 1 token ≈ 4 characters.
 * Useful for staying within LLM context budgets.
 */
export function estimateTokens(text: string): number {
  return Math.ceil(text.length / 4);
}

/**
 * Truncate text to a token budget (default 1500 tokens ≈ 6000 chars).
 * Appends a truncation notice if cut.
 */
export function truncateToTokenBudget(
  text: string,
  maxTokens = 1500
): string {
  const maxChars = maxTokens * 4;
  if (text.length <= maxChars) return text;
  return (
    text.slice(0, maxChars) +
    `\n... [truncated — ${estimateTokens(text)} tokens, showing first ${maxTokens}]`
  );
}

/**
 * Truncate strings to max lengths and remove non-printable characters.
 * Retains printable ASCII, tabs, and newlines.
 */
export function sanitizeOutput(str: string, maxLength: number): string {
  if (!str) return "";
  let s = str.slice(0, maxLength);
  // Keep printable ASCII (x20-x7E), tabs (x09), newlines (x0A), carriage returns (x0D)
  s = s.replace(/[^\x09\x0A\x0D\x20-\x7E]/g, "");
  return s;
}

/**
 * Stringify JSON safely, handling circular references, BigInts, and undefined.
 */
export function forceSafeJson(value: any, replacer?: any, space?: string | number): string {
  const seen = new WeakSet();
  return JSON.stringify(
    value,
    (key, val) => {
      if (typeof val === "object" && val !== null) {
        if (seen.has(val)) {
          return "[Circular]";
        }
        seen.add(val);
      }
      if (typeof val === "bigint") {
        return val.toString();
      }
      if (typeof val === "undefined") {
        return null;
      }
      // Combine with user-provided replacer if it's a function
      if (typeof replacer === "function") {
        return replacer(key, val);
      }
      return val;
    },
    space
  );
}

