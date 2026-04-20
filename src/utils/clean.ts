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
