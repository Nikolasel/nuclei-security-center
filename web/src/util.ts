/** parseList splits a comma/newline separated string into a trimmed, non-empty list. */
export function parseList(s: string): string[] {
  return s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);
}
