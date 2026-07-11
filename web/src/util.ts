/** parseList splits a comma/newline separated string into a trimmed, non-empty list. */
export function parseList(s: string): string[] {
  return s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);
}

/**
 * safeHref returns the URL only when it parses as an absolute http(s) URL, and
 * undefined otherwise. Finding-derived strings (a template-url, a reference) are
 * influenced by an untrusted actor; React escapes text nodes but does NOT block
 * `javascript:` / `data:` URLs in an `href`, so an unchecked value would yield a
 * clickable script link running in the BFF same-origin context. Callers must
 * fall back to rendering the value as plain text when this returns undefined.
 */
export function safeHref(url: string | undefined | null): string | undefined {
  if (!url) return undefined;
  try {
    const parsed = new URL(url);
    if (parsed.protocol === "http:" || parsed.protocol === "https:") return url;
  } catch {
    // Not an absolute URL — treat as unsafe.
  }
  return undefined;
}
