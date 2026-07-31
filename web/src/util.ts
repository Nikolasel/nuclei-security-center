import type { ScanProgress } from "./api";

/**
 * scanEtaSeconds estimates the seconds remaining for a running scan from its live
 * progress (#107). It is deliberately approximate — Nuclei's own request-based
 * completion signal — so callers should label it an estimate, not a countdown.
 *
 * Primary signal: remaining requests / current rps. Fallback when rps isn't
 * usable: extrapolate from elapsed time and percent complete
 * (elapsed * (100 - percent) / percent). Returns null when no usable estimate
 * exists yet (early in the run, before rps/percent settle) so the UI can show
 * "estimating…" rather than a wild number.
 */
export function scanEtaSeconds(p: ScanProgress, elapsedSec: number): number | null {
  const requests = p.requests ?? 0;
  if (p.rps && p.rps > 0 && p.total && p.total > requests) {
    return (p.total - requests) / p.rps;
  }
  if (p.percent > 0 && p.percent < 100 && elapsedSec > 0) {
    return (elapsedSec * (100 - p.percent)) / p.percent;
  }
  return null;
}

/** formatDuration renders a rough seconds value as "~45s" / "~3m" / "~1h 12m". */
export function formatDuration(sec: number): string {
  if (sec < 60) return `~${Math.max(1, Math.round(sec))}s`;
  if (sec < 3600) return `~${Math.round(sec / 60)}m`;
  const h = Math.floor(sec / 3600);
  const m = Math.round((sec % 3600) / 60);
  return m > 0 ? `~${h}h ${m}m` : `~${h}h`;
}

/** parseList splits a comma/newline separated string into a trimmed, non-empty list. */
export function parseList(s: string): string[] {
  return s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean);
}

/**
 * duplicateName returns a case-insensitive, non-colliding name for a copied
 * resource. The backend enforces the same uniqueness rule with lower(name),
 * so checking normalized names here avoids an avoidable conflict response.
 */
export function duplicateName(name: string, existingNames: Iterable<string>): string {
  const base = name.trim();
  const taken = new Set<string>();
  for (const existingName of existingNames) {
    taken.add(existingName.trim().toLowerCase());
  }

  for (let copyNumber = 1; ; copyNumber += 1) {
    const suffix = copyNumber === 1 ? "" : ` ${copyNumber}`;
    const candidate = `${base} (copy${suffix})`;
    if (!taken.has(candidate.toLowerCase())) return candidate;
  }
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
