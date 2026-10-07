// Mirrors the backend's channel derivation (templateSyncChannel /
// SafeTemplateRepo / isDefaultTemplateRepo in internal/backend/template_syncer.go)
// so the SPA's pills and picker agree with what the server records. The default
// repository is the ProjectDiscovery community catalog; only on it does `main`
// mean the Preview channel — on any custom repository `main` is just a ref.

export const DEFAULT_TEMPLATE_REPO = "https://github.com/projectdiscovery/nuclei-templates.git";

export type SyncChannel = "stable" | "preview" | "custom";

export const CHANNEL_LABELS: Record<SyncChannel, string> = {
  stable: "Stable",
  preview: "Preview",
  custom: "Custom",
};

/** Drops credentials, query and fragment the way the backend's SafeTemplateRepo
 *  does, so comparisons ignore embedded credentials. Unparseable input is
 *  returned trimmed, matching the backend's pass-through. */
export function sanitizeRepo(raw: string): string {
  const t = raw.trim();
  try {
    const u = new URL(t);
    u.username = "";
    u.password = "";
    u.search = "";
    u.hash = "";
    return u.toString();
  } catch {
    return t;
  }
}

export function isDefaultRepo(repo?: string | null): boolean {
  const t = (repo ?? "").trim();
  return t !== "" && sanitizeRepo(t) === DEFAULT_TEMPLATE_REPO;
}

export function channelFor(repo: string | undefined, ref: string): SyncChannel {
  switch (ref.trim()) {
    case "latest":
      return "stable";
    case "main":
      return isDefaultRepo(repo) ? "preview" : "custom";
    default:
      return "custom";
  }
}

export type SourceDescriptor = { repo?: string; ref?: string };

/**
 * "Stable → Preview" when the source changed between two sync runs; empty when
 * it did not. A run predating the recorded source columns (no `ref`) yields an
 * empty string. A missing repo only matters when the channel labels would be
 * equal: `latest` is stable on any repository, but a same-channel repository
 * change is only claimed when both runs carry a recorded repo.
 */
export function describeSourceSwitch(prev: SourceDescriptor, next: SourceDescriptor): string {
  const prevRef = prev.ref?.trim() ?? "";
  const nextRef = next.ref?.trim() ?? "";
  if (!prevRef || !nextRef) return "";
  const prevRepo = prev.repo?.trim() ?? "";
  const nextRepo = next.repo?.trim() ?? "";
  const sameRepo = sanitizeRepo(prevRepo) === sanitizeRepo(nextRepo);
  if (prevRef === nextRef && sameRepo) return "";
  const from = CHANNEL_LABELS[channelFor(prev.repo, prevRef)];
  const to = CHANNEL_LABELS[channelFor(next.repo, nextRef)];
  if (from !== to) return `${from} → ${to}`;
  if (prevRepo && nextRepo && !sameRepo) return "repository changed";
  return "";
}