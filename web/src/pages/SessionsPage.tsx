import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, type SessionInfo } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Input, Spinner } from "../components/ui";

function fmtTime(s?: string) {
  return s ? new Date(s).toLocaleString() : "—";
}

function groupBySubject(sessions: SessionInfo[]) {
  const m = new Map<string, SessionInfo[]>();
  for (const s of sessions) {
    const arr = m.get(s.subject) ?? [];
    arr.push(s);
    m.set(s.subject, arr);
  }
  return m;
}

export function SessionsPage() {
  const me = useMe();
  const isAdmin = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const [query, setQuery] = useState("");

  const q = useQuery({
    queryKey: ["sessions"],
    queryFn: () => api.listSessions(),
    enabled: isAdmin,
  });

  const revokeOne = useMutation({
    mutationFn: (id: string) => api.deleteSession(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["sessions"] }),
  });

  const revokeSubject = useMutation({
    mutationFn: (subject: string) => api.deleteSessionsBySubject(subject),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["sessions"] }),
  });

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle || !q.data) return q.data ?? [];
    return q.data.filter((s) => {
      const hay = `${s.subject} ${s.email ?? ""} ${s.name ?? ""} ${s.roles.join(" ")}`.toLowerCase();
      return hay.includes(needle);
    });
  }, [q.data, query]);

  const grouped = useMemo(() => groupBySubject(filtered), [filtered]);

  if (!me.isLoading && !isAdmin) {
    return (
      <Card className="p-8 text-center text-sm text-neutral-500">
        Sessions are managed by admins.
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Sessions</h1>
          <p className="mt-1 max-w-2xl text-sm text-neutral-500">
            Active browser sessions (server-side BFF). Roles are frozen for the life of each
            session — at most <code>SESSION_TTL</code> (default 12h, max 24h). Revoke a user&apos;s
            sessions immediately on offboarding or role change instead of waiting for expiry. The
            grouping key is the OIDC <code>sub</code> (opaque, often a UUID) — copy it from the mono
            line below, not the email.
          </p>
        </div>
        <Button variant="secondary" onClick={() => void qc.invalidateQueries({ queryKey: ["sessions"] })}>
          Refresh
        </Button>
      </div>

      <Card className="space-y-3 p-4">
        <div className="flex flex-wrap items-center gap-3">
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Filter by subject, email or role…"
            className="max-w-sm"
          />
          <span className="text-xs text-neutral-400">
            {q.data ? `${filtered.length} of ${q.data.length} sessions` : ""}
          </span>
        </div>
        <p className="text-xs text-neutral-500">
          Each row is one live server-side session. Its <code>id</code> is the stored hash, not the
          raw cookie value. &ldquo;Subject&rdquo; is the OIDC <code>sub</code> claim (opaque, often a
          UUID) — not the email. Revoking by subject is the offboarding path — it terminates every
          live session for that <code>sub</code> at once (404 if no live session matches, so a typo
          or email-instead-of-<code>sub</code> does not silently no-op). Single-session revoke is for
          targeted termination.
        </p>
      </Card>

      {(revokeOne.isError || revokeSubject.isError) && (
        <ErrorText error={(revokeOne.error ?? revokeSubject.error) as unknown} />
      )}

      {q.isLoading ? (
        <Spinner />
      ) : q.isError ? (
        <ErrorText error={q.error} />
      ) : filtered.length === 0 ? (
        <Card className="p-8 text-center text-sm text-neutral-500">
          {q.data?.length ? "No sessions match this filter." : "No active sessions."}
        </Card>
      ) : (
        <div className="space-y-4">
          {Array.from(grouped.entries())
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([subject, sessions]) => {
              const rep = sessions[0];
              const label = rep.email ? `${rep.name ? `${rep.name} — ` : ""}${rep.email}` : subject;
              return (
                <Card key={subject} className="overflow-hidden">
                  <div className="flex flex-wrap items-center justify-between gap-2 border-b border-neutral-200 bg-neutral-50 px-3 py-2 dark:border-neutral-800 dark:bg-neutral-900/50">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-medium" title={subject}>
                        {label}
                      </div>
                      <div className="truncate font-mono text-xs text-neutral-500" title={subject}>
                        {subject}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-neutral-500">
                        {sessions.length} session{sessions.length === 1 ? "" : "s"}
                      </span>
                      <Button
                        variant="danger"
                        disabled={revokeSubject.isPending}
                        onClick={() => {
                          if (
                            confirm(
                              `Revoke every active session for ${subject}?\n\nThey will be signed out immediately (next request → 401) and must sign in again. This is the offboarding path.`,
                            )
                          )
                            revokeSubject.mutate(subject);
                        }}
                      >
                        Revoke all
                      </Button>
                    </div>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                          <th className="px-3 py-2 font-medium">Roles</th>
                          <th className="px-3 py-2 font-medium">Created</th>
                          <th className="px-3 py-2 font-medium">Expires</th>
                          <th className="px-3 py-2 font-medium">Session id (hash)</th>
                          <th className="px-3 py-2" />
                        </tr>
                      </thead>
                      <tbody>
                        {sessions.map((s) => (
                          <tr
                            key={s.id}
                            className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60"
                          >
                            <td className="px-3 py-2 text-neutral-700 dark:text-neutral-300">
                              {s.roles.length ? s.roles.join(", ") : "—"}
                            </td>
                            <td className="px-3 py-2 text-neutral-500">{fmtTime(s.created_at)}</td>
                            <td className="px-3 py-2 text-neutral-500">{fmtTime(s.expires_at)}</td>
                            <td className="px-3 py-2 font-mono text-xs text-neutral-500" title={s.id}>
                              {s.id.slice(0, 12)}…{s.id.slice(-6)}
                            </td>
                            <td className="px-3 py-2 text-right whitespace-nowrap">
                              <Button
                                variant="ghost"
                                className="text-red-600 dark:text-red-400"
                                disabled={revokeOne.isPending}
                                onClick={() => {
                                  if (
                                    confirm(
                                      `Revoke this session for ${subject}?\n\nThe holder will be signed out on their next request.`,
                                    )
                                  )
                                    revokeOne.mutate(s.id);
                                }}
                              >
                                Revoke
                              </Button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </Card>
              );
            })}
        </div>
      )}
    </div>
  );
}
