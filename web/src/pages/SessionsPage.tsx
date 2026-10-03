import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type SessionInfo } from "../api";
import { hasRole, useMe } from "../auth";
import {
  Badge,
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorText,
  FormHint,
  Input,
  Muted,
  Page,
  PageHeader,
  Pager,
  RowActions,
  Spinner,
  Table,
  Td,
  Th,
  THead,
  TRow,
  useConfirm,
} from "../components/ui";

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
  const confirm = useConfirm();
  const [query, setQuery] = useState("");
  const [cursor, setCursor] = useState("");
  const [stack, setStack] = useState<string[]>([]);
  const limit = 50;

  const search = query.trim();

  const q = useQuery({
    queryKey: ["sessions", cursor, search],
    queryFn: () => api.listSessions({ limit, cursor: cursor || undefined, q: search || undefined }),
    enabled: isAdmin,
  });

  const sessions = q.data?.items ?? [];
  const total = q.data?.total ?? 0;
  const nextCursor = (q.data as unknown as { next_cursor?: string })?.next_cursor ?? "";
  const hasPrev = stack.length > 0;
  const hasNext = !!nextCursor;

  // If the current page is empty but there is a previous page (e.g. every
  // session on this page was revoked/expired between fetches), offer a clamp.
  const isEmptyPage = !q.isLoading && !q.isError && sessions.length === 0 && total > 0;
  const isSearchEmpty = isEmptyPage && !!search;
  const grouped = groupBySubject(sessions);

  const revokeOne = useMutation({
    mutationFn: (id: string) => api.deleteSession(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["sessions"] }),
  });

  const revokeSubject = useMutation({
    mutationFn: (subject: string) => api.deleteSessionsBySubject(subject),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["sessions"] }),
  });

  if (!me.isLoading && !isAdmin) {
    return <EmptyState>Sessions are managed by admins.</EmptyState>;
  }

  const goPrev = () => {
    if (!hasPrev) return;
    const prev = stack[stack.length - 1];
    setStack((s) => s.slice(0, -1));
    setCursor(prev);
  };
  const goFirst = () => {
    setStack([]);
    setCursor("");
  };

  const paginationBar = (
    <Pager
      summary={
        q.data
          ? `${sessions.length} on this page · ${total} total${stack.length ? ` · page ${stack.length + 1}` : ""}`
          : ""
      }
      hasPrev={hasPrev}
      hasNext={hasNext}
      onPrev={goPrev}
      onNext={() => {
        if (!hasNext) return;
        setStack((s) => [...s, cursor]);
        setCursor(nextCursor);
      }}
    />
  );

  return (
    <Page>
      <PageHeader
        title="Sessions"
        description={
          <>
            Active browser sessions (server-side BFF). Roles are frozen for the life of each session — at most{" "}
            <code>SESSION_TTL</code> (default 12h, max 24h). Revoke a user&apos;s sessions on offboarding or role change
            instead of waiting for expiry.
          </>
        }
        actions={<Button onClick={() => void qc.invalidateQueries({ queryKey: ["sessions"] })}>Refresh</Button>}
      />

      <Card className="space-y-3 p-4">
        <div className="flex flex-wrap items-center gap-3">
          <Input
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              // Server-side search is global — reset pagination to first page.
              goFirst();
            }}
            placeholder="Filter by subject, email or role…"
            aria-label="Filter sessions"
            className="w-full max-w-sm"
          />
          <span className="text-xs text-neutral-500">
            {q.data ? (search ? `${total} match${total === 1 ? "" : "es"} for “${search}”` : `${total} total`) : ""}
          </span>
        </div>
        <FormHint>
          Each row is one live server-side session. Its <code>id</code> is the stored hash, not the raw cookie value.
          &ldquo;Subject&rdquo; is the OIDC <code>sub</code> claim (opaque, often a UUID) — not the email. Revoking by
          subject is the offboarding path: it terminates every live session for that <code>sub</code> at once (404 if no
          live session matches, so a typo does not silently no-op). Filtering is server-side and global across all pages.
        </FormHint>
      </Card>

      {(revokeOne.isError || revokeSubject.isError) && (
        <ErrorText error={(revokeOne.error ?? revokeSubject.error) as unknown} />
      )}

      {q.isLoading ? (
        <Spinner />
      ) : q.isError ? (
        <ErrorText error={q.error} />
      ) : (
        <div className="space-y-4">
          {/* Pagination bar is always rendered when there is more than one page,
              independently of whether the current page has rows (fixes the bug where
              a filtered miss or an emptied later page hid Previous/Next). */}
          {(total > limit || hasPrev || hasNext) && paginationBar}

          {sessions.length === 0 ? (
            <EmptyState
              action={
                isEmptyPage && (
                  <>
                    {hasPrev && <Button onClick={goPrev}>Previous</Button>}
                    <Button onClick={goFirst}>First page</Button>
                  </>
                )
              }
            >
              {total === 0
                ? search
                  ? `No sessions match “${search}”.`
                  : "No active sessions."
                : isSearchEmpty
                  ? `No sessions on this page match “${search}”.`
                  : "No sessions on this page."}
            </EmptyState>
          ) : (
            Array.from(grouped.entries())
              .sort(([a], [b]) => a.localeCompare(b))
              .map(([subject, sessions]) => {
                const rep = sessions[0];
                const label = rep.email ? `${rep.name ? `${rep.name} — ` : ""}${rep.email}` : subject;
                return (
                  <Card key={subject} className="overflow-hidden">
                    <CardHeader className="bg-neutral-50 dark:bg-neutral-900/50">
                      <div className="min-w-0">
                        <div className="truncate font-medium" title={subject}>
                          {label}
                        </div>
                        <div className="truncate font-mono text-xs text-neutral-500" title={subject}>
                          {subject}
                        </div>
                      </div>
                      <div className="flex items-center gap-3">
                        <span className="text-xs text-neutral-500">
                          {sessions.length} session{sessions.length === 1 ? "" : "s"}
                        </span>
                        <Button
                          variant="danger"
                          size="sm"
                          disabled={revokeSubject.isPending}
                          onClick={async () => {
                            if (
                              await confirm({
                                title: `Revoke every session for ${label}?`,
                                description: (
                                  <>
                                    They are signed out immediately (next request → 401) and must sign in again. This is
                                    the offboarding path. Subject: <span className="font-mono">{subject}</span>
                                  </>
                                ),
                                confirmLabel: "Revoke all",
                              })
                            )
                              revokeSubject.mutate(subject);
                          }}
                        >
                          Revoke all
                        </Button>
                      </div>
                    </CardHeader>
                    <Table>
                      <THead>
                        <Th>Roles</Th>
                        <Th>Created</Th>
                        <Th>Expires</Th>
                        <Th>Session id (hash)</Th>
                        <Th aria-label="Actions" />
                      </THead>
                      <tbody>
                        {sessions.map((s) => (
                          <TRow key={s.id}>
                            <Td>
                              {s.roles.length ? (
                                <div className="flex flex-wrap gap-1">
                                  {s.roles.map((r) => (
                                    <Badge key={r}>{r}</Badge>
                                  ))}
                                </div>
                              ) : (
                                <Muted />
                              )}
                            </Td>
                            <Td className="whitespace-nowrap text-neutral-500">{fmtTime(s.created_at)}</Td>
                            <Td className="whitespace-nowrap text-neutral-500">{fmtTime(s.expires_at)}</Td>
                            <Td className="font-mono text-xs text-neutral-500" title={s.id}>
                              {s.id.slice(0, 12)}…{s.id.slice(-6)}
                            </Td>
                            <RowActions
                              label="session"
                              actions={[
                                {
                                  label: "Revoke",
                                  danger: true,
                                  disabled: revokeOne.isPending,
                                  onSelect: async () => {
                                    if (
                                      await confirm({
                                        title: `Revoke this session for ${label}?`,
                                        description: "The holder is signed out on their next request.",
                                        confirmLabel: "Revoke session",
                                      })
                                    )
                                      revokeOne.mutate(s.id);
                                  },
                                },
                              ]}
                            />
                          </TRow>
                        ))}
                      </tbody>
                    </Table>
                  </Card>
                );
              })
          )}
        </div>
      )}
    </Page>
  );
}
