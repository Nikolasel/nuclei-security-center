import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  ASSIGNABLE_ROLES,
  DEFAULT_TOKEN_TTL_DAYS,
  api,
  type ServiceAccount,
  type ServiceAccountWithToken,
} from "../api";
import { hasRole, useMe } from "../auth";
import {
  Button,
  Card,
  ErrorText,
  Field,
  Input,
  Modal,
  Pill,
  Select,
  Spinner,
} from "../components/ui";

function fmtTime(s?: string) {
  return s ? new Date(s).toLocaleString() : "—";
}

/** isExpired reports whether an expiry timestamp has already passed. Expired
 *  tokens stay listed (revocation is a separate, deliberate act) but are marked,
 *  because the backend rejects them and a silent 401 in a cron job is otherwise a
 *  confusing thing to debug. */
function isExpired(sa: ServiceAccount) {
  return sa.expires_at != null && new Date(sa.expires_at).getTime() <= Date.now();
}

/** TokenReveal shows a freshly minted token. The server stores only a hash, so
 *  this is the one and only time it can be displayed — the dialog is therefore
 *  not dismissible by overlay/Esc, and says plainly that closing is final. */
function TokenReveal({ result, onClose }: { result: ServiceAccountWithToken; onClose: () => void }) {
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);

  async function copy() {
    try {
      await navigator.clipboard.writeText(result.token);
      setCopied(true);
      setCopyFailed(false);
    } catch {
      // Clipboard access can be denied; the token is selectable above regardless.
      setCopyFailed(true);
    }
  }

  return (
    <Modal open dismissible={false} onOpenChange={() => {}} title={`Token for “${result.name}”`}>
      <div className="space-y-4">
        <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-sm text-amber-900 dark:border-amber-800 dark:bg-amber-950 dark:text-amber-200">
          Copy this token now — it is shown <strong>once</strong> and cannot be retrieved
          afterwards. If you lose it, rotate the account to mint a new one.
        </div>

        <div className="break-all rounded-md border border-neutral-300 bg-neutral-50 p-3 font-mono text-sm select-all dark:border-neutral-700 dark:bg-neutral-800">
          {result.token}
        </div>

        <div className="flex items-center gap-2">
          <Button onClick={() => void copy()}>{copied ? "Copied ✓" : "Copy token"}</Button>
          <span className="text-xs text-neutral-500">
            Role <strong>{result.role}</strong> ·{" "}
            {result.expires_at ? `expires ${fmtTime(result.expires_at)}` : "no expiry"}
          </span>
        </div>
        {copyFailed && (
          <p className="text-xs text-red-600 dark:text-red-400">
            Couldn’t copy automatically — select the token above and copy it manually.
          </p>
        )}

        <p className="text-xs text-neutral-500">
          Use it as <code>Authorization: Bearer &lt;token&gt;</code> on <code>/api</code> requests.
        </p>

        <div className="flex justify-end">
          <Button variant="primary" onClick={onClose}>
            I’ve saved it
          </Button>
        </div>
      </div>
    </Modal>
  );
}

/** CreateModal mints a new service account. */
function CreateModal({
  onCreated,
  onClose,
}: {
  onCreated: (r: ServiceAccountWithToken) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [role, setRole] = useState<string>("viewer");
  const [ttl, setTtl] = useState(String(DEFAULT_TOKEN_TTL_DAYS));

  const create = useMutation({
    mutationFn: () =>
      api.createServiceAccount({ name: name.trim(), role, ttl_days: Number(ttl) }),
    onSuccess: onCreated,
  });

  const ttlNum = Number(ttl);
  const ttlInvalid = ttl.trim() === "" || !Number.isInteger(ttlNum) || ttlNum < 0;

  return (
    <Modal open onOpenChange={(v) => !v && onClose()} title="New service account">
      <div className="space-y-4">
        <Field label="Name">
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="defectdojo-export"
          />
        </Field>

        <Field label="Role">
          <Select value={role} onChange={(e) => setRole(e.target.value)} className="w-full">
            {ASSIGNABLE_ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </Select>
        </Field>
        <p className="-mt-2 text-xs text-neutral-500">
          Grant the least role the automation needs — <code>viewer</code> is enough to read and
          export findings.
        </p>

        <Field label="Expires in (days — 0 for no expiry)">
          <Input
            type="number"
            min={0}
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
            placeholder={String(DEFAULT_TOKEN_TTL_DAYS)}
          />
        </Field>
        {ttlNum === 0 && !ttlInvalid && (
          <p className="-mt-2 text-xs text-amber-700 dark:text-amber-400">
            A token with no expiry stays valid until it is rotated or revoked.
          </p>
        )}

        {create.isError && <ErrorText error={create.error} />}

        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={create.isPending || !name.trim() || ttlInvalid}
            onClick={() => create.mutate()}
          >
            {create.isPending ? "Creating…" : "Create"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export function ServiceAccountsPage() {
  const me = useMe();
  const isAdmin = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const [creating, setCreating] = useState(false);
  const [revealed, setRevealed] = useState<ServiceAccountWithToken | null>(null);

  // The backend enforces admin on every one of these routes; this check only
  // keeps a non-admin from being shown a page whose every call would 403.
  const q = useQuery({
    queryKey: ["service-accounts"],
    queryFn: () => api.listServiceAccounts(),
    enabled: isAdmin,
  });

  const rotate = useMutation({
    mutationFn: (id: string) => api.rotateServiceAccount(id),
    onSuccess: (r) => {
      setRevealed(r);
      void qc.invalidateQueries({ queryKey: ["service-accounts"] });
    },
  });
  const del = useMutation({
    mutationFn: (id: string) => api.deleteServiceAccount(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["service-accounts"] }),
  });

  if (!me.isLoading && !isAdmin) {
    return (
      <Card className="p-8 text-center text-sm text-neutral-500">
        Service accounts are managed by admins.
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold">Service Accounts</h1>
          <p className="mt-1 text-sm text-neutral-500">
            API tokens for headless automation (cron, CI, exports). Interactive users sign in with
            SSO instead.
          </p>
        </div>
        <Button variant="primary" onClick={() => setCreating(true)}>
          New service account
        </Button>
      </div>

      {rotate.isError && <ErrorText error={rotate.error} />}
      {del.isError && <ErrorText error={del.error} />}

      {q.isLoading ? (
        <Spinner />
      ) : q.isError ? (
        <ErrorText error={q.error} />
      ) : (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                  <th className="px-3 py-2 font-medium">Name</th>
                  <th className="px-3 py-2 font-medium">Role</th>
                  <th className="px-3 py-2 font-medium">Token</th>
                  <th className="px-3 py-2 font-medium">Created</th>
                  <th className="px-3 py-2 font-medium">Expires</th>
                  <th className="px-3 py-2 font-medium">Last used</th>
                  <th className="px-3 py-2" />
                </tr>
              </thead>
              <tbody>
                {(q.data ?? []).map((sa) => (
                  <tr
                    key={sa.id}
                    className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60"
                  >
                    <td className="px-3 py-2 font-medium">{sa.name}</td>
                    <td className="px-3 py-2 text-neutral-500">{sa.role}</td>
                    <td className="px-3 py-2 font-mono text-xs text-neutral-600 dark:text-neutral-400">
                      {sa.token_prefix}…
                    </td>
                    <td className="px-3 py-2 text-neutral-500">{fmtTime(sa.created_at)}</td>
                    <td className="px-3 py-2 text-neutral-500">
                      {isExpired(sa) ? (
                        <Pill tone="warn">expired</Pill>
                      ) : (
                        (sa.expires_at ? fmtTime(sa.expires_at) : "never")
                      )}
                    </td>
                    <td className="px-3 py-2 text-neutral-500">{fmtTime(sa.last_used_at)}</td>
                    <td className="px-3 py-2 text-right whitespace-nowrap">
                      <Button
                        variant="ghost"
                        disabled={rotate.isPending}
                        onClick={() => {
                          if (
                            confirm(
                              `Rotate "${sa.name}"?\n\nA new token is minted and the current one stops working immediately.`,
                            )
                          )
                            rotate.mutate(sa.id);
                        }}
                      >
                        Rotate
                      </Button>
                      <Button
                        variant="ghost"
                        className="text-red-600 dark:text-red-400"
                        onClick={() => {
                          if (
                            confirm(
                              `Revoke "${sa.name}"?\n\nIts token stops working immediately and anything using it will start failing.`,
                            )
                          )
                            del.mutate(sa.id);
                        }}
                      >
                        Revoke
                      </Button>
                    </td>
                  </tr>
                ))}
                {(q.data ?? []).length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-3 py-8 text-center text-neutral-400">
                      No service accounts yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {creating && (
        <CreateModal
          onClose={() => setCreating(false)}
          onCreated={(r) => {
            setCreating(false);
            setRevealed(r);
            void qc.invalidateQueries({ queryKey: ["service-accounts"] });
          }}
        />
      )}
      {revealed && <TokenReveal result={revealed} onClose={() => setRevealed(null)} />}
    </div>
  );
}
