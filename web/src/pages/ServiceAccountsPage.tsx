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
  Alert,
  Badge,
  Button,
  Card,
  EmptyState,
  ErrorText,
  Field,
  FormHint,
  Input,
  Modal,
  ModalActions,
  Page,
  PageHeader,
  RowActions,
  Select,
  Spinner,
  Table,
  TableEmpty,
  Td,
  Th,
  THead,
  TRow,
  useConfirm,
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
        <Alert tone="warning">
          Copy this token now — it is shown <strong>once</strong> and cannot be retrieved
          afterwards. If you lose it, rotate the account to mint a new one.
        </Alert>

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
          <FormHint tone="danger">Couldn’t copy automatically — select the token above and copy it manually.</FormHint>
        )}

        <FormHint>
          Use it as <code>Authorization: Bearer &lt;token&gt;</code> on <code>/api</code> requests.
        </FormHint>

        <ModalActions>
          <Button variant="primary" onClick={onClose}>
            I’ve saved it
          </Button>
        </ModalActions>
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
        <Field label="Name" required>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="defectdojo-export"
            className="w-full"
          />
        </Field>

        <Field
          label="Role"
          hint={
            <>
              Grant the least role the automation needs — <code>viewer</code> is enough to read and export findings.
            </>
          }
        >
          <Select value={role} onChange={(e) => setRole(e.target.value)} className="w-full">
            {ASSIGNABLE_ROLES.map((r) => (
              <option key={r} value={r}>
                {r}
              </option>
            ))}
          </Select>
        </Field>

        <Field label="Expires in (days)" hint="0 for no expiry." error={ttlInvalid && "Enter a whole number of days (0 or more)."}>
          <Input
            type="number"
            min={0}
            value={ttl}
            onChange={(e) => setTtl(e.target.value)}
            placeholder={String(DEFAULT_TOKEN_TTL_DAYS)}
            className="w-full"
          />
        </Field>
        {ttlNum === 0 && !ttlInvalid && (
          <FormHint tone="warning">A token with no expiry stays valid until it is rotated or revoked.</FormHint>
        )}

        {create.isError && <ErrorText error={create.error} />}

        <ModalActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            disabled={create.isPending || !name.trim() || ttlInvalid}
            onClick={() => create.mutate()}
          >
            {create.isPending ? "Creating…" : "Create service account"}
          </Button>
        </ModalActions>
      </div>
    </Modal>
  );
}

export function ServiceAccountsPage() {
  const me = useMe();
  const isAdmin = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const confirm = useConfirm();
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
    return <EmptyState>Service accounts are managed by admins.</EmptyState>;
  }

  return (
    <Page>
      <PageHeader
        title="Service accounts"
        description="API tokens for headless automation (cron, CI, exports). Interactive users sign in with SSO instead."
        actions={
          <Button variant="primary" onClick={() => setCreating(true)}>
            New service account
          </Button>
        }
      />

      {rotate.isError && <ErrorText error={rotate.error} />}
      {del.isError && <ErrorText error={del.error} />}

      {q.isLoading ? (
        <Spinner />
      ) : q.isError ? (
        <ErrorText error={q.error} />
      ) : (
        <Card>
          <Table>
            <THead>
              <Th>Name</Th>
              <Th>Role</Th>
              <Th>Token</Th>
              <Th>Created</Th>
              <Th>Expires</Th>
              <Th>Last used</Th>
              <Th aria-label="Actions" />
            </THead>
            <tbody>
              {(q.data ?? []).map((sa) => (
                <TRow key={sa.id}>
                  <Td className="font-medium">{sa.name}</Td>
                  <Td>
                    <Badge>{sa.role}</Badge>
                  </Td>
                  <Td className="font-mono text-xs text-neutral-600 dark:text-neutral-400">{sa.token_prefix}…</Td>
                  <Td className="whitespace-nowrap text-neutral-500">{fmtTime(sa.created_at)}</Td>
                  <Td className="whitespace-nowrap text-neutral-500">
                    {isExpired(sa) ? <Badge tone="danger">expired</Badge> : sa.expires_at ? fmtTime(sa.expires_at) : "never"}
                  </Td>
                  <Td className="whitespace-nowrap text-neutral-500">{fmtTime(sa.last_used_at)}</Td>
                  <RowActions
                    label={sa.name}
                    actions={[
                      {
                        label: "Rotate",
                        primary: true,
                        disabled: rotate.isPending,
                        onSelect: async () => {
                          if (
                            await confirm({
                              title: `Rotate “${sa.name}”?`,
                              description: "A new token is minted and the current one stops working immediately.",
                              confirmLabel: "Rotate token",
                              tone: "primary",
                            })
                          )
                            rotate.mutate(sa.id);
                        },
                      },
                      {
                        label: "Revoke",
                        danger: true,
                        onSelect: async () => {
                          if (
                            await confirm({
                              title: `Revoke “${sa.name}”?`,
                              description: "Its token stops working immediately and anything using it will start failing.",
                              confirmLabel: "Revoke",
                            })
                          )
                            del.mutate(sa.id);
                        },
                      },
                    ]}
                  />
                </TRow>
              ))}
              {(q.data ?? []).length === 0 && <TableEmpty colSpan={7}>No service accounts yet.</TableEmpty>}
            </tbody>
          </Table>
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
    </Page>
  );
}
