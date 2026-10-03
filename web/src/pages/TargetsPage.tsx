import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type Target } from "../api";
import { hasRole, useMe } from "../auth";
import {
  Alert,
  Button,
  Card,
  ErrorText,
  Field,
  Input,
  Modal,
  ModalActions,
  Muted,
  Page,
  PageHeader,
  RowActions,
  Spinner,
  Table,
  TableEmpty,
  Td,
  Textarea,
  Th,
  THead,
  TRow,
  useConfirm,
} from "../components/ui";
import { duplicateName, parseList } from "../util";

function TargetModal({
  existing,
  duplicate = false,
  existingNames,
  onClose,
}: {
  existing?: Target;
  duplicate?: boolean;
  existingNames: string[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const [name, setName] = useState(
    existing ? (duplicate ? duplicateName(existing.name, existingNames) : existing.name) : "",
  );
  const [hosts, setHosts] = useState((existing?.hosts ?? []).join("\n"));
  const [tags, setTags] = useState((existing?.tags ?? []).join(", "));
  const canSave = name.trim() !== "" && parseList(hosts).length > 0;

  const save = useMutation({
    mutationFn: () => {
      const body = { name: name.trim(), hosts: parseList(hosts), tags: parseList(tags) };
      return existing && !duplicate ? api.updateTarget(existing.id, body) : api.createTarget(body);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["targets"] });
      onClose();
    },
  });

  return (
    <Modal
      open
      onOpenChange={(v) => !v && onClose()}
      title={duplicate ? "Duplicate target" : existing ? "Edit target" : "New target"}
    >
      <div className="space-y-4">
        <Field label="Name" required>
          <Input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="prod-web"
            required
            aria-required="true"
            className="w-full"
          />
        </Field>
        <Field
          label="Hosts"
          required
          hint="One per line: hostname, IP, CIDR or URL. This is the scope allowlist — scans can only reach these hosts."
        >
          <Textarea
            value={hosts}
            onChange={(e) => setHosts(e.target.value)}
            rows={4}
            placeholder="scanme.sh&#10;10.0.0.0/24&#10;https://example.com"
            required
            aria-required="true"
          />
        </Field>
        <Field label="Tags" hint="Comma separated.">
          <Input value={tags} onChange={(e) => setTags(e.target.value)} placeholder="prod, external" className="w-full" />
        </Field>
        {save.isError && <ErrorText error={save.error} />}
        <ModalActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={save.isPending || !canSave} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save target"}
          </Button>
        </ModalActions>
      </div>
    </Modal>
  );
}

export function TargetsPage() {
  const me = useMe();
  const canWrite = hasRole(me.data ?? undefined, "operator");
  const canDelete = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const confirm = useConfirm();
  const [editing, setEditing] = useState<Target | "new" | null>(null);
  const [duplicating, setDuplicating] = useState(false);
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedTargetID = searchParams.get("target") ?? "";

  const q = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const visibleTargets = selectedTargetID
    ? (q.data ?? []).filter((target) => target.id === selectedTargetID)
    : (q.data ?? []);
  const del = useMutation({
    mutationFn: (id: string) => api.deleteTarget(id),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["targets"] }),
  });
  const openEditor = (target: Target | "new", duplicate = false) => {
    setDuplicating(duplicate);
    setEditing(target);
  };
  const closeEditor = () => {
    setEditing(null);
    setDuplicating(false);
  };

  return (
    <Page>
      <PageHeader
        title="Targets"
        description="Approved scan scope. A scan can only reach hosts listed on the target it runs against."
        actions={
          canWrite && (
            <Button variant="primary" onClick={() => openEditor("new")}>
              New target
            </Button>
          )
        }
      />

      {selectedTargetID && (
        <Alert
          tone="info"
          action={
            <Button variant="link" onClick={() => setSearchParams({})}>
              Show all targets
            </Button>
          }
        >
          Showing the linked target.
        </Alert>
      )}
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
              <Th>Hosts</Th>
              <Th>Tags</Th>
              {(canWrite || canDelete) && <Th aria-label="Actions" />}
            </THead>
            <tbody>
              {visibleTargets.map((t) => (
                <TRow key={t.id} highlighted={t.id === selectedTargetID}>
                  <Td className="whitespace-nowrap font-medium">{t.name}</Td>
                  <Td className="font-mono text-xs text-neutral-600 dark:text-neutral-400">{t.hosts.join(", ")}</Td>
                  <Td className="text-neutral-500">{t.tags.join(", ") || <Muted />}</Td>
                  {(canWrite || canDelete) && (
                    <RowActions
                      label={t.name}
                      actions={[
                        { label: "Edit", primary: true, hidden: !canWrite, onSelect: () => openEditor(t) },
                        { label: "Duplicate", hidden: !canWrite, onSelect: () => openEditor(t, true) },
                        {
                          label: "Delete",
                          danger: true,
                          hidden: !canDelete,
                          onSelect: async () => {
                            if (
                              await confirm({
                                title: `Delete target “${t.name}”?`,
                                description: "Schedules that use this target are deleted with it. Past scans keep their history.",
                                confirmLabel: "Delete target",
                              })
                            )
                              del.mutate(t.id);
                          },
                        },
                      ]}
                    />
                  )}
                </TRow>
              ))}
              {visibleTargets.length === 0 && (
                <TableEmpty colSpan={4}>
                  {selectedTargetID ? "The linked target no longer exists." : "No targets yet."}
                </TableEmpty>
              )}
            </tbody>
          </Table>
        </Card>
      )}

      {editing && (
        <TargetModal
          existing={editing === "new" ? undefined : editing}
          duplicate={duplicating}
          existingNames={(q.data ?? []).map((target) => target.name)}
          onClose={closeEditor}
        />
      )}
    </Page>
  );
}
