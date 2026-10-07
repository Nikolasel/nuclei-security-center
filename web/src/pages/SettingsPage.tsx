import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import * as Tooltip from "@radix-ui/react-tooltip";
import { CircleHelp } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api, type EnvVariable } from "../api";
import { hasRole, useMe } from "../auth";
import {
  Button,
  Checkbox,
  cn,
  EmptyState,
  ErrorText,
  Field,
  focusRing,
  Input,
  Muted,
  Page,
  PageHeader,
  Pill,
  Section,
  Spinner,
  Table,
  Td,
  Th,
  THead,
  TRow,
} from "../components/ui";

function groupEnvVariables(vars: EnvVariable[]): { group: string; items: EnvVariable[] }[] {
  const order: string[] = [];
  const map = new Map<string, EnvVariable[]>();
  for (const v of vars) {
    const list = map.get(v.group);
    if (!list) {
      order.push(v.group);
      map.set(v.group, [v]);
    } else {
      list.push(v);
    }
  }
  return order.map((group) => ({ group, items: map.get(group) ?? [] }));
}

function effectiveDisplay(v: EnvVariable): string {
  if (v.effective != null && v.effective !== "") return v.effective;
  if (v.sensitive) return v.set ? "hidden" : "—";
  if (v.effective === "") return "(empty)";
  return "—";
}

function EnvConfigTable({ variables }: { variables: EnvVariable[] }) {
  const groups = groupEnvVariables(variables);
  return (
    <Tooltip.Provider delayDuration={0}>
      <Table className="table-fixed">
        <colgroup>
          <col className="w-[34%]" />
          <col className="w-[10%]" />
          <col className="w-[32%]" />
          <col className="w-[24%]" />
        </colgroup>
        <THead>
          <Th>Variable</Th>
          <Th>Status</Th>
          <Th>Effective</Th>
          <Th>Default</Th>
        </THead>
        {groups.map(({ group, items }) => (
          <tbody key={group}>
            <tr>
              <th
                scope="colgroup"
                colSpan={4}
                className="px-4 pb-1.5 pt-4 text-left text-sm font-semibold text-neutral-900 dark:text-neutral-100"
              >
                {group}
              </th>
            </tr>
            {items.map((v) => (
              <TRow key={v.name}>
                <Td>
                  <div className="flex min-w-0 items-center gap-1">
                    <span className="truncate font-mono text-xs">{v.name}</span>
                    {v.seed_only && <Pill>seed-only</Pill>}
                    <EnvVarInfo name={v.name} description={v.description} />
                  </div>
                </Td>
                <Td className="text-neutral-500">{v.set ? "set" : "unset"}</Td>
                <Td className="truncate font-mono text-xs text-neutral-700 dark:text-neutral-300" title={effectiveDisplay(v)}>
                  {effectiveDisplay(v)}
                </Td>
                <Td className="truncate font-mono text-xs text-neutral-500" title={v.default || "—"}>
                  {v.default || <Muted />}
                </Td>
              </TRow>
            ))}
          </tbody>
        ))}
      </Table>
    </Tooltip.Provider>
  );
}

function EnvVarInfo({ name, description }: { name: string; description: string }) {
  const [open, setOpen] = useState(false);
  const lastPointerType = useRef<string>("");
  if (!description) return null;
  return (
    <Tooltip.Root open={open} delayDuration={0} onOpenChange={setOpen}>
      <Tooltip.Trigger asChild>
        <button
          type="button"
          aria-label={`About ${name}`}
          aria-expanded={open}
          className={cn("shrink-0 rounded p-0.5 text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200", focusRing)}
          onPointerDown={(e) => {
            lastPointerType.current = e.pointerType;
          }}
          onClick={(e) => {
            // Touch/pen have no hover. Toggle here and preventDefault so
            // Radix Trigger's composed onClick (context.onClose) does not
            // immediately close the tooltip that this click just opened.
            if (lastPointerType.current === "touch" || lastPointerType.current === "pen") {
              e.preventDefault();
              setOpen((v) => !v);
            }
          }}
        >
          <CircleHelp className="h-3.5 w-3.5" aria-hidden />
        </button>
      </Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content
          side="bottom"
          align="start"
          sideOffset={6}
          collisionPadding={8}
          className="z-50 max-w-xs rounded-md border border-neutral-200 bg-white px-3 py-2 text-xs leading-relaxed text-neutral-700 shadow-md dark:border-neutral-700 dark:bg-neutral-900 dark:text-neutral-200"
        >
          {description}
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  );
}

export function SettingsPage() {
  const me = useMe();
  const isAdmin = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();

  const settings = useQuery({
    queryKey: ["settings"],
    queryFn: () => api.getSettings(),
    enabled: isAdmin,
  });

  const environment = useQuery({
    queryKey: ["settings", "environment"],
    queryFn: () => api.getEnvironment(),
    enabled: isAdmin,
  });

  const [enabled, setEnabled] = useState(false);
  const [days, setDays] = useState("");
  const [includeAdhoc, setIncludeAdhoc] = useState(false);

  // Seed the form from the server once it loads; re-seed whenever the fetched
  // record changes (e.g. after a save invalidates and refetches).
  useEffect(() => {
    if (settings.data) {
      setEnabled(settings.data.retention_enabled);
      setDays(settings.data.scan_retention_days != null ? String(settings.data.scan_retention_days) : "");
      setIncludeAdhoc(settings.data.retention_include_adhoc);
    }
  }, [settings.data]);

  const daysNum = Number(days);
  const daysValid = days.trim() !== "" && Number.isInteger(daysNum) && daysNum > 0 && daysNum <= 36500;
  // Enabling retention requires a valid window; disabled retention may leave the
  // window blank (it's simply ignored until re-enabled).
  const invalid = enabled && !daysValid;

  const save = useMutation({
    mutationFn: () =>
      api.updateSettings({
        retention_enabled: enabled,
        scan_retention_days: daysValid ? daysNum : null,
        retention_include_adhoc: includeAdhoc,
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["settings"] }),
  });

  if (!isAdmin) {
    return <EmptyState>Settings are available to administrators only.</EmptyState>;
  }

  return (
    <Page narrow>
      <PageHeader title="Settings" description="Global configuration for this Nuclei Security Center." />

      {settings.isLoading ? (
        <Spinner />
      ) : settings.isError ? (
        <ErrorText error={settings.error} />
      ) : (
        <Section
          title="Scan retention"
          description={
            <>
              Automatically delete scans (and their findings occurrences and archived output) older than a set number of
              days. Each target&apos;s most recent scan is always kept. Deletion is evidence-preserving — a finding&apos;s
              lifecycle is recomputed from the scans that remain.
            </>
          }
        >
          <div className="space-y-4">
            <Checkbox label="Enable automatic scan deletion" checked={enabled} onChange={setEnabled} />

            <Field
              label="Delete scans older than (days)"
              error={enabled && !daysValid && "Enter a whole number between 1 and 36500."}
            >
              <Input
                type="number"
                min={1}
                max={36500}
                value={days}
                disabled={!enabled}
                placeholder="e.g. 90"
                onChange={(e) => setDays(e.target.value)}
                className="w-full max-w-[12rem]"
              />
            </Field>

            <Checkbox
              label="Also delete ad-hoc scans (not tied to a target)"
              description="Ad-hoc scans have no target history to anchor, so when included they're deleted purely on age. Off by default — only target-linked scans are swept."
              checked={includeAdhoc}
              disabled={!enabled}
              onChange={setIncludeAdhoc}
            />

            {save.isError && <ErrorText error={save.error} />}

            <div className="flex flex-wrap items-center gap-3 border-t border-neutral-200 pt-4 dark:border-neutral-800">
              <Button variant="primary" disabled={invalid || save.isPending} onClick={() => save.mutate()}>
                {save.isPending ? "Saving…" : "Save retention"}
              </Button>
              {settings.data?.updated_at && (
                <span className="text-xs text-neutral-500">
                  Last updated {new Date(settings.data.updated_at).toLocaleString()}
                  {settings.data.updated_by ? ` by ${settings.data.updated_by}` : ""}
                </span>
              )}
            </div>
          </div>
        </Section>
      )}

      {environment.isLoading ? (
        <Spinner />
      ) : environment.isError ? (
        <ErrorText error={environment.error} />
      ) : (
        <Section
          title="Environment configuration"
          description="Read-only view of this backend process's allowlisted environment. Secrets are never shown. Changing a value requires a redeploy or restart — this page cannot edit env."
        >
          <div className="-mx-4 sm:-mx-5">
            <EnvConfigTable variables={environment.data?.variables ?? []} />
          </div>
        </Section>
      )}
    </Page>
  );
}
