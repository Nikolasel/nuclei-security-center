import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useId, useMemo, useRef, useState } from "react";
import { api, type Schedule } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Field, Input, Modal, Select, Spinner } from "../components/ui";
import { duplicateName } from "../util";

// Common cron presets offered as one-click buttons in the editor.
const CRON_PRESETS: { label: string; cron: string }[] = [
  { label: "Hourly", cron: "0 * * * *" },
  { label: "Daily 03:00", cron: "0 3 * * *" },
  { label: "Weekly (Mon 03:00)", cron: "0 3 * * 1" },
  { label: "Every 15 min", cron: "*/15 * * * *" },
];

function ianaTimezones(): string[] {
  const supported =
    typeof Intl !== "undefined" && "supportedValuesOf" in Intl
      ? Intl.supportedValuesOf("timeZone")
      : [];
  return Array.from(new Set(["UTC", ...supported])).sort((a, b) => a.localeCompare(b));
}

function browserTimezone(): string {
  try {
    const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
    if (tz) return tz;
  } catch {
    // ignore missing Intl
  }
  return "UTC";
}

function fmtInZone(iso: string | undefined, timeZone: string): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "—";
  try {
    return d.toLocaleString(undefined, { timeZone, timeZoneName: "short" });
  } catch {
    return d.toLocaleString();
  }
}

/** Fold spaces and underscores so "new york" matches America/New_York. */
function normalizeTzSearch(s: string): string {
  return s.trim().toLowerCase().replace(/[\s_]+/g, " ");
}

function TimezoneField({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const zones = useMemo(() => ianaTimezones(), []);
  const listId = useId();
  const [query, setQuery] = useState(value);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(0);
  // Zone at focus: blur/Escape restore this unless the current query is unique or exact.
  const focusedZone = useRef(value);

  const matches = useMemo(() => {
    const q = normalizeTzSearch(query);
    return q ? zones.filter((z) => normalizeTzSearch(z).includes(q)) : zones;
  }, [query, zones]);

  function pick(z: string) {
    onChange(z);
    focusedZone.current = z;
    setQuery(z);
    setOpen(false);
  }

  /** Unique/exact match of the current query, else the zone from when the field was focused. */
  function commitTyped() {
    const q = normalizeTzSearch(query);
    if (q) {
      const exact = zones.find((z) => normalizeTzSearch(z) === q);
      if (exact) {
        pick(exact);
        return;
      }
      if (matches.length === 1) {
        pick(matches[0]);
        return;
      }
    }
    setQuery(focusedZone.current);
    onChange(focusedZone.current);
  }

  function applyQuery(next: string) {
    setQuery(next);
    setOpen(true);
    setActive(0);
  }

  useEffect(() => {
    if (!open) return;
    // Radix Dialog listens for Escape on document in the capture phase and
    // dismisses unless defaultPrevented. The input handler is too late (bubble).
    function onKeyDown(e: KeyboardEvent) {
      if (e.key !== "Escape") return;
      e.preventDefault();
      setQuery(focusedZone.current);
      onChange(focusedZone.current);
      setOpen(false);
    }
    window.addEventListener("keydown", onKeyDown, true);
    return () => window.removeEventListener("keydown", onKeyDown, true);
  }, [open, onChange]);

  const activeId = matches[active] ? `${listId}-${matches[active]}` : undefined;
  const activeOption = useRef<HTMLLIElement | null>(null);

  useEffect(() => {
    if (!open) return;
    activeOption.current?.scrollIntoView({ block: "nearest" });
  }, [open, active]);

  return (
    <div className="space-y-1">
      <Input
        value={query}
        onChange={(e) => applyQuery(e.target.value)}
        onFocus={(e) => {
          focusedZone.current = value;
          setOpen(true);
          e.currentTarget.select();
        }}
        onBlur={() => {
          commitTyped();
          setOpen(false);
        }}
        onKeyDown={(e) => {
          if (e.key === "ArrowDown") {
            e.preventDefault();
            setOpen(true);
            setActive((i) => (matches.length === 0 ? 0 : Math.min(i + 1, matches.length - 1)));
          } else if (e.key === "ArrowUp") {
            e.preventDefault();
            setOpen(true);
            setActive((i) => Math.max(i - 1, 0));
          } else if (e.key === "Enter" && open && matches[active]) {
            e.preventDefault();
            pick(matches[active]);
          }
        }}
        placeholder="Search IANA timezones…"
        className="w-full font-mono"
        role="combobox"
        aria-label="Timezone"
        aria-autocomplete="list"
        aria-expanded={open}
        aria-controls={listId}
        aria-activedescendant={open ? activeId : undefined}
      />
      {open && (
        <ul
          id={listId}
          role="listbox"
          aria-label="IANA timezones"
          className="max-h-48 overflow-y-auto rounded-md border border-neutral-300 bg-white text-sm dark:border-neutral-700 dark:bg-neutral-800"
          onMouseDown={(e) => e.preventDefault()}
        >
          {matches.length === 0 ? (
            <li className="px-3 py-2 text-xs text-neutral-500" role="presentation">
              No matching IANA timezone.
            </li>
          ) : (
            matches.map((z, i) => (
              <li
                key={z}
                id={`${listId}-${z}`}
                ref={i === active ? activeOption : undefined}
                role="option"
                aria-selected={z === value}
                className={
                  "cursor-pointer px-3 py-1.5 font-mono " +
                  (i === active
                    ? "bg-indigo-600 text-white"
                    : "hover:bg-neutral-100 dark:hover:bg-neutral-700")
                }
                onMouseEnter={() => setActive(i)}
                onClick={() => pick(z)}
              >
                {z}
              </li>
            ))
          )}
        </ul>
      )}
    </div>
  );
}

function ScheduleModal({
  existing,
  duplicate = false,
  existingNames,
  onClose,
}: {
  existing?: Schedule;
  duplicate?: boolean;
  existingNames: string[];
  onClose: () => void;
}) {
  const qc = useQueryClient();
  const scanPolicies = useQuery({ queryKey: ["scan-policies"], queryFn: () => api.listScanPolicies() });
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });

  const [name, setName] = useState(
    existing ? (duplicate ? duplicateName(existing.name, existingNames) : existing.name) : "",
  );
  const [scanPolicyId, setScanPolicyId] = useState(existing?.scan_policy_id ?? "");
  const [targetId, setTargetId] = useState(existing?.target_id ?? "");
  const [cron, setCron] = useState(existing?.cron ?? "0 3 * * *");
  const [timezone, setTimezone] = useState(existing?.timezone || browserTimezone());
  const [enabled, setEnabled] = useState(duplicate ? false : (existing?.enabled ?? true));

  const policies = scanPolicies.data ?? [];

  const save = useMutation({
    mutationFn: () => {
      const body: Partial<Schedule> = {
        name: name.trim(),
        scan_policy_id: scanPolicyId,
        target_id: targetId,
        cron: cron.trim(),
        timezone: timezone.trim() || "UTC",
        enabled,
      };
      return existing && !duplicate ? api.updateSchedule(existing.id, body) : api.createSchedule(body);
    },
    onSuccess: () => {
      void qc.invalidateQueries({ queryKey: ["schedules"] });
      onClose();
    },
  });

  const canSave = name.trim() && scanPolicyId && targetId && cron.trim() && timezone.trim();

  return (
    <Modal
      open
      onOpenChange={(v) => !v && onClose()}
      title={duplicate ? "Duplicate schedule" : existing ? "Edit schedule" : "New schedule"}
    >
      <div className="space-y-4">
        <Field label="Name">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="nightly-prod" className="w-full" />
        </Field>
        <Field label="Scan policy (templates + execution settings)">
          <Select value={scanPolicyId} onChange={(e) => setScanPolicyId(e.target.value)} className="w-full">
            <option value="">Select a scan policy…</option>
            {policies.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </Select>
        </Field>
        {!scanPolicies.isLoading && policies.length === 0 && (
          <p className="-mt-2 text-xs text-amber-700 dark:text-amber-400">
            No scan policies yet — create one under Scan Policies first.
          </p>
        )}
        <Field label="Target (approved scope)">
          <Select value={targetId} onChange={(e) => setTargetId(e.target.value)} className="w-full">
            <option value="">Select a target…</option>
            {(targets.data ?? []).map((target) => (
              <option key={target.id} value={target.id}>
                {target.name} ({target.host_count} host{target.host_count === 1 ? "" : "s"})
              </option>
            ))}
          </Select>
        </Field>
        {!targets.isLoading && (targets.data ?? []).length === 0 && (
          <p className="-mt-2 text-xs text-amber-700 dark:text-amber-400">
            No approved targets yet — create one under Targets first.
          </p>
        )}
        <Field label="Cron (min hour day-of-month month day-of-week)">
          <Input value={cron} onChange={(e) => setCron(e.target.value)} placeholder="0 3 * * *" className="w-full font-mono" />
        </Field>
        <div className="flex flex-wrap gap-1">
          {CRON_PRESETS.map((p) => (
            <button
              key={p.cron}
              type="button"
              onClick={() => setCron(p.cron)}
              className="rounded border border-neutral-300 px-2 py-1 text-xs text-neutral-600 hover:bg-neutral-100 dark:border-neutral-700 dark:text-neutral-400 dark:hover:bg-neutral-800"
            >
              {p.label}
            </button>
          ))}
        </div>
        <div className="block space-y-1">
          <span className="text-sm font-medium text-neutral-700 dark:text-neutral-300">Timezone</span>
          <TimezoneField value={timezone} onChange={setTimezone} />
          <p className="text-xs text-neutral-500">
            Cron clock fields fire in this IANA zone (DST from the timezone database). New schedules
            default to the browser timezone; omit on the API for UTC.
          </p>
        </div>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
          Enabled (the ticker dispatches this schedule)
        </label>
        {save.isError && <ErrorText error={save.error} />}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={!canSave || save.isPending} onClick={() => save.mutate()}>
            {save.isPending ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}

export function SchedulesPage() {
  const me = useMe();
  const canWrite = hasRole(me.data ?? undefined, "operator");
  const canDelete = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();
  const [editing, setEditing] = useState<Schedule | "new" | null>(null);
  const [duplicating, setDuplicating] = useState(false);

  const q = useQuery({ queryKey: ["schedules"], queryFn: () => api.listSchedules() });
  const policies = useQuery({ queryKey: ["scan-policies"], queryFn: () => api.listScanPolicies() });
  const targets = useQuery({ queryKey: ["targets"], queryFn: () => api.listTargets() });
  const policyName = (id: string) => policies.data?.find((p) => p.id === id)?.name ?? id.slice(0, 8);
  const targetName = (id: string) => targets.data?.find((target) => target.id === id)?.name ?? id.slice(0, 8);

  const invalidate = () => void qc.invalidateQueries({ queryKey: ["schedules"] });
  const del = useMutation({ mutationFn: (id: string) => api.deleteSchedule(id), onSuccess: invalidate });
  const toggle = useMutation({
    mutationFn: (s: Schedule) =>
      api.updateSchedule(s.id, {
        name: s.name,
        scan_policy_id: s.scan_policy_id,
        target_id: s.target_id,
        cron: s.cron,
        timezone: s.timezone,
        enabled: !s.enabled,
      }),
    onSuccess: invalidate,
  });
  const run = useMutation({ mutationFn: (id: string) => api.runSchedule(id), onSuccess: invalidate });
  const closeEditor = () => {
    setEditing(null);
    setDuplicating(false);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Schedules</h1>
          <p className="text-sm text-neutral-500">Cron-driven scans dispatched automatically by the backend.</p>
        </div>
        {canWrite && (
          <Button
            variant="primary"
            onClick={() => {
              setDuplicating(false);
              setEditing("new");
            }}
          >
            New schedule
          </Button>
        )}
      </div>

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
                  <th className="px-3 py-2 font-medium">Scan policy</th>
                  <th className="px-3 py-2 font-medium">Target</th>
                  <th className="px-3 py-2 font-medium">Cron</th>
                  <th className="px-3 py-2 font-medium">Timezone</th>
                  <th className="px-3 py-2 font-medium">Status</th>
                  <th className="px-3 py-2 font-medium">Next run</th>
                  <th className="px-3 py-2 font-medium">Last run</th>
                  {(canWrite || canDelete) && <th className="px-3 py-2" />}
                </tr>
              </thead>
              <tbody>
                {(q.data ?? []).map((s) => (
                  <tr key={s.id} className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60">
                    <td className="px-3 py-2 font-medium">{s.name}</td>
                    <td className="px-3 py-2 text-neutral-600 dark:text-neutral-400">{policyName(s.scan_policy_id)}</td>
                    <td className="px-3 py-2 text-neutral-600 dark:text-neutral-400">{targetName(s.target_id)}</td>
                    <td className="px-3 py-2 font-mono text-xs text-neutral-600 dark:text-neutral-400">{s.cron}</td>
                    <td className="px-3 py-2 font-mono text-xs text-neutral-600 dark:text-neutral-400">{s.timezone || "UTC"}</td>
                    <td className="px-3 py-2">
                      {s.enabled ? (
                        <span className="inline-block rounded bg-green-100 px-1.5 py-0.5 text-xs font-medium text-green-800 dark:bg-green-950 dark:text-green-300">
                          enabled
                        </span>
                      ) : (
                        <span className="inline-block rounded bg-neutral-200 px-1.5 py-0.5 text-xs font-medium text-neutral-600 dark:bg-neutral-800 dark:text-neutral-400">
                          disabled
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-xs text-neutral-500">
                      {s.enabled ? fmtInZone(s.next_run_at, s.timezone || "UTC") : "—"}
                    </td>
                    <td className="px-3 py-2 text-xs text-neutral-500">{fmtInZone(s.last_run_at, s.timezone || "UTC")}</td>
                    {(canWrite || canDelete) && (
                      <td className="px-3 py-2 text-right whitespace-nowrap">
                        {canWrite && (
                          <>
                            <Button
                              variant="ghost"
                              disabled={run.isPending}
                              onClick={() => run.mutate(s.id)}
                              title="Dispatch now, off-schedule"
                            >
                              Run now
                            </Button>
                            <Button variant="ghost" disabled={toggle.isPending} onClick={() => toggle.mutate(s)}>
                              {s.enabled ? "Disable" : "Enable"}
                            </Button>
                            <Button
                              variant="ghost"
                              onClick={() => {
                                setDuplicating(false);
                                setEditing(s);
                              }}
                            >
                              Edit
                            </Button>
                            <Button
                              variant="ghost"
                              onClick={() => {
                                setDuplicating(true);
                                setEditing(s);
                              }}
                            >
                              Duplicate
                            </Button>
                          </>
                        )}
                        {canDelete && (
                          <Button
                            variant="ghost"
                            className="text-red-600 dark:text-red-400"
                            onClick={() => {
                              if (confirm(`Delete schedule "${s.name}"?`)) del.mutate(s.id);
                            }}
                          >
                            Delete
                          </Button>
                        )}
                      </td>
                    )}
                  </tr>
                ))}
                {(q.data ?? []).length === 0 && (
                  <tr>
                    <td colSpan={8 + (canWrite || canDelete ? 1 : 0)} className="px-3 py-8 text-center text-neutral-400">
                      No schedules yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </Card>
      )}

      {editing && (
        <ScheduleModal
          existing={editing === "new" ? undefined : editing}
          duplicate={duplicating}
          existingNames={(q.data ?? []).map((schedule) => schedule.name)}
          onClose={closeEditor}
        />
      )}
    </div>
  );
}
