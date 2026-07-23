import * as Dialog from "@radix-ui/react-dialog";
import clsx from "clsx";
import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";
import { STATE_LABELS, type EffectiveState } from "../api";

export function cn(...parts: Array<string | false | undefined | null>) {
  return clsx(parts);
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "danger" | "ghost";
};

export function Button({ variant = "secondary", className, ...props }: ButtonProps) {
  const styles: Record<string, string> = {
    primary: "bg-indigo-600 text-white hover:bg-indigo-500 disabled:bg-indigo-600/50",
    secondary:
      "bg-white dark:bg-neutral-800 border border-neutral-300 dark:border-neutral-700 hover:bg-neutral-50 dark:hover:bg-neutral-700",
    danger: "bg-red-600 text-white hover:bg-red-500 disabled:bg-red-600/50",
    ghost: "hover:bg-neutral-100 dark:hover:bg-neutral-800",
  };
  return (
    <button
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-sm font-medium transition disabled:cursor-not-allowed disabled:opacity-60",
        styles[variant],
        className,
      )}
      {...props}
    />
  );
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "rounded-lg border border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900",
        className,
      )}
    >
      {children}
    </div>
  );
}

const severityStyles: Record<string, string> = {
  critical: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-950 dark:text-orange-300",
  medium: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  low: "bg-yellow-100 text-yellow-800 dark:bg-yellow-950 dark:text-yellow-300",
  info: "bg-sky-100 text-sky-800 dark:bg-sky-950 dark:text-sky-300",
};

export function SeverityBadge({ severity, recast }: { severity: string; recast?: boolean }) {
  const s = severity.toLowerCase();
  return (
    <span
      title={recast ? "Recast severity (analyst override)" : undefined}
      className={cn(
        "inline-block rounded px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide",
        severityStyles[s] ?? "bg-neutral-100 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300",
        recast && "ring-1 ring-inset ring-indigo-500",
      )}
    >
      {severity || "unknown"}
      {recast && " ⟲"}
    </span>
  );
}

const stateStyles: Record<string, string> = {
  queued: "bg-neutral-100 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300",
  running: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300",
  complete: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300",
  failed: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  cancelled: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
};

export function StateBadge({ state }: { state: string }) {
  return (
    <span
      className={cn(
        "inline-block rounded px-1.5 py-0.5 text-xs font-medium",
        stateStyles[state] ?? "bg-neutral-100 text-neutral-700",
      )}
    >
      {state}
    </span>
  );
}

/** ProgressBar renders a 0–100% determinate bar. `label` is shown to the right. */
// ProgressBar shows a determinate bar by percent, or — when `indeterminate` is
// set (e.g. the naabu discovery phase, which has no clean percentage, #86) — an
// animated sliding bar. The label still carries whatever live tally the caller has.
export function ProgressBar({
  percent,
  label,
  indeterminate,
}: {
  percent: number;
  label?: string;
  indeterminate?: boolean;
}) {
  const pct = Math.max(0, Math.min(100, percent));
  return (
    <div className="flex items-center gap-2">
      <div className="h-2 flex-1 overflow-hidden rounded-full bg-neutral-200 dark:bg-neutral-800">
        {indeterminate ? (
          <div
            className="h-full w-1/3 animate-[indeterminate_1.4s_ease-in-out_infinite] rounded-full bg-indigo-500"
            role="progressbar"
            aria-label="working"
          />
        ) : (
          <div
            className="h-full rounded-full bg-indigo-500 transition-[width] duration-500"
            style={{ width: `${pct}%` }}
            role="progressbar"
            aria-valuenow={Math.round(pct)}
            aria-valuemin={0}
            aria-valuemax={100}
          />
        )}
      </div>
      <span className="w-24 shrink-0 text-right text-xs tabular-nums text-neutral-500">
        {label ?? `${pct.toFixed(0)}%`}
      </span>
    </div>
  );
}

// Effective-state palette (Tenable-style lifecycle). Cumulative states (still
// detected) are warm/attention-grabbing; mitigated states are green (good);
// analyst overlays are muted.
const findingStateStyles: Record<string, string> = {
  new: "bg-indigo-100 text-indigo-800 dark:bg-indigo-950 dark:text-indigo-300",
  active: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  resurfaced: "bg-rose-100 text-rose-800 dark:bg-rose-950 dark:text-rose-300",
  mitigated: "bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300",
  previously_mitigated: "bg-teal-100 text-teal-800 dark:bg-teal-950 dark:text-teal-300",
  accepted: "bg-neutral-200 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300",
  false_positive: "bg-neutral-200 text-neutral-500 dark:bg-neutral-800 dark:text-neutral-500",
};

/** FindingStateBadge renders a finding's derived effective lifecycle state. */
export function FindingStateBadge({ state }: { state: EffectiveState | string }) {
  return (
    <span
      className={cn(
        "inline-block rounded px-1.5 py-0.5 text-xs font-medium",
        findingStateStyles[state] ?? "bg-neutral-100 text-neutral-700",
      )}
    >
      {STATE_LABELS[state as EffectiveState] ?? state}
    </span>
  );
}

/** Pill is a small outlined marker for secondary facets. */
export function Pill({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "neutral" | "warn" | "good";
}) {
  const styles = {
    warn: "border-rose-300 text-rose-700 dark:border-rose-800 dark:text-rose-300",
    good: "border-emerald-300 text-emerald-700 dark:border-emerald-800 dark:text-emerald-300",
    neutral: "border-neutral-300 text-neutral-600 dark:border-neutral-700 dark:text-neutral-400",
  }[tone];
  return (
    <span className={cn("inline-block rounded-full border px-2 py-0.5 text-xs font-medium", styles)}>
      {children}
    </span>
  );
}

export function Select({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={cn(
        // Explicit h-9 so the native control matches Input pixel-for-pixel (native
        // selects render shorter than a padded input at the same py).
        "h-9 rounded-md border border-neutral-300 bg-white px-2 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-800",
        className,
      )}
      {...props}
    />
  );
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="block space-y-1">
      <span className="text-sm font-medium text-neutral-700 dark:text-neutral-300">{label}</span>
      {children}
    </label>
  );
}

export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={cn(
        "h-9 w-full rounded-md border border-neutral-300 bg-white px-3 text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-800",
        className,
      )}
      {...props}
    />
  );
}

// Textarea matches Input's styling but grows vertically and is user-resizable —
// for longer free-text values (e.g. a port list) that a single line cramps.
export function Textarea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={cn(
        "w-full rounded-md border border-neutral-300 bg-white px-3 py-2 font-mono text-sm outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-800",
        className,
      )}
      {...props}
    />
  );
}

export function Modal({
  open,
  onOpenChange,
  title,
  children,
  dismissible = true,
  size = "default",
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  title: string;
  children: ReactNode;
  /** When false, clicking the overlay or pressing Esc won't close the dialog, so
   *  it can only be dismissed through its own controls. For content that is
   *  destroyed by closing and cannot be recovered — a secret shown exactly once. */
  dismissible?: boolean;
  /** "wide" roughly doubles the max width — for forms with long free-text fields
   *  (e.g. a port list) that need room to stretch. */
  size?: "default" | "wide";
}) {
  const widthClass = size === "wide" ? "w-[min(94vw,48rem)]" : "w-[min(92vw,32rem)]";
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-black/40" />
        <Dialog.Content
          onPointerDownOutside={dismissible ? undefined : (e) => e.preventDefault()}
          onEscapeKeyDown={dismissible ? undefined : (e) => e.preventDefault()}
          onInteractOutside={dismissible ? undefined : (e) => e.preventDefault()}
          className={`fixed left-1/2 top-1/2 max-h-[90dvh] ${widthClass} -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-lg border border-neutral-200 bg-white p-5 shadow-xl focus:outline-none dark:border-neutral-800 dark:bg-neutral-900`}
        >
          <Dialog.Title className="mb-3 text-base font-semibold">{title}</Dialog.Title>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <div className="flex items-center gap-2 py-6 text-sm text-neutral-500">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-neutral-300 border-t-indigo-500" />
      {label ?? "Loading…"}
    </div>
  );
}

export function ErrorText({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return <p className="py-4 text-sm text-red-600 dark:text-red-400">{msg}</p>;
}
