// Shared UI primitives. docs/UI_STYLE_GUIDE.md is the contract for how these are
// used — read it before adding a page or a one-off style. Pages compose these
// components instead of re-spelling their Tailwind classes, so a visual change
// lands here once and every screen follows.
import * as Dialog from "@radix-ui/react-dialog";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import clsx from "clsx";
import { ChevronLeft, MoreHorizontal } from "lucide-react";
import {
  createContext,
  useCallback,
  useContext,
  useState,
  type ButtonHTMLAttributes,
  type ComponentPropsWithRef,
  type CSSProperties,
  type InputHTMLAttributes,
  type ReactNode,
  type SelectHTMLAttributes,
  type TdHTMLAttributes,
  type TextareaHTMLAttributes,
  type ThHTMLAttributes,
} from "react";
import { Link } from "react-router-dom";
import { STATE_LABELS, type EffectiveState } from "../api";

export function cn(...parts: Array<string | false | undefined | null>) {
  return clsx(parts);
}

// ---------------------------------------------------------------------------
// Shared class strings. Exported for the few places a primitive cannot be used
// directly (a react-router <Link>, a Radix trigger, an <a download>).

/** focusRing is the one keyboard-focus treatment for every interactive element. */
export const focusRing =
  "focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-500";

/** linkClass styles an inline text link (navigation, not an action). */
export const linkClass = cn(
  "rounded-sm text-indigo-600 hover:underline dark:text-indigo-400",
  focusRing,
);

/** Dropdown menu surface + item classes (Radix DropdownMenu). */
export const menuContentClass =
  "z-50 min-w-44 rounded-md border border-neutral-200 bg-white p-1 shadow-lg dark:border-neutral-800 dark:bg-neutral-900";
export const menuItemClass =
  "flex cursor-pointer select-none items-center gap-2 rounded px-2 py-1.5 text-sm outline-none data-[disabled]:cursor-not-allowed data-[disabled]:opacity-50 data-[highlighted]:bg-neutral-100 dark:data-[highlighted]:bg-neutral-800";
export const menuSeparatorClass = "my-1 h-px bg-neutral-200 dark:bg-neutral-800";

const controlBase =
  "rounded-md border border-neutral-300 bg-white text-sm outline-none transition placeholder:text-neutral-400 dark:placeholder:text-neutral-500 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 disabled:cursor-not-allowed disabled:bg-neutral-100 disabled:text-neutral-500 dark:border-neutral-700 dark:bg-neutral-800 dark:disabled:bg-neutral-900";

// ---------------------------------------------------------------------------
// Buttons

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "danger-ghost" | "link";
export type ButtonSize = "sm" | "md";

const buttonVariants: Record<ButtonVariant, string> = {
  primary: "bg-indigo-600 text-white shadow-sm hover:bg-indigo-500 disabled:hover:bg-indigo-600",
  secondary:
    "border border-neutral-300 bg-white text-neutral-800 shadow-sm hover:bg-neutral-50 disabled:hover:bg-white dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-100 dark:hover:bg-neutral-700 dark:disabled:hover:bg-neutral-800",
  ghost:
    "text-neutral-700 hover:bg-neutral-100 disabled:hover:bg-transparent dark:text-neutral-300 dark:hover:bg-neutral-800",
  danger: "bg-red-600 text-white shadow-sm hover:bg-red-500 disabled:hover:bg-red-600",
  "danger-ghost":
    "text-red-600 hover:bg-red-50 disabled:hover:bg-transparent dark:text-red-400 dark:hover:bg-red-950/50",
  link: "text-indigo-600 hover:underline dark:text-indigo-400",
};

const buttonSizes: Record<ButtonSize, string> = {
  // md matches Input/Select (h-9) so a button lines up with the control beside it.
  md: "h-9 px-3 text-sm",
  sm: "h-8 px-2.5 text-sm",
};

/** buttonClass returns the Button styling for elements that must not be a
 *  <button> (an <a href> download, a Radix trigger rendered asChild). */
export function buttonClass(variant: ButtonVariant = "secondary", size: ButtonSize = "md", selected = false) {
  return cn(
    "inline-flex shrink-0 items-center justify-center gap-1.5 whitespace-nowrap rounded-md font-medium transition disabled:cursor-not-allowed disabled:opacity-50",
    focusRing,
    variant === "link" ? "h-auto p-0 text-sm" : buttonSizes[size],
    buttonVariants[variant],
    // `selected` marks a toggled-on secondary/ghost button (an open filter panel).
    selected &&
      "border-indigo-400 bg-indigo-50 text-indigo-700 hover:bg-indigo-50 dark:border-indigo-600 dark:bg-indigo-950 dark:text-indigo-300 dark:hover:bg-indigo-950",
  );
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** Toggled-on state for a secondary button that opens/closes something. */
  selected?: boolean;
};

export function Button({ variant = "secondary", size = "md", selected, className, type = "button", ...props }: ButtonProps) {
  return <button type={type} className={cn(buttonClass(variant, size, selected), className)} {...props} />;
}

/** IconButton is a square ghost button holding only an icon; `label` is required
 *  because it is the accessible name (and the hover tooltip). */
export function IconButton({
  label,
  className,
  size = "md",
  ...props
}: Omit<ButtonProps, "aria-label" | "variant" | "children"> & { label: string; children: ReactNode }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cn(
        "inline-flex shrink-0 items-center justify-center rounded-md text-neutral-500 transition hover:bg-neutral-100 hover:text-neutral-800 disabled:cursor-not-allowed disabled:opacity-50 dark:hover:bg-neutral-800 dark:hover:text-neutral-200",
        size === "md" ? "h-9 w-9" : "h-8 w-8",
        focusRing,
        className,
      )}
      {...props}
    />
  );
}

// ---------------------------------------------------------------------------
// Page structure

/** Page is the root of every routed page: one vertical rhythm for the app. */
export function Page({ children, narrow }: { children: ReactNode; narrow?: boolean }) {
  return <div className={cn("space-y-5", narrow && "max-w-4xl")}>{children}</div>;
}

/** PageHeader is the title row of every page: optional back link, title (plus
 *  inline badges), one-sentence description, and the page's actions — primary
 *  action rightmost. */
export function PageHeader({
  title,
  description,
  actions,
  back,
  badges,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  back?: { label: string; to?: string; onClick?: () => void };
  badges?: ReactNode;
}) {
  const backContent = (
    <>
      <ChevronLeft className="h-4 w-4" aria-hidden />
      {back?.label}
    </>
  );
  const backClass = cn(
    "mb-1 inline-flex items-center gap-0.5 rounded-sm text-sm text-neutral-500 hover:text-neutral-800 dark:hover:text-neutral-200",
    focusRing,
  );
  return (
    <div className="space-y-1">
      {back &&
        (back.to ? (
          <Link to={back.to} className={backClass}>
            {backContent}
          </Link>
        ) : (
          <button type="button" onClick={back.onClick} className={backClass}>
            {backContent}
          </button>
        ))}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <h1 className="min-w-0 break-words text-xl font-semibold tracking-tight">{title}</h1>
            {badges}
          </div>
          {description && (
            <p className="mt-1 max-w-3xl text-sm text-neutral-500 dark:text-neutral-400">{description}</p>
          )}
        </div>
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </div>
    </div>
  );
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "rounded-lg border border-neutral-200 bg-white shadow-sm dark:border-neutral-800 dark:bg-neutral-900",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** Section is a titled card — the building block of detail and settings pages. */
export function Section({
  title,
  description,
  actions,
  children,
  className,
}: {
  title: ReactNode;
  description?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <Card className={cn("p-4 sm:p-5", className)}>
      <div className="mb-3 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">{title}</h2>
          {description && <p className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">{description}</p>}
        </div>
        {actions && <div className="flex shrink-0 flex-wrap items-center gap-2">{actions}</div>}
      </div>
      {children}
    </Card>
  );
}

/** CardHeader is the toolbar strip at the top of a table card. */
export function CardHeader({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={cn(
        "flex flex-wrap items-center justify-between gap-3 border-b border-neutral-200 px-4 py-2.5 text-sm dark:border-neutral-800",
        className,
      )}
    >
      {children}
    </div>
  );
}

/** EmptyState fills a card when there is nothing to show (or no access). */
export function EmptyState({ children, action }: { children: ReactNode; action?: ReactNode }) {
  return (
    <Card className="px-6 py-10 text-center text-sm text-neutral-500">
      <div>{children}</div>
      {action && <div className="mt-4 flex justify-center gap-2">{action}</div>}
    </Card>
  );
}

/** DescriptionList + Meta lay out label/value pairs on detail pages. */
export function DescriptionList({
  children,
  columns = 3,
  className,
}: {
  children: ReactNode;
  columns?: 2 | 3 | 4;
  className?: string;
}) {
  return (
    <dl
      className={cn(
        "grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2",
        columns === 3 && "lg:grid-cols-3",
        columns === 4 && "lg:grid-cols-4",
        className,
      )}
    >
      {children}
    </dl>
  );
}

export function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs font-medium text-neutral-500 dark:text-neutral-400">{label}</dt>
      <dd className="mt-0.5 break-words">{children}</dd>
    </div>
  );
}

/** Muted renders a de-emphasized placeholder ("—", "ad-hoc", "defaults"). */
export function Muted({ children = "—" }: { children?: ReactNode }) {
  return <span className="text-neutral-400 dark:text-neutral-500">{children}</span>;
}

/** Tabs is an underline tab strip. Content switching stays with the caller. */
export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
}: {
  tabs: { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
}) {
  return (
    <div role="tablist" className="flex flex-wrap gap-1 border-b border-neutral-200 dark:border-neutral-800">
      {tabs.map((t) => (
        <button
          key={t.value}
          type="button"
          role="tab"
          aria-selected={value === t.value}
          onClick={() => onChange(t.value)}
          className={cn(
            "-mb-px rounded-t-md border-b-2 px-3 py-2 text-sm font-medium transition",
            focusRing,
            value === t.value
              ? "border-indigo-600 text-indigo-700 dark:border-indigo-400 dark:text-indigo-300"
              : "border-transparent text-neutral-500 hover:text-neutral-800 dark:hover:text-neutral-200",
          )}
        >
          {t.label}
        </button>
      ))}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Tables

/** Table wraps a <table> in its own horizontal scroller (the page never
 *  scrolls sideways). Put it inside a Card, or a Section for nested tables. */
export function Table({
  children,
  className,
  style,
}: {
  children: ReactNode;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <div className="overflow-x-auto">
      <table className={cn("w-full text-sm", className)} style={style}>
        {children}
      </table>
    </div>
  );
}

/** THead renders the header row; pass <Th> cells as children. */
export function THead({ children }: { children: ReactNode }) {
  return (
    <thead>
      <tr className="border-b border-neutral-200 bg-neutral-50/60 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800 dark:bg-neutral-900/60 dark:text-neutral-400">
        {children}
      </tr>
    </thead>
  );
}

export function Th({ className, children, ...props }: ThHTMLAttributes<HTMLTableCellElement>) {
  return (
    <th scope="col" className={cn("whitespace-nowrap px-4 py-2.5 font-medium", className)} {...props}>
      {children}
    </th>
  );
}

/** TRow is a body row. `onClick` makes the whole row a navigation target;
 *  `highlighted` marks the row a deep link points at. */
export function TRow({
  children,
  onClick,
  highlighted,
  className,
}: {
  children: ReactNode;
  onClick?: () => void;
  highlighted?: boolean;
  className?: string;
}) {
  return (
    <tr
      onClick={onClick}
      className={cn(
        "border-b border-neutral-100 last:border-0 dark:border-neutral-800/60",
        onClick && "cursor-pointer hover:bg-neutral-50 dark:hover:bg-neutral-800/40",
        highlighted && "bg-indigo-50 dark:bg-indigo-950/30",
        className,
      )}
    >
      {children}
    </tr>
  );
}

export function Td({ className, children, ...props }: TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td className={cn("px-4 py-2.5", className)} {...props}>
      {children}
    </td>
  );
}

/** TableEmpty is the single "nothing here" row of an empty table. */
export function TableEmpty({ colSpan, children }: { colSpan: number; children: ReactNode }) {
  return (
    <tr>
      <td colSpan={colSpan} className="px-4 py-10 text-center text-sm text-neutral-400">
        {children}
      </td>
    </tr>
  );
}

export type RowAction = {
  label: string;
  onSelect: () => void;
  /** Show as an inline button instead of inside the "More actions" menu. */
  primary?: boolean;
  /** Destructive: always in the menu, last, red, after a separator. */
  danger?: boolean;
  disabled?: boolean;
  title?: string;
  /** Role gate — hidden actions are dropped entirely. */
  hidden?: boolean;
};

/** RowActions is the trailing actions cell of a table row: at most two
 *  `primary` actions inline, everything else in a "⋯" menu with destructive
 *  actions last. Render it as the row's last cell (it is a <td>). */
export function RowActions({ actions, label }: { actions: RowAction[]; label?: string }) {
  const visible = actions.filter((a) => !a.hidden);
  const inline = visible.filter((a) => a.primary && !a.danger);
  const menu = visible.filter((a) => !a.primary && !a.danger);
  const danger = visible.filter((a) => a.danger);
  return (
    <td className="w-px whitespace-nowrap px-2 py-1.5 text-right" onClick={(e) => e.stopPropagation()}>
      <div className="flex items-center justify-end gap-1">
        {inline.map((a) => (
          <Button key={a.label} variant="ghost" size="sm" disabled={a.disabled} title={a.title} onClick={a.onSelect}>
            {a.label}
          </Button>
        ))}
        {menu.length + danger.length > 0 && (
          <ActionMenu label={label ? `More actions for ${label}` : "More actions"}>
            {menu.map((a) => (
              <ActionMenuItem key={a.label} onSelect={a.onSelect} disabled={a.disabled} title={a.title}>
                {a.label}
              </ActionMenuItem>
            ))}
            {menu.length > 0 && danger.length > 0 && <DropdownMenu.Separator className={menuSeparatorClass} />}
            {danger.map((a) => (
              <ActionMenuItem key={a.label} onSelect={a.onSelect} disabled={a.disabled} title={a.title} danger>
                {a.label}
              </ActionMenuItem>
            ))}
          </ActionMenu>
        )}
      </div>
    </td>
  );
}

/** ActionMenu is a "⋯" overflow menu trigger; children are ActionMenuItems. */
export function ActionMenu({ label, children }: { label: string; children: ReactNode }) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <IconButton label={label} size="sm">
          <MoreHorizontal className="h-4 w-4" aria-hidden />
        </IconButton>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="end" sideOffset={4} className={menuContentClass}>
          {children}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

export function ActionMenuItem({
  children,
  onSelect,
  disabled,
  danger,
  title,
}: {
  children: ReactNode;
  onSelect: () => void;
  disabled?: boolean;
  danger?: boolean;
  title?: string;
}) {
  return (
    <DropdownMenu.Item
      onSelect={onSelect}
      disabled={disabled}
      title={title}
      className={cn(menuItemClass, danger && "text-red-600 dark:text-red-400")}
    >
      {children}
    </DropdownMenu.Item>
  );
}

/** Pager is the one previous/next control for paged lists. `summary` is the
 *  left-hand position text ("31–60 of 412"). */
export function Pager({
  summary,
  hasPrev,
  hasNext,
  onPrev,
  onNext,
  className,
}: {
  summary?: ReactNode;
  hasPrev: boolean;
  hasNext: boolean;
  onPrev: () => void;
  onNext: () => void;
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-center justify-between gap-3 text-sm text-neutral-500", className)}>
      <span className="tabular-nums">{summary}</span>
      <div className="flex gap-2">
        <Button size="sm" disabled={!hasPrev} onClick={onPrev}>
          Previous
        </Button>
        <Button size="sm" disabled={!hasNext} onClick={onNext}>
          Next
        </Button>
      </div>
    </div>
  );
}

/** OffsetPager is Pager for offset/limit lists; renders nothing on one page. */
export function OffsetPager({
  offset,
  total,
  pageSize,
  onChange,
  className,
}: {
  offset: number;
  total: number;
  pageSize: number;
  onChange: (offset: number) => void;
  className?: string;
}) {
  if (total <= pageSize) return null;
  return (
    <Pager
      className={className}
      summary={`${offset + 1}–${Math.min(offset + pageSize, total)} of ${total.toLocaleString()}`}
      hasPrev={offset > 0}
      hasNext={offset + pageSize < total}
      onPrev={() => onChange(Math.max(0, offset - pageSize))}
      onNext={() => onChange(offset + pageSize)}
    />
  );
}

// ---------------------------------------------------------------------------
// Badges

export type Tone = "neutral" | "info" | "success" | "warning" | "danger" | "accent";

const badgeTones: Record<Tone, string> = {
  neutral: "bg-neutral-100 text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300",
  info: "bg-blue-100 text-blue-800 dark:bg-blue-950 dark:text-blue-300",
  success: "bg-green-100 text-green-800 dark:bg-green-950 dark:text-green-300",
  warning: "bg-amber-100 text-amber-800 dark:bg-amber-950 dark:text-amber-300",
  danger: "bg-red-100 text-red-800 dark:bg-red-950 dark:text-red-300",
  accent: "bg-indigo-100 text-indigo-800 dark:bg-indigo-950 dark:text-indigo-300",
};

/** Badge is a filled status label (a state a thing is in). */
export function Badge({
  children,
  tone = "neutral",
  title,
  className,
}: {
  children: ReactNode;
  tone?: Tone;
  title?: string;
  className?: string;
}) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center whitespace-nowrap rounded px-1.5 py-0.5 text-xs font-medium",
        badgeTones[tone],
        className,
      )}
    >
      {children}
    </span>
  );
}

/** Tag is a neutral token in a list of values (tags, CWEs, endpoints). */
export function Tag({ children, mono, title }: { children: ReactNode; mono?: boolean; title?: string }) {
  return (
    <span
      title={title}
      className={cn(
        "inline-flex items-center rounded bg-neutral-100 px-1.5 py-0.5 text-xs text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300",
        mono && "font-mono",
      )}
    >
      {children}
    </span>
  );
}

/** TagList renders values as Tags, or a muted dash when empty. */
export function TagList({ items, mono }: { items?: string[]; mono?: boolean }) {
  if (!items?.length) return <Muted />;
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((x, i) => (
        <Tag key={`${x}-${i}`} mono={mono}>
          {x}
        </Tag>
      ))}
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
        "inline-block whitespace-nowrap rounded px-1.5 py-0.5 text-xs font-semibold uppercase tracking-wide",
        severityStyles[s] ?? badgeTones.neutral,
        recast && "ring-1 ring-inset ring-indigo-500",
      )}
    >
      {severity || "unknown"}
      {recast && " ⟲"}
    </span>
  );
}

const scanStateTones: Record<string, Tone> = {
  queued: "neutral",
  running: "info",
  complete: "success",
  failed: "danger",
  cancelled: "warning",
};

/** StateBadge renders a scan's run state. */
export function StateBadge({ state }: { state: string }) {
  return <Badge tone={scanStateTones[state] ?? "neutral"}>{state}</Badge>;
}

/** ProgressBar shows a determinate bar by percent, or — when `indeterminate` is
 *  set (e.g. the naabu discovery phase, which has no clean percentage, #86) — an
 *  animated sliding bar. The label still carries whatever live tally the caller has. */
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
      <span className="shrink-0 whitespace-nowrap text-right text-xs tabular-nums text-neutral-500">
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

/** FindingStateBadge renders a finding's derived effective lifecycle state.
 *  `description` is extra context that does not fit in the row (for example
 *  why auto-mitigation does not apply). It is the tooltip and part of the
 *  accessible name; the visible label stays the state. */
export function FindingStateBadge({
  state,
  description,
}: {
  state: EffectiveState | string;
  description?: string;
}) {
  const label = STATE_LABELS[state as EffectiveState] ?? state;
  return (
    <span
      title={description || undefined}
      aria-label={description ? `${label}. ${description}` : undefined}
      className={cn(
        "inline-block whitespace-nowrap rounded px-1.5 py-0.5 text-xs font-medium",
        findingStateStyles[state] ?? badgeTones.neutral,
      )}
    >
      {label}
    </span>
  );
}

/** Pill is a small outlined marker for secondary facets (a property of a
 *  thing, not its status — use Badge for status). */
export function Pill({
  children,
  tone = "neutral",
  title,
}: {
  children: ReactNode;
  tone?: "neutral" | "warn" | "good";
  title?: string;
}) {
  const styles = {
    warn: "border-rose-300 text-rose-700 dark:border-rose-800 dark:text-rose-300",
    good: "border-emerald-300 text-emerald-700 dark:border-emerald-800 dark:text-emerald-300",
    neutral: "border-neutral-300 text-neutral-600 dark:border-neutral-700 dark:text-neutral-400",
  }[tone];
  return (
    <span
      title={title}
      className={cn("inline-block whitespace-nowrap rounded-full border px-2 py-0.5 text-xs font-medium", styles)}
    >
      {children}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Feedback

const alertTones: Record<"info" | "success" | "warning" | "danger", string> = {
  info: "border-indigo-200 bg-indigo-50 text-indigo-900 dark:border-indigo-900 dark:bg-indigo-950/40 dark:text-indigo-200",
  success:
    "border-emerald-200 bg-emerald-50 text-emerald-900 dark:border-emerald-900 dark:bg-emerald-950/40 dark:text-emerald-200",
  warning: "border-amber-200 bg-amber-50 text-amber-900 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-200",
  danger: "border-red-200 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300",
};

/** Alert is the one inline message box: notices after an action (success),
 *  caveats (warning), failures (danger), context banners (info). */
export function Alert({
  tone = "info",
  title,
  children,
  action,
  onDismiss,
  className,
}: {
  tone?: "info" | "success" | "warning" | "danger";
  title?: ReactNode;
  children?: ReactNode;
  action?: ReactNode;
  onDismiss?: () => void;
  className?: string;
}) {
  return (
    <div
      role={tone === "danger" ? "alert" : "status"}
      className={cn("flex items-start gap-3 rounded-md border px-3 py-2 text-sm", alertTones[tone], className)}
    >
      <div className="min-w-0 flex-1 break-words">
        {title && <div className="font-medium">{title}</div>}
        {children && <div className={title ? "mt-0.5" : undefined}>{children}</div>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
      {onDismiss && (
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss"
          className={cn("-mr-1 shrink-0 rounded px-1 opacity-60 hover:opacity-100", focusRing)}
        >
          ×
        </button>
      )}
    </div>
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

/** ErrorText shows a failed request or mutation as a danger Alert. */
export function ErrorText({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return <Alert tone="danger">{msg}</Alert>;
}

// ---------------------------------------------------------------------------
// Forms

export function Select({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  // Explicit h-9 so the native control matches Input pixel-for-pixel (native
  // selects render shorter than a padded input at the same py).
  return <select className={cn(controlBase, "h-9 px-2", className)} {...props} />;
}

/** Field labels a control and carries its help text (`hint`) and validation
 *  message (`error`) directly beneath it. */
export function Field({
  label,
  children,
  required,
  hint,
  error,
  className,
}: {
  label: string;
  children: ReactNode;
  required?: boolean;
  hint?: ReactNode;
  error?: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("space-y-1", className)}>
      <label className="block space-y-1">
        <span className="block text-sm font-medium text-neutral-700 dark:text-neutral-300">
          {label}
          {required ? (
            <>
              <span className="ml-0.5 text-rose-600 dark:text-rose-400" aria-hidden="true">
                *
              </span>
              <span className="sr-only"> (required)</span>
            </>
          ) : null}
        </span>
        {children}
      </label>
      {hint && <p className="text-xs text-neutral-500 dark:text-neutral-400">{hint}</p>}
      {error && <p className="text-xs text-red-600 dark:text-red-400">{error}</p>}
    </div>
  );
}

/** FormHint is a standalone help line inside a form (not tied to one Field). */
export function FormHint({ children, tone = "neutral" }: { children: ReactNode; tone?: "neutral" | "warning" | "danger" }) {
  return (
    <p
      className={cn(
        "text-xs",
        tone === "neutral" && "text-neutral-500 dark:text-neutral-400",
        tone === "warning" && "text-amber-700 dark:text-amber-400",
        tone === "danger" && "text-red-600 dark:text-red-400",
      )}
    >
      {children}
    </p>
  );
}

/** FormSection groups related fields under a heading, separated by a rule. */
export function FormSection({ title, children }: { title?: ReactNode; children: ReactNode }) {
  return (
    <div className="space-y-4 border-t border-neutral-200 pt-4 dark:border-neutral-800">
      {title && <h3 className="text-sm font-semibold text-neutral-900 dark:text-neutral-100">{title}</h3>}
      {children}
    </div>
  );
}

// Width is caller-owned. A baked `w-full` would win over numeric widths (`w-40`)
// because `cn` concatenates and Tailwind emits `w-full` later in the sheet.
export function Input({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return <input className={cn(controlBase, "h-9 px-3", className)} {...props} />;
}

// Textarea matches Input's styling but grows vertically and is user-resizable —
// for longer free-text values (host lists, PEM, YAML) that a single line cramps.
export function Textarea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return <textarea className={cn(controlBase, "w-full resize-y px-3 py-2 font-mono", className)} {...props} />;
}

/** Checkbox is a labelled checkbox with optional description beneath the label. */
export function Checkbox({
  label,
  description,
  checked,
  onChange,
  disabled,
}: {
  label: ReactNode;
  description?: ReactNode;
  checked: boolean;
  onChange: (checked: boolean) => void;
  disabled?: boolean;
}) {
  return (
    <label className={cn("flex items-start gap-2.5 text-sm", disabled && "cursor-not-allowed opacity-60")}>
      <input
        type="checkbox"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 h-4 w-4 shrink-0 rounded border-neutral-300 accent-indigo-600 dark:border-neutral-700"
      />
      <span>
        <span className="font-medium text-neutral-800 dark:text-neutral-200">{label}</span>
        {description && (
          <span className="mt-0.5 block text-xs text-neutral-500 dark:text-neutral-400">{description}</span>
        )}
      </span>
    </label>
  );
}

/** FileInput is the styled native file picker. */
export function FileInput({ className, ...props }: Omit<ComponentPropsWithRef<"input">, "type">) {
  return (
    <input
      type="file"
      className={cn(
        "block w-full text-sm text-neutral-500 file:mr-3 file:h-9 file:cursor-pointer file:rounded-md file:border file:border-neutral-300 file:bg-white file:px-3 file:text-sm file:font-medium file:text-neutral-800 hover:file:bg-neutral-50 dark:file:border-neutral-700 dark:file:bg-neutral-800 dark:file:text-neutral-100 dark:hover:file:bg-neutral-700",
        className,
      )}
      {...props}
    />
  );
}

// ---------------------------------------------------------------------------
// Dialogs

export function Modal({
  open,
  onOpenChange,
  title,
  description,
  children,
  dismissible = true,
  size = "default",
}: {
  open: boolean;
  onOpenChange: (v: boolean) => void;
  title: string;
  /** One-line context under the title (also the dialog's accessible description). */
  description?: ReactNode;
  children: ReactNode;
  /** When false, clicking the overlay or pressing Esc won't close the dialog, so
   *  it can only be dismissed through its own controls. For content that is
   *  destroyed by closing and cannot be recovered — a secret shown exactly once. */
  dismissible?: boolean;
  /** "wide" roughly doubles the max width — for forms with long free-text fields
   *  (e.g. a port list) that need room to stretch. "workspace" is a stable,
   *  viewport-aware work surface for editors whose filtered content changes. */
  size?: "default" | "wide" | "workspace";
}) {
  const workspace = size === "workspace";
  const sizeClass = {
    default: "w-[min(92vw,32rem)]",
    wide: "w-[min(94vw,48rem)]",
    workspace: "h-[min(94dvh,64rem)] w-[min(96vw,72rem)]",
  }[size];
  return (
    <Dialog.Root open={open} onOpenChange={onOpenChange}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-40 bg-black/40 backdrop-blur-[1px]" />
        <Dialog.Content
          // Without a Description, opt out of Radix's aria-describedby wiring
          // (an explicit undefined) so it doesn't point at a missing element.
          {...(description ? {} : { "aria-describedby": undefined })}
          onPointerDownOutside={dismissible ? undefined : (e) => e.preventDefault()}
          onEscapeKeyDown={dismissible ? undefined : (e) => e.preventDefault()}
          onInteractOutside={dismissible ? undefined : (e) => e.preventDefault()}
          className={cn(
            "fixed left-1/2 top-1/2 z-50 max-h-[94dvh] -translate-x-1/2 -translate-y-1/2 rounded-lg border border-neutral-200 bg-white shadow-xl focus:outline-none dark:border-neutral-800 dark:bg-neutral-900",
            sizeClass,
            workspace ? "flex flex-col overflow-hidden p-0" : "overflow-y-auto p-5",
          )}
        >
          <div
            className={cn(
              workspace ? "shrink-0 border-b border-neutral-200 px-5 py-4 dark:border-neutral-800" : "mb-4",
            )}
          >
            <Dialog.Title className="text-base font-semibold">{title}</Dialog.Title>
            {description && (
              <Dialog.Description className="mt-1 text-sm text-neutral-500 dark:text-neutral-400">
                {description}
              </Dialog.Description>
            )}
          </div>
          <div className={workspace ? "min-h-0 flex-1" : undefined}>{children}</div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

/** ModalActions is the button row at the bottom of a dialog: secondary
 *  actions first, the primary (or destructive) action rightmost. */
export function ModalActions({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={cn("flex flex-wrap justify-end gap-2 pt-2", className)}>{children}</div>;
}

type ConfirmOptions = {
  title: string;
  description?: ReactNode;
  /** Verb for the confirm button ("Delete", "Revoke"). Defaults to "Confirm". */
  confirmLabel?: string;
  /** "danger" for destructive or irreversible actions (the default). */
  tone?: "danger" | "primary";
};

const ConfirmContext = createContext<((o: ConfirmOptions) => Promise<boolean>) | null>(null);

/** ConfirmProvider hosts the app-wide confirmation dialog behind useConfirm(). */
export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [request, setRequest] = useState<(ConfirmOptions & { resolve: (ok: boolean) => void }) | null>(null);
  const confirm = useCallback(
    (o: ConfirmOptions) => new Promise<boolean>((resolve) => setRequest({ ...o, resolve })),
    [],
  );
  const settle = (ok: boolean) => {
    request?.resolve(ok);
    setRequest(null);
  };
  return (
    <ConfirmContext.Provider value={confirm}>
      {children}
      {request && (
        <Modal open onOpenChange={(open) => !open && settle(false)} title={request.title}>
          <div className="space-y-4">
            {request.description && (
              <div className="text-sm text-neutral-600 dark:text-neutral-300">{request.description}</div>
            )}
            <ModalActions>
              <Button onClick={() => settle(false)}>Cancel</Button>
              {/* Radix focuses the first control (Cancel) on open — the safe default. */}
              <Button
                variant={request.tone === "primary" ? "primary" : "danger"}
                onClick={() => settle(true)}
              >
                {request.confirmLabel ?? "Confirm"}
              </Button>
            </ModalActions>
          </div>
        </Modal>
      )}
    </ConfirmContext.Provider>
  );
}

/** useConfirm returns `confirm(options) → Promise<boolean>`; use it instead of
 *  window.confirm so confirmations match the app (and the dark theme). */
export function useConfirm() {
  const confirm = useContext(ConfirmContext);
  if (!confirm) throw new Error("useConfirm must be used inside <ConfirmProvider>");
  return confirm;
}
