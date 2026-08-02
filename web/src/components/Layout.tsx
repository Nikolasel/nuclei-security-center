import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import * as Tooltip from "@radix-ui/react-tooltip";
import {
  Bug,
  CalendarClock,
  Gauge,
  KeyRound,
  Layers,
  Library,
  type LucideIcon,
  PanelLeftClose,
  PanelLeftOpen,
  Radar,
  Server,
  SlidersHorizontal,
  Target,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import { NavLink, useLocation } from "react-router-dom";
import type { Identity } from "../api";
import { hasRole } from "../auth";
import { Brand } from "./Brand";
import { cn } from "./ui";

// Nav data model. Categories are an IA hint; routes are unchanged. The `role`
// gate on a category hides it from users who don't hold the role — purely
// cosmetic, the backend enforces authz on every route. Each pane carries an
// icon so the sidebar can collapse to an icon-only rail (labels drop away).
type Pane = { to: string; label: string; icon: LucideIcon; role?: "admin" | "operator" | "viewer" };
type Category = { id: string; label: string; panes: Pane[]; role?: Pane["role"] };

const categories: Category[] = [
  { id: "findings", label: "Findings", panes: [{ to: "/findings", label: "Findings", icon: Bug }] },
  {
    id: "scanning",
    label: "Scanning",
    panes: [
      { to: "/scans", label: "Scans", icon: Radar },
      { to: "/schedules", label: "Schedules", icon: CalendarClock },
      { to: "/scan-policies", label: "Scan Policies", icon: Gauge },
      { to: "/targets", label: "Targets", icon: Target },
      { to: "/templates", label: "Templates", icon: Library },
      { to: "/template-sets", label: "Template Sets", icon: Layers },
    ],
  },
  {
    id: "admin",
    label: "Admin",
    role: "admin",
    panes: [
      { to: "/nodes", label: "Scanner Nodes", icon: Server },
      { to: "/service-accounts", label: "Service Accounts", icon: KeyRound },
      { to: "/settings", label: "Settings", icon: SlidersHorizontal },
    ],
  },
];

// Collapsed/expanded sidebar preference persists across sessions (per browser).
const NAV_COLLAPSED_KEY = "nsc.nav.collapsed";

function readCollapsed(): boolean {
  try {
    return localStorage.getItem(NAV_COLLAPSED_KEY) === "1";
  } catch {
    return false;
  }
}

function writeCollapsed(collapsed: boolean) {
  try {
    localStorage.setItem(NAV_COLLAPSED_KEY, collapsed ? "1" : "0");
  } catch {
    // ignore (private mode / storage disabled) — state still works in-session.
  }
}

function visibleCategories(identity: Identity): Category[] {
  return categories
    .filter((c) => !c.role || hasRole(identity, c.role))
    .map((c) => ({
      ...c,
      panes: c.panes.filter((p) => !p.role || hasRole(identity, p.role)),
    }))
    .filter((c) => c.panes.length > 0);
}

function isCategoryActive(category: Category, currentPath: string): boolean {
  return category.panes.some((p) => currentPath === p.to || currentPath.startsWith(p.to + "/"));
}

function isPaneActive(pane: Pane, currentPath: string): boolean {
  return currentPath === pane.to || currentPath.startsWith(pane.to + "/");
}

function paneLinkClass(isActive: boolean, collapsed: boolean) {
  return cn(
    "flex items-center gap-2 rounded-md text-sm font-medium",
    collapsed ? "justify-center px-0 py-2" : "px-3 py-1.5",
    isActive
      ? "bg-indigo-50 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300"
      : "text-neutral-600 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-neutral-800",
  );
}

async function logout() {
  await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
  window.location.assign("/");
}

export function Layout({
  identity,
  children,
  currentPath: currentPathOverride,
}: {
  identity: Identity;
  children: ReactNode;
  /** Override the path used for active-link highlighting. Defaults to
   *  `window.location.pathname`. Exposed primarily so callers (e.g. tests, the
   *  Storybook-style dev preview) can render any path without lying to the
   *  browser. */
  currentPath?: string;
}) {
  const who = identity.name || identity.email || identity.subject;
  const visible = visibleCategories(identity);
  // Subscribe to router location so active-pane highlighting re-renders on
  // client-side navigation. `window.location.pathname` (the previous source) is
  // read once and never updates, which left the highlight stuck on the pane the
  // app first loaded.
  const location = useLocation();
  const currentPath = currentPathOverride ?? location.pathname;
  const [collapsed, setCollapsed] = useState(readCollapsed);
  const toggleCollapsed = () =>
    setCollapsed((c) => {
      writeCollapsed(!c);
      return !c;
    });

  return (
    <div className="min-h-screen bg-neutral-50 text-neutral-900 dark:bg-neutral-950 dark:text-neutral-100">
      <header className="border-b border-cyan-300/20 bg-slate-950 text-white shadow-[0_1px_28px_rgba(34,211,238,0.12)] dark:bg-slate-950">
        <div className="mx-auto flex max-w-[96rem] items-center gap-6 px-4">
          <Brand className="py-2" />
          <div className="ml-auto">
            <DropdownMenu.Root>
              <DropdownMenu.Trigger className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm text-slate-100 hover:bg-white/10">
                <span className="flex h-7 w-7 items-center justify-center rounded-full bg-gradient-to-br from-cyan-300 to-violet-500 text-xs font-bold text-slate-950 shadow-[0_0_14px_rgba(103,232,249,0.42)]">
                  {who.slice(0, 2).toUpperCase()}
                </span>
                <span className="hidden sm:inline">{who}</span>
              </DropdownMenu.Trigger>
              <DropdownMenu.Portal>
                <DropdownMenu.Content
                  align="end"
                  sideOffset={6}
                  className="min-w-52 rounded-md border border-neutral-200 bg-white p-1 shadow-lg dark:border-neutral-800 dark:bg-neutral-900"
                >
                  <div className="px-2 py-1.5 text-xs text-neutral-500">
                    {identity.email || identity.subject}
                    <div className="mt-1 flex flex-wrap gap-1">
                      {identity.roles.length ? (
                        identity.roles.map((r) => (
                          <span
                            key={r}
                            className="rounded bg-neutral-100 px-1.5 py-0.5 font-medium text-neutral-700 dark:bg-neutral-800 dark:text-neutral-300"
                          >
                            {r}
                          </span>
                        ))
                      ) : (
                        <span className="text-neutral-400">no roles</span>
                      )}
                    </div>
                  </div>
                  <DropdownMenu.Separator className="my-1 h-px bg-neutral-200 dark:bg-neutral-800" />
                  <DropdownMenu.Item
                    onSelect={() => void logout()}
                    className="cursor-pointer rounded px-2 py-1.5 text-sm outline-none hover:bg-neutral-100 dark:hover:bg-neutral-800"
                  >
                    Log out
                  </DropdownMenu.Item>
                </DropdownMenu.Content>
              </DropdownMenu.Portal>
            </DropdownMenu.Root>
          </div>
        </div>
      </header>
      <main className="mx-auto max-w-[96rem] px-4 py-6">
        <div
          className={cn(
            "grid gap-8",
            collapsed ? "grid-cols-[3.25rem_minmax(0,1fr)]" : "grid-cols-[12rem_minmax(0,1fr)]",
          )}
        >
          <aside className="sticky top-6 self-start">
            <div className="max-h-[calc(100dvh-3rem)] overflow-y-auto pr-1">
              <div className={cn("mb-4 flex", collapsed ? "justify-center" : "justify-end")}>
                <button
                  type="button"
                  onClick={toggleCollapsed}
                  aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
                  aria-expanded={!collapsed}
                  title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
                  className="rounded-md p-1.5 text-neutral-500 hover:bg-neutral-100 hover:text-neutral-700 dark:hover:bg-neutral-800 dark:hover:text-neutral-300"
                >
                  {collapsed ? <PanelLeftOpen className="h-4 w-4" /> : <PanelLeftClose className="h-4 w-4" />}
                </button>
              </div>
              <Tooltip.Provider delayDuration={0}>
                <nav aria-label="Sections" className="space-y-6">
                  {visible.map((c, ci) => (
                    <div key={c.id}>
                      {collapsed ? (
                        // Icon rail: replace the category heading with a hairline
                        // separator between groups (skip it before the first group).
                        ci > 0 && <div className="mx-auto mb-2 h-px w-6 bg-neutral-200 dark:bg-neutral-800" />
                      ) : (
                        <div
                          className={cn(
                            "px-2 pb-1 text-xs font-semibold uppercase tracking-wide",
                            isCategoryActive(c, currentPath)
                              ? "text-indigo-700 dark:text-indigo-300"
                              : "text-neutral-500 dark:text-neutral-400",
                          )}
                        >
                          {c.label}
                        </div>
                      )}
                      <ul className="space-y-0.5">
                        {c.panes.map((p) => {
                          const Icon = p.icon;
                          const link = (
                            <NavLink
                              to={p.to}
                              aria-label={p.label}
                              className={paneLinkClass(isPaneActive(p, currentPath), collapsed)}
                            >
                              <Icon className="h-4 w-4 shrink-0" aria-hidden />
                              {!collapsed && <span>{p.label}</span>}
                            </NavLink>
                          );
                          return (
                            <li key={p.to}>
                              {collapsed ? (
                                // Icon-only rail: surface the pane name as a hover
                                // tooltip since the label is hidden.
                                <Tooltip.Root>
                                  <Tooltip.Trigger asChild>{link}</Tooltip.Trigger>
                                  <Tooltip.Portal>
                                    <Tooltip.Content
                                      side="right"
                                      sideOffset={8}
                                      className="z-50 rounded-md bg-neutral-900 px-2 py-1 text-xs font-medium text-white shadow-md dark:bg-neutral-100 dark:text-neutral-900"
                                    >
                                      {p.label}
                                      <Tooltip.Arrow className="fill-neutral-900 dark:fill-neutral-100" />
                                    </Tooltip.Content>
                                  </Tooltip.Portal>
                                </Tooltip.Root>
                              ) : (
                                link
                              )}
                            </li>
                          );
                        })}
                      </ul>
                    </div>
                  ))}
                </nav>
              </Tooltip.Provider>
            </div>
          </aside>
          <div className="min-w-0">{children}</div>
        </div>
      </main>
    </div>
  );
}
