import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import type { ReactNode } from "react";
import { NavLink } from "react-router-dom";
import type { Identity } from "../api";
import { cn } from "./ui";

const nav = [
  { to: "/findings", label: "Findings" },
  { to: "/scans", label: "Scans" },
  { to: "/targets", label: "Targets" },
  { to: "/template-sets", label: "Template Sets" },
];

async function logout() {
  await fetch("/api/auth/logout", { method: "POST", credentials: "same-origin" });
  window.location.assign("/");
}

export function Layout({ identity, children }: { identity: Identity; children: ReactNode }) {
  const who = identity.name || identity.email || identity.subject;
  return (
    <div className="min-h-screen bg-neutral-50 text-neutral-900 dark:bg-neutral-950 dark:text-neutral-100">
      <header className="border-b border-neutral-200 bg-white dark:border-neutral-800 dark:bg-neutral-900">
        <div className="mx-auto flex max-w-6xl items-center gap-6 px-4">
          <span className="py-3 font-semibold">Nuclei Security Center</span>
          <nav className="flex items-center gap-1">
            {nav.map((n) => (
              <NavLink
                key={n.to}
                to={n.to}
                className={({ isActive }) =>
                  cn(
                    "rounded-md px-3 py-1.5 text-sm font-medium",
                    isActive
                      ? "bg-indigo-50 text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300"
                      : "text-neutral-600 hover:bg-neutral-100 dark:text-neutral-400 dark:hover:bg-neutral-800",
                  )
                }
              >
                {n.label}
              </NavLink>
            ))}
          </nav>
          <div className="ml-auto">
            <DropdownMenu.Root>
              <DropdownMenu.Trigger className="flex items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-neutral-100 dark:hover:bg-neutral-800">
                <span className="flex h-7 w-7 items-center justify-center rounded-full bg-indigo-600 text-xs font-semibold text-white">
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
      <main className="mx-auto max-w-6xl px-4 py-6">{children}</main>
    </div>
  );
}
