import { useCallback, useEffect, useLayoutEffect, useState } from "react";

export type Theme = "light" | "dark";

// Theme preference persists across sessions (per browser), mirroring the
// sidebar-collapsed preference in components/Layout.tsx.
const THEME_STORAGE_KEY = "nsc.theme";

/** readStoredTheme returns the user's explicit choice, or null if they never toggled. */
export function readStoredTheme(): Theme | null {
  try {
    const raw = localStorage.getItem(THEME_STORAGE_KEY);
    if (raw === "light" || raw === "dark") return raw;
    return null;
  } catch {
    return null; // private mode / storage disabled — fall back to the OS setting.
  }
}

function writeStoredTheme(theme: Theme): void {
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme);
  } catch {
    // ignore (private mode / storage disabled) — state still works in-session.
  }
}

function systemTheme(): Theme {
  if (typeof window === "undefined" || typeof window.matchMedia !== "function") return "light";
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

/** resolveTheme is the stored choice when present, else the OS preference. */
export function resolveTheme(): Theme {
  return readStoredTheme() ?? systemTheme();
}

/** applyTheme flips the `dark` class Tailwind's class-based variant keys off. */
export function applyTheme(theme: Theme): void {
  document.documentElement.classList.toggle("dark", theme === "dark");
}

/**
 * initTheme applies the resolved theme before first paint. Call once in
 * main.tsx so the initial render (and browser chrome via `color-scheme`)
 * matches instead of flashing the wrong theme.
 */
export function initTheme(): Theme {
  const theme = resolveTheme();
  applyTheme(theme);
  return theme;
}

/**
 * useTheme is the logged-in chrome's theme state. It follows the OS
 * preference until the user first toggles; after that the stored choice wins
 * (the OS listener ignores changes once a choice is stored). A `storage`
 * listener keeps multiple open tabs on the same choice in real time.
 */
export function useTheme(): { theme: Theme; toggle: () => void } {
  const [theme, setTheme] = useState<Theme>(resolveTheme);

  // Pre-paint so the `dark` class and the button icon flip in the same frame.
  useLayoutEffect(() => {
    applyTheme(theme);
  }, [theme]);

  useEffect(() => {
    if (typeof window === "undefined" || typeof window.matchMedia !== "function") return;
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    const onChange = (e: MediaQueryListEvent) => {
      if (readStoredTheme() === null) setTheme(e.matches ? "dark" : "light");
    };
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      // `clear()` fires with `key === null`; a targeted removeItem carries the
      // key. Either way the stored choice may be gone, so re-resolve.
      if (e.key !== THEME_STORAGE_KEY && e.key !== null) return;
      const next = readStoredTheme();
      // No stored choice (removed/cleared): fall back to the OS preference.
      setTheme(next ?? systemTheme());
    };
    window.addEventListener("storage", onStorage);
    return () => window.removeEventListener("storage", onStorage);
  }, []);

  const toggle = useCallback(() => {
    setTheme((current) => {
      const next: Theme = current === "dark" ? "light" : "dark";
      writeStoredTheme(next);
      // Synchronous with the icon flip; the layout effect re-applies idempotently.
      applyTheme(next);
      return next;
    });
  }, []);

  return { theme, toggle };
}
