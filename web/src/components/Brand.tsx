import { NavLink } from "react-router-dom";

type BrandProps = {
  compact?: boolean;
  className?: string;
};

/**
 * The GoodnightSec product lockup: the GoodnightSec mark plus the
 * two-line name "GOODNIGHT / Check". Used in the header and the login screen.
 */
export function Brand({ compact = false, className = "" }: BrandProps) {
  const mark = <img src="/goodnightsec-mark.svg" alt="" className="h-9 w-9 shrink-0" />;

  if (compact) {
    return <div className={`flex items-center ${className}`}>{mark}</div>;
  }

  return (
    <NavLink
      to="/"
      className={`flex items-center gap-2.5 rounded-md outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 ${className}`}
      aria-label="Goodnight Check home"
    >
      {mark}
      <span className="leading-none">
        <span className="block text-[11px] font-bold uppercase tracking-[0.22em] text-lantern">Goodnight</span>
        <span className="mt-1 block text-sm font-semibold text-on-brand">Check</span>
      </span>
    </NavLink>
  );
}
