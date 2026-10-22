import { NavLink } from "react-router-dom";

type BrandProps = {
  compact?: boolean;
  className?: string;
};

/**
 * The Goodnight Check product lockup from the corporate design
 * (`web/public/goodnight-check-lockup-on-dark.svg`): the tile, "Goodnight"
 * and "Check". The header is midnight in both themes, so it is always the
 * `-on-dark` file. `compact` shows the GoodnightSec mark alone, for the
 * login screen and the mobile navigation.
 */
export function Brand({ compact = false, className = "" }: BrandProps) {
  if (compact) {
    return (
      <div className={`flex items-center ${className}`}>
        <img src="/goodnightsec-mark.svg" alt="" className="h-9 w-9 shrink-0" />
      </div>
    );
  }

  return (
    <NavLink
      to="/"
      className={`flex items-center rounded-md outline-none focus-visible:ring-2 focus-visible:ring-indigo-400 ${className}`}
      aria-label="Goodnight Check home"
    >
      <img src="/goodnight-check-lockup-on-dark.svg" alt="" className="h-9 w-auto shrink-0" />
    </NavLink>
  );
}
