import { NavLink } from "react-router-dom";

type BrandProps = {
  compact?: boolean;
  className?: string;
};

/** Shared product mark used in the header and authentication experience. */
export function Brand({ compact = false, className = "" }: BrandProps) {
  const mark = <img src="/nuclei-logo.svg" alt="" className="h-9 w-9 shrink-0" />;

  if (compact) {
    return <div className={`flex items-center ${className}`}>{mark}</div>;
  }

  return (
    <NavLink
      to="/"
      className={`flex items-center gap-2.5 rounded-md outline-none focus-visible:ring-2 focus-visible:ring-cyan-300 ${className}`}
      aria-label="Nuclei Security Center home"
    >
      {mark}
      <span className="leading-none">
        <span className="block text-[0.68rem] font-bold uppercase tracking-[0.22em] text-cyan-300">Nuclei</span>
        <span className="mt-1 block text-sm font-semibold tracking-wide text-white">Security Center</span>
      </span>
    </NavLink>
  );
}
