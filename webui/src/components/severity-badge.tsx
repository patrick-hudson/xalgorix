import { cn, normalizeSeverity, type Severity } from "@/lib/utils";

const STYLES: Record<Severity, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  low: "bg-green-500/10 text-green-400 border-green-500/30",
  info: "bg-sky-500/10 text-sky-400 border-sky-500/30",
};

export function SeverityBadge({
  severity,
  className,
  showDot = true,
}: {
  severity?: string;
  className?: string;
  showDot?: boolean;
}) {
  const sev = normalizeSeverity(severity);
  const dotColor: Record<Severity, string> = {
    critical: "bg-red-500",
    high: "bg-orange-500",
    medium: "bg-amber-500",
    low: "bg-green-500",
    info: "bg-sky-500",
  };
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide",
        STYLES[sev],
        className,
      )}
    >
      {showDot && (
        <span
          className={cn("h-1.5 w-1.5 rounded-full", dotColor[sev])}
          aria-hidden
        />
      )}
      {sev}
    </span>
  );
}
