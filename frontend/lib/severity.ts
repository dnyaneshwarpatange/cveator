import type { Severity } from "@/lib/types";

export const severityLabel: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  unknown: "Unscored"
};

export const severityClassName: Record<Severity, string> = {
  critical: "bg-rose-100 text-rose-800 ring-rose-200",
  high: "bg-orange-100 text-orange-800 ring-orange-200",
  medium: "bg-amber-100 text-amber-800 ring-amber-200",
  low: "bg-sky-100 text-sky-800 ring-sky-200",
  unknown: "bg-slate-100 text-slate-700 ring-slate-200"
};
