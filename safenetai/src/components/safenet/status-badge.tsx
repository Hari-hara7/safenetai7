import { Badge } from "~/components/ui/badge";
import { mapStatusLabel, type RiskStatus } from "~/lib/security";

const colorClasses: Record<RiskStatus, string> = {
  safe: "border-[color:var(--success)]/35 bg-[color:var(--success)]/15 text-[color:var(--success)]",
  suspicious: "border-[color:var(--warning)]/35 bg-[color:var(--warning)]/15 text-[color:var(--warning)]",
  dangerous: "border-[color:var(--danger)]/35 bg-[color:var(--danger)]/15 text-[color:var(--danger)]",
};

export function StatusBadge({ status }: { status: RiskStatus }) {
  return <Badge className={colorClasses[status]}>{mapStatusLabel(status)}</Badge>;
}
