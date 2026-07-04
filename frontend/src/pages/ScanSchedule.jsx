import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import { Clock, Warning, CalendarBlank, ArrowSquareOut, CircleDashed } from "@phosphor-icons/react";

// One view over the three separate scan schedulers (Nmap, Nikto, recon-ng) instead of
// checking three "Schedules" tabs to know what's coming up. Read-only: schedules are
// still created/edited on each tool's own page -- the links on each row take you there.

const SOURCE_META = {
  nmap: { color: "blue" },
  nikto: { color: "orange" },
  "recon-ng": { color: "purple" },
};

const BUCKET_META = {
  overdue: { label: "Overdue", icon: Warning, color: "text-red-300" },
  today: { label: "Today", icon: Clock, color: "text-amber-300" },
  this_week: { label: "This week", icon: CalendarBlank, color: "text-blue-300" },
  later: { label: "Later", icon: CalendarBlank, color: "text-slate-400" },
  disabled: { label: "Disabled", icon: CircleDashed, color: "text-slate-600" },
};
const BUCKET_ORDER = ["overdue", "today", "this_week", "later", "disabled"];

function relTime(iso) {
  if (!iso) return "due now — never run yet";
  const d = new Date(iso), now = new Date();
  const diffMs = d - now;
  const abs = Math.abs(diffMs);
  const hours = abs / 3600000;
  const label = hours < 1 ? `${Math.round(abs / 60000)}m` : hours < 48 ? `${Math.round(hours)}h` : `${Math.round(hours / 24)}d`;
  return diffMs < 0 ? `${label} overdue` : `in ${label}`;
}

export default function ScanSchedule() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get("/v1/admin/scan-schedule").then(r => setData(r.data)).finally(() => setLoading(false));
  }, []);

  if (loading) return <Layout title="Scan Schedule"><div className="text-slate-500 py-8 text-center">Loading…</div></Layout>;

  const items = data?.items || [];
  const grouped = BUCKET_ORDER.map(b => ({ bucket: b, items: items.filter(it => it.bucket === b) })).filter(g => g.items.length > 0);

  return (
    <Layout title="Scan Schedule" subtitle="Every scheduled Nmap, Nikto, and recon-ng scan in one place — schedules are still managed on each tool's own page">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
        {BUCKET_ORDER.map(b => {
          const meta = BUCKET_META[b];
          return (
            <div key={b} className="border border-[#30363D] bg-[#0D1117] rounded-md p-3">
              <div className="text-[10px] uppercase tracking-wider text-slate-500 font-mono flex items-center gap-1.5">
                <meta.icon size={12}/> {meta.label}
              </div>
              <div className={`text-[20px] font-semibold font-mono mt-1 ${meta.color}`}>{data?.counts?.[b] ?? 0}</div>
            </div>
          );
        })}
      </div>

      {items.length === 0 && (
        <div className="text-[12.5px] text-slate-500 border border-[#30363D] bg-[#0D1117] rounded-md p-8 text-center">
          No scheduled scans yet. Set a schedule on the Nmap, Nikto, or Recon & OSINT page to see it here.
        </div>
      )}

      <div className="space-y-5">
        {grouped.map(({ bucket, items: bucketItems }) => {
          const meta = BUCKET_META[bucket];
          return (
            <div key={bucket}>
              <div className={`text-[11px] uppercase font-mono tracking-wider mb-2 flex items-center gap-1.5 ${meta.color}`}>
                <meta.icon size={12}/> {meta.label} ({bucketItems.length})
              </div>
              <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
                <table className="dense w-full">
                  <thead>
                    <tr>
                      <th className="text-left">Source</th>
                      <th className="text-left">Name / Target</th>
                      <th className="text-left">Every</th>
                      <th className="text-left">Last run</th>
                      <th className="text-left">Next run</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {bucketItems.map(it => (
                      <tr key={`${it.source}-${it.id}`} className="border-t border-[#30363D]/60">
                        <td><Chip color={SOURCE_META[it.source]?.color || "slate"}>{it.source_label}</Chip></td>
                        <td>
                          <div className="text-slate-200">{it.name}</div>
                          <div className="text-[10.5px] text-slate-500 font-mono truncate max-w-[280px]">{it.target_summary}</div>
                        </td>
                        <td className="text-slate-400 font-mono">{it.interval_hours}h</td>
                        <td className="text-slate-400">{it.last_run_at ? new Date(it.last_run_at).toLocaleString() : "never"}</td>
                        <td className={bucket === "overdue" ? "text-red-300" : "text-slate-300"}>{relTime(it.next_run_at)}</td>
                        <td className="text-right pr-2">
                          <Link to={it.manage_url} className="text-blue-300 hover:underline text-[11px] inline-flex items-center gap-1">
                            Manage <ArrowSquareOut size={11}/>
                          </Link>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          );
        })}
      </div>
    </Layout>
  );
}
