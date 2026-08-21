import { useEffect, useState, useCallback } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { AsyncState } from "@/components/AsyncState";
import { Globe, Warning, Bug, Broadcast, ShieldCheck, MagnifyingGlass, ArrowSquareOut } from "@phosphor-icons/react";

// Global-events situational-awareness board.
//
// Not a news ticker: every event is tagged with whether it touches OUR estate,
// and the board leads with those. The relevance chips are the whole point --
// "affects us" is an action item, "global" is background.

const REL_STYLE = {
  affects_us: { label: "Affects us", dot: "bg-red-500", text: "text-red-200", ring: "border-red-500/40" },
  watched: { label: "Watched", dot: "bg-amber-500", text: "text-amber-200", ring: "border-amber-500/30" },
  global: { label: "Global", dot: "bg-slate-600", text: "text-slate-400", ring: "border-[#30363D]" },
};

const CAT_ICON = {
  kev: Bug, ransomware: Warning, news: Broadcast,
  detection: ShieldCheck, incident: Warning, osint: MagnifyingGlass,
};

const SEV_COLOR = {
  Critical: "text-red-400", High: "text-orange-400", Medium: "text-amber-400",
  Low: "text-blue-400", Info: "text-slate-500",
};

// Item 51 (PYTHIA globe half): a dependency-free equirectangular world map that
// plots located events from data.map_points. This is situational awareness over
// events the platform ALREADY observed -- never forecasts. Coordinates are coarse
// country centroids; the dot size reflects volume, red means some of it touches us.
function GlobalActivityMap({ points }) {
  if (!points || points.length === 0) return null;
  const W = 360, H = 180;
  const proj = (lat, lon) => [lon + 180, 90 - lat];   // equirectangular
  const max = Math.max(...points.map((p) => p.count), 1);
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-3 mb-4">
      <div className="flex items-center justify-between mb-2">
        <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500">Global activity map</div>
        <div className="text-[10px] text-slate-600">observed events, located · not a forecast</div>
      </div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ maxHeight: 260 }} role="img" aria-label="World activity map">
        <rect x="0" y="0" width={W} height={H} fill="#0B0F14" />
        {[...Array(5)].map((_, i) => (
          <line key={`h${i}`} x1="0" y1={(H / 4) * i} x2={W} y2={(H / 4) * i} stroke="#243040" strokeWidth="0.3" opacity="0.15" />
        ))}
        {[...Array(7)].map((_, i) => (
          <line key={`v${i}`} x1={(W / 6) * i} y1="0" x2={(W / 6) * i} y2={H} stroke="#243040" strokeWidth="0.3" opacity="0.4" />
        ))}
        {points.map((pt) => {
          const [x, y] = proj(pt.lat, pt.lon);
          const r = 1.5 + 4 * Math.sqrt(pt.count / max);
          const hot = pt.affects_us > 0;
          return (
            <g key={pt.country}>
              <circle cx={x} cy={y} r={r} fill={hot ? "#ef4444" : "#3b82f6"} opacity={hot ? 0.75 : 0.55} />
              <circle cx={x} cy={y} r={r} fill="none" stroke={hot ? "#ef4444" : "#3b82f6"} strokeWidth="0.4" opacity="0.6">
                <title>{`${pt.country}: ${pt.count} event(s)${pt.affects_us ? `, ${pt.affects_us} affecting you` : ""}`}</title>
              </circle>
            </g>
          );
        })}
      </svg>
      <div className="flex items-center gap-3 mt-1 text-[10px] text-slate-600">
        <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-red-500 inline-block" /> touches your environment</span>
        <span className="inline-flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500 inline-block" /> global</span>
        <span>· dot size = event volume</span>
      </div>
    </div>
  );
}


export default function WorldMonitor() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [days, setDays] = useState(7);
  const [rel, setRel] = useState(null); // null = all

  const load = useCallback(() => {
    setLoading(true); setError(null);
    const params = { days };
    if (rel) params.relevance = rel;
    api.get("/v1/world-monitor", { params })
      .then((r) => setData(r.data))
      .catch(setError)
      .finally(() => setLoading(false));
  }, [days, rel]);

  useEffect(() => { load(); }, [load]);

  // Refresh every 2 minutes so the board stays live without a manual reload.
  useEffect(() => {
    const t = setInterval(load, 120000);
    return () => clearInterval(t);
  }, [load]);

  const counts = data?.counts || {};

  return (
    <Layout title="World Monitor"
            subtitle="Global security events — tagged with whether they touch your environment"
            actions={
              <div className="flex items-center gap-2">
                {[7, 14, 30].map((d) => (
                  <button key={d} onClick={() => setDays(d)}
                    className={`text-[12px] px-2 py-1 rounded ${days === d ? "bg-blue-500/15 text-blue-300" : "text-slate-500 hover:text-slate-300"}`}>
                    {d}d
                  </button>
                ))}
              </div>
            }>
      {/* headline + relevance filter chips */}
      <div className="mb-4">
        {data?.headline && (
          <div className="text-[13.5px] text-slate-200 mb-3 flex items-center gap-2">
            <Globe size={16} className="text-blue-400 shrink-0" /> {data.headline}
          </div>
        )}
        <div className="flex items-center gap-2">
          {[["affects_us", counts.affects_us], ["watched", counts.watched], ["global", counts.global], [null, null]].map(([r, n]) => {
            const st = r ? REL_STYLE[r] : { label: "All", dot: "bg-blue-500", text: "text-blue-200", ring: "border-blue-500/40" };
            const active = rel === r;
            return (
              <button key={r || "all"} onClick={() => setRel(r)}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded-md border text-[12px] ${active ? st.ring + " bg-white/[0.03]" : "border-[#30363D]"} ${st.text} hover:bg-white/[0.02]`}>
                <span className={`w-1.5 h-1.5 rounded-full ${st.dot}`} />
                {st.label}{n != null && <span className="text-slate-500 ml-0.5">{n}</span>}
              </button>
            );
          })}
        </div>
      </div>

      {data?.map_points?.length > 0 && <GlobalActivityMap points={data.map_points} />}

      <AsyncState loading={loading} error={error} empty={data && data.events.length === 0}
                  onRetry={load} label="the world monitor"
                  emptyMessage="No security events in this window.">
        <div className="flex flex-col gap-1.5">
          {data?.events.map((e) => {
            const st = REL_STYLE[e.relevance] || REL_STYLE.global;
            const Icon = CAT_ICON[e.category] || Broadcast;
            return (
              <div key={e.id}
                className={`border ${e.relevance === "affects_us" ? "border-red-500/30 bg-red-500/[0.03]" : "border-[#30363D] bg-[#0D1117]"} rounded-md p-3`}>
                <div className="flex items-start gap-3">
                  <Icon size={16} weight="duotone" className={`mt-0.5 shrink-0 ${SEV_COLOR[e.severity] || "text-slate-500"}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`text-[9.5px] uppercase font-mono tracking-wider px-1.5 py-0.5 rounded-full border ${st.ring} ${st.text}`}>
                        {st.label}
                      </span>
                      <span className="text-[10px] font-mono text-slate-600">{e.category_label}</span>
                      <span className={`text-[10px] font-mono ${SEV_COLOR[e.severity]}`}>{e.severity}</span>
                      {e.country && <span className="text-[10px] font-mono text-slate-600">📍 {e.country}</span>}
                    </div>
                    <div className="text-[13px] text-slate-100 mt-1 leading-snug">
                      {e.link
                        ? <a href={e.link} target="_blank" rel="noreferrer" className="hover:text-blue-300 inline-flex items-center gap-1">{e.title} <ArrowSquareOut size={11} className="opacity-60" /></a>
                        : e.title}
                    </div>
                    {e.why && <div className="text-[11.5px] text-red-300/80 mt-0.5">{e.why}</div>}
                    {e.summary && <div className="text-[11px] text-slate-500 mt-1 leading-relaxed line-clamp-2">{e.summary}</div>}
                    <div className="text-[10px] font-mono text-slate-600 mt-1">
                      {e.source}{e.when ? ` · ${new Date(e.when).toLocaleString()}` : ""}
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </AsyncState>
    </Layout>
  );
}
