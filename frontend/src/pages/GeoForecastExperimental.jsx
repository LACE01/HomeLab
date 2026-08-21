import { useEffect, useState } from "react";
import { Warning, Flask, Prohibit } from "@phosphor-icons/react";
import Layout from "@/components/Layout";
import { api } from "@/lib/api";

// Item 51 (PYTHIA forecasting half) — a deliberately SEPARATE, experimental
// surface. It is never rendered alongside KEV/findings/world-monitor data. When
// the feature is disabled (the default) or no vetted source is registered (the
// shipped state), it shows the governance disclaimer instead of any prediction.
export default function GeoForecastExperimental() {
  const [status, setStatus] = useState(null);
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.get("/v1/geo-forecast/status").then((r) => setStatus(r.data)).catch(() => {});
    api.get("/v1/geo-forecast")
      .then((r) => setData(r.data))
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, []);

  const enabled = status?.enabled;
  const hasSource = status?.vetted_source_registered;

  return (
    <Layout title="Geopolitical Forecast" subtitle="Experimental — not an intelligence product">
      <div className="border-2 border-amber-500/40 bg-amber-500/[0.06] rounded-md p-4 mb-4">
        <div className="flex items-start gap-2">
          <Warning size={20} weight="fill" className="text-amber-400 shrink-0 mt-0.5" />
          <div className="text-[12.5px] text-amber-100 leading-relaxed">
            <div className="font-semibold mb-1">Experimental — do not use for decisions.</div>
            {status?.disclaimer ||
              "Any output here is an algorithmic guess, not a verified assessment. Reliable geopolitical " +
              "forecasting is unsolved. This is walled off from observed data on purpose and must never be " +
              "read as an intelligence product."}
            <div className="mt-1 text-amber-200/80">{status?.separation_policy}</div>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3 mb-4">
        <StatePill label="Feature" value={enabled ? "Enabled" : "Disabled (default)"} ok={!enabled} />
        <StatePill label="Vetted source" value={hasSource ? "Registered" : "None configured"} ok={!hasSource} />
        <StatePill label="Decision-bearing" value="No — never" ok />
      </div>

      {loading ? (
        <div className="text-[12px] text-slate-500">Loading…</div>
      ) : !enabled ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-6 text-center">
          <Prohibit size={26} className="text-slate-600 mx-auto mb-2" />
          <div className="text-[13px] text-slate-300">The experimental forecast feature is disabled.</div>
          <div className="text-[11.5px] text-slate-500 mt-1">
            It is off by default. Enabling it does not produce forecasts on its own — a forecast source must be
            vetted through legal/policy review and registered explicitly before anything can be shown.
          </div>
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="flex items-center gap-2 mb-2">
            <Flask size={16} className="text-purple-300" />
            <div className="text-[12px] text-slate-300">{data?.message || "No forecasts."}</div>
          </div>
          {(data?.items || []).length === 0 ? (
            <div className="text-[11.5px] text-slate-500">
              No vetted forecast source is configured, so there is nothing to show. This is the shipped state by
              design.
            </div>
          ) : (
            <ul className="space-y-2">
              {data.items.map((it, i) => (
                <li key={i} className="border border-[#30363D] rounded p-2.5">
                  <div className="text-[9.5px] uppercase tracking-wider font-mono text-amber-300/80 mb-1">
                    experimental · not decision-bearing · estimated confidence
                  </div>
                  <pre className="text-[11px] text-slate-400 whitespace-pre-wrap">{JSON.stringify(it, null, 2)}</pre>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </Layout>
  );
}

function StatePill({ label, value, ok }) {
  return (
    <div className={`border rounded-md px-3 py-2 ${ok ? "border-[#30363D] bg-[#0D1117]" : "border-amber-500/30 bg-amber-500/[0.04]"}`}>
      <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">{label}</div>
      <div className={`text-[13px] mt-0.5 ${ok ? "text-slate-200" : "text-amber-200"}`}>{value}</div>
    </div>
  );
}
