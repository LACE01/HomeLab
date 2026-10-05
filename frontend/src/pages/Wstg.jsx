import { useEffect, useMemo, useState } from "react";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { CaretDown, CaretRight, MagnifyingGlass, ArrowSquareOut } from "@phosphor-icons/react";

// Item 44 -- OWASP Web Security Testing Guide as a test-case library. The backend
// (wstg.py) already mapped findings to WSTG test ids; this is the page that makes
// it usable: the catalogue as a reference, and per category which tests have
// evidence in the open backlog and which have NONE (= not tested, not "clean").
const WSTG_URL = "https://owasp.org/www-project-web-security-testing-guide/stable/";

export default function Wstg() {
  const [cat, setCat] = useState(null);
  const [cov, setCov] = useState(null);
  const [err, setErr] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState({});
  const [onlyGaps, setOnlyGaps] = useState(false);

  useEffect(() => {
    Promise.all([api.get("/v1/wstg/catalogue"), api.get("/v1/wstg/coverage")])
      .then(([a, b]) => { setCat(a.data); setCov(b.data); })
      .catch(e => setErr(e.response?.data?.detail || "Could not load the WSTG library"));
  }, []);

  const evidence = useMemo(() => {
    const m = {};
    for (const c of cov?.categories || []) for (const t of c.evidenced_tests || []) m[t.id] = t.findings;
    return m;
  }, [cov]);

  const categories = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return (cat?.categories || []).map(c => {
      const tests = c.tests.filter(t => {
        if (onlyGaps && evidence[t.id]) return false;
        if (!needle) return true;
        return `${t.id} ${t.name} ${(t.cwes || []).join(" ")}`.toLowerCase().includes(needle);
      });
      const withEv = c.tests.filter(t => evidence[t.id]).length;
      return { ...c, tests, withEv, total: c.tests.length };
    }).filter(c => c.tests.length > 0 || (!q && !onlyGaps));
  }, [cat, q, onlyGaps, evidence]);

  const searching = !!q.trim();

  return (
    <Layout title="OWASP WSTG Library"
      subtitle="Web Security Testing Guide test cases, mapped to your open findings — evidence per test, and the categories with none">
      {err && <div className="text-[12px] text-red-300 mb-3">{err}</div>}
      {!cat && !err && <div className="text-[12px] text-slate-500">Loading…</div>}
      {cat && (
        <div className="space-y-4 max-w-6xl">
          {cov && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
                <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Tests with evidence</div>
                <div className="text-[24px] font-mono font-semibold text-slate-100">{cov.tests_with_evidence}<span className="text-slate-500 text-[14px]"> / {cov.tests_total}</span></div>
                <div className="h-1.5 bg-slate-800 rounded mt-2 overflow-hidden"><div className="h-full bg-blue-500" style={{ width: `${cov.coverage_pct}%` }} /></div>
              </div>
              <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
                <div className="text-[10px] uppercase tracking-wider font-mono text-slate-500">Categories with no evidence</div>
                <div className="text-[24px] font-mono font-semibold text-amber-300">{(cov.categories || []).filter(c => c.status === "no_evidence").length}<span className="text-slate-500 text-[14px]"> / {(cov.categories || []).length}</span></div>
                <div className="text-[11px] text-slate-500 mt-1">Likely untested — not proven clean.</div>
              </div>
              <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4 text-[11.5px] text-slate-400 leading-relaxed">
                {cov.note}
                <a href={WSTG_URL} target="_blank" rel="noreferrer" className="ml-1 text-blue-400 hover:text-blue-300 inline-flex items-center gap-0.5">OWASP WSTG <ArrowSquareOut size={11}/></a>
              </div>
            </div>
          )}

          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative">
              <MagnifyingGlass size={13} className="absolute left-2 top-2.5 text-slate-500" />
              <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search id, name or CWE (e.g. INPV-05, CWE-89)"
                data-testid="wstg-search"
                className="h-8 pl-7 pr-2 w-80 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200" />
            </div>
            <label className="flex items-center gap-2 text-[12px] text-slate-300">
              <input type="checkbox" checked={onlyGaps} onChange={e => setOnlyGaps(e.target.checked)} /> Only tests with no evidence
            </label>
            <span className="text-[11px] text-slate-500">{cat.test_count} test cases across {cat.categories.length} categories</span>
          </div>

          <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
            {categories.map(c => {
              const isOpen = searching || onlyGaps || !!open[c.category];
              return (
                <div key={c.category}>
                  <button type="button" onClick={() => setOpen({ ...open, [c.category]: !open[c.category] })}
                    data-testid={`wstg-cat-${c.category}`}
                    className="w-full px-4 py-2.5 flex items-center gap-3 text-left hover:bg-slate-800/30">
                    {isOpen ? <CaretDown size={12} className="text-slate-500"/> : <CaretRight size={12} className="text-slate-500"/>}
                    <span className="font-mono text-[11px] text-slate-500 w-12">{c.category}</span>
                    <span className="text-[13px] text-slate-200 flex-1">{c.name}</span>
                    <span className={`text-[10.5px] px-2 py-0.5 rounded border ${c.withEv ? "border-blue-500/30 text-blue-300 bg-blue-500/10" : "border-amber-500/30 text-amber-300 bg-amber-500/10"}`}>
                      {c.withEv ? `${c.withEv}/${c.total} with evidence` : "no evidence"}
                    </span>
                  </button>
                  {isOpen && (
                    <div className="pb-2">
                      {c.tests.map(t => (
                        <div key={t.id} className="pl-12 pr-4 py-1.5 flex items-center gap-3 text-[12px]">
                          <span className="font-mono text-[11px] text-slate-400 w-28 shrink-0">{t.id}</span>
                          <span className="text-slate-200 flex-1">{t.name}</span>
                          {(t.cwes || []).length > 0 && <span className="text-[10.5px] font-mono text-slate-500">{t.cwes.join(", ")}</span>}
                          {evidence[t.id]
                            ? <span className="text-[10.5px] text-blue-300 w-28 text-right">{evidence[t.id].toLocaleString()} open finding{evidence[t.id] === 1 ? "" : "s"}</span>
                            : <span className="text-[10.5px] text-slate-600 w-28 text-right">not evidenced</span>}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
            {categories.length === 0 && <div className="px-4 py-6 text-[12px] text-slate-500 text-center">No test cases match.</div>}
          </div>
        </div>
      )}
    </Layout>
  );
}
