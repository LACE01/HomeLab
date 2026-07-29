import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { toast } from "sonner";
import { api } from "@/lib/api";
import Layout from "@/components/Layout";
import { Chip } from "@/components/Badges";
import {
  MagnifyingGlass, Rss, Skull, Fire, Certificate, Globe, Broadcast, Plus, Trash,
  ArrowsClockwise, ArrowSquareOut, CaretDown, CaretRight, Warning, Database,
} from "@phosphor-icons/react";

const SEV_COLOR = { Critical: "red", High: "orange", Medium: "amber", Low: "blue", Info: "slate" };
const STATUS_COLOR = { found: "red", clean: "emerald", not_configured: "slate", error: "amber" };

const TABS = [
  { id: "investigate", label: "Investigate", icon: MagnifyingGlass },
  { id: "news", label: "Threat News", icon: Rss },
  { id: "ransomware", label: "Ransomware Watch", icon: Skull },
  { id: "kev", label: "CISA KEV", icon: Fire },
  { id: "certs", label: "Cert Transparency", icon: Certificate },
  { id: "typosquat", label: "Typosquats", icon: Globe },
  { id: "shodan", label: "Shodan Exposure", icon: Broadcast },
];

export default function CtiHub() {
  const [tab, setTab] = useState("investigate");
  const [overview, setOverview] = useState(null);

  const loadOverview = () => api.get("/v1/cti/overview").then(r => setOverview(r.data)).catch(() => {});
  useEffect(() => { loadOverview(); }, []);

  return (
    <Layout title="CTI & OSINT Hub"
      subtitle="Threat news monitoring, ransomware leak-site watch, CISA KEV exposure, certificate transparency, typosquat detection, and ad-hoc indicator investigation — all matched against your own assets, domains, and vendors">

      {overview && (
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2.5 mb-4">
          <Stat label="Owned domains" value={overview.owned_domains.length}/>
          <Stat label="News matches" value={overview.articles_matched} tone={overview.articles_matched ? "amber" : null}/>
          <Stat label="Ransomware matches" value={overview.ransomware_matches} tone={overview.ransomware_matches ? "red" : null}/>
          <Stat label="KEV in environment" value={overview.kev_in_environment} tone={overview.kev_in_environment ? "red" : null}/>
          <Stat label="New certificates" value={overview.certificates_new} tone={overview.certificates_new ? "amber" : null}/>
          <Stat label="Lookalike domains" value={overview.typosquats_registered} tone={overview.typosquats_unreviewed ? "amber" : null}/>
        </div>
      )}

      <div className="flex items-center gap-1 border-b border-[#30363D] mb-4 overflow-x-auto">
        {TABS.map(t => {
          const Icon = t.icon;
          return (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`h-9 px-3 text-[12.5px] inline-flex items-center gap-1.5 border-b-2 -mb-px whitespace-nowrap ${
                tab === t.id ? "border-blue-500 text-blue-300" : "border-transparent text-slate-400 hover:text-slate-200"}`}>
              <Icon size={14}/> {t.label}
            </button>
          );
        })}
      </div>

      {tab === "investigate" && <InvestigateTab/>}
      {tab === "news" && <NewsTab onChange={loadOverview}/>}
      {tab === "ransomware" && <RansomwareTab onChange={loadOverview}/>}
      {tab === "kev" && <KevTab/>}
      {tab === "certs" && <CertsTab overview={overview} onChange={loadOverview}/>}
      {tab === "typosquat" && <TyposquatTab overview={overview} onChange={loadOverview}/>}
      {tab === "shodan" && <ShodanTab/>}
    </Layout>
  );
}

function Stat({ label, value, tone }) {
  return (
    <div className="border border-[#30363D] bg-[#0D1117] rounded-md px-3.5 py-3">
      <div className="text-[10.5px] text-slate-500 uppercase tracking-wider">{label}</div>
      <div className={`text-[20px] font-semibold mt-0.5 ${tone === "red" ? "text-red-300" : tone === "amber" ? "text-amber-300" : "text-slate-100"}`}>{value ?? 0}</div>
    </div>
  );
}

/* ------------------------------ Investigate ------------------------------ */

function InvestigateTab() {
  const [value, setValue] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [history, setHistory] = useState([]);

  const loadHistory = () => api.get("/v1/cti/investigations", { params: { limit: 15 } })
    .then(r => setHistory(r.data.items || [])).catch(() => {});
  useEffect(() => { loadHistory(); }, []);

  const run = async () => {
    if (!value.trim()) return;
    setRunning(true);
    try {
      const r = await api.post("/v1/cti/investigate", { value: value.trim() });
      setResult(r.data);
      loadHistory();
    } catch (e) { toast.error(e.response?.data?.detail || "Investigation failed"); }
    finally { setRunning(false); }
  };

  return (
    <div className="space-y-4">
      <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
        <div className="text-[12px] text-slate-400 mb-2">
          Paste any IP, domain, URL, or file hash. Every configured source runs at once — OpenCTI, GreyNoise,
          AlienVault OTX, abuse.ch, VirusTotal — plus internal checks (IOC watchlist, OSINT history, your own
          asset inventory) that need no API key.
        </div>
        <div className="flex gap-2">
          <input value={value} onChange={e => setValue(e.target.value)} onKeyDown={e => e.key === "Enter" && run()}
            placeholder="1.2.3.4 · evil.example.com · https://… · sha256…"
            className="flex-1 h-9 px-3 bg-[#161B22] border border-[#30363D] rounded text-[12.5px] text-slate-100 font-mono"/>
          <button onClick={run} disabled={running}
            className="h-9 px-4 text-[12.5px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded inline-flex items-center gap-1.5">
            <MagnifyingGlass size={14}/> {running ? "Running…" : "Investigate"}
          </button>
        </div>
      </div>

      {result && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md">
          <div className="px-4 py-2.5 border-b border-[#30363D] flex items-center gap-3 flex-wrap">
            <span className="font-mono text-[13px] text-slate-100">{result.value}</span>
            <Chip color="slate">{result.kind}</Chip>
            <span className="text-[11.5px] text-slate-500">
              {result.verdict_counts.found} source(s) reported something · {result.verdict_counts.clean} clean
              {result.verdict_counts.not_configured > 0 && ` · ${result.verdict_counts.not_configured} not configured`}
              {result.verdict_counts.error > 0 && ` · ${result.verdict_counts.error} error`}
            </span>
          </div>
          <div className="divide-y divide-[#30363D]">
            {result.results.map((s, i) => (
              <div key={i} className="px-4 py-2.5">
                <div className="flex items-center justify-between">
                  <span className="text-[12.5px] text-slate-200">{s.source}</span>
                  <Chip color={STATUS_COLOR[s.status] || "slate"}>{s.status.replace("_", " ")}</Chip>
                </div>
                {s.message && <div className="text-[11px] text-slate-500 mt-1">{s.message}</div>}
                {s.rows.map((row, j) => (
                  <div key={j} className="text-[11.5px] mt-1.5">
                    <span className="text-slate-300">{row.name}</span>
                    {row.resource && <span className="text-slate-500 font-mono ml-2">{row.resource}</span>}
                    {row.detail && <div className="text-slate-500 mt-0.5">{row.detail}</div>}
                    {row.asset_id && <Link to={`/assets/${row.asset_id}`} className="text-blue-300 hover:underline">Open asset →</Link>}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      {history.length > 0 && (
        <div>
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-500 mb-2">Recent investigations</div>
          <div className="space-y-1">
            {history.map(h => (
              <button key={h.id} onClick={() => setResult(h)}
                className="w-full text-left border border-[#30363D] bg-[#0D1117] rounded px-3 py-1.5 hover:border-slate-500 flex items-center gap-3">
                <span className="font-mono text-[11.5px] text-slate-300">{h.value}</span>
                <Chip color="slate">{h.kind}</Chip>
                {h.verdict_counts.found > 0 && <Chip color="red">{h.verdict_counts.found} hit(s)</Chip>}
                <span className="text-[10.5px] text-slate-600 ml-auto">{new Date(h.ran_at).toLocaleString()}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

/* ------------------------------ Threat News ------------------------------ */

function NewsTab({ onChange }) {
  const [data, setData] = useState({ feeds: [], keywords: [] });
  const [articles, setArticles] = useState([]);
  const [matchedOnly, setMatchedOnly] = useState(true);
  const [newFeed, setNewFeed] = useState({ name: "", url: "" });
  const [newKeyword, setNewKeyword] = useState("");
  const [syncing, setSyncing] = useState(false);
  const [octi, setOcti] = useState(false);

  const syncOpenCti = async () => {
    setOcti(true);
    try {
      const r = await api.post("/v1/cti/opencti/sync");
      toast.success(`OpenCTI: ${r.data.articles_created} new report(s) from ${r.data.reports_seen} pulled, ${r.data.articles_matched} matched your watchlist`);
      load(); onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "OpenCTI sync failed"); }
    finally { setOcti(false); }
  };

  const load = async () => {
    const [f, a] = await Promise.all([
      api.get("/v1/cti/feeds"),
      api.get("/v1/cti/articles", { params: { matched_only: matchedOnly, limit: 100 } }),
    ]);
    setData(f.data); setArticles(a.data.items || []);
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [matchedOnly]);

  const addFeed = async () => {
    if (!newFeed.url.trim()) { toast.error("Feed URL required"); return; }
    try {
      await api.post("/v1/cti/feeds", { name: newFeed.name || newFeed.url, url: newFeed.url });
      setNewFeed({ name: "", url: "" }); load(); onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Failed to add feed"); }
  };
  const addKeyword = async () => {
    if (!newKeyword.trim()) return;
    try { await api.post("/v1/cti/keywords", { keyword: newKeyword.trim() }); setNewKeyword(""); load(); }
    catch (e) { toast.error(e.response?.data?.detail || "Failed"); }
  };
  const sync = async () => {
    setSyncing(true);
    try {
      const r = await api.post("/v1/cti/feeds/sync");
      toast.success(`${r.data.articles_created} new article(s), ${r.data.articles_matched} matched your watchlist`);
      load(); onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Sync failed"); }
    finally { setSyncing(false); }
  };

  return (
    <div className="grid lg:grid-cols-3 gap-4">
      <div className="lg:col-span-2 space-y-3">
        <div className="flex items-center justify-between">
          <label className="text-[12px] text-slate-400 inline-flex items-center gap-1.5">
            <input type="checkbox" checked={matchedOnly} onChange={e => setMatchedOnly(e.target.checked)}/>
            Only articles mentioning something we own or watch
          </label>
          <div className="flex gap-2">
            <button onClick={syncOpenCti} disabled={syncing || octi}
              title="Pull OpenCTI's own Reports into this stream"
              className="h-8 px-3 text-[12px] border border-purple-500/40 text-purple-300 hover:border-purple-400 rounded inline-flex items-center gap-1.5 disabled:opacity-50">
              <Database size={13} className={octi ? "animate-spin" : ""}/> Sync OpenCTI
            </button>
            <button onClick={sync} disabled={syncing}
              className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-slate-500 text-slate-300 rounded inline-flex items-center gap-1.5 disabled:opacity-50">
              <ArrowsClockwise size={13} className={syncing ? "animate-spin" : ""}/> Sync RSS feeds
            </button>
          </div>
        </div>
        {articles.length === 0 ? (
          <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
            No articles yet. Add a feed and sync — matches against your owned domains, tracked vendors, and keywords raise a Security Alert automatically.
          </div>
        ) : articles.map(a => (
          <a key={a.id} href={a.link} target="_blank" rel="noreferrer"
            className="block border border-[#30363D] bg-[#0D1117] rounded-md px-4 py-3 hover:border-blue-500/40 group">
            <div className="flex items-start justify-between gap-3">
              <div className="text-[12.5px] text-slate-200 group-hover:text-blue-300">{a.title}</div>
              <ArrowSquareOut size={12} className="text-slate-600 shrink-0 mt-1"/>
            </div>
            <div className="text-[11px] text-slate-500 mt-1">{a.source} · {a.published_at ? new Date(a.published_at).toLocaleDateString() : ""}</div>
            {a.matches?.length > 0 && (
              <div className="flex gap-1.5 mt-1.5 flex-wrap">
                {a.matches.map((m, i) => <Chip key={i} color={m.kind === "owned_domain" ? "red" : m.kind === "vendor" ? "amber" : "blue"}>{m.term}</Chip>)}
              </div>
            )}
          </a>
        ))}
      </div>
      <div className="space-y-4">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">Monitored feeds</div>
          {data.feeds.map(f => (
            <div key={f.id} className="flex items-center gap-2 py-1 text-[11.5px]">
              <span className="flex-1 text-slate-300 truncate" title={f.url}>{f.name}</span>
              <button onClick={async () => { await api.delete(`/v1/cti/feeds/${f.id}`); load(); onChange(); }}
                className="text-slate-600 hover:text-red-400"><Trash size={12}/></button>
            </div>
          ))}
          {data.feeds.length === 0 && <div className="text-[11.5px] text-slate-500">None yet — the five built-in outlets still feed vendor pages, and OpenCTI can be pulled with the button above.</div>}
          <div className="mt-2 space-y-1.5">
            <input placeholder="Feed name" value={newFeed.name} onChange={e => setNewFeed({ ...newFeed, name: e.target.value })}
              className="w-full h-7 px-2 bg-[#161B22] border border-[#30363D] rounded text-[11.5px] text-slate-200"/>
            <input placeholder="https://example.com/feed.xml" value={newFeed.url} onChange={e => setNewFeed({ ...newFeed, url: e.target.value })}
              className="w-full h-7 px-2 bg-[#161B22] border border-[#30363D] rounded text-[11.5px] text-slate-200 font-mono"/>
            <button onClick={addFeed} className="h-7 px-2.5 text-[11.5px] border border-[#30363D] rounded text-slate-300 inline-flex items-center gap-1"><Plus size={11}/> Add feed</button>
          </div>
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">Keyword watchlist</div>
          <div className="flex gap-1.5 flex-wrap mb-2">
            {data.keywords.map(k => (
              <span key={k.id} className="inline-flex items-center gap-1 text-[11px] bg-slate-800/60 border border-[#30363D] rounded px-2 py-0.5 text-slate-300">
                {k.keyword}
                <button onClick={async () => { await api.delete(`/v1/cti/keywords/${k.id}`); load(); }} className="text-slate-600 hover:text-red-400">×</button>
              </span>
            ))}
          </div>
          <div className="flex gap-1.5">
            <input placeholder="e.g. product name" value={newKeyword} onChange={e => setNewKeyword(e.target.value)}
              onKeyDown={e => e.key === "Enter" && addKeyword()}
              className="flex-1 h-7 px-2 bg-[#161B22] border border-[#30363D] rounded text-[11.5px] text-slate-200"/>
            <button onClick={addKeyword} className="h-7 px-2 text-[11.5px] border border-[#30363D] rounded text-slate-300">Add</button>
          </div>
          <div className="text-[10.5px] text-slate-600 mt-2">Owned domains and tracked vendor names are matched automatically — keywords are for anything else.</div>
        </div>
      </div>
    </div>
  );
}

/* ------------------------------ Ransomware ------------------------------ */

function RansomwareTab({ onChange }) {
  const [items, setItems] = useState([]);
  const [matchedOnly, setMatchedOnly] = useState(false);
  const [syncing, setSyncing] = useState(false);

  const load = () => api.get("/v1/cti/ransomware", { params: { matched_only: matchedOnly } })
    .then(r => setItems(r.data.items || []));
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [matchedOnly]);

  const sync = async () => {
    setSyncing(true);
    try {
      const r = await api.post("/v1/cti/ransomware/sync");
      toast.success(`${r.data.created} new victim posting(s), ${r.data.matched} matched a vendor or owned domain`);
      load(); onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Sync failed"); }
    finally { setSyncing(false); }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <label className="text-[12px] text-slate-400 inline-flex items-center gap-1.5">
          <input type="checkbox" checked={matchedOnly} onChange={e => setMatchedOnly(e.target.checked)}/>
          Only victims matching a tracked vendor or owned domain
        </label>
        <button onClick={sync} disabled={syncing}
          className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-slate-500 text-slate-300 rounded inline-flex items-center gap-1.5 disabled:opacity-50">
          <ArrowsClockwise size={13} className={syncing ? "animate-spin" : ""}/> Sync ransomware.live
        </button>
      </div>
      {items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No victim postings pulled yet. Sync to check recent leak-site postings against your vendors and domains.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr className="border-b border-[#30363D] text-left text-slate-500 text-[11px] uppercase tracking-wider">
                <th className="px-4 py-2.5 font-medium">Victim</th>
                <th className="px-4 py-2.5 font-medium">Group</th>
                <th className="px-4 py-2.5 font-medium">Match</th>
                <th className="px-4 py-2.5 font-medium">Discovered</th>
              </tr>
            </thead>
            <tbody>
              {items.map(v => (
                <tr key={v.id} className={`border-b border-[#30363D] last:border-0 ${v.match ? "bg-red-500/5" : ""}`}>
                  <td className="px-4 py-2.5 text-slate-200">
                    {v.victim}
                    {v.victim_domain && <div className="text-[11px] text-slate-500 font-mono">{v.victim_domain}</div>}
                  </td>
                  <td className="px-4 py-2.5 text-slate-400">{v.group || "—"}</td>
                  <td className="px-4 py-2.5">
                    {v.match ? (
                      v.match.vendor_id
                        ? <Link to={`/vendors/${v.match.vendor_id}`}><Chip color="red">{v.match.label} ↗</Chip></Link>
                        : <Chip color="red">{v.match.label}</Chip>
                    ) : <span className="text-slate-600">—</span>}
                  </td>
                  <td className="px-4 py-2.5 text-slate-500 text-[11.5px]">{v.discovered || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

/* ------------------------------ KEV ------------------------------ */

function KevTab() {
  const [data, setData] = useState(null);
  const [expanded, setExpanded] = useState(new Set());
  useEffect(() => { api.get("/v1/cti/kev-report").then(r => setData(r.data)); }, []);
  if (!data) return <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>;
  const today = new Date().toISOString().slice(0, 10);

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
        <Stat label="KEV catalog size" value={data.catalog_size}/>
        <Stat label="KEV CVEs present here" value={data.kev_in_environment} tone={data.kev_in_environment ? "red" : null}/>
        <Stat label="Past CISA due date" value={data.past_kev_due_date} tone={data.past_kev_due_date ? "red" : null}/>
        <Stat label="Ransomware-linked" value={data.ransomware_linked} tone={data.ransomware_linked ? "amber" : null}/>
      </div>
      {data.items.length === 0 ? (
        <div className="border border-emerald-500/30 bg-emerald-500/5 rounded-md py-8 text-center text-[12.5px] text-emerald-200">
          No CISA KEV vulnerabilities are currently open in this environment.
        </div>
      ) : data.items.map(k => {
        const isOpen = expanded.has(k.cve);
        const overdue = (k.kev_due_date || "9999") < today;
        return (
          <div key={k.cve} className="border border-[#30363D] bg-[#0D1117] rounded-md">
            <div className="px-4 py-2.5 flex items-center gap-3 cursor-pointer"
              onClick={() => setExpanded(prev => { const n = new Set(prev); n.has(k.cve) ? n.delete(k.cve) : n.add(k.cve); return n; })}>
              {isOpen ? <CaretDown size={13} className="text-slate-500"/> : <CaretRight size={13} className="text-slate-500"/>}
              <span className="font-mono text-[12.5px] text-slate-100">{k.cve}</span>
              <span className="text-[12px] text-slate-400 flex-1 truncate">{k.vulnerability_name || `${k.vendor_project || ""} ${k.product || ""}`}</span>
              {String(k.known_ransomware).toLowerCase() === "known" && <Chip color="red">ransomware</Chip>}
              <Chip color="slate">{k.asset_count} asset(s)</Chip>
              {k.kev_due_date && <Chip color={overdue ? "red" : "amber"}>due {k.kev_due_date}</Chip>}
            </div>
            {isOpen && (
              <div className="border-t border-[#30363D] px-4 py-3 space-y-2">
                {k.required_action && <div className="text-[12px] text-slate-300"><span className="text-slate-500">CISA required action:</span> {k.required_action}</div>}
                <div className="space-y-1">
                  {k.findings.slice(0, 25).map(f => (
                    <div key={f.id} className="flex items-center gap-2 text-[11.5px]">
                      <Chip color={SEV_COLOR[f.severity] || "slate"}>{f.severity}</Chip>
                      <Link to={`/findings/${f.id}`} className="text-blue-300 hover:underline">{f.asset_hostname || "(no host)"}</Link>
                      <span className="text-slate-500">{f.status}</span>
                      {f.due_at && <span className="text-slate-600 ml-auto">SLA {f.due_at.slice(0, 10)}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

/* ------------------------------ Certificates ------------------------------ */

function CertsTab({ overview, onChange }) {
  const [items, setItems] = useState([]);
  const [newOnly, setNewOnly] = useState(false);
  const [syncing, setSyncing] = useState(false);

  const load = () => api.get("/v1/cti/certificates", { params: { new_only: newOnly } })
    .then(r => setItems(r.data.items || []));
  useEffect(() => { load(); /* eslint-disable-next-line */ }, [newOnly]);

  const sync = async () => {
    setSyncing(true);
    try {
      const r = await api.post("/v1/cti/certificates/sync", { domain: null });
      toast.success(`${r.data.new_certs} new certificate(s), ${r.data.new_hostnames} new hostname(s) queued for EASM review`);
      load(); onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Sync failed"); }
    finally { setSyncing(false); }
  };

  return (
    <div className="space-y-3">
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 text-[12px] text-blue-200">
        Monitors crt.sh for every owned domain ({(overview?.owned_domains || []).join(", ") || "none registered yet — add them under Email Auth monitoring"}).
        A certificate issued for your domain that you didn't request is worth a look; discovered hostnames also
        feed the EASM discovery queue automatically.
      </div>
      <div className="flex items-center justify-between">
        <label className="text-[12px] text-slate-400 inline-flex items-center gap-1.5">
          <input type="checkbox" checked={newOnly} onChange={e => setNewOnly(e.target.checked)}/>
          Only newly-issued since the first sweep
        </label>
        <button onClick={sync} disabled={syncing}
          className="h-8 px-3 text-[12px] border border-[#30363D] hover:border-slate-500 text-slate-300 rounded inline-flex items-center gap-1.5 disabled:opacity-50">
          <ArrowsClockwise size={13} className={syncing ? "animate-spin" : ""}/> Sweep crt.sh
        </button>
      </div>
      {items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">No certificates recorded yet.</div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
          {items.map(c => (
            <div key={c.id} className="px-4 py-2.5">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[12.5px] text-slate-200 font-mono">{c.common_name}</span>
                {c.newly_issued && <Chip color="amber">newly issued</Chip>}
                <span className="text-[11px] text-slate-500 ml-auto">{c.not_before?.slice(0, 10)} → {c.not_after?.slice(0, 10)}</span>
              </div>
              <div className="text-[11px] text-slate-500 mt-0.5">{c.issuer}</div>
              {c.names?.length > 1 && <div className="text-[10.5px] text-slate-600 mt-0.5">{c.names.slice(0, 6).join(", ")}{c.names.length > 6 ? ` +${c.names.length - 6} more` : ""}</div>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ------------------------------ Typosquats ------------------------------ */

function TyposquatTab({ overview, onChange }) {
  const [items, setItems] = useState([]);
  const [domain, setDomain] = useState("");
  const [scanning, setScanning] = useState(false);

  const load = () => api.get("/v1/cti/typosquats").then(r => setItems(r.data.items || []));
  useEffect(() => { load(); }, []);
  useEffect(() => { if (!domain && overview?.owned_domains?.length) setDomain(overview.owned_domains[0]); }, [overview, domain]);

  const scan = async () => {
    if (!domain) { toast.error("Pick a domain"); return; }
    setScanning(true);
    try {
      const r = await api.post("/v1/cti/typosquats/scan", { domain });
      toast.success(`${r.data.checked} permutations checked — ${r.data.registered} registered, ${r.data.new} newly discovered`);
      load(); onChange();
    } catch (e) { toast.error(e.response?.data?.detail || "Scan failed"); }
    finally { setScanning(false); }
  };

  const setStatus = async (s, status) => {
    await api.patch(`/v1/cti/typosquats/${s.id}`, { status });
    load(); onChange();
  };

  return (
    <div className="space-y-3">
      <div className="border border-blue-500/30 bg-blue-500/5 rounded-md px-3 py-2.5 text-[12px] text-blue-200">
        Generates plausible lookalikes (omissions, doublings, transpositions, homoglyphs, hyphenation, TLD swaps,
        prefix/suffix) and resolves each — only REGISTERED lookalikes are recorded, because a permutation nobody
        owns isn't a threat. A newly-registered one raises a High security alert.
      </div>
      <div className="flex gap-2">
        <select value={domain} onChange={e => setDomain(e.target.value)}
          className="h-8 px-2 bg-[#161B22] border border-[#30363D] rounded text-[12px] text-slate-200">
          {(overview?.owned_domains || []).map(d => <option key={d} value={d}>{d}</option>)}
          {(overview?.owned_domains || []).length === 0 && <option value="">No owned domains registered</option>}
        </select>
        <button onClick={scan} disabled={scanning || !domain}
          className="h-8 px-3 text-[12px] bg-blue-500 hover:bg-blue-400 disabled:opacity-50 text-white rounded inline-flex items-center gap-1.5">
          <Globe size={13}/> {scanning ? "Scanning…" : "Scan for lookalikes"}
        </button>
      </div>
      {items.length === 0 ? (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md py-10 text-center text-[12.5px] text-slate-500">
          No registered lookalike domains found yet.
        </div>
      ) : (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md divide-y divide-[#30363D]">
          {items.map(s => (
            <div key={s.id} className="px-4 py-2.5 flex items-center gap-3 flex-wrap">
              <Warning size={13} className={s.status === "malicious" ? "text-red-400" : "text-amber-400"}/>
              <span className="font-mono text-[12.5px] text-slate-200">{s.domain_candidate}</span>
              <span className="text-[11px] text-slate-500">→ {(s.ips || []).join(", ")}</span>
              <span className="text-[11px] text-slate-600">lookalike of {s.domain}</span>
              <div className="flex gap-1 ml-auto">
                {["new", "monitoring", "benign", "malicious"].map(st => (
                  <button key={st} onClick={() => setStatus(s, st)}
                    className={`h-6 px-2 text-[10.5px] rounded border capitalize ${s.status === st
                      ? (st === "malicious" ? "bg-red-500/15 border-red-500/40 text-red-300" : "bg-blue-500/15 border-blue-500/40 text-blue-300")
                      : "border-[#30363D] text-slate-500"}`}>{st}</button>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* ------------------------------ Shodan ------------------------------ */

function ShodanTab() {
  const [data, setData] = useState(null);
  useEffect(() => { api.get("/v1/cti/shodan-exposure").then(r => setData(r.data)); }, []);
  if (!data) return <div className="text-[12.5px] text-slate-500 py-8 text-center">Loading…</div>;

  return (
    <div className="space-y-4">
      <div className="text-[12px] text-slate-500">
        What Shodan sees on our own assets — populated by the Shodan connector's enrichment sync (Integrations → Shodan).
        {data.assets_with_exposure === 0 && " No assets have Shodan data yet; run the Shodan sync from Integrations."}
      </div>
      <div className="grid md:grid-cols-2 gap-3">
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">Most-exposed ports</div>
          {data.top_ports.map(p => (
            <div key={p.port} className="flex justify-between text-[12.5px] py-0.5">
              <span className="text-slate-300 font-mono">{p.port}</span><span className="text-slate-500">{p.count} asset(s)</span>
            </div>
          ))}
          {data.top_ports.length === 0 && <div className="text-[12px] text-slate-500">No port data.</div>}
        </div>
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md p-4">
          <div className="text-[11px] uppercase tracking-wider font-mono text-slate-400 mb-2">CVEs Shodan flags on our IPs</div>
          {data.top_vulns.map(v => (
            <div key={v.cve} className="flex justify-between text-[12.5px] py-0.5">
              <Link to={`/findings?q=${v.cve}`} className="text-blue-300 hover:underline font-mono">{v.cve}</Link>
              <span className="text-slate-500">{v.count} asset(s)</span>
            </div>
          ))}
          {data.top_vulns.length === 0 && <div className="text-[12px] text-slate-500">None flagged.</div>}
        </div>
      </div>
      {data.assets.length > 0 && (
        <div className="border border-[#30363D] bg-[#0D1117] rounded-md overflow-hidden">
          <table className="w-full text-[12.5px]">
            <thead>
              <tr className="border-b border-[#30363D] text-left text-slate-500 text-[11px] uppercase tracking-wider">
                <th className="px-4 py-2.5 font-medium">Asset</th>
                <th className="px-4 py-2.5 font-medium">IP</th>
                <th className="px-4 py-2.5 font-medium">Open ports</th>
                <th className="px-4 py-2.5 font-medium">Shodan CVEs</th>
              </tr>
            </thead>
            <tbody>
              {data.assets.map(a => (
                <tr key={a.id} className="border-b border-[#30363D] last:border-0">
                  <td className="px-4 py-2.5"><Link to={`/assets/${a.id}`} className="text-blue-300 hover:underline">{a.hostname}</Link></td>
                  <td className="px-4 py-2.5 text-slate-400 font-mono text-[11.5px]">{a.ip}</td>
                  <td className="px-4 py-2.5 text-slate-400 font-mono text-[11.5px]">{(a.shodan_ports || []).join(", ")}</td>
                  <td className="px-4 py-2.5">{(a.shodan_vulns || []).length > 0 ? <Chip color="red">{a.shodan_vulns.length}</Chip> : <span className="text-slate-600">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
