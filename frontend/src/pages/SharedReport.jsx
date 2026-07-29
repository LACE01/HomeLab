import { useEffect, useState } from "react";
import { useParams } from "react-router-dom";
import { API } from "@/lib/api";
import { renderBlocks } from "@/components/ReportBlocks";

// PUBLIC page -- resolves a tokenized share grant to a read-only Security Review
// report. Item 26: the link ALONE is never enough. Either the recipient enters
// the one-time code emailed to them, or they're signed in as the platform user
// the report was shared with. Uses plain fetch (not the app's api client) so a
// signed-out external recipient is never bounced to /login by the auth
// interceptor -- but credentials are included so the platform-user mode can
// authenticate off the existing session.



export default function SharedReport() {
  const { token } = useParams();
  const [data, setData] = useState(null);
  const [meta, setMeta] = useState(null);
  const [error, setError] = useState(null);
  const [code, setCode] = useState("");
  const [verifying, setVerifying] = useState(false);

  const tryFetch = async () => {
    const r = await fetch(`${API}/v1/shared/security-review/${token}`, { credentials: "include" });
    if (r.ok) { setData(await r.json()); return true; }
    if (r.status === 404) { setError((await r.json()).detail || "This link is invalid or expired."); return true; }
    return false; // 401/403 -> needs the gate
  };

  useEffect(() => {
    (async () => {
      try {
        const m = await fetch(`${API}/v1/shared/security-review/${token}/meta`);
        if (!m.ok) { setError((await m.json()).detail || "This link is invalid or expired."); return; }
        const metaJson = await m.json();
        setMeta(metaJson);
        await tryFetch();
      } catch {
        setError("Could not reach the server.");
      }
    })();
    // eslint-disable-next-line
  }, [token]);

  const verify = async () => {
    setVerifying(true);
    try {
      const r = await fetch(`${API}/v1/shared/security-review/${token}/verify`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code }),
      });
      if (!r.ok) { setError(null); alert((await r.json()).detail || "Incorrect code"); return; }
      setData(await r.json());
    } finally { setVerifying(false); }
  };

  if (error) {
    return (
      <div className="min-h-screen bg-slate-100 flex items-center justify-center p-6">
        <div className="bg-white rounded shadow p-8 text-center max-w-md">
          <div className="text-[16px] font-semibold text-slate-800">{error}</div>
          <div className="text-[13px] text-slate-500 mt-2">Ask the review team for a fresh link.</div>
        </div>
      </div>
    );
  }

  if (!data) {
    if (meta?.mode === "email_code") {
      return (
        <div className="min-h-screen bg-slate-100 flex items-center justify-center p-6">
          <div className="bg-white rounded shadow p-8 max-w-sm w-full">
            <div className="text-[16px] font-semibold text-slate-800">Enter your access code</div>
            <div className="text-[13px] text-slate-500 mt-1">
              We emailed a 6-digit code to {meta.recipient_hint}. It's required to open this report.
            </div>
            <input value={code} onChange={e => setCode(e.target.value)} onKeyDown={e => e.key === "Enter" && verify()}
              placeholder="123456" maxLength={6}
              className="w-full mt-4 h-10 px-3 border border-slate-300 rounded text-[16px] tracking-[0.3em] text-center font-mono"/>
            <button onClick={verify} disabled={verifying || code.length < 6}
              className="w-full mt-3 h-9 bg-slate-800 disabled:opacity-50 text-white rounded text-[13px]">
              {verifying ? "Checking…" : "View report"}
            </button>
          </div>
        </div>
      );
    }
    if (meta?.mode === "platform_user") {
      return (
        <div className="min-h-screen bg-slate-100 flex items-center justify-center p-6">
          <div className="bg-white rounded shadow p-8 text-center max-w-md">
            <div className="text-[16px] font-semibold text-slate-800">Sign in required</div>
            <div className="text-[13px] text-slate-500 mt-2">
              This report was shared with a specific platform user ({meta.recipient_hint}). Sign in as that
              user, then reopen this link.
            </div>
            <a href="/login" className="inline-block mt-4 h-9 px-4 leading-9 bg-slate-800 text-white rounded text-[13px]">Sign in</a>
          </div>
        </div>
      );
    }
    return <div className="min-h-screen bg-slate-100 flex items-center justify-center text-slate-500">Loading…</div>;
  }

  const { review, generated_at } = data;

  return (
    <div className="min-h-screen bg-slate-100 py-8 print:py-0 print:bg-white">
      <div className="bg-white text-slate-900 max-w-3xl mx-auto rounded shadow print:shadow-none print:rounded-none px-8 py-6 print:px-10">
        <div className="print:hidden flex justify-end mb-3">
          <button onClick={() => window.print()} className="h-8 px-3 text-[12px] bg-slate-800 text-white rounded">
            Print / PDF
          </button>
        </div>

        {/* Same block renderer as the in-app report. The server already stripped
            internal-only blocks for the shared copy, so no layout edit here can
            expose working notes or the audit trail. */}
        {renderBlocks(data)}

        <div className="border-t border-slate-300 pt-2 mt-4 text-[10.5px] text-slate-500">
          {review.review_number} · Playbook {review.playbook_key} v{review.playbook_version} ·
          Template {review.template_key} v{review.template_version} ·
          Generated {new Date(generated_at).toLocaleString()} · Read-only shared report
        </div>
      </div>
    </div>
  );
}
