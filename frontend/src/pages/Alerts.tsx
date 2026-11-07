import { useState } from "react";
import { Search } from "lucide-react";
import type { PageProps } from "../App";
import type { Severity } from "../types";
import { api } from "../lib/api";
import { useLoad } from "../lib/hooks";
import { num, SEVERITY_ORDER, SOURCE_NAMES, when } from "../lib/format";
import { AlertDrawer, EventDrawer } from "../components/Drawers";
import { Start } from "../components/Start";
import { Mono, Sev, SevMark } from "../components/ui";

export function AlertsPage({ version, route, status, notify, changed }: PageProps) {
  const { data, error } = useLoad(() => api.alerts(), [version]);
  const [sev, setSev] = useState<Severity[]>([]);
  const [source, setSource] = useState("");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<string | null>(route.params.get("open"));
  const [event, setEvent] = useState<number | null>(null);

  if (error) return <p className="text-critical">{error}</p>;
  if (!data) return <p className="text-muted">Loading…</p>;
  if (!status?.counts.events && !data.length) return <Start notify={notify} changed={changed} />;

  const ql = q.trim().toLowerCase();
  const rows = data.filter(
    (a) => (!sev.length || sev.includes(a.severity)) && (!source || a.source === source) &&
      (!ql || `${a.title} ${a.description} ${a.ip ?? ""} ${a.user ?? ""} ${a.host ?? ""}`.toLowerCase().includes(ql)),
  );
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, data.filter((a) => a.severity === s).length]));
  const sources = [...new Set(data.map((a) => a.source))];

  return (
    <div className="grid gap-6">
      <header>
        <h1 className="display text-[2rem]">Alerts</h1>
        <p className="mt-1 max-w-2xl text-muted">Everything the detection rules, threat feeds and anomaly model flagged, newest first. Open one to see its evidence and what to do.</p>
      </header>

      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter by severity">
          {SEVERITY_ORDER.map((s) => {
            const on = sev.includes(s);
            return (
              <button key={s} type="button" aria-pressed={on} onClick={() => setSev(on ? sev.filter((x) => x !== s) : [...sev, s])}
                className={`flex items-center gap-2 rounded-lg border px-3 py-1.5 text-sm font-semibold ${on ? "border-text bg-panel-2" : "border-line text-muted hover:border-line-strong"}`}>
                <SevMark severity={s} />
                <span className="capitalize">{s}</span>
                <span className="tabular text-faint">{counts[s]}</span>
              </button>
            );
          })}
        </div>
        <label className="sr-only" htmlFor="alert-source">Log source</label>
        <select id="alert-source" className="field text-sm" value={source} onChange={(e) => setSource(e.target.value)}>
          <option value="">All log sources</option>
          {sources.map((s) => <option key={s} value={s}>{SOURCE_NAMES[s]}</option>)}
        </select>
        <div className="relative min-w-[14rem] flex-1">
          <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" aria-hidden />
          <label className="sr-only" htmlFor="alert-q">Search alerts</label>
          <input id="alert-q" className="field w-full pl-9 text-sm" placeholder="Search by IP, account, host or words" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
      </div>

      <p className="text-sm text-muted">{rows.length === data.length ? `${num(data.length)} alerts` : `${num(rows.length)} of ${num(data.length)} alerts`}</p>

      <div className="overflow-hidden rounded-xl border border-line">
        <table className="w-full table-fixed border-collapse text-left text-sm">
          <thead className="hidden bg-panel text-muted md:table-header-group">
            <tr>
              <th className="w-[7.5rem] px-4 py-2.5 font-medium">Severity</th>
              <th className="px-4 py-2.5 font-medium">Alert</th>
              <th className="w-[9rem] px-4 py-2.5 font-medium">Source</th>
              <th className="w-[9.5rem] px-4 py-2.5 font-medium">IP address</th>
              <th className="w-[5.5rem] px-4 py-2.5 text-right font-medium">Events</th>
              <th className="w-[11.5rem] px-4 py-2.5 font-medium">Last seen</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {rows.map((a) => (
              <tr key={a.id} className="grid cursor-pointer grid-cols-[minmax(0,1fr)_auto] gap-x-3 gap-y-1 bg-panel px-4 py-3 hover:bg-panel-2 md:table-row md:p-0" onClick={() => setOpen(a.id)}>
                <td className="order-2 md:px-4 md:py-3"><Sev severity={a.severity} /></td>
                <td className="order-1 min-w-0 md:px-4 md:py-3">
                  <button type="button" className="text-left font-semibold hover:underline" onClick={(e) => (e.stopPropagation(), setOpen(a.id))}>{a.title}</button>
                  <p className="truncate text-muted">{a.description}</p>
                </td>
                <td className="order-3 text-muted md:px-4 md:py-3">{SOURCE_NAMES[a.source]}</td>
                <td className="order-4 md:px-4 md:py-3">{a.ip ? <Mono>{a.ip}</Mono> : <span className="text-faint">–</span>}</td>
                <td className="tabular order-5 text-muted md:px-4 md:py-3 md:text-right">{num(a.count)}<span className="md:hidden"> events</span></td>
                <td className="order-6 text-muted md:px-4 md:py-3">{when(a.last_seen)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!rows.length && <p className="px-5 py-8 text-muted">{data.length ? "No alerts match these filters." : "No alerts. Nothing in the loaded logs matched a detection rule or a threat feed."}</p>}
      </div>
      {open && <AlertDrawer id={open} onClose={() => setOpen(null)} onEvent={setEvent} />}
      {event !== null && <EventDrawer id={event} onClose={() => setEvent(null)} />}
    </div>
  );
}
