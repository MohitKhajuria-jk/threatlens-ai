import { useState } from "react";
import type { PageProps } from "../App";
import type { IncidentStatus } from "../types";
import { api } from "../lib/api";
import { useLoad } from "../lib/hooks";
import { duration, plural, STATUS_NAMES, when } from "../lib/format";
import { Start } from "../components/Start";
import { Mono, Sev } from "../components/ui";
import { RiskGauge } from "./Overview";

const FILTERS: Array<{ id: string; label: string; match: (s: IncidentStatus) => boolean }> = [
  { id: "active", label: "Open", match: (s) => s === "open" || s === "investigating" },
  { id: "contained", label: "Contained", match: (s) => s === "contained" },
  { id: "closed", label: "Closed", match: (s) => s === "resolved" || s === "false_positive" },
  { id: "all", label: "All", match: () => true },
];

export function IncidentsPage({ version, status, notify, changed }: PageProps) {
  const { data, error } = useLoad(() => api.incidents(), [version]);
  const [filter, setFilter] = useState("all");
  if (error) return <p className="text-critical">{error}</p>;
  if (!data) return <p className="text-muted">Loading…</p>;
  if (!status?.counts.events && !data.length) return <Start notify={notify} changed={changed} />;
  const f = FILTERS.find((x) => x.id === filter)!;
  const rows = data.filter((i) => f.match(i.state.status));

  return (
    <div className="grid gap-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="display text-[2rem]">Incidents</h1>
          <p className="mt-1 max-w-2xl text-muted">Alerts that share an attacker, an account session or an indicator are grouped into one incident, across all your log sources.</p>
        </div>
        <div role="tablist" aria-label="Filter incidents" className="flex rounded-lg border border-line p-0.5">
          {FILTERS.map((x) => (
            <button key={x.id} role="tab" aria-selected={filter === x.id} onClick={() => setFilter(x.id)}
              className={`rounded-md px-3 py-1.5 text-sm font-semibold ${filter === x.id ? "bg-panel-2 text-text" : "text-muted hover:text-text"}`}>
              {x.label} <span className="tabular text-faint">{data.filter((i) => x.match(i.state.status)).length}</span>
            </button>
          ))}
        </div>
      </header>
      {rows.length ? (
        <ul className="grid gap-3">
          {rows.map((inc) => (
            <li key={inc.id}>
              <a href={`#/incident/${inc.id}`} className="grid gap-x-5 gap-y-3 rounded-xl border border-line bg-panel px-4 py-4 hover:border-line-strong hover:bg-panel-2 sm:grid-cols-[auto_minmax(0,1fr)] sm:px-5">
                <div className="flex items-center gap-3 sm:block">
                  <RiskGauge risk={inc.risk} severity={inc.severity} />
                  <span className="sm:hidden"><Sev severity={inc.severity} /></span>
                </div>
                <div className="grid min-w-0 gap-2">
                  <p className="display text-[1.08rem] leading-snug">{inc.title}</p>
                  <p className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted">
                    <span className="hidden sm:inline"><Sev severity={inc.severity} /></span>
                    <span className="font-semibold text-text">{STATUS_NAMES[inc.state.status]}</span>
                    <span>{when(inc.first_seen)}, lasted {duration(inc.first_seen, inc.last_seen)}</span>
                    <span>{plural(inc.alerts, "alert")}</span>
                    {inc.has_report && <span>AI report ready</span>}
                  </p>
                  <p className="flex flex-wrap gap-x-3 gap-y-1 text-sm">
                    {inc.ips.slice(0, 3).map((ip) => <Mono key={ip}>{ip}</Mono>)}
                    {inc.hosts.slice(0, 2).map((h) => <span key={h} className="text-muted">{h}</span>)}
                    {inc.users.slice(0, 3).map((u) => <span key={u} className="text-muted">{u}</span>)}
                  </p>
                  <ol className="flex flex-wrap gap-1.5" aria-label="Attack stages">
                    {inc.tactics.map((t) => <li key={t} className="rounded-md bg-ink px-2 py-0.5 text-xs text-muted">{t}</li>)}
                  </ol>
                </div>
              </a>
            </li>
          ))}
        </ul>
      ) : (
        <p className="rounded-xl border border-line px-5 py-8 text-muted">{data.length ? `No ${f.label.toLowerCase()} incidents.` : "No incidents found. Single alerts that don't add up to an attack are on the Alerts page."}</p>
      )}
    </div>
  );
}
