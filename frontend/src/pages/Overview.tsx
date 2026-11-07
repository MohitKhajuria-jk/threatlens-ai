import type { PageProps } from "../App";
import { api } from "../lib/api";
import { useLoad } from "../lib/hooks";
import { ago, list, num, plural, SOURCE_NAMES, span, STATUS_NAMES, when } from "../lib/format";
import { ActivityChart, TacticStrip } from "../components/Charts";
import { Start } from "../components/Start";
import { Mono, Section, Sev, SevMark, VerdictTag } from "../components/ui";

export function OverviewPage({ version, notify, changed, status }: PageProps) {
  const { data, error } = useLoad(() => api.overview(), [version]);

  if (error) return <p className="text-critical">{error}</p>;
  if (!data) return <p className="text-muted">Loading…</p>;
  if (!data.events) return <Start notify={notify} changed={changed} />;

  const critical = data.incidents.filter((i) => i.severity === "critical" && i.status !== "resolved" && i.status !== "false_positive").length;
  const open = data.incidents.filter((i) => i.status === "open" || i.status === "investigating").length;
  const headline = critical
    ? `${plural(critical, "critical incident")} ${critical === 1 ? "needs" : "need"} attention`
    : open
      ? `${plural(open, "incident")} to review`
      : data.alerts
        ? "No open incidents"
        : "Nothing suspicious found";
  const sources = Object.entries(data.sources).map(([s, n]) => `${SOURCE_NAMES[s] ?? s} (${num(n ?? 0)})`);

  return (
    <div className="grid grid-cols-[minmax(0,1fr)] gap-10">
      <header className="grid gap-2">
        <h1 className="display text-[2rem] sm:text-[2.5rem]">{headline}</h1>
        <p className="max-w-3xl text-muted">
          {num(data.events)} events from {list(sources)}
          {data.span.start && data.span.end ? `, covering ${span(data.span.start, data.span.end)}` : ""}.
          {data.analyzed_at ? ` Analysed ${ago(data.analyzed_at)}.` : ""}
        </p>
      </header>

      <Section
        title="Activity"
        aside={
          <span className="flex flex-wrap items-center gap-x-4 gap-y-1">
            <span className="flex items-center gap-1.5"><span className="size-2.5 rounded-[2px] bg-activity" aria-hidden /> Log events per {data.timeline.length > 1 && new Date(data.timeline[1].t).getTime() - new Date(data.timeline[0].t).getTime() > 3600_000 ? "6 hours" : "hour"}</span>
            <span className="flex items-center gap-1.5"><SevMark severity="high" size={10} /> Worst new alert</span>
          </span>
        }
      >
        <ActivityChart timeline={data.timeline} />
      </Section>

      <div className="grid grid-cols-[minmax(0,1fr)] gap-10 xl:grid-cols-[minmax(0,1.55fr)_minmax(0,1fr)]">
        <Section title="Incidents" aside={<a href="#/incidents" className="font-semibold text-text hover:underline">All incidents</a>}>
          {data.incidents.length ? (
            <ul className="grid divide-y divide-line overflow-hidden rounded-xl border border-line">
              {data.incidents.map((inc) => (
                <li key={inc.id}>
                  <a href={`#/incident/${inc.id}`} className="grid grid-cols-[auto_minmax(0,1fr)] gap-x-4 gap-y-1 bg-panel px-4 py-4 hover:bg-panel-2 sm:px-5">
                    <div className="row-span-2 pt-1">
                      <RiskGauge risk={inc.risk} severity={inc.severity} />
                    </div>
                    <p className="font-semibold leading-snug">{inc.title}</p>
                    <p className="flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted">
                      <Sev severity={inc.severity} />
                      <span>{STATUS_NAMES[inc.status]}</span>
                      <span>{plural(inc.alerts, "alert")}</span>
                      {inc.tactics.length > 0 && <span>{plural(inc.tactics.length, "attack stage")}</span>}
                      <span>Last activity {when(inc.last_seen)}</span>
                    </p>
                  </a>
                </li>
              ))}
            </ul>
          ) : (
            <p className="rounded-xl border border-line px-5 py-6 text-muted">No incidents. Alerts that don't add up to an attack are listed on the Alerts page.</p>
          )}
        </Section>

        <Section title="Most active threats" aside={data.intel_matches ? plural(data.intel_matches, "threat-intel match", "threat-intel matches") : undefined}>
          {data.top_attackers.length ? (
            <ul className="grid gap-px overflow-hidden rounded-xl border border-line bg-line">
              {data.top_attackers.map((a) => (
                <li key={a.ip} className="bg-panel px-4 py-3">
                  <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-1">
                    <a href={`#/intel?value=${encodeURIComponent(a.ip)}`} className="hover:underline">
                      <Mono className="text-[0.92rem] font-medium">{a.ip}</Mono>
                    </a>
                    <VerdictTag verdict={a.verdict} />
                  </div>
                  <p className="mt-1 flex items-start gap-2 text-sm text-muted">
                    <span className="pt-1"><SevMark severity={a.severity} size={10} /></span>
                    <span>
                      {a.rules.slice(0, 3).join(", ")}
                      {a.rules.length > 3 ? ` and ${a.rules.length - 3} more` : ""}
                      {a.country ? `, from ${a.country}` : ""}
                    </span>
                  </p>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-muted">No outside addresses triggered alerts.</p>
          )}
        </Section>
      </div>

      <Section title="MITRE ATT&CK coverage" aside="Alerts mapped to each attack stage, in the order attacks usually unfold">
        <TacticStrip tactics={data.tactics} onPick={() => (window.location.hash = "#/alerts")} />
      </Section>

      <div className="grid grid-cols-[minmax(0,1fr)] gap-10 xl:grid-cols-2">
        <Section title="What the anomaly model noticed" aside="Isolation Forest over each outside IP's behaviour">
          {data.anomalies.filter((a) => a.reasons.length).length ? (
            <ul className="grid gap-3">
              {data.anomalies.filter((a) => a.reasons.length).slice(0, 5).map((a) => (
                <li key={a.ip} className="grid grid-cols-[4.5rem_minmax(0,1fr)] gap-3">
                  <div>
                    <div className="h-1.5 overflow-hidden rounded-full bg-panel-2" aria-hidden>
                      <div className="h-full rounded-full bg-activity-hi" style={{ width: `${Math.round(a.score * 100)}%` }} />
                    </div>
                    <p className="tabular mt-1 text-xs text-muted">score {a.score.toFixed(2)}</p>
                  </div>
                  <div className="min-w-0 text-sm">
                    <Mono className="font-medium">{a.ip}</Mono>
                    <p className="text-muted">{a.reasons.join("; ")}</p>
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-muted">{data.anomalies.length ? "No outside IP behaves very differently from the rest." : "The model needs at least 15 outside IPs to compare."}</p>
          )}
        </Section>

        <Section title="Latest alerts" aside={<a href="#/alerts" className="font-semibold text-text hover:underline">All {num(data.alerts)} alerts</a>}>
          <ul className="grid grid-cols-[minmax(0,1fr)] divide-y divide-line">
            {data.recent_alerts.map((a) => (
              <li key={a.id}>
                <a href={`#/alerts?open=${a.id}`} className="flex items-start gap-3 py-2.5 hover:text-white">
                  <span className="pt-1.5"><SevMark severity={a.severity} /></span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate font-medium">{a.title}</span>
                    <span className="block text-sm text-muted">{SOURCE_NAMES[a.source]}, {when(a.last_seen)}</span>
                  </span>
                </a>
              </li>
            ))}
          </ul>
        </Section>
      </div>
      {status && !status.llm.ready && (
        <p className="rounded-xl border border-line px-5 py-4 text-sm text-muted">
          The AI analyst is off. Add your Gemini key as <code className="code">LLM_API_KEY</code> in <code className="code">backend/.env</code> and restart the backend to get
          investigation reports and the Ask ThreatLens chat. Detection and threat intel work without it.
        </p>
      )}
    </div>
  );
}

export function RiskGauge({ risk, severity }: { risk: number; severity: import("../types").Severity }) {
  const r = 17;
  const c = 2 * Math.PI * r;
  return (
    <svg width="44" height="44" viewBox="0 0 44 44" role="img" aria-label={`Risk ${risk} out of 100`}>
      <circle cx="22" cy="22" r={r} fill="none" stroke="var(--color-panel-2)" strokeWidth="4" />
      <circle cx="22" cy="22" r={r} fill="none" stroke={`var(--color-${severity})`} strokeWidth="4" strokeLinecap="round"
        strokeDasharray={`${(risk / 100) * c} ${c}`} transform="rotate(-90 22 22)" />
      <text x="22" y="26.5" textAnchor="middle" className="tabular fill-text text-[12px] font-bold">{risk}</text>
    </svg>
  );
}
