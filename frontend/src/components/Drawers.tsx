import { ExternalLink } from "lucide-react";
import type { AlertDetail, LogEvent, Step } from "../types";
import { api } from "../lib/api";
import { useLoad } from "../lib/hooks";
import { duration, PHASE_NAMES, plural, SOURCE_NAMES, when, whenFull } from "../lib/format";
import { Command, Drawer, LogLine, Mono, Sev, SourceTag, VerdictTag } from "./ui";

export function StepList({ steps, done, onToggle, collapsible = false }: { steps: Step[]; done?: string[]; onToggle?: (key: string) => void; collapsible?: boolean }) {
  const phases = [...new Set(steps.map((s) => s.phase))];
  return (
    <div className="grid gap-5">
      {phases.map((phase, i) => {
        const items = steps.filter((s) => s.phase === phase);
        const finished = items.filter((s) => done?.includes(s.key)).length;
        const list = (
          <ul className="grid gap-2">
            {items.map((s) => {
              const checked = done?.includes(s.key) ?? false;
              return (
                <li key={s.key} className="rounded-lg border border-line bg-panel px-3 py-2.5">
                  <label className={`flex items-start gap-3 ${onToggle ? "cursor-pointer" : ""}`}>
                    {onToggle && (
                      <input type="checkbox" checked={checked} onChange={() => onToggle(s.key)} className="mt-1 size-4 shrink-0 accent-[#56c2b8]" />
                    )}
                    <span className={`min-w-0 flex-1 text-[0.93rem] ${checked ? "text-faint line-through" : ""}`}>{s.action}</span>
                  </label>
                  {s.command && !checked && <Command text={s.command} platform={s.platform} />}
                </li>
              );
            })}
          </ul>
        );
        const label = (
          <span className="flex items-baseline justify-between gap-2 text-sm font-semibold text-muted">
            {PHASE_NAMES[phase]}
            {done && <span className="tabular font-normal text-faint">{finished} of {items.length}</span>}
          </span>
        );
        if (!collapsible) return <div key={phase}><div className="mb-2">{label}</div>{list}</div>;
        return (
          <details key={phase} open={i === 0} className="group">
            <summary className="mb-2 cursor-pointer list-none [&::-webkit-details-marker]:hidden">
              <span className="flex items-center gap-2"><span className="text-faint transition-transform group-open:rotate-90" aria-hidden>›</span><span className="flex-1">{label}</span></span>
            </summary>
            {list}
          </details>
        );
      })}
    </div>
  );
}

function Facts({ rows }: { rows: Array<[string, React.ReactNode]> }) {
  return (
    <dl className="grid grid-cols-[8rem_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
      {rows.filter(([, v]) => v !== null && v !== undefined && v !== "").map(([k, v]) => (
        <div key={k} className="contents">
          <dt className="text-muted">{k}</dt>
          <dd className="min-w-0 [overflow-wrap:anywhere]">{v}</dd>
        </div>
      ))}
    </dl>
  );
}

export function AlertDrawer({ id, onClose, onEvent }: { id: string; onClose: () => void; onEvent?: (id: number) => void }) {
  const { data: a, error } = useLoad<AlertDetail>(() => api.alert(id), [id]);
  const highlight = a?.ip ?? a?.user ?? null;
  return (
    <Drawer
      wide
      onClose={onClose}
      title={
        a ? (
          <div className="grid gap-1.5">
            <div className="flex flex-wrap items-center gap-3">
              <Sev severity={a.severity} />
              <SourceTag source={a.source} />
            </div>
            <h2 className="display text-[1.25rem]">{a.title}</h2>
          </div>
        ) : (
          <h2 className="display text-lg">{error ? "Alert not found" : "Loading alert…"}</h2>
        )
      }
    >
      {error && <p className="px-5 py-4 text-critical">{error}</p>}
      {a && (
        <div className="grid gap-7 px-5 py-5">
          <p className="text-[0.98rem] leading-relaxed">{a.description}</p>
          <Facts
            rows={[
              ["When", `${whenFull(a.first_seen)}${a.last_seen - a.first_seen > 1 ? `, for ${duration(a.first_seen, a.last_seen)}` : ""}`],
              ["Events", plural(a.count, "event")],
              ["IP address", a.ip ? <Mono>{a.ip}</Mono> : null],
              ["Account", a.user ? <Mono>{a.user}</Mono> : null],
              ["Host", a.host ? <Mono>{a.host}</Mono> : null],
              ["Threat intel", a.intel ? <span className="grid gap-1"><VerdictTag verdict={a.intel.verdict} />{a.intel.reasons.map((r) => <span key={r} className="text-muted">{r}</span>)}</span> : null],
              ["Anomaly model", a.details.anomaly ? `${a.details.anomaly.label} (score ${a.details.anomaly.score.toFixed(2)})${a.details.anomaly.reasons.length ? `: ${a.details.anomaly.reasons.join("; ")}` : ""}` : null],
              ["Incident", a.incident_id ? <a className="font-semibold underline-offset-2 hover:underline" href={`#/incident/${a.incident_id}`}>Open the incident</a> : "Not part of an incident"],
            ]}
          />
          {!!a.details.mitre?.length && (
            <div>
              <h3 className="mb-2 font-semibold">MITRE ATT&CK</h3>
              <ul className="grid gap-1.5">
                {a.details.mitre.map((t) => (
                  <li key={t.id} className="flex flex-wrap items-baseline gap-x-2 text-sm">
                    <a href={t.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 font-semibold hover:underline">
                      <Mono>{t.id}</Mono> <ExternalLink size={12} aria-hidden />
                    </a>
                    <span>{t.name}</span>
                    <span className="text-muted">({t.tactic})</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
          {!!a.details.steps?.length && (
            <div>
              <h3 className="mb-3 font-semibold">What to do</h3>
              <StepList steps={a.details.steps} />
            </div>
          )}
          <div>
            <h3 className="mb-2 font-semibold">Evidence ({plural(a.events.length, "log line")}{a.events.length < a.count ? ` of ${a.count}` : ""})</h3>
            <div className="divide-y divide-line overflow-hidden rounded-lg border border-line bg-ink">
              {a.events.map((e) => <LogLine key={e.id} event={e} onOpen={onEvent} highlight={highlight} />)}
            </div>
          </div>
        </div>
      )}
    </Drawer>
  );
}

const HIDDEN_FIELDS = new Set(["decoded", "raw"]);

export function EventDrawer({ id, onClose }: { id: number; onClose: () => void }) {
  const { data: e, error } = useLoad<LogEvent>(() => api.event(id), [id]);
  return (
    <Drawer onClose={onClose} title={<h2 className="display text-[1.15rem]">{e ? `Log event E${e.id}` : error ? "Event not found" : "Loading…"}</h2>}>
      {error && <p className="px-5 py-4 text-critical">{error}</p>}
      {e && (
        <div className="grid gap-6 px-5 py-5">
          <div className="rounded-lg border border-line bg-ink px-3 py-3">
            <p className="log text-text">{e.raw}</p>
          </div>
          <p className="text-[0.98rem]">{e.message}</p>
          <Facts
            rows={[
              ["Time", whenFull(e.ts)],
              ["Log source", `${SOURCE_NAMES[e.source]}${e.host ? `, ${e.host}` : ""}`],
              ["Event type", <Mono>{e.kind}</Mono>],
              ["Result", e.outcome],
              ["From", e.src_ip ? <a className="hover:underline" href={`#/logs?ip=${e.src_ip}`}><Mono>{e.src_ip}</Mono></a> : null],
              ["To", e.dst_ip ? <Mono>{e.dst_ip}{e.dst_port ? `:${e.dst_port}` : ""}</Mono> : e.dst_port ? <Mono>port {e.dst_port}</Mono> : null],
              ["Account", e.user ? <Mono>{e.user}</Mono> : null],
              ["Line", `${e.line} of its file`],
              ...Object.entries(e.fields)
                .filter(([k, v]) => !HIDDEN_FIELDS.has(k) && v !== null && v !== "" && v !== false)
                .map(([k, v]) => [k.replace(/_/g, " "), <Mono key={k}>{typeof v === "object" ? JSON.stringify(v) : String(v)}</Mono>] as [string, React.ReactNode]),
            ]}
          />
          <a className="btn btn-quiet w-fit" href={`#/logs?ip=${e.src_ip ?? ""}${!e.src_ip && e.user ? `&user=${e.user}` : ""}`}>
            Search related events
          </a>
          <p className="text-xs text-faint">Seen {when(e.ts)}.</p>
        </div>
      )}
    </Drawer>
  );
}
