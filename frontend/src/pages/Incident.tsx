import { useMemo, useState } from "react";
import { ArrowLeft, FileText, RefreshCw, Sparkles } from "lucide-react";
import type { PageProps } from "../App";
import type { Alert, IncidentDetail, IncidentStatus, Report, Severity } from "../types";
import { api } from "../lib/api";
import { useLoad } from "../lib/hooks";
import { ago, duration, list, PHASE_NAMES, plural, SOURCE_NAMES, STATUS_NAMES, when, whenFull } from "../lib/format";
import { AlertDrawer, EventDrawer, StepList } from "../components/Drawers";
import { Chat } from "../components/Chat";
import { Command, LogLine, Mono, Section, Sev, SevMark, Spinner, VerdictTag } from "../components/ui";
import { RiskGauge } from "./Overview";

const RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };

interface Stage {
  tactic: string;
  alerts: Alert[];
  first: number;
  severity: Severity;
}

function stagesOf(alerts: Alert[]): Stage[] {
  const map = new Map<string, Stage>();
  // Threat-intel and anomaly alerts aren't attack stages; they only form one when nothing else does.
  const mapped = alerts.some((a) => a.details.mitre?.length);
  for (const a of alerts) {
    const tactics = [...new Set((a.details.mitre ?? []).map((t) => t.tactic).filter(Boolean))];
    const fallback = mapped ? [] : [a.rule_id === "ml_anomaly" ? "Unusual behaviour" : "Threat intel match"];
    for (const tactic of tactics.length ? tactics : fallback) {
      const s = map.get(tactic) ?? { tactic, alerts: [], first: a.first_seen, severity: a.severity };
      s.alerts.push(a);
      s.first = Math.min(s.first, a.first_seen);
      if (RANK[a.severity] > RANK[s.severity]) s.severity = a.severity;
      map.set(tactic, s);
    }
  }
  return [...map.values()].sort((a, b) => a.first - b.first);
}

function AttackChain({ stages, picked, onPick }: { stages: Stage[]; picked: string | null; onPick: (t: string | null) => void }) {
  return (
    <div className="-mx-4 overflow-x-auto px-4 pb-1 sm:mx-0 sm:px-0">
      <ol className="flex min-w-max items-stretch" aria-label="Attack stages in the order they happened">
        {stages.map((s, i) => {
          const on = picked === s.tactic;
          return (
            <li key={s.tactic} className="flex items-stretch">
              {i > 0 && <span className="my-auto h-px w-4 bg-line-strong sm:w-6" aria-hidden />}
              <button
                type="button"
                onClick={() => onPick(on ? null : s.tactic)}
                aria-pressed={on}
                className={`grid w-[9.5rem] gap-1 rounded-lg border px-3 py-2.5 text-left ${on ? "border-text bg-panel-2" : "border-line bg-panel hover:border-line-strong"}`}
              >
                <span className="flex items-center gap-1.5 text-[0.78rem] text-muted">
                  <SevMark severity={s.severity} size={10} />
                  {new Date(s.first * 1000).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}
                </span>
                <span className="text-[0.9rem] font-semibold leading-tight">{s.tactic}</span>
                <span className="text-[0.78rem] text-muted">{plural(s.alerts.length, "alert")}</span>
              </button>
            </li>
          );
        })}
      </ol>
    </div>
  );
}

/** Shows `code` spans the model writes as code, instead of literal backticks. */
function Inline({ text }: { text: string }) {
  return <>{text.split(/`([^`]+)`/).map((part, i) => (i % 2 ? <code key={i} className="code rounded bg-ink px-1">{part}</code> : part))}</>;
}

const VERDICT_TEXT: Record<Report["verdict"], string> = {
  true_positive: "Real attack", likely_true_positive: "Probably a real attack", needs_review: "Needs a closer look", likely_benign: "Probably harmless",
};

function ReportView({ inc, onEvent, onWrite, writing, ready }: { inc: IncidentDetail; onEvent: (id: number) => void; onWrite: () => void; writing: boolean; ready: boolean }) {
  const r = inc.state.report;
  const evidenceCount = inc.alerts.reduce((n, a) => n + Math.min(6, a.evidence_count ?? 0), 0);
  if (!r) {
    return (
      <div className="rounded-xl border border-line-strong bg-panel px-5 py-5">
        <div className="flex flex-wrap items-start gap-4">
          <Sparkles size={22} className="mt-0.5 shrink-0 text-muted" aria-hidden />
          <div className="min-w-0 flex-1">
            <h2 className="display text-[1.15rem]">AI investigation report</h2>
            <p className="mt-1 max-w-2xl text-muted">
              {ready
                ? `Gemini reads the ${plural(inc.alerts.length, "alert")}, ${plural(evidenceCount, "key log line")} and the threat intel, then writes up what happened and a response plan for this incident.`
                : "Add your Gemini key as LLM_API_KEY in backend/.env and restart the backend to write AI reports. The playbook steps below work without it."}
            </p>
          </div>
          <button className="btn btn-primary" onClick={onWrite} disabled={writing || !ready}>
            {writing ? <Spinner /> : <FileText size={17} />} {writing ? "Writing the report…" : "Write the report"}
          </button>
        </div>
      </div>
    );
  }
  return (
    <article className="grid gap-7 rounded-xl border border-line-strong bg-panel px-5 py-6 sm:px-7">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted">
            <span className={`font-semibold ${r.verdict === "likely_benign" ? "text-safe" : r.verdict === "needs_review" ? "text-medium" : "text-critical"}`}>{VERDICT_TEXT[r.verdict]}</span>
            <span>{r.confidence} confidence</span>
            {r.severity && <Sev severity={r.severity} quiet />}
          </p>
          <h2 className="display mt-1 text-[1.2rem]">AI investigation report</h2>
        </div>
        <button className="btn btn-ghost min-h-9 px-3 text-sm" onClick={onWrite} disabled={writing || !ready} title="Write the report again with the latest data">
          {writing ? <Spinner /> : <RefreshCw size={15} />} {writing ? "Rewriting…" : "Rewrite"}
        </button>
      </header>
      <p className="max-w-[72ch] text-[1.06rem] leading-relaxed"><Inline text={r.summary} /></p>

      {!!r.warnings.length && (
        <div className="rounded-lg border border-medium/40 bg-ink px-4 py-3">
          <p className="flex items-center gap-2 text-sm font-semibold text-medium"><SevMark severity="medium" size={10} /> The AI noticed something odd in the evidence</p>
          <ul className="mt-1 grid gap-1 text-sm">{r.warnings.map((w) => <li key={w}><Inline text={w} /></li>)}</ul>
        </div>
      )}

      {!!r.timeline.length && (
        <div>
          <h3 className="mb-3 font-semibold">How it unfolded</h3>
          <ol className="relative grid gap-4 border-l border-line-strong pl-5">
            {r.timeline.map((t, i) => (
              <li key={i} className="relative">
                <span className="absolute -left-[1.6rem] top-1.5 size-2.5 rounded-full border-2 border-panel bg-muted" aria-hidden />
                <p className="text-sm text-muted">
                  {t.time ? new Date(t.time).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : "Time unknown"}
                  {t.stage ? `, ${t.stage}` : ""}
                </p>
                <p className="max-w-[70ch]">
                  <Inline text={t.description} />{" "}
                  {t.events.map((id) => (
                    <button key={id} type="button" onClick={() => onEvent(id)} className="code mx-0.5 rounded border border-line-strong bg-ink px-1 text-[0.72rem] hover:border-muted" aria-label={`Log event ${id}`}>
                      E{id}
                    </button>
                  ))}
                </p>
              </li>
            ))}
          </ol>
        </div>
      )}

      {(r.impact || r.affected.length > 0) && (
        <div>
          <h3 className="mb-1 font-semibold">Impact</h3>
          <p className="max-w-[72ch] text-muted"><Inline text={r.impact} /></p>
          {!!r.affected.length && <p className="mt-2 flex flex-wrap gap-2">{r.affected.map((a) => <span key={a} className="rounded-md bg-ink px-2 py-0.5 text-sm">{a}</span>)}</p>}
        </div>
      )}

      {!!r.recommendations.length && (
        <div>
          <h3 className="mb-3 font-semibold">Recommended response, in order</h3>
          <ol className="grid gap-3">
            {r.recommendations.map((rec, i) => (
              <li key={i} className="grid grid-cols-[1.75rem_minmax(0,1fr)] gap-2">
                <span className="tabular display pt-0.5 text-muted">{i + 1}</span>
                <div className="min-w-0">
                  <p>
                    <span className="mr-2 text-sm font-semibold text-muted">{PHASE_NAMES[rec.phase]}</span>
                    <Inline text={rec.action} />
                  </p>
                  {rec.why && <p className="text-sm text-muted">{rec.why}</p>}
                  {rec.command && <Command text={rec.command} platform={rec.platform} />}
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}

      {!!r.open_questions.length && (
        <div>
          <h3 className="mb-1 font-semibold">Still to find out</h3>
          <ul className="grid list-disc gap-1 pl-5 text-muted">{r.open_questions.map((q) => <li key={q}>{q}</li>)}</ul>
        </div>
      )}
      <p className="text-xs text-faint">
        Written {ago(inc.state.report_at)} by {inc.state.report_model}. AI output can be wrong; check it against the evidence.
      </p>
    </article>
  );
}

export function IncidentPage({ route, version, status, notify, changed }: PageProps) {
  const id = route.id ?? "";
  const { data: inc, error, setData } = useLoad(() => api.incident(id), [id, version]);
  const [openAlert, setOpenAlert] = useState<string | null>(null);
  const [openEvent, setOpenEvent] = useState<number | null>(null);
  const [stage, setStage] = useState<string | null>(null);
  const [writing, setWriting] = useState(false);
  const [notes, setNotes] = useState<string | null>(null);
  const [allEvidence, setAllEvidence] = useState(false);
  const stages = useMemo(() => (inc ? stagesOf(inc.alerts) : []), [inc]);

  if (error) {
    return (
      <div className="grid gap-4">
        <a href="#/incidents" className="flex items-center gap-2 text-sm text-muted hover:text-text"><ArrowLeft size={16} /> Incidents</a>
        <p className="text-critical">{error}</p>
      </div>
    );
  }
  if (!inc) return <p className="text-muted">Loading…</p>;

  const shownAlerts = stage ? stages.find((s) => s.tactic === stage)?.alerts ?? [] : inc.alerts;
  const shownIds = new Set(shownAlerts.map((a) => a.id));
  const timeline = inc.timeline.filter((t) => shownIds.has(t.alert_id));
  const done = inc.state.done;

  async function save(patch: { status?: IncidentStatus; notes?: string; done?: string[] }) {
    try {
      const state = await api.updateIncident(id, patch);
      setData((d) => (d ? { ...d, state: { ...d.state, ...state } } : d));
      if (patch.status) {
        notify(`Marked as ${STATUS_NAMES[patch.status].toLowerCase()}.`);
        changed();
      }
    } catch (e) {
      notify((e as Error).message, "error");
    }
  }

  async function write() {
    setWriting(true);
    try {
      const state = await api.report(id);
      setData((d) => (d ? { ...d, state: { ...d.state, ...state } } : d));
      notify("The AI report is ready.");
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setWriting(false);
    }
  }

  const ipRows = [...inc.ips, ...inc.indicators.ips.filter((ip) => !inc.ips.includes(ip)), ...inc.indicators.domains];

  return (
    <div className="grid gap-9">
      <header className="grid gap-4">
        <a href="#/incidents" className="flex w-fit items-center gap-2 text-sm text-muted hover:text-text"><ArrowLeft size={16} /> Incidents</a>
        <div className="flex items-start gap-4">
          <div className="hidden sm:block"><RiskGauge risk={inc.risk} severity={inc.severity} /></div>
          <div className="min-w-0 flex-1">
            <h1 className="display text-[1.45rem] sm:text-[2.1rem]">{inc.title}</h1>
            <p className="mt-2 flex flex-wrap items-center gap-x-5 gap-y-2 text-sm text-muted">
              <Sev severity={inc.severity} />
              <span className="sm:hidden">Risk {inc.risk}/100</span>
              <span title={`${whenFull(inc.first_seen)} to ${whenFull(inc.last_seen)}`}>{when(inc.first_seen)}, lasted {duration(inc.first_seen, inc.last_seen)}</span>
              <span>{plural(inc.alerts.length, "alert")} from {list(inc.sources.map((s) => SOURCE_NAMES[s]))} logs</span>
              <label className="flex items-center gap-2">
                <span>Status</span>
                <select className="field min-h-9 py-0 text-sm text-text" value={inc.state.status} onChange={(e) => void save({ status: e.target.value as IncidentStatus })}>
                  {Object.entries(STATUS_NAMES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
                </select>
              </label>
            </p>
          </div>
        </div>
      </header>

      <Section title="Attack chain" aside={stage ? <button className="font-semibold text-text hover:underline" onClick={() => setStage(null)}>Show all stages</button> : "Pick a stage to see its alerts and evidence"}>
        <AttackChain stages={stages} picked={stage} onPick={setStage} />
      </Section>

      <div className="grid gap-9 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
        <div className="grid min-w-0 content-start gap-9">
          <ReportView inc={inc} onEvent={setOpenEvent} onWrite={write} writing={writing} ready={!!status?.llm.ready} />

          <Section title={stage ? `Alerts in ${stage}` : "Alerts"} aside={plural(shownAlerts.length, "alert")}>
            <ul className="grid divide-y divide-line overflow-hidden rounded-xl border border-line">
              {shownAlerts.map((a) => (
                <li key={a.id}>
                  <button type="button" onClick={() => setOpenAlert(a.id)} className="grid w-full grid-cols-[auto_minmax(0,1fr)] gap-x-3 bg-panel px-4 py-3 text-left hover:bg-panel-2">
                    <span className="pt-1.5"><SevMark severity={a.severity} /></span>
                    <span className="min-w-0">
                      <span className="block font-semibold">{a.title}</span>
                      <span className="block text-sm text-muted">{a.description}</span>
                      <span className="mt-1 block text-[0.8rem] text-faint">
                        {when(a.first_seen)}, {plural(a.count, "event")}{a.techniques.length ? `, ${a.techniques.join(", ")}` : ""}
                      </span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          </Section>

        </div>

        <aside className="grid min-w-0 content-start gap-9">
          <Section title="Who and what">
            <div className="grid gap-5">
              {!!ipRows.length && (
                <div>
                  <p className="mb-2 text-sm font-semibold text-muted">Outside addresses and indicators</p>
                  <ul className="grid gap-2">
                    {ipRows.map((v) => {
                      const intel = inc.intel_details[v];
                      const anomaly = inc.anomaly[v];
                      return (
                        <li key={v} className="rounded-lg border border-line bg-panel px-3 py-2.5">
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <a href={`#/intel?value=${encodeURIComponent(v)}`} className="hover:underline"><Mono className="font-medium">{v}</Mono></a>
                            {intel && <VerdictTag verdict={intel.verdict} />}
                          </div>
                          {intel?.reasons.slice(0, 2).map((r) => <p key={r} className="mt-1 text-sm text-muted">{r}</p>)}
                          {anomaly && <p className="mt-1 text-sm text-muted">Anomaly model: {anomaly.label} (score {anomaly.score.toFixed(2)})</p>}
                        </li>
                      );
                    })}
                  </ul>
                </div>
              )}
              <dl className="grid grid-cols-[6.5rem_minmax(0,1fr)] gap-x-3 gap-y-2 text-sm">
                {!!inc.users.length && (<><dt className="text-muted">Accounts</dt><dd className="flex flex-wrap gap-x-3">{inc.users.map((u) => <a key={u} href={`#/logs?user=${encodeURIComponent(u)}`} className="hover:underline"><Mono>{u}</Mono></a>)}</dd></>)}
                {!!inc.hosts.length && (<><dt className="text-muted">Hosts</dt><dd className="flex flex-wrap gap-x-3">{inc.hosts.map((h) => <Mono key={h}>{h}</Mono>)}</dd></>)}
                {!!inc.assets?.length && (<><dt className="text-muted">Internal IPs</dt><dd className="flex flex-wrap gap-x-3">{inc.assets.map((h) => <Mono key={h}>{h}</Mono>)}</dd></>)}
              </dl>
            </div>
          </Section>

          <Section title="Response playbook" aside={`${done.filter((k) => inc.steps.some((s) => s.key === k)).length} of ${inc.steps.length} done`}>
            <StepList collapsible steps={inc.steps} done={done} onToggle={(key) => void save({ done: done.includes(key) ? done.filter((k) => k !== key) : [...done, key] })} />
          </Section>

          <Section title="Notes">
            <label htmlFor="notes" className="sr-only">Investigation notes</label>
            <textarea
              id="notes"
              className="field min-h-28 w-full py-2.5 text-sm"
              placeholder="What you checked, what you changed, who you told…"
              value={notes ?? inc.state.notes}
              onChange={(e) => setNotes(e.target.value)}
              onBlur={() => notes !== null && notes !== inc.state.notes && void save({ notes })}
            />
            <p className="mt-1 text-xs text-faint">Saved when you click away.</p>
          </Section>

          <Section title="Ask about this incident">
            <Chat
              scope={inc.id}
              compact
              ready={!!status?.llm.ready}
              onEvent={setOpenEvent}
              notify={notify}
              suggestions={[
                inc.ips[0] ? `Did ${inc.ips[0]} get in anywhere else?` : "What should I check first?",
                inc.users[0] ? `What did ${inc.users[0]} do after logging in?` : "Which accounts are affected?",
                "Is anything still happening?",
              ]}
            />
          </Section>
        </aside>
      </div>

      <Section title="Evidence" aside={`Key log lines from ${stage ? `the ${stage} stage` : "every alert"}, oldest first`}>
        <div className="divide-y divide-line overflow-hidden rounded-xl border border-line bg-ink">
          {(allEvidence ? timeline : timeline.slice(0, 24)).map((t) => (
            <div key={t.id} className="grid grid-cols-[1.5rem_minmax(0,1fr)] items-start">
              <span className="pl-3 pt-3" title={t.alert_title}><SevMark severity={t.severity} size={9} /></span>
              <LogLine event={t} onOpen={setOpenEvent} />
            </div>
          ))}
        </div>
        {timeline.length > 24 && (
          <button className="btn btn-quiet mt-3" onClick={() => setAllEvidence(!allEvidence)}>
            {allEvidence ? "Show fewer lines" : `Show all ${timeline.length} lines`}
          </button>
        )}
      </Section>

      {openAlert && <AlertDrawer id={openAlert} onClose={() => setOpenAlert(null)} onEvent={setOpenEvent} />}
      {openEvent !== null && <EventDrawer id={openEvent} onClose={() => setOpenEvent(null)} />}
    </div>
  );
}
