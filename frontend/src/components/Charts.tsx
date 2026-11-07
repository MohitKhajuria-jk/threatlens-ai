import { useState } from "react";
import type { Overview, Severity } from "../types";
import { num, plural } from "../lib/format";
import { SevMark } from "./ui";

const ORDER: Severity[] = ["critical", "high", "medium", "low"];

function topSeverity(alerts: Partial<Record<Severity, number>>): Severity | null {
  return ORDER.find((s) => (alerts[s] ?? 0) > 0) ?? null;
}

function hourLabel(iso: string, withDay: boolean) {
  const d = new Date(iso);
  return withDay ? d.toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" }) : d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

/** Log volume per time bucket (one cool hue), with each bucket's worst new alert marked above it. */
export function ActivityChart({ timeline }: { timeline: Overview["timeline"] }) {
  const [hover, setHover] = useState<number | null>(null);
  if (!timeline.length) return null;
  const max = Math.max(...timeline.map((b) => b.events), 1);
  const bucketMs = timeline.length > 1 ? new Date(timeline[1].t).getTime() - new Date(timeline[0].t).getTime() : 3600_000;
  const every = Math.max(1, Math.ceil(timeline.length / 8));
  const multiDay = new Date(timeline[0].t).toDateString() !== new Date(timeline[timeline.length - 1].t).toDateString();
  const h = hover !== null ? timeline[hover] : null;
  let lastDay = "";
  const labels = timeline.map((b, i) => {
    if (i % every || i > timeline.length - Math.ceil(every * 0.75)) return "";
    const day = new Date(b.t).toDateString();
    const label = hourLabel(b.t, multiDay && day !== lastDay);
    lastDay = day;
    return label;
  });

  return (
    <figure className="relative">
      <figcaption className="sr-only">Log events and new alerts over time</figcaption>
      <div className="relative">
        <div className="pointer-events-none absolute inset-x-0 top-6 flex items-center gap-2 text-[0.72rem] text-faint" aria-hidden>
          <span className="tabular">{num(max)}</span>
          <span className="h-px flex-1 bg-line" />
        </div>
        <div className="flex h-48 items-end gap-[2px] pt-6" onMouseLeave={() => setHover(null)}>
          {timeline.map((b, i) => {
            const sev = topSeverity(b.alerts);
            const alertCount = Object.values(b.alerts).reduce((a, n) => a + (n ?? 0), 0);
            return (
              <div
                key={b.t}
                className="group relative flex h-full min-w-0 flex-1 flex-col items-center justify-end"
                onMouseEnter={() => setHover(i)}
                onFocus={() => setHover(i)}
                onBlur={() => setHover(null)}
                tabIndex={0}
                aria-label={`${hourLabel(b.t, true)}: ${plural(b.events, "event")}, ${plural(alertCount, "new alert")}`}
              >
                {sev && (
                  <span className="mb-1 flex items-center" aria-hidden>
                    <SevMark severity={sev} size={10} />
                  </span>
                )}
                <span
                  className={`w-full rounded-t-[4px] ${hover === i ? "bg-activity-hi" : "bg-activity"}`}
                  style={{ height: `${b.events ? Math.max(2, (b.events / max) * 100) : 0}%`, maxHeight: "calc(100% - 1.25rem)" }}
                />
              </div>
            );
          })}
        </div>
        <div className="h-px bg-line-strong" aria-hidden />
        {h && hover !== null && (
          <div
            className="pointer-events-none absolute top-0 z-10 w-56 rounded-lg border border-line-strong bg-raised px-3 py-2 text-[0.8rem] shadow-xl"
            style={{ left: `clamp(0px, calc(${((hover + 0.5) / timeline.length) * 100}% - 7rem), calc(100% - 14rem))` }}
            role="status"
          >
            <p className="font-semibold">
              {hourLabel(h.t, true)} to {new Date(new Date(h.t).getTime() + bucketMs).toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" })}
            </p>
            <p className="text-muted">{plural(h.events, "event")}, {num(h.failures)} failed or blocked</p>
            {ORDER.filter((s) => h.alerts[s]).map((s) => (
              <p key={s} className="flex items-center gap-1.5 text-muted">
                <SevMark severity={s} size={9} /> {plural(h.alerts[s]!, `new ${s} alert`)}
              </p>
            ))}
          </div>
        )}
      </div>
      <div className="mt-2 flex text-[0.72rem] text-faint" aria-hidden>
        {labels.map((label, i) => (
          <span key={timeline[i].t} className={`min-w-0 flex-1 overflow-visible whitespace-nowrap ${(i / every) % 2 ? "max-sm:invisible" : ""}`}>
            {label}
          </span>
        ))}
      </div>
      <table className="sr-only">
        <caption>Events and alerts per time bucket</caption>
        <thead>
          <tr><th>Time</th><th>Events</th><th>Failed or blocked</th><th>New alerts</th></tr>
        </thead>
        <tbody>
          {timeline.map((b) => (
            <tr key={b.t}><td>{hourLabel(b.t, true)}</td><td>{b.events}</td><td>{b.failures}</td><td>{Object.values(b.alerts).reduce((a, n) => a + (n ?? 0), 0)}</td></tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
}

/** MITRE ATT&CK tactics in kill-chain order; warmth shows how many alerts map to each. */
export function TacticStrip({ tactics, onPick }: { tactics: Overview["tactics"]; onPick?: (tactic: string) => void }) {
  const max = Math.max(...tactics.map((t) => t.alerts), 1);
  return (
    <ol className="grid grid-cols-2 gap-[2px] overflow-hidden rounded-lg min-[520px]:grid-cols-3 md:grid-cols-4 xl:grid-cols-6 2xl:grid-cols-12">
      {tactics.map((t) => {
        const level = t.alerts ? 0.12 + 0.43 * (t.alerts / max) : 0; // capped so white text keeps 4.5:1 contrast
        return (
          <li key={t.tactic}>
            <button
              type="button"
              disabled={!t.alerts || !onPick}
              onClick={() => onPick?.(t.tactic)}
              className="relative flex h-full min-h-[4.6rem] w-full flex-col justify-between gap-2 bg-panel px-3 py-2.5 text-left enabled:hover:bg-panel-2 disabled:cursor-default"
              aria-label={`${t.tactic}: ${plural(t.alerts, "alert")}`}
            >
              <span className="absolute inset-0 bg-high" style={{ opacity: level }} aria-hidden />
              <span className={`relative text-[0.8rem] leading-snug ${t.alerts ? "text-text" : "text-faint"}`}>{t.tactic}</span>
              <span className={`tabular relative display text-lg ${t.alerts ? "text-text" : "text-faint"}`}>{t.alerts || "–"}</span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}
