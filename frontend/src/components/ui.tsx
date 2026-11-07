import { useEffect, useRef, useState, type ReactNode } from "react";
import { Check, Copy, X } from "lucide-react";
import type { LogEvent, Severity, Verdict } from "../types";
import { SOURCE_NAMES, whenFull } from "../lib/format";

export const SEV_COLOR: Record<Severity, string> = { low: "text-low", medium: "text-medium", high: "text-high", critical: "text-critical" };
export const SEV_BG: Record<Severity, string> = { low: "bg-low", medium: "bg-medium", high: "bg-high", critical: "bg-critical" };
const SEV_LABEL: Record<Severity, string> = { low: "Low", medium: "Medium", high: "High", critical: "Critical" };

/** Each level has its own shape too, so severity never depends on color alone. */
export function SevMark({ severity, size = 11 }: { severity: Severity; size?: number }) {
  const cls = `${SEV_COLOR[severity]} shrink-0`;
  if (severity === "low") return <svg width={size} height={size} viewBox="0 0 12 12" className={cls} aria-hidden><circle cx="6" cy="6" r="4" fill="none" stroke="currentColor" strokeWidth="2" /></svg>;
  if (severity === "medium") return <svg width={size} height={size} viewBox="0 0 12 12" className={cls} aria-hidden><circle cx="6" cy="6" r="5" fill="currentColor" /></svg>;
  if (severity === "high") return <svg width={size} height={size} viewBox="0 0 12 12" className={cls} aria-hidden><path d="M6 0.8 11.4 11H0.6z" fill="currentColor" /></svg>;
  return <svg width={size} height={size} viewBox="0 0 12 12" className={cls} aria-hidden><path d="M6 0 12 6 6 12 0 6z" fill="currentColor" /></svg>;
}

export function Sev({ severity, quiet = false }: { severity: Severity; quiet?: boolean }) {
  return (
    <span className={`inline-flex items-center gap-1.5 text-[0.82rem] font-semibold ${quiet ? "text-muted" : SEV_COLOR[severity]}`}>
      <SevMark severity={severity} />
      {SEV_LABEL[severity]}
    </span>
  );
}

const VERDICT: Record<Verdict, { label: string; cls: string; dot: string }> = {
  malicious: { label: "Known malicious", cls: "text-critical", dot: "bg-critical" },
  suspicious: { label: "Suspicious", cls: "text-medium", dot: "bg-medium" },
  clean: { label: "No bad reports", cls: "text-safe", dot: "bg-safe" },
  unknown: { label: "No intel", cls: "text-faint", dot: "bg-faint" },
};

export function VerdictTag({ verdict }: { verdict: Verdict }) {
  const v = VERDICT[verdict] ?? VERDICT.unknown;
  return (
    <span className={`inline-flex items-center gap-1.5 text-[0.8rem] font-semibold ${v.cls}`}>
      <span className={`size-2 rounded-[2px] ${v.dot}`} aria-hidden />
      {v.label}
    </span>
  );
}

export function SourceTag({ source }: { source: string }) {
  return <span className="rounded border border-line px-1.5 py-px text-[0.72rem] font-medium text-muted">{SOURCE_NAMES[source] ?? source}</span>;
}

export function Mono({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <span className={`code text-text ${className}`}>{children}</span>;
}

export function LogLine({ event, onOpen, highlight }: { event: Pick<LogEvent, "id" | "ts" | "source" | "raw"> & Partial<LogEvent>; onOpen?: (id: number) => void; highlight?: string | null }) {
  const raw = event.raw;
  let body: ReactNode = raw;
  if (highlight && raw.includes(highlight)) {
    const parts = raw.split(highlight);
    body = parts.flatMap((p, i) => (i ? [<mark key={i} className="rounded-sm bg-transparent text-text underline decoration-critical decoration-2 underline-offset-2">{highlight}</mark>, p] : [p]));
  }
  const Tag = onOpen ? "button" : "div";
  return (
    <Tag
      {...(onOpen ? { type: "button" as const, onClick: () => onOpen(event.id) } : {})}
      className={`log grid w-full grid-cols-[minmax(0,1fr)] gap-0.5 px-3 py-2 text-left text-muted sm:grid-cols-[9.5rem_minmax(0,1fr)] sm:gap-3 ${onOpen ? "hover:bg-panel-2" : ""}`}
      title={whenFull(event.ts)}
    >
      <span className="text-faint">
        {new Date(event.ts).toLocaleString(undefined, { day: "numeric", month: "short", hour: "2-digit", minute: "2-digit", second: "2-digit" })}
      </span>
      <span className="text-text/90">{body}</span>
    </Tag>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="inline-flex shrink-0 items-center gap-1 rounded-md px-2 py-1 text-xs font-semibold text-muted hover:bg-raised hover:text-text"
      onClick={() => {
        void navigator.clipboard?.writeText(text).then(() => {
          setDone(true);
          setTimeout(() => setDone(false), 1500);
        });
      }}
      aria-label={`${label}: ${text}`}
    >
      {done ? <Check size={14} /> : <Copy size={14} />}
      {done ? "Copied" : label}
    </button>
  );
}

export function Command({ text, platform }: { text: string; platform?: string | null }) {
  return (
    <div className="mt-2 flex items-start gap-2 rounded-md border border-line bg-ink py-1.5 pl-3 pr-1.5">
      <code className="code min-w-0 flex-1 py-1 text-[0.78rem] leading-relaxed text-text/90 [overflow-wrap:anywhere]" title={platform ?? undefined}>
        {text}
      </code>
      <CopyButton text={text} />
    </div>
  );
}

export function Spinner({ className = "" }: { className?: string }) {
  return <span className={`inline-block size-4 animate-spin rounded-full border-2 border-current border-r-transparent ${className}`} aria-hidden />;
}

export function Toast({ message, tone, onDone }: { message: string; tone: "info" | "error"; onDone: () => void }) {
  useEffect(() => {
    const t = setTimeout(onDone, tone === "error" ? 9000 : 4500);
    return () => clearTimeout(t);
  }, [message, tone, onDone]);
  return (
    <div role={tone === "error" ? "alert" : "status"} className="fixed inset-x-3 bottom-3 z-50 mx-auto flex max-w-lg items-start gap-3 rounded-lg border border-line-strong bg-raised px-4 py-3 shadow-2xl [animation:rise_160ms_ease-out] sm:bottom-5">
      {tone === "error" ? <SevMark severity="critical" size={13} /> : <Check size={16} className="mt-0.5 shrink-0 text-safe" />}
      <p className="min-w-0 flex-1 text-sm">{message}</p>
      <button className="text-muted hover:text-text" onClick={onDone} aria-label="Dismiss">
        <X size={16} />
      </button>
    </div>
  );
}

/** A side sheet on wide screens, a full-height sheet on phones. Closes with Escape. */
export function Drawer({ title, onClose, children, wide = false }: { title: ReactNode; onClose: () => void; children: ReactNode; wide?: boolean }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    ref.current?.focus();
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      prev?.focus?.();
    };
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-40">
      <div className="absolute inset-0 bg-black/55" onClick={onClose} aria-hidden />
      <div
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        className={`absolute inset-y-0 right-0 flex w-full flex-col border-l border-line-strong bg-panel shadow-2xl outline-none [animation:rise_140ms_ease-out] ${wide ? "max-w-3xl" : "max-w-xl"}`}
      >
        <div className="flex items-start gap-3 border-b border-line px-5 py-4">
          <div className="min-w-0 flex-1">{title}</div>
          <button className="btn btn-ghost -mr-2 min-h-9 px-2" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <div className="min-h-0 flex-1 overflow-y-auto">{children}</div>
      </div>
    </div>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-start gap-3 rounded-xl border border-dashed border-line-strong px-6 py-10 sm:items-center sm:text-center">
      <p className="display text-lg">{title}</p>
      {children && <div className="max-w-md text-muted">{children}</div>}
      {action}
    </div>
  );
}

export function Reticle({ size = 30, spinning = false }: { size?: number; spinning?: boolean }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" aria-hidden className="shrink-0">
      <circle cx="16" cy="16" r="12" fill="none" stroke="#8c88d6" strokeWidth="2" />
      <circle cx="16" cy="16" r="5.5" fill="none" stroke="#5d58a8" strokeWidth="1.6" />
      <path d="M16 1.5v5M16 25.5v5M1.5 16h5M25.5 16h5" stroke="#8c88d6" strokeWidth="2" strokeLinecap="round" />
      {spinning && (
        <g style={{ transformOrigin: "16px 16px", animation: "sweep 4s linear infinite" }}>
          <path d="M16 16 L16 4 A12 12 0 0 1 26.4 10 Z" fill="#8c88d6" opacity="0.18" />
        </g>
      )}
      <circle cx="21.8" cy="10.4" r="3" fill="#ee3f86" />
    </svg>
  );
}

export function Section({ title, aside, children, className = "" }: { title: ReactNode; aside?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`min-w-0 ${className}`}>
      <div className="mb-3 flex flex-wrap items-end justify-between gap-x-4 gap-y-1">
        <h2 className="display text-[1.05rem]">{title}</h2>
        {aside && <div className="text-sm text-muted">{aside}</div>}
      </div>
      {children}
    </section>
  );
}
