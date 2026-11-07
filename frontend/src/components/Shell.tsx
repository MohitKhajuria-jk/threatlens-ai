import { useState, type ReactNode } from "react";
import { BellRing, Flame, Gauge, Menu, MessageSquareText, ScanSearch, ScrollText, Upload, X } from "lucide-react";
import type { Status } from "../types";
import { Reticle } from "./ui";

export type Page = "overview" | "incidents" | "incident" | "alerts" | "logs" | "intel" | "data" | "ask";

const NAV: Array<{ page: Page; label: string; Icon: typeof Gauge }> = [
  { page: "overview", label: "Overview", Icon: Gauge },
  { page: "incidents", label: "Incidents", Icon: Flame },
  { page: "alerts", label: "Alerts", Icon: BellRing },
  { page: "logs", label: "Log search", Icon: ScrollText },
  { page: "intel", label: "Threat intel", Icon: ScanSearch },
  { page: "ask", label: "Ask ThreatLens", Icon: MessageSquareText },
  { page: "data", label: "Log files", Icon: Upload },
];

function Rail({ page, status, onNavigate }: { page: Page; status: Status | null; onNavigate: () => void }) {
  const active = page === "incident" ? "incidents" : page;
  const feeds = status?.intel?.feeds?.filter((f) => f.id !== "demo") ?? [];
  const liveFeeds = feeds.filter((f) => f.entries > 0).length;
  return (
    <div className="flex h-full flex-col gap-6 px-3 py-5">
      <a href="#/overview" onClick={onNavigate} className="flex items-center gap-2.5 px-2">
        <Reticle size={30} />
        <span className="display text-[1.15rem]">ThreatLens</span>
      </a>
      <nav aria-label="Main" className="grid gap-0.5">
        {NAV.map(({ page: p, label, Icon }) => {
          const on = active === p;
          const badge = p === "incidents" ? status?.counts.open_incidents : undefined;
          return (
            <a
              key={p}
              href={`#/${p}`}
              onClick={onNavigate}
              aria-current={on ? "page" : undefined}
              className={`flex items-center gap-3 rounded-lg px-3 py-2.5 text-[0.95rem] font-medium ${on ? "bg-panel-2 text-text" : "text-muted hover:bg-panel hover:text-text"}`}
            >
              <Icon size={18} strokeWidth={on ? 2.2 : 1.8} aria-hidden />
              <span className="flex-1">{label}</span>
              {!!badge && <span className="tabular rounded-md bg-raised px-1.5 text-xs font-semibold text-text">{badge}</span>}
            </a>
          );
        })}
      </nav>
      <div className="mt-auto grid gap-3 border-t border-line px-2 pt-4 text-[0.82rem] text-muted">
        <p className="flex items-start gap-2" title={status?.llm.label}>
          <span className={`mt-1.5 size-2 shrink-0 rounded-full ${status?.llm.ready ? "bg-safe" : "bg-faint"}`} aria-hidden />
          <span className="min-w-0">
            <span className="block text-text">{status?.llm.ready ? "AI analyst on" : "AI analyst off"}</span>
            <span className="block truncate">{status?.llm.ready ? (status.llm.using_fallback ? status.llm.fallback_model : status.llm.model) : "Add a Gemini key to turn it on"}</span>
          </span>
        </p>
        <p className="flex items-start gap-2" data-feeds>
          <span className={`mt-1.5 size-2 shrink-0 rounded-full ${liveFeeds ? "bg-safe" : "bg-faint"}`} aria-hidden />
          <span>
            <span className="block text-text">{liveFeeds ? `${liveFeeds} of ${feeds.length} threat feeds` : "Threat feeds not loaded"}</span>
            <span className="block">
              {[status?.intel.abuseipdb && "AbuseIPDB", status?.intel.virustotal && "VirusTotal"].filter(Boolean).join(" and ") || "No API keys added"}
            </span>
          </span>
        </p>
      </div>
    </div>
  );
}

export function Shell({ page, status, children }: { page: Page; status: Status | null; children: ReactNode }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="flex min-h-dvh">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-md focus:bg-text focus:px-3 focus:py-2 focus:text-ink">
        Skip to content
      </a>
      <aside className="sticky top-0 hidden h-dvh w-60 shrink-0 border-r border-line bg-ink lg:block">
        <Rail page={page} status={status} onNavigate={() => undefined} />
      </aside>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setOpen(false)} aria-hidden />
          <aside className="absolute inset-y-0 left-0 w-[min(17rem,86vw)] overflow-y-auto border-r border-line-strong bg-ink">
            <button className="absolute right-2 top-4 grid size-9 place-items-center rounded-md text-muted hover:bg-panel" onClick={() => setOpen(false)} aria-label="Close menu">
              <X size={18} />
            </button>
            <Rail page={page} status={status} onNavigate={() => setOpen(false)} />
          </aside>
        </div>
      )}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-30 flex items-center gap-3 border-b border-line bg-ink/95 px-4 py-3 backdrop-blur lg:hidden">
          <button className="grid size-10 place-items-center rounded-lg border border-line" onClick={() => setOpen(true)} aria-label="Open menu">
            <Menu size={19} />
          </button>
          <a href="#/overview" className="flex items-center gap-2">
            <Reticle size={24} />
            <span className="display">ThreatLens</span>
          </a>
        </header>
        <main id="main" className="mx-auto w-full max-w-[90rem] flex-1 px-4 py-6 sm:px-6 lg:px-10 lg:py-9">
          {children}
        </main>
      </div>
    </div>
  );
}
