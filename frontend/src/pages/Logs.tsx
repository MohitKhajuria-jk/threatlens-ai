import { useEffect, useState, type FormEvent } from "react";
import { Search } from "lucide-react";
import type { PageProps } from "../App";
import type { LogEvent } from "../types";
import { api } from "../lib/api";
import { num } from "../lib/format";
import { EventDrawer } from "../components/Drawers";
import { LogLine, SourceTag, Spinner } from "../components/ui";

const KINDS = ["auth_failure", "auth_success", "auth_invalid_user", "sudo", "su", "user_created", "group_add", "cron", "http_request", "process", "powershell",
  "service_install", "scheduled_task", "log_cleared", "fw_block", "fw_allow", "net_connection", "dns_query"];
const PAGE = 100;

export function LogsPage({ route, version, notify }: PageProps) {
  const initial = {
    q: route.params.get("q") ?? "", ip: route.params.get("ip") ?? "", user: route.params.get("user") ?? "", host: route.params.get("host") ?? "",
    kind: route.params.get("kind") ?? "", source: route.params.get("source") ?? "", outcome: route.params.get("outcome") ?? "",
  };
  const [form, setForm] = useState(initial);
  const [query, setQuery] = useState(initial);
  const [rows, setRows] = useState<LogEvent[]>([]);
  const [total, setTotal] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [open, setOpen] = useState<number | null>(null);

  async function load(q: typeof initial, offset = 0) {
    setBusy(true);
    try {
      const r = await api.events({ ...q, limit: PAGE, offset });
      setRows((prev) => (offset ? [...prev, ...r.events] : r.events));
      setTotal(r.total);
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    void load(query);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query, version]);

  function submit(e: FormEvent) {
    e.preventDefault();
    setQuery({ ...form });
  }
  const set = (k: keyof typeof initial) => (e: { target: { value: string } }) => setForm({ ...form, [k]: e.target.value });
  const active = Object.values(query).some(Boolean);

  return (
    <div className="grid gap-6">
      <header>
        <h1 className="display text-[2rem]">Log search</h1>
        <p className="mt-1 text-muted">Search every loaded log line. Filters combine; leave them empty to see everything, newest first.</p>
      </header>
      <form onSubmit={submit} className="grid gap-3 rounded-xl border border-line bg-panel p-4">
        <div className="relative">
          <Search size={16} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-faint" aria-hidden />
          <label htmlFor="log-q" className="sr-only">Text in the log line</label>
          <input id="log-q" className="field w-full pl-9" placeholder="Text in the log line, like /etc/passwd, sqlmap or vssadmin" value={form.q} onChange={set("q")} />
        </div>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3 xl:grid-cols-6">
          {(["ip", "user", "host"] as const).map((k) => (
            <label key={k} className="grid gap-1 text-sm text-muted">
              {k === "ip" ? "IP address" : k === "user" ? "Account" : "Host"}
              <input className="field code w-full min-w-0 text-[0.85rem]" value={form[k]} onChange={set(k)} />
            </label>
          ))}
          <label className="grid gap-1 text-sm text-muted">
            Event type
            <select className="field w-full min-w-0 text-text" value={form.kind} onChange={set("kind")}>
              <option value="">Any</option>
              {KINDS.map((k) => <option key={k} value={k}>{k.replace(/_/g, " ")}</option>)}
            </select>
          </label>
          <label className="grid gap-1 text-sm text-muted">
            Log source
            <select className="field w-full min-w-0 text-text" value={form.source} onChange={set("source")}>
              <option value="">Any</option>
              <option value="linux">Linux</option><option value="web">Web server</option><option value="windows">Windows</option><option value="firewall">Firewall</option>
            </select>
          </label>
          <label className="grid gap-1 text-sm text-muted">
            Result
            <select className="field w-full min-w-0 text-text" value={form.outcome} onChange={set("outcome")}>
              <option value="">Any</option><option value="success">Succeeded or allowed</option><option value="failure">Failed or blocked</option>
            </select>
          </label>
        </div>
        <div className="flex flex-wrap gap-2">
          <button className="btn btn-primary" type="submit" disabled={busy}>{busy ? <Spinner /> : <Search size={16} />} Search</button>
          {active && (
            <button className="btn btn-ghost" type="button" onClick={() => { const empty = { q: "", ip: "", user: "", host: "", kind: "", source: "", outcome: "" }; setForm(empty); setQuery(empty); }}>
              Clear filters
            </button>
          )}
        </div>
      </form>
      {total !== null && <p className="text-sm text-muted">{total ? `${num(total)} matching events${total > rows.length ? `, showing ${num(rows.length)}` : ""}` : "No events match."}</p>}
      {!!rows.length && (
        <div className="divide-y divide-line overflow-hidden rounded-xl border border-line bg-ink">
          {rows.map((e) => (
            <div key={e.id} className="grid grid-cols-[minmax(0,1fr)] sm:grid-cols-[6.5rem_minmax(0,1fr)]">
              <span className="hidden pl-3 pt-2 sm:block"><SourceTag source={e.source} /></span>
              <LogLine event={e} onOpen={setOpen} highlight={query.ip || query.q || null} />
            </div>
          ))}
        </div>
      )}
      {total !== null && total > rows.length && (
        <button className="btn btn-quiet w-fit" onClick={() => void load(query, rows.length)} disabled={busy}>
          {busy ? <Spinner /> : null} Show {num(Math.min(PAGE, total - rows.length))} more
        </button>
      )}
      {open !== null && <EventDrawer id={open} onClose={() => setOpen(null)} />}
    </div>
  );
}
