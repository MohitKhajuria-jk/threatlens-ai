import { useRef, useState, type DragEvent } from "react";
import { ClipboardPaste, Download, FileUp, FlaskConical, Trash2 } from "lucide-react";
import type { PageProps } from "../App";
import type { UploadResult } from "../types";
import { api, demoFileUrl } from "../lib/api";
import { useLoad } from "../lib/hooks";
import { bytes, num, plural, when } from "../lib/format";
import { Section, Spinner } from "../components/ui";

const DEMO_FILES = ["web-01_auth.log", "web-01_nginx_access.log", "WS-FIN-07_security.json", "gw-01_ufw_firewall.log"];

export function DataPage({ version, status, notify, changed }: PageProps) {
  const { data } = useLoad(() => api.datasets(), [version]);
  const [busy, setBusy] = useState<string | null>(null);
  const [drag, setDrag] = useState(false);
  const [paste, setPaste] = useState(false);
  const [pasteText, setPasteText] = useState("");
  const [pasteName, setPasteName] = useState("pasted.log");
  const [confirmClear, setConfirmClear] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  function report(r: UploadResult) {
    for (const e of r.errors) notify(`${e.file}: ${e.error}`, "error");
    if (r.added.length && r.analysis) {
      notify(`${plural(r.added.length, "file")} added. ${plural(r.analysis.alerts, "alert")} and ${plural(r.analysis.incidents, "incident")} across all logs.`);
    }
    changed();
  }

  async function run(label: string, fn: () => Promise<UploadResult | { ok: boolean }>) {
    setBusy(label);
    try {
      const r = await fn();
      if ("added" in r) report(r);
      else changed();
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setBusy(null);
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDrag(false);
    const files = [...e.dataTransfer.files];
    if (files.length) void run("upload", () => api.upload(files));
  }

  return (
    <div className="grid gap-10">
      <header>
        <h1 className="display text-[2rem]">Log files</h1>
        <p className="mt-1 max-w-2xl text-muted">Add log files and ThreatLens works out the format, then re-analyses everything together so attacks that span several logs are connected.</p>
      </header>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]">
        <div
          onDragOver={(e) => (e.preventDefault(), setDrag(true))}
          onDragLeave={() => setDrag(false)}
          onDrop={onDrop}
          className={`flex flex-col items-start justify-center gap-4 rounded-xl border-2 border-dashed px-6 py-8 ${drag ? "border-text bg-panel-2" : "border-line-strong"}`}
        >
          <FileUp size={26} className="text-muted" aria-hidden />
          <div>
            <p className="display text-lg">Drop log files here</p>
            <p className="mt-1 text-sm text-muted">
              Linux auth.log or syslog, Apache or Nginx access logs, Windows .evtx files or events exported to JSON or CSV, UFW, iptables or Windows Firewall logs. Plain or in .gz and .zip, up to {status?.limits?.upload_mb ?? 50} MB each.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <button className="btn btn-primary" onClick={() => input.current?.click()} disabled={!!busy}>
              {busy === "upload" ? <Spinner /> : <FileUp size={17} />} {busy === "upload" ? "Analysing…" : "Choose files"}
            </button>
            <button className="btn btn-quiet" onClick={() => setPaste(!paste)} aria-expanded={paste}>
              <ClipboardPaste size={17} /> Paste log text
            </button>
          </div>
          <input ref={input} type="file" multiple hidden onChange={(e) => { const f = [...(e.target.files ?? [])]; e.target.value = ""; if (f.length) void run("upload", () => api.upload(f)); }} />
        </div>

        <div className="grid content-start gap-3 rounded-xl border border-line bg-panel px-5 py-5">
          <p className="display text-lg">Demo logs</p>
          <p className="text-sm text-muted">A fictional day on a small network: a web server break-in, a Remote Desktop intrusion that ends in ransomware preparation, a scanner and a slow password bot, among normal traffic.</p>
          <button className="btn btn-quiet w-fit" onClick={() => void run("demo", api.loadDemo)} disabled={!!busy}>
            {busy === "demo" ? <Spinner /> : <FlaskConical size={17} />} {data?.some((d) => d.demo) ? "Reload the demo logs" : "Load the demo logs"}
          </button>
          <details className="text-sm">
            <summary className="cursor-pointer text-muted hover:text-text">Download them to try uploading</summary>
            <ul className="mt-2 grid gap-1">
              {DEMO_FILES.map((f) => (
                <li key={f}><a className="inline-flex items-center gap-1.5 hover:underline" href={demoFileUrl(f)} download><Download size={13} aria-hidden /> <span className="code">{f}</span></a></li>
              ))}
            </ul>
          </details>
        </div>
      </div>

      {paste && (
        <form className="grid gap-3 rounded-xl border border-line bg-panel p-4" onSubmit={(e) => { e.preventDefault(); void run("paste", () => api.paste(pasteName, pasteText)).then(() => setPasteText("")); }}>
          <label className="grid max-w-sm gap-1 text-sm text-muted">
            Name
            <input className="field code text-text" value={pasteName} onChange={(e) => setPasteName(e.target.value)} />
          </label>
          <label className="grid gap-1 text-sm text-muted">
            Log text
            <textarea className="field log min-h-48 py-2 text-text" value={pasteText} onChange={(e) => setPasteText(e.target.value)} placeholder="Nov  6 10:15:01 web-01 sshd[1201]: Failed password for root from 203.0.113.45 port 51122 ssh2" />
          </label>
          <button className="btn btn-primary w-fit" disabled={!pasteText.trim() || !!busy}>{busy === "paste" ? <Spinner /> : null} Analyse this text</button>
        </form>
      )}

      <Section
        title="Loaded files"
        aside={
          data?.length ? (
            confirmClear ? (
              <span className="flex items-center gap-2">
                <span>Remove all files and results?</span>
                <button className="btn btn-quiet min-h-8 px-3 text-sm text-critical" onClick={() => { setConfirmClear(false); void run("clear", api.clearDatasets); }}>Remove all</button>
                <button className="btn btn-ghost min-h-8 px-3 text-sm" onClick={() => setConfirmClear(false)}>Keep</button>
              </span>
            ) : (
              <button className="btn btn-ghost min-h-8 px-3 text-sm" onClick={() => setConfirmClear(true)}>Remove all</button>
            )
          ) : undefined
        }
      >
        {data?.length ? (
          <ul className="grid divide-y divide-line overflow-hidden rounded-xl border border-line">
            {data.map((d) => (
              <li key={d.id} className="grid gap-x-4 gap-y-1 bg-panel px-4 py-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
                <div className="min-w-0">
                  <p className="flex flex-wrap items-center gap-2">
                    <span className="code truncate font-medium">{d.name}</span>
                    {d.demo && <span className="rounded border border-line px-1.5 text-[0.72rem] text-muted">demo</span>}
                  </p>
                  <p className="text-sm text-muted">
                    {status?.formats[d.format ?? ""] ?? d.format}, {plural(d.events, "event")} from {num(d.lines)} {d.format?.startsWith("windows_") && d.format !== "windows_firewall" ? "records" : "lines"}, {bytes(d.size_bytes)}
                    {d.first_ts && d.last_ts ? `, ${when(d.first_ts)} to ${when(d.last_ts)}` : ""}
                  </p>
                  {d.skipped_samples.length > 0 && d.events < d.lines && (
                    <details className="mt-1 text-sm">
                      <summary className="cursor-pointer text-faint hover:text-muted">{num(d.lines - d.events)} lines weren't security events (examples)</summary>
                      <ul className="log mt-1 grid gap-0.5 text-faint">{d.skipped_samples.map((s, i) => <li key={i}>{s}</li>)}</ul>
                    </details>
                  )}
                </div>
                <button className="btn btn-ghost min-h-9 w-fit px-3 text-sm" onClick={() => void run(`del-${d.id}`, () => api.deleteDataset(d.id))} disabled={!!busy} aria-label={`Remove ${d.name}`}>
                  {busy === `del-${d.id}` ? <Spinner /> : <Trash2 size={15} />} Remove
                </button>
              </li>
            ))}
          </ul>
        ) : (
          <p className="rounded-xl border border-line px-5 py-6 text-muted">No files yet. Add some above, or load the demo logs.</p>
        )}
      </Section>
    </div>
  );
}
