import { useEffect, useRef, useState, type DragEvent, type FormEvent } from "react";
import { Download, ExternalLink, FileSearch, RefreshCw, ScanSearch, TriangleAlert } from "lucide-react";
import type { PageProps } from "../App";
import type { IntelLookup } from "../types";
import { api, demoSampleUrl } from "../lib/api";
import { ago, bytes, num } from "../lib/format";
import { CopyButton, Mono, Section, Spinner, VerdictTag } from "../components/ui";

export function IntelPage({ route, status, notify, changed }: PageProps) {
  const [value, setValue] = useState(route.params.get("value") ?? "");
  const [result, setResult] = useState<IntelLookup | null>(null);
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [checking, setChecking] = useState<string | null>(null);
  const [drag, setDrag] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  async function checkFile(file: File) {
    setChecking(file.name);
    setResult(null);
    try {
      setResult(await api.checkFile(file));
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setChecking(null);
    }
  }

  function onDrop(e: DragEvent) {
    e.preventDefault();
    setDrag(false);
    const f = e.dataTransfer.files[0];
    if (f) void checkFile(f);
  }

  async function lookup(v: string) {
    if (!v.trim()) return;
    setBusy(true);
    try {
      setResult(await api.lookup(v.trim()));
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    const v = route.params.get("value");
    if (v) void lookup(v);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function submit(e: FormEvent) {
    e.preventDefault();
    void lookup(value);
  }

  async function refresh() {
    setRefreshing(true);
    try {
      const r = await api.refreshFeeds();
      notify(r.updated ? `${r.updated} feed(s) updated and the logs re-checked.` : "The feeds are already up to date (each is downloaded at most once an hour).");
      changed();
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setRefreshing(false);
    }
  }

  const feeds = status?.intel.feeds ?? [];
  return (
    <div className="grid gap-10">
      <header>
        <h1 className="display text-[2rem]">Threat intel</h1>
        <p className="mt-1 max-w-2xl text-muted">Check IP addresses, domains, file hashes and files against free blocklists and, if you've added keys, AbuseIPDB and VirusTotal. Every IP in your logs is checked against the feeds automatically.</p>
      </header>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1.25fr)_minmax(0,1fr)]">
        <form onSubmit={submit} className="grid content-start gap-3 rounded-xl border border-line bg-panel px-5 py-5">
          <div>
            <h2 className="display text-lg">Look up an indicator</h2>
            <p className="mt-1 text-sm text-muted">An IP address, a domain name, or an MD5, SHA-1 or SHA-256 file hash.</p>
          </div>
          <div className="flex flex-col gap-3 sm:flex-row">
            <label htmlFor="indicator" className="sr-only">IP address, domain or file hash</label>
            <input id="indicator" className="field code min-h-12 min-w-0 flex-1 text-base" placeholder="e.g. 203.0.113.45 or update-check.example" value={value} onChange={(e) => setValue(e.target.value)} />
            <button className="btn btn-primary min-h-12 px-5" disabled={busy || !value.trim()}>{busy ? <Spinner /> : <ScanSearch size={18} />} Check</button>
          </div>
        </form>

        <div
          onDragOver={(e) => (e.preventDefault(), setDrag(true))}
          onDragLeave={() => setDrag(false)}
          onDrop={onDrop}
          className={`grid content-start gap-3 rounded-xl border-2 border-dashed px-5 py-5 ${drag ? "border-text bg-panel-2" : "border-line-strong"}`}
        >
          <div>
            <h2 className="display text-lg">Check a file</h2>
            <p className="mt-1 text-sm text-muted">
              Drop a file you're unsure about. ThreatLens works out what kind of file it really is and its hashes, then checks them. The file isn't saved, and only its SHA-256 hash leaves this computer (to VirusTotal, if you've added a key).
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
            <button className="btn btn-quiet" onClick={() => fileInput.current?.click()} disabled={!!checking}>
              {checking ? <Spinner /> : <FileSearch size={17} />} {checking ? "Checking…" : "Choose a file"}
            </button>
            <a className="inline-flex items-center gap-1.5 text-sm text-muted hover:text-text hover:underline" href={demoSampleUrl} download>
              <Download size={13} aria-hidden /> Demo sample to try
            </a>
          </div>
          <input ref={fileInput} type="file" hidden onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ""; if (f) void checkFile(f); }} />
        </div>
      </div>

      {result && (
        <article className="grid gap-6 rounded-xl border border-line-strong bg-panel px-5 py-5 sm:px-6" aria-live="polite">
          <header className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-sm text-muted">{result.file ? "File" : result.type === "ip" ? "IP address" : result.type === "domain" ? "Domain" : "File hash"}</p>
              <Mono className="display text-[1.3rem] [overflow-wrap:anywhere]">{result.file ? result.file.name : result.indicator}</Mono>
            </div>
            <span className="text-base"><VerdictTag verdict={result.verdict} /></span>
          </header>
          {result.file && (
            <dl className="grid grid-cols-[5.5rem_minmax(0,1fr)] items-center gap-x-3 gap-y-1.5 text-sm">
              <dt className="text-muted">Type</dt>
              <dd className="flex flex-wrap items-center gap-2">
                {result.file.type}
                {result.file.can_run && <span className="inline-flex items-center gap-1 rounded-md bg-raised px-1.5 py-0.5 text-xs font-semibold text-high"><TriangleAlert size={12} aria-hidden /> Can run code</span>}
              </dd>
              <dt className="text-muted">Size</dt><dd className="tabular">{bytes(result.file.size)}</dd>
              {(["md5", "sha1", "sha256"] as const).map((k) => (
                <div key={k} className="contents">
                  <dt className="text-muted">{k === "md5" ? "MD5" : k === "sha1" ? "SHA-1" : "SHA-256"}</dt>
                  <dd className="flex min-w-0 items-center gap-2"><span className="code min-w-0 [overflow-wrap:anywhere]">{result.file![k]}</span><CopyButton text={result.file![k]} /></dd>
                </div>
              ))}
            </dl>
          )}
          {result.reasons.length ? <ul className="grid gap-1">{result.reasons.map((r) => <li key={r}>{r}</li>)}</ul> : <p className="text-muted">None of the sources know anything about it.</p>}
          <div className={`grid gap-4 ${result.type === "ip" ? "md:grid-cols-2" : ""}`}>
            {result.type === "ip" && <div className="rounded-lg border border-line px-4 py-3">
              <p className="font-semibold">AbuseIPDB</p>
              {result.abuseipdb ? (
                <dl className="mt-2 grid grid-cols-[7rem_minmax(0,1fr)] gap-y-1 text-sm">
                  <dt className="text-muted">Abuse score</dt><dd className="tabular">{result.abuseipdb.score ?? "–"}%</dd>
                  <dt className="text-muted">Reports</dt><dd className="tabular">{num(result.abuseipdb.reports ?? 0)}</dd>
                  {result.abuseipdb.country && <><dt className="text-muted">Country</dt><dd>{result.abuseipdb.country}</dd></>}
                  {result.abuseipdb.isp && <><dt className="text-muted">Network</dt><dd>{result.abuseipdb.isp}</dd></>}
                  {result.abuseipdb.usage && <><dt className="text-muted">Used for</dt><dd>{result.abuseipdb.usage}</dd></>}
                  <dd className="col-span-2 mt-1"><a className="inline-flex items-center gap-1 font-semibold hover:underline" href={result.abuseipdb.link} target="_blank" rel="noreferrer">Open on AbuseIPDB <ExternalLink size={13} /></a></dd>
                </dl>
              ) : (
                <p className="mt-1 text-sm text-muted">{result.errors.abuseipdb ?? (status?.intel.abuseipdb ? "Not checked." : "Add ABUSEIPDB_API_KEY to backend/.env to use it.")}</p>
              )}
            </div>}
            <div className="rounded-lg border border-line px-4 py-3">
              <p className="font-semibold">VirusTotal</p>
              {result.virustotal ? (
                result.virustotal.found ? (
                  <dl className="mt-2 grid grid-cols-[7rem_minmax(0,1fr)] gap-y-1 text-sm">
                    <dt className="text-muted">Malicious</dt><dd className="tabular">{result.virustotal.malicious} engines</dd>
                    <dt className="text-muted">Suspicious</dt><dd className="tabular">{result.virustotal.suspicious} engines</dd>
                    <dt className="text-muted">Harmless</dt><dd className="tabular">{result.virustotal.harmless} engines</dd>
                    {result.virustotal.owner && <><dt className="text-muted">Owner</dt><dd>{result.virustotal.owner}</dd></>}
                    {result.virustotal.name && <><dt className="text-muted">File name</dt><dd>{result.virustotal.name}</dd></>}
                    <dd className="col-span-2 mt-1"><a className="inline-flex items-center gap-1 font-semibold hover:underline" href={result.virustotal.link} target="_blank" rel="noreferrer">Open on VirusTotal <ExternalLink size={13} /></a></dd>
                  </dl>
                ) : (
                  <p className="mt-1 text-sm text-muted">VirusTotal has never seen it.</p>
                )
              ) : (
                <p className="mt-1 text-sm text-muted">{result.errors.virustotal ?? (status?.intel.virustotal ? "Not checked." : "Add VIRUSTOTAL_API_KEY to backend/.env to use it.")}</p>
              )}
            </div>
          </div>
          {/* The provider boxes above already say when a key is missing. */}
          {result.notes.some((n) => !n.includes("_API_KEY")) && (
            <ul className="grid gap-1 text-sm text-muted">{result.notes.filter((n) => !n.includes("_API_KEY")).map((n) => <li key={n}>{n}</li>)}</ul>
          )}
        </article>
      )}

      <Section
        title="Threat feeds"
        aside={
          <button className="btn btn-quiet min-h-9 text-sm" onClick={refresh} disabled={refreshing || !status?.intel.feeds_enabled}>
            {refreshing ? <Spinner /> : <RefreshCw size={15} />} Update feeds
          </button>
        }
      >
        {!status?.intel.feeds_enabled && <p className="mb-3 text-sm text-muted">Feeds are turned off (INTEL_FEEDS_ENABLED=false in backend/.env).</p>}
        <div className="overflow-hidden rounded-xl border border-line">
          <table className="w-full border-collapse text-left text-sm">
            <thead className="bg-panel text-muted">
              <tr>
                <th className="px-4 py-2.5 font-medium">Feed</th>
                <th className="hidden px-4 py-2.5 font-medium md:table-cell">What it lists</th>
                <th className="px-4 py-2.5 text-right font-medium">Entries</th>
                <th className="px-4 py-2.5 font-medium">Updated</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {feeds.map((f) => (
                <tr key={f.id} className="align-top">
                  <td className="px-4 py-3">
                    {f.homepage ? <a href={f.homepage} target="_blank" rel="noreferrer" className="font-semibold hover:underline">{f.name}</a> : <span className="font-semibold">{f.name}</span>}
                    <p className="text-muted md:hidden">{f.category}</p>
                  </td>
                  <td className="hidden px-4 py-3 text-muted md:table-cell">{f.category}</td>
                  <td className="tabular px-4 py-3 text-right">{f.entries ? num(f.entries) : "–"}</td>
                  <td className="px-4 py-3 text-muted">
                    {f.id === "demo" ? "Built in" : f.error ? <span className="text-high">{f.error}</span> : f.updated_at ? ago(f.updated_at) : status?.intel.refreshing ? "Downloading…" : "Not yet"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-3 text-xs text-faint">Spamhaus DROP data © The Spamhaus Project, used under its free-use terms. VirusTotal's free API is for personal, non-commercial use.</p>
      </Section>
    </div>
  );
}
