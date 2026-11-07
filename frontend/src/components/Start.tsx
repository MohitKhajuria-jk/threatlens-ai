import { useState } from "react";
import { FlaskConical, Upload } from "lucide-react";
import { api } from "../lib/api";
import { plural } from "../lib/format";
import { Reticle, Spinner } from "./ui";

/** First run: nothing is loaded yet. */
export function Start({ notify, changed }: { notify: (m: string, t?: "info" | "error") => void; changed: () => void }) {
  const [busy, setBusy] = useState(false);
  async function demo() {
    setBusy(true);
    try {
      const r = await api.loadDemo();
      notify(`Demo logs loaded: ${plural(r.analysis?.events ?? 0, "event")}, ${plural(r.analysis?.incidents ?? 0, "incident")} found.`);
      changed();
    } catch (e) {
      notify((e as Error).message, "error");
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="grid gap-10 py-6 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,1fr)] lg:items-center lg:py-14">
      <div className="max-w-xl">
        <Reticle size={56} spinning />
        <h1 className="display mt-6 text-[2.3rem] sm:text-[2.9rem]">Find the attack hiding in your logs.</h1>
        <p className="mt-4 text-[1.05rem] leading-relaxed text-muted">
          ThreatLens reads Linux, web server, Windows and firewall logs, flags suspicious activity, checks it against threat intelligence and pieces the
          alerts together into incidents you can investigate and respond to.
        </p>
        <div className="mt-7 flex flex-wrap gap-3">
          <a className="btn btn-primary" href="#/data">
            <Upload size={17} /> Upload logs
          </a>
          <button className="btn btn-quiet" onClick={demo} disabled={busy}>
            {busy ? <Spinner /> : <FlaskConical size={17} />} {busy ? "Analysing demo logs…" : "Try the demo logs"}
          </button>
        </div>
        <p className="mt-4 text-sm text-faint">The demo is a fictional day on a small company network with two real-world style attacks in it.</p>
      </div>
      <ul className="grid gap-px overflow-hidden rounded-xl border border-line bg-line text-sm">
        {[
          ["Linux auth and syslog", "auth.log, secure, UFW and iptables lines"],
          ["Web server access logs", "Apache and Nginx, common or combined format"],
          ["Windows event logs", ".evtx files, or JSON and CSV exports, including Sysmon"],
          ["Firewall logs", "Windows Firewall, CSV exports and key=value logs"],
        ].map(([name, detail]) => (
          <li key={name} className="bg-panel px-5 py-4">
            <p className="font-semibold">{name}</p>
            <p className="text-muted">{detail}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}
