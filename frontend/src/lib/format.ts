import type { Severity } from "../types";

const toDate = (v: string | number) => (typeof v === "number" ? new Date(v * 1000) : new Date(v));

/** "10:15" today, "Yesterday 10:15", "4 Nov 10:15" otherwise, in the viewer's timezone. */
export function when(v: string | number | null | undefined): string {
  if (v === null || v === undefined || v === "") return "";
  const d = toDate(v);
  const now = new Date();
  const time = d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  const day = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate()).getTime();
  if (day === today) return time;
  if (today - day === 86400000) return `Yesterday ${time}`;
  return `${d.toLocaleDateString(undefined, { day: "numeric", month: "short", ...(d.getFullYear() !== now.getFullYear() ? { year: "numeric" } : {}) })} ${time}`;
}

export function whenFull(v: string | number): string {
  return toDate(v).toLocaleString(undefined, { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

/** "6 Nov, 00:52 to 10:39" or "6 Nov 00:52 to 7 Nov 00:39". */
export function span(from: number, to: number): string {
  const a = new Date(from * 1000);
  const b = new Date(to * 1000);
  const t = (d: Date) => d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
  const day = (d: Date) => d.toLocaleDateString(undefined, { day: "numeric", month: "short" });
  return a.toDateString() === b.toDateString() ? `${day(a)}, ${t(a)} to ${t(b)}` : `${day(a)} ${t(a)} to ${day(b)} ${t(b)}`;
}

/** "a, b and c" */
export function list(items: string[]): string {
  return items.length <= 1 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

export function ago(v: string | number | null | undefined): string {
  if (v === null || v === undefined) return "";
  const s = Math.round((Date.now() - toDate(v).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} days ago`;
}

export function duration(from: string | number, to: string | number): string {
  const s = Math.max(0, Math.round((toDate(to).getTime() - toDate(from).getTime()) / 1000));
  if (s < 60) return `${s} s`;
  if (s < 3600) return `${Math.round(s / 60)} min`;
  const h = Math.floor(s / 3600);
  const m = Math.round((s % 3600) / 60);
  return m ? `${h} h ${m} min` : `${h} h`;
}

export const num = (n: number) => n.toLocaleString();

export function bytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(1)} MB`;
}

export function plural(n: number, word: string, many = `${word}s`): string {
  return `${num(n)} ${n === 1 ? word : many}`;
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low"];

export const SOURCE_NAMES: Record<string, string> = { linux: "Linux", web: "Web server", windows: "Windows", firewall: "Firewall" };

export const STATUS_NAMES: Record<string, string> = {
  open: "Open", investigating: "Investigating", contained: "Contained", resolved: "Resolved", false_positive: "False positive",
};

export const PHASE_NAMES: Record<string, string> = {
  contain: "Contain", investigate: "Investigate", eradicate: "Remove", recover: "Recover", harden: "Prevent",
};

/** Splits answer text into plain text and [E123] citation tokens. */
export function citationParts(text: string): Array<string | number> {
  const out: Array<string | number> = [];
  let last = 0;
  for (const m of text.matchAll(/\[E(\d+)\]/g)) {
    if (m.index! > last) out.push(text.slice(last, m.index));
    out.push(Number(m[1]));
    last = m.index! + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

/** Replaces [E123] with markdown links the renderer turns into citation chips. */
export function linkCitations(text: string): string {
  return text.replace(/\[E(\d+)\]/g, (_, n) => `[E${n}](#event-${n})`);
}
