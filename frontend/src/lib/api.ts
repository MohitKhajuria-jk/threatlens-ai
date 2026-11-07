import type {
  AlertDetail, Alert, ChatMessage, Dataset, IncidentDetail, IncidentState, IncidentSummary, IntelLookup, LogEvent, Overview, Status, StreamEvent, UploadResult,
} from "../types";
import { SseParser } from "./sse";

const OFFLINE = "Can't reach the ThreatLens backend. Start it on port 8001 (see the README), then try again.";
const WRONG_BACKEND = "Another app is answering instead of the ThreatLens backend. Start the ThreatLens backend on port 8001 (see the README), then reload.";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`/api${path}`, init?.body instanceof FormData ? init : { headers: { "Content-Type": "application/json" }, ...init });
  } catch {
    throw new Error(OFFLINE);
  }
  if (!res.ok) {
    let detail = `Request failed (${res.status}).`;
    try {
      const body = await res.json();
      if (typeof body.detail === "string") detail = body.detail;
      else if (Array.isArray(body.detail) && body.detail[0]?.msg) detail = body.detail[0].msg;
    } catch {
      if (res.status === 502 || res.status === 504) detail = OFFLINE;
    }
    throw new Error(detail);
  }
  return res.json() as Promise<T>;
}

const json = (method: string, body?: unknown): RequestInit => ({ method, body: body === undefined ? undefined : JSON.stringify(body), headers: { "Content-Type": "application/json" } });

export const api = {
  status: async () => {
    const s = await request<Status>("/status");
    if (!s || !("intel" in s) || !("counts" in s)) throw new Error(WRONG_BACKEND);
    return s;
  },
  overview: () => request<Overview>("/overview"),
  incidents: () => request<IncidentSummary[]>("/incidents"),
  incident: (id: string) => request<IncidentDetail>(`/incidents/${id}`),
  updateIncident: (id: string, patch: Partial<Pick<IncidentState, "status" | "notes" | "done">>) => request<IncidentState>(`/incidents/${id}`, json("PATCH", patch)),
  report: (id: string) => request<IncidentState>(`/incidents/${id}/report`, { method: "POST" }),
  alerts: (params: Record<string, string> = {}) => request<Alert[]>(`/alerts?${new URLSearchParams(params)}`),
  alert: (id: string) => request<AlertDetail>(`/alerts/${id}`),
  events: (params: Record<string, string | number>) =>
    request<{ total: number; events: LogEvent[] }>(`/events?${new URLSearchParams(Object.entries(params).filter(([, v]) => v !== "").map(([k, v]) => [k, String(v)]))}`),
  event: (id: number) => request<LogEvent>(`/events/${id}`),
  datasets: () => request<Dataset[]>("/datasets"),
  upload: (files: File[]) => {
    const form = new FormData();
    files.forEach((f) => form.append("files", f));
    return request<UploadResult>("/datasets", { method: "POST", body: form });
  },
  paste: (name: string, text: string) => request<UploadResult>("/datasets/paste", json("POST", { name, text })),
  loadDemo: () => request<UploadResult>("/datasets/demo", { method: "POST" }),
  deleteDataset: (id: string) => request<{ ok: boolean }>(`/datasets/${id}`, { method: "DELETE" }),
  clearDatasets: () => request<{ ok: boolean }>("/datasets", { method: "DELETE" }),
  lookup: (value: string) => request<IntelLookup>(`/intel/lookup?${new URLSearchParams({ value })}`),
  checkFile: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return request<IntelLookup>("/intel/file", { method: "POST", body: form });
  },
  refreshFeeds: () => request<Status["intel"] & { updated: number }>("/intel/refresh", { method: "POST" }),
  chat: (scope: string) => request<ChatMessage[]>(`/chat/${scope}`),
  clearChat: (scope: string) => request<{ ok: boolean }>(`/chat/${scope}`, { method: "DELETE" }),
};

export const demoSampleUrl = "/api/intel/demo-sample";
export const demoFileUrl = (name: string) => `/api/datasets/demo/download/${encodeURIComponent(name)}`;

/** Asks the investigator and calls `onEvent` for each step as it streams in. */
export async function ask(scope: string, content: string, onEvent: (e: StreamEvent) => void): Promise<void> {
  let res: Response;
  try {
    res = await fetch(`/api/chat/${scope}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ content }) });
  } catch {
    throw new Error(OFFLINE);
  }
  if (!res.ok || !res.body) throw new Error(`The question wasn't sent (${res.status}).`);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  const parser = new SseParser();
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    for (const { event, data } of parser.push(decoder.decode(value, { stream: true }))) onEvent({ type: event, data } as StreamEvent);
  }
}
