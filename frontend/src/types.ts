export type Severity = "low" | "medium" | "high" | "critical";
export type Verdict = "malicious" | "suspicious" | "clean" | "unknown";
export type Source = "linux" | "web" | "windows" | "firewall";
export type IncidentStatus = "open" | "investigating" | "contained" | "resolved" | "false_positive";

export interface Technique {
  id: string;
  name: string;
  tactic: string;
  url: string;
}

export interface LogEvent {
  id: number;
  dataset_id: string;
  line: number;
  ts: string;
  source: Source;
  host: string | null;
  kind: string;
  outcome: string | null;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  user: string | null;
  message: string;
  fields: Record<string, unknown>;
  raw: string;
}

export interface Step {
  key: string;
  phase: "contain" | "investigate" | "eradicate" | "recover" | "harden";
  action: string;
  command: string | null;
  platform: string;
  rule: string;
}

export interface AnomalyInfo {
  score: number;
  label: string;
  reasons: string[];
}

export interface Alert {
  id: string;
  rule_id: string;
  title: string;
  short: string;
  severity: Severity;
  source: Source;
  techniques: string[];
  first_seen: number;
  last_seen: number;
  count: number;
  ip: string | null;
  user: string | null;
  host: string | null;
  description: string;
  incident_id: string | null;
  evidence_count?: number;
  details: { mitre?: Technique[]; anomaly?: AnomalyInfo; steps?: Step[]; [k: string]: unknown };
}

export interface AlertDetail extends Alert {
  evidence: number[];
  events: LogEvent[];
  intel: IntelVerdict | null;
}

export interface IntelVerdict {
  indicator: string;
  verdict: Verdict;
  reasons: string[];
  feeds: Array<{ feed: string; name: string; category: string; verdict: Verdict; demo: boolean }>;
  abuseipdb: AbuseResult | null;
  virustotal: VTResult | null;
}

export interface AbuseResult {
  score: number | null;
  reports: number | null;
  country: string | null;
  isp: string | null;
  usage: string | null;
  domain: string | null;
  is_tor: boolean | null;
  last_reported: string | null;
  link: string;
  cached_at?: number;
}

export interface VTResult {
  found: boolean;
  malicious?: number;
  suspicious?: number;
  harmless?: number;
  undetected?: number;
  reputation?: number | null;
  owner?: string | null;
  country?: string | null;
  name?: string | null;
  type?: string | null;
  link: string;
}

export interface IntelLookup extends IntelVerdict {
  type: "ip" | "domain" | "hash";
  errors: Record<string, string>;
  notes: string[];
  file?: CheckedFile;
}

export interface CheckedFile {
  name: string;
  size: number;
  type: string;
  md5: string;
  sha1: string;
  sha256: string;
  can_run: boolean;
}

export interface Report {
  summary: string;
  verdict: "true_positive" | "likely_true_positive" | "needs_review" | "likely_benign";
  confidence: "high" | "medium" | "low";
  severity: Severity | null;
  timeline: Array<{ time: string | null; stage: string; description: string; events: number[] }>;
  impact: string;
  affected: string[];
  mitre: Array<{ id: string; name: string; evidence: string }>;
  recommendations: Array<{ priority: number; phase: Step["phase"]; action: string; command: string | null; platform: string | null; why: string }>;
  open_questions: string[];
  warnings: string[];
}

export interface IncidentState {
  status: IncidentStatus;
  notes: string;
  done: string[];
  report: Report | null;
  report_at: number | null;
  report_model: string | null;
}

export interface IncidentSummary {
  id: string;
  title: string;
  severity: Severity;
  risk: number;
  first_seen: string;
  last_seen: string;
  ips: string[];
  users: string[];
  hosts: string[];
  assets: string[];
  tactics: string[];
  techniques: string[];
  sources: string[];
  severity_counts: Partial<Record<Severity, number>>;
  intel: Record<string, { verdict: Verdict; reasons: string[] }>;
  anomaly: Record<string, AnomalyInfo>;
  event_count: number;
  alerts: number;
  has_report: boolean;
  state: { status: IncidentStatus; report_at: number | null };
}

export interface IncidentDetail extends Omit<IncidentSummary, "alerts" | "state" | "has_report"> {
  alert_ids: string[];
  alerts: Alert[];
  steps: Step[];
  mitre: Technique[];
  indicators: { ips: string[]; domains: string[] };
  timeline: Array<LogEvent & { alert_id: string; alert_title: string; severity: Severity }>;
  intel_details: Record<string, IntelVerdict>;
  state: IncidentState;
}

export interface Dataset {
  id: string;
  name: string;
  format: string | null;
  source: Source | null;
  size_bytes: number;
  lines: number;
  events: number;
  skipped_samples: string[];
  demo: boolean;
  uploaded_at: number;
  first_ts: number | null;
  last_ts: number | null;
}

export interface Feed {
  id: string;
  name: string;
  url: string | null;
  homepage: string | null;
  category: string;
  verdict: Verdict;
  entries: number;
  updated_at: number | null;
  error: string | null;
  enabled: boolean;
}

export interface Status {
  llm: { ready: boolean; provider: string; model: string; fallback_model: string | null; using_fallback: boolean; label: string };
  intel: { feeds: Feed[]; feeds_enabled: boolean; refreshing: boolean; abuseipdb: boolean; virustotal: boolean };
  counts: { datasets: number; events: number; alerts: number; open_incidents: number; incidents: number };
  analyzed_at: number | null;
  timezone: string;
  formats: Record<string, string>;
  limits?: { upload_mb: number; check_mb: number };
}

export interface Overview {
  span: { start: number | null; end: number | null };
  events: number;
  sources: Partial<Record<Source, number>>;
  severity: Record<Severity, number>;
  alerts: number;
  alerts_by_source: Partial<Record<Source, number>>;
  tactics: Array<{ tactic: string; alerts: number }>;
  timeline: Array<{ t: string; events: number; failures: number; alerts: Partial<Record<Severity, number>> }>;
  top_attackers: Array<{ ip: string; alerts: number; severity: Severity; last_seen: number; rules: string[]; verdict: Verdict; country: string | null; abuse_score: number | null; events: number }>;
  incidents: Array<{ id: string; title: string; severity: Severity; risk: number; last_seen: string; ips: string[]; hosts: string[]; tactics: string[]; status: IncidentStatus; alerts: number }>;
  recent_alerts: Array<Pick<Alert, "id" | "title" | "severity" | "source" | "last_seen" | "ip" | "incident_id" | "count">>;
  anomalies: Array<{ ip: string; score: number; outlier: boolean; reasons: string[]; features: Record<string, number> }>;
  intel_matches: number;
  analyzed_at: number | null;
}

export interface ChatStep {
  id: number;
  tool: string;
  label: string;
  status: "running" | "done" | "error";
  summary?: string;
}

export interface ChatMessage {
  id: number;
  role: "user" | "assistant";
  content: string;
  steps: ChatStep[];
  cited: Array<Pick<LogEvent, "id" | "ts" | "source" | "host" | "kind" | "src_ip" | "user" | "message" | "raw">>;
  created_at: number;
}

export interface UploadResult {
  added: Dataset[];
  errors: Array<{ file: string; error: string }>;
  analysis: { events: number; alerts: number; incidents: number; by_severity: Record<Severity, number>; seconds: number } | null;
}

export type StreamEvent =
  | { type: "user"; data: ChatMessage }
  | { type: "step" | "step_done"; data: { step: ChatStep } }
  | { type: "answer"; data: ChatMessage }
  | { type: "error"; data: { message: string } }
  | { type: "done"; data: Record<string, never> };
