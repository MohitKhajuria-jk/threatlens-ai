import { useCallback, useEffect, useState } from "react";
import type { Status } from "./types";
import { api } from "./lib/api";
import { Shell, type Page } from "./components/Shell";
import { parseRoute, type Route } from "./lib/route";
import { Toast } from "./components/ui";
import { OverviewPage } from "./pages/Overview";
import { IncidentsPage } from "./pages/Incidents";
import { IncidentPage } from "./pages/Incident";
import { AlertsPage } from "./pages/Alerts";
import { LogsPage } from "./pages/Logs";
import { IntelPage } from "./pages/Intel";
import { DataPage } from "./pages/Data";
import { AskPage } from "./pages/Ask";

export interface PageProps {
  status: Status | null;
  version: number;
  notify: (message: string, tone?: "info" | "error") => void;
  changed: () => void;
  route: Route;
}

export default function App() {
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.hash));
  const [status, setStatus] = useState<Status | null>(null);
  const [version, setVersion] = useState(0);
  const [toast, setToast] = useState<{ message: string; tone: "info" | "error" } | null>(null);

  const notify = useCallback((message: string, tone: "info" | "error" = "info") => setToast({ message, tone }), []);
  const refreshStatus = useCallback(() => api.status().then(setStatus, (e: Error) => notify(e.message, "error")), [notify]);
  const changed = useCallback(() => {
    setVersion((v) => v + 1);
    void refreshStatus();
  }, [refreshStatus]);

  useEffect(() => {
    const onHash = () => {
      setRoute(parseRoute(window.location.hash));
      window.scrollTo({ top: 0 });
    };
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, []);

  useEffect(() => {
    void refreshStatus();
    const t = setInterval(() => void refreshStatus(), 30_000);
    return () => clearInterval(t);
  }, [refreshStatus]);

  useEffect(() => {
    const titles: Record<Page, string> = {
      overview: "Overview", incidents: "Incidents", incident: "Incident", alerts: "Alerts", logs: "Log search", intel: "Threat intel", data: "Log files", ask: "Ask ThreatLens",
    };
    document.title = `${titles[route.page]} | ThreatLens AI`;
  }, [route.page]);

  const props: PageProps = { status, version, notify, changed, route };
  const Page = {
    overview: OverviewPage, incidents: IncidentsPage, incident: IncidentPage, alerts: AlertsPage, logs: LogsPage, intel: IntelPage, data: DataPage, ask: AskPage,
  }[route.page];

  return (
    <Shell page={route.page} status={status}>
      <Page key={route.page === "incident" ? `incident-${route.id}` : route.page} {...props} />
      {toast && <Toast message={toast.message} tone={toast.tone} onDone={() => setToast(null)} />}
    </Shell>
  );
}
