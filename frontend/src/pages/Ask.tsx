import { useState } from "react";
import type { PageProps } from "../App";
import { Chat } from "../components/Chat";
import { EventDrawer } from "../components/Drawers";

export function AskPage({ status, notify }: PageProps) {
  const [event, setEvent] = useState<number | null>(null);
  return (
    <div className="grid gap-5">
      <header>
        <h1 className="display text-[2rem]">Ask ThreatLens</h1>
        <p className="mt-1 max-w-2xl text-muted">Ask questions about all your logs in plain language. The AI searches the logs and alerts, checks threat intel and cites the exact lines it used.</p>
      </header>
      <Chat
        scope="global"
        ready={!!status?.llm.ready}
        onEvent={setEvent}
        notify={notify}
        suggestions={[
          "Which accounts were compromised, and how?",
          "Is any internal machine talking to a malicious server?",
          "Which IPs attacked the web server, and did any attack work?",
          "Summarise what happened on WS-FIN-07",
        ]}
      />
      {event !== null && <EventDrawer id={event} onClose={() => setEvent(null)} />}
    </div>
  );
}
