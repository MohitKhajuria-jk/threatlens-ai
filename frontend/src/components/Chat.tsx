import { useEffect, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Check, CornerDownLeft, RotateCcw, Search } from "lucide-react";
import type { ChatMessage, ChatStep } from "../types";
import { api, ask } from "../lib/api";
import { linkCitations } from "../lib/format";
import { Reticle, Spinner } from "./ui";

function Answer({ message, onEvent }: { message: ChatMessage; onEvent: (id: number) => void }) {
  const known = new Set(message.cited.map((c) => c.id));
  return (
    <div className="prose-answer text-[0.95rem] leading-relaxed">
      <ReactMarkdown
        remarkPlugins={[remarkGfm]}
        components={{
          a: ({ href, children }) => {
            const m = href?.match(/^#event-(\d+)$/);
            if (m && known.has(Number(m[1]))) {
              const id = Number(m[1]);
              const cite = message.cited.find((c) => c.id === id);
              return (
                <button
                  type="button"
                  onClick={() => onEvent(id)}
                  title={cite?.raw}
                  className="code mx-0.5 rounded border border-line-strong bg-ink px-1 py-px align-baseline text-[0.74rem] text-text hover:border-muted"
                  aria-label={`Log event ${id}`}
                >
                  E{id}
                </button>
              );
            }
            return <a href={href} target="_blank" rel="noreferrer" className="underline">{children}</a>;
          },
        }}
      >
        {linkCitations(message.content)}
      </ReactMarkdown>
    </div>
  );
}

function Steps({ steps, live = false }: { steps: ChatStep[]; live?: boolean }) {
  if (!steps.length) return null;
  return (
    <ol className="mb-2 grid gap-1 text-[0.82rem] text-muted">
      {steps.map((s) => (
        <li key={s.id} className="flex items-start gap-2">
          <span className="mt-0.5">{s.status === "running" && live ? <Spinner className="size-3" /> : s.status === "error" ? <span className="text-critical">!</span> : <Check size={13} className="text-safe" />}</span>
          <span className="min-w-0">
            {s.label}
            {s.summary && <span className="text-faint">: {s.summary}</span>}
          </span>
        </li>
      ))}
    </ol>
  );
}

export function Chat({ scope, suggestions, ready, onEvent, compact = false, notify }: {
  scope: string;
  suggestions: string[];
  ready: boolean;
  onEvent: (id: number) => void;
  compact?: boolean;
  notify: (m: string, t?: "info" | "error") => void;
}) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [draft, setDraft] = useState("");
  const [pending, setPending] = useState<{ steps: ChatStep[] } | null>(null);
  const list = useRef<HTMLDivElement>(null);
  const input = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    api.chat(scope).then(setMessages, () => undefined);
  }, [scope]);

  useEffect(() => {
    const el = list.current;
    if (el) el.scrollTo({ top: el.scrollHeight, behavior: "smooth" });
  }, [messages.length, pending?.steps.length]);

  useEffect(() => {
    const el = input.current;
    if (!el) return;
    el.style.height = "auto";
    el.style.height = `${Math.min(el.scrollHeight, 160)}px`;
  }, [draft]);

  async function send(text: string) {
    const q = text.trim();
    if (!q || pending) return;
    setDraft("");
    setPending({ steps: [] });
    try {
      await ask(scope, q, (ev) => {
        if (ev.type === "user") setMessages((m) => [...m, ev.data]);
        else if (ev.type === "step" || ev.type === "step_done")
          setPending((p) => (p ? { steps: [...p.steps.filter((s) => s.id !== ev.data.step.id), ev.data.step].sort((a, b) => a.id - b.id) } : p));
        else if (ev.type === "answer") setMessages((m) => [...m, ev.data]);
        else if (ev.type === "error") {
          setMessages((m) => (m.length && m[m.length - 1].role === "user" && m[m.length - 1].content === q ? m.slice(0, -1) : m));
          setDraft(q);
          notify(ev.data.message, "error");
        }
      });
    } catch (e) {
      setDraft(q);
      notify((e as Error).message, "error");
    } finally {
      setPending(null);
    }
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    void send(draft);
  }
  function onKey(e: KeyboardEvent<HTMLTextAreaElement>) {
    if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault();
      void send(draft);
    }
  }

  return (
    <div className={`flex min-h-0 flex-col overflow-hidden rounded-xl border border-line bg-panel ${compact ? "" : "h-[calc(100dvh-13rem)] min-h-[30rem]"}`}>
      <div ref={list} className={`min-h-0 flex-1 overflow-y-auto px-4 py-4 sm:px-5 ${compact ? "max-h-[28rem]" : ""}`}>
        {!messages.length && !pending ? (
          <div className="grid gap-4 py-2">
            <div className="flex items-center gap-3 text-muted">
              <Reticle size={26} />
              <p className="text-sm">{ready ? "Ask a question and ThreatLens will search the logs, check threat intel and cite the lines it used." : "Add a Gemini key in backend/.env to use the investigator."}</p>
            </div>
            <ul className="flex flex-wrap gap-2">
              {suggestions.map((s) => (
                <li key={s}>
                  <button type="button" disabled={!ready} onClick={() => void send(s)} className="flex items-center gap-2 rounded-lg border border-line-strong px-3 py-2 text-left text-sm hover:bg-panel-2 disabled:opacity-50">
                    <Search size={14} className="shrink-0 text-muted" aria-hidden /> {s}
                  </button>
                </li>
              ))}
            </ul>
          </div>
        ) : (
          <div className="grid gap-5">
            {messages.map((m) =>
              m.role === "user" ? (
                <p key={m.id} className="ml-auto max-w-[88%] whitespace-pre-wrap rounded-xl rounded-br-sm bg-raised px-3.5 py-2.5 text-[0.95rem]">{m.content}</p>
              ) : (
                <div key={m.id} className="max-w-full">
                  <Steps steps={m.steps} />
                  <Answer message={m} onEvent={onEvent} />
                </div>
              ),
            )}
            {pending && (
              <div aria-live="polite">
                <Steps steps={pending.steps} live />
                <p className="flex items-center gap-2 text-sm text-muted">
                  <Spinner className="size-3.5" /> {pending.steps.some((s) => s.status === "running") ? "Investigating…" : pending.steps.length ? "Writing the answer…" : "Planning where to look…"}
                </p>
              </div>
            )}
          </div>
        )}
      </div>
      <form onSubmit={submit} className="border-t border-line p-3">
        <div className="flex items-end gap-2 rounded-lg border border-line-strong bg-ink p-1.5 pl-3 focus-within:border-muted">
          <label htmlFor={`ask-${scope}`} className="sr-only">Ask about the logs</label>
          <textarea
            id={`ask-${scope}`}
            ref={input}
            rows={1}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={onKey}
            disabled={!ready}
            placeholder={ready ? "Ask about these logs…" : "The AI analyst is off"}
            className="max-h-40 min-h-10 flex-1 resize-none bg-transparent py-2 text-[0.95rem] placeholder:text-faint focus:outline-none"
          />
          {messages.length > 0 && !pending && (
            <button type="button" className="btn btn-ghost min-h-10 px-2.5" onClick={() => api.clearChat(scope).then(() => setMessages([]))} aria-label="Clear the conversation" title="Clear the conversation">
              <RotateCcw size={16} />
            </button>
          )}
          <button type="submit" className="btn btn-primary min-h-10 px-3" disabled={!draft.trim() || !!pending || !ready} aria-label="Ask">
            <CornerDownLeft size={16} /> Ask
          </button>
        </div>
      </form>
    </div>
  );
}
